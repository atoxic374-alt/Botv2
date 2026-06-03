/**
 * jsonStore.js — safe persistent JSON storage.
 *
 * Fixes the three problems we had with naive `fs.writeFileSync(JSON.stringify(...))`:
 *
 *   1. Concurrent writes corrupting the file
 *      → all writes go through a per-file promise queue (mutex).
 *      → writes are atomic: write to `<file>.tmp` then rename.
 *
 *   2. No backups
 *      → before every write we rotate the current file to `<file>.bak.0`,
 *        keeping up to MAX_BACKUPS generations. On load failure we
 *        automatically restore from the newest valid backup.
 *
 *   3. Slow growth (history log etc.)
 *      → reads are served from an in-memory cache (one parse at boot).
 *      → writes are debounced/coalesced — many `.write()` calls within
 *        WRITE_DEBOUNCE_MS produce a single disk write.
 *      → on SIGINT/SIGTERM/beforeExit we flush synchronously so nothing
 *        pending is lost.
 */
const fs = require('fs');
const path = require('path');

const MAX_BACKUPS = 3;
const WRITE_DEBOUNCE_MS = 250;

const stores = new Map();

class JsonStore {
  constructor(filePath, defaults) {
    this.filePath = filePath;
    this.defaults = defaults;
    this.cache = null;
    this.dirty = false;
    this.pendingTimer = null;
    this.writeQueue = Promise.resolve();
    this._ensureDir();
    this._load();
  }

  _ensureDir() {
    try { fs.mkdirSync(path.dirname(this.filePath), { recursive: true }); } catch {}
  }

  _cloneDefaults() {
    return JSON.parse(JSON.stringify(this.defaults));
  }

  _load() {
    // Try the main file first, then walk through backups.
    const candidates = [this.filePath];
    for (let i = 0; i < MAX_BACKUPS; i++) candidates.push(`${this.filePath}.bak.${i}`);
    for (const p of candidates) {
      try {
        if (!fs.existsSync(p)) continue;
        const raw = fs.readFileSync(p, 'utf8');
        const trimmed = raw.trim();
        if (!trimmed) continue;
        this.cache = JSON.parse(trimmed);
        if (p !== this.filePath) {
          console.warn(`[jsonStore] restored ${this.filePath} from ${p}`);
          this._writeSyncAtomic(this.cache);
        }
        return;
      } catch (e) {
        console.warn(`[jsonStore] failed to read ${p}: ${e.message}`);
      }
    }
    this.cache = this._cloneDefaults();
    this._writeSyncAtomic(this.cache);
  }

  read() {
    return this.cache;
  }

  /**
   * Persist a value. Caller may pass back the same reference (mutated)
   * or a brand new object. Either way we mark dirty and schedule a flush.
   */
  write(value) {
    this.cache = value;
    this.dirty = true;
    this._scheduleFlush();
  }

  /** Mark the in-memory cache as dirty without replacing the reference. */
  touch() {
    this.dirty = true;
    this._scheduleFlush();
  }

  _scheduleFlush() {
    if (this.pendingTimer) return;
    this.pendingTimer = setTimeout(() => {
      this.pendingTimer = null;
      this._flushAsync();
    }, WRITE_DEBOUNCE_MS);
  }

  _flushAsync() {
    if (!this.dirty) return;
    const snapshot = this.cache;
    this.dirty = false;
    this.writeQueue = this.writeQueue.then(async () => {
      try {
        await this._writeAtomicAsync(snapshot);
      } catch (e) {
        console.warn(`[jsonStore] write failed for ${this.filePath}: ${e.message}`);
        // Keep dirty so next scheduled flush retries.
        this.dirty = true;
        this._scheduleFlush();
      }
    });
  }

  /** Wait for any pending writes to complete (async). */
  async flush() {
    if (this.pendingTimer) {
      clearTimeout(this.pendingTimer);
      this.pendingTimer = null;
      this._flushAsync();
    }
    await this.writeQueue;
  }

  /** Synchronously persist any pending writes — for shutdown handlers. */
  flushSync() {
    if (this.pendingTimer) {
      clearTimeout(this.pendingTimer);
      this.pendingTimer = null;
    }
    if (this.dirty) {
      this.dirty = false;
      try { this._writeSyncAtomic(this.cache); }
      catch (e) { console.warn(`[jsonStore] sync flush failed for ${this.filePath}: ${e.message}`); }
    }
  }

  _rotateBackups() {
    try {
      if (!fs.existsSync(this.filePath)) return;
      // Shift bak.(n-1) → bak.n
      for (let i = MAX_BACKUPS - 1; i > 0; i--) {
        const src = `${this.filePath}.bak.${i - 1}`;
        const dst = `${this.filePath}.bak.${i}`;
        if (fs.existsSync(src)) {
          try { fs.renameSync(src, dst); } catch {}
        }
      }
      // Current file → bak.0
      try { fs.copyFileSync(this.filePath, `${this.filePath}.bak.0`); } catch {}
    } catch {}
  }

  async _writeAtomicAsync(value) {
    this._rotateBackups();
    const tmp = `${this.filePath}.tmp`;
    const json = JSON.stringify(value, null, 2);
    await fs.promises.writeFile(tmp, json, 'utf8');
    await fs.promises.rename(tmp, this.filePath);
  }

  _writeSyncAtomic(value) {
    this._rotateBackups();
    const tmp = `${this.filePath}.tmp`;
    const json = JSON.stringify(value, null, 2);
    fs.writeFileSync(tmp, json, 'utf8');
    fs.renameSync(tmp, this.filePath);
  }
}

function getStore(filePath, defaults = {}) {
  const abs = path.resolve(filePath);
  if (!stores.has(abs)) stores.set(abs, new JsonStore(abs, defaults));
  return stores.get(abs);
}

function flushAllSync() {
  for (const s of stores.values()) {
    try { s.flushSync(); } catch {}
  }
}

// Persist everything on shutdown so we never lose buffered writes.
let _installedShutdown = false;
function installShutdownHandlers() {
  if (_installedShutdown) return;
  _installedShutdown = true;
  const handler = (signal) => {
    flushAllSync();
    if (signal === 'SIGINT' || signal === 'SIGTERM') process.exit(0);
  };
  process.on('SIGINT',  () => handler('SIGINT'));
  process.on('SIGTERM', () => handler('SIGTERM'));
  process.on('beforeExit', () => flushAllSync());
}
installShutdownHandlers();

module.exports = { getStore, flushAllSync };
