const { AsyncLocalStorage } = require('async_hooks');
const path = require('path');
const fs = require('fs');
const { getStore } = require('./jsonStore');

const ctx = new AsyncLocalStorage();
const SYSTEM_UID = '__system__';
const ROOT = path.join(__dirname, '..', 'data', 'users');

function currentUserId() {
  return ctx.getStore()?.userId || SYSTEM_UID;
}

function userDir(userId = SYSTEM_UID) {
  const safe = String(userId || SYSTEM_UID).replace(/[^a-zA-Z0-9_-]/g, '_');
  const dir = path.join(ROOT, safe);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function scopedStore(filename, defaults) {
  const cache = new Map();
  function pick() {
    const uid = currentUserId();
    if (!cache.has(uid)) cache.set(uid, getStore(path.join(userDir(uid), filename), defaults));
    return cache.get(uid);
  }
  return {
    read() { return pick().read(); },
    write(value) { return pick().write(value); },
    touch() { return pick().touch(); },
    flush() { return pick().flush(); },
    flushSync() { return pick().flushSync(); },
    async get() { return pick().read(); },
    async set(value) {
      pick().write(value);
      await pick().flush();
    },
  };
}

module.exports = {
  ctx,
  userCtx: ctx,
  currentUserId,
  scopedStore,
  SYSTEM_UID,
};
