// TrueStudioManager — TOTP-based Discord automation (accounts + teams + bots).
// Replaces the old captcha-based BotsManager with a more reliable, batched
// orchestrator. Stores email/password/2FA secret per account (encrypted on
// the server) and runs a configurable pipeline: create team → create bots →
// link bots into the team. Live progress + countdown + log are streamed via SSE.
import { showNotification, showConfirm } from '../utils/ui.js';
import { copyToClipboard } from '../utils/clipboard.js';
import { t, getLang } from '../utils/i18n.js';
import { sfx } from '../utils/sounds.js';

const VERSION = '6.0';
const OWNER_NAME = 'Ahmed (4_3a)';
const DISCORD_INVITE = 'https://discord.gg/ens';
const DISCORD_LABEL = 'discord.gg/ens';

export class TrueStudioManager {
  constructor(contentArea) {
    this.contentArea = contentArea;
    this.accounts = [];               // [{email, hasPassword, hasTotp, hasDirectToken, addedAt}]
    this.snapshot = null;
    this.selectedEmail = null;
    this.form = {
      email: '',
      password: '',
      totpSecret: '',
      directToken: '',
      rules: { createTeams: false, createBots: true, linkBots: false },
      count: 10,
      prefix: 'True-Studio',
      waitMinutes: 15,
      proxyUrl: '',
      speed: 'medium',
      selectedTeamId: '',
      brightData: {
        enabled:      false,
        customerId:   '',
        zoneName:     '',
        zonePassword: '',
        protocol:     'http', // 'http' (port 33335) | 'socks5h' (port 22228)
      },
      batchSize: 1,
      sessionBudget: 0,
    };
    this.sse = null;
    this._countdownTimer = null;
    this._inited = false;
    this.library = null;          // { teams: [...], personal: [...], totals: {}, currentUserId }
    this.libraryEmail = null;     // which account is currently loaded
    this.libraryLoading = false;
    this.libraryError = '';
    this.currentUserId = null;    // Discord user ID of selected account
    // Captcha solver settings + the currently-open manual challenge modal.
    this.captchaSettings = { provider: '2captcha', hasApiKey: false, manualFallback: true };
    this._captchaModal = null;     // DOM root of the open modal (or null)
    this._captchaCurrentId = null; // id of the challenge the modal is solving
    this._hcaptchaLoaded = false;  // lazy-loaded the hCaptcha script yet?
    this._captchaVerifyResult = null; // { ok, balance, currency, provider, error } | null
    this._logFilter = 'all';       // 'all' | 'success' | 'info' | 'warn' | 'error'
    this._logAutoScroll = true;    // whether log auto-scrolls on new entries
    this.botTokens = [];              // persistent saved tokens [{appId,name,icon,token,resetAt,email}]
    this._resetAllInFlight = false;   // guard: only one reset-all at a time
    this.availableTeams = [];         // [{id, name, appCount}] for linkBots dropdown
    this._teamsLoading = false;       // loading state for team dropdown
    this._proxyTestResult = null;     // { ok, ip } | { error } | null
    this._pfpPreviewVisible = false;  // toggle pfp preview section
    this._intentsAllRunning = false;  // guard: only one intents-all at a time
    this._pfpAllRunning = false;      // guard: only one pfp-all at a time
    this._autoIntents = false;        // auto-enable intents when creating new bots
    this.pfp = { avatar: null, banner: null, updatedAt: 0 };
    this.bulkTokensText = '';         // raw textarea content for bulk token import
  }

  async init() {
    if (!this._inited) {
      await this.refresh();
      await this._loadCaptchaSettings();
      await this._loadBotTokens();
      await this._loadPfp();
      await this._loadAutoIntents();
      this.openSSE();
      this._startCountdownTicker();
      this._inited = true;
    } else {
      await this.refresh();
      await this._loadBotTokens();
      await this._loadPfp();
    }
    this.render();
    // If a captcha is already pending when this view opens, surface the modal.
    this._maybeOpenCaptchaModal();
  }

  async _loadCaptchaSettings() {
    try {
      const r = await window.electronAPI.tsCaptchaSettings();
      if (r && r.settings) this.captchaSettings = r.settings;
    } catch (e) { /* non-fatal */ }
  }

  async refresh() {
    try {
      const r = await window.electronAPI.tsState();
      this.snapshot = r?.snapshot || null;
      this.accounts = r?.accounts || [];
      // Auto-select the most recently added account if nothing is selected
      if (!this.selectedEmail && this.accounts.length) {
        this.selectedEmail = this.accounts[0].email;
      } else if (this.selectedEmail && !this.accounts.find(a => a.email === this.selectedEmail)) {
        this.selectedEmail = this.accounts[0]?.email || null;
      }
      // Mirror selected email into the editor inputs (so password/2FA placeholders update)
      if (this.selectedEmail) this.form.email = this.selectedEmail;
    } catch (e) {
      showNotification('Failed to load True-Studio state: ' + e.message, 'error');
    }
  }

  openSSE() {
    try {
      const types = [
        'ts_progress', 'ts_log', 'ts_bot_created', 'ts_done',
        'ts_captcha', 'ts_captcha_resolved', 'ts_captcha_cancelled', 'ts_captcha_timeout',
        'ts_reset_all_progress', 'ts_reset_all_done',
      ].join(',');
      this.sse = new EventSource(`/api/features/stream?types=${types}`);
      this.sse.onmessage = (ev) => {
        try {
          const data = JSON.parse(ev.data);
          if (data.snapshot) this.snapshot = data.snapshot;
          if (data.type === 'ts_done') sfx.ding?.();
          if (data.type === 'ts_bot_created') {
            sfx.click?.();
            // Reload botTokens so the Created Bots tab can cross-reference them
            this._loadBotTokens().then(() => {
              this._updateTokensTabBadge();
              if (this._libModal && this._libCurrentTab === 'created') this._renderLibraryTab();
            });
          }
          if (data.type === 'ts_captcha') {
            sfx.ding?.();
            this._openCaptchaModal(data.challenge || data.snapshot?.pendingCaptcha);
          }
          if (data.type === 'ts_captcha_resolved' || data.type === 'ts_captcha_cancelled' || data.type === 'ts_captcha_timeout') {
            this._closeCaptchaModal();
          }
          // ── Reset-All SSE events ─────────────────────────
          if (data.type === 'ts_reset_all_progress' && data.resetAll) {
            const ra = data.resetAll;
            this._resetAllInFlight = ra.state === 'running';
            this._updateTokensTabBadge();
            if (this._resetAllProgress) {
              if (ra.current) this._resetAllProgress.update(ra.done + ra.failed + 1, ra.current);
              if (data.lastBot) {
                this._resetAllProgress.success(ra.done, data.lastBot.name);
                const idx = this.botTokens.findIndex(t => t.appId === data.lastBot.appId);
                if (idx >= 0) this.botTokens.splice(idx, 1);
                this.botTokens.unshift({ appId: data.lastBot.appId, name: data.lastBot.name, icon: data.lastBot.icon || null, token: data.lastBot.token, resetAt: Date.now() });
                this._updateTokensTabBadge();
                if (this._libModal && this._libCurrentTab === 'tokens') this._renderLibraryTab();
                this._refreshBotTokensUI();
              } else if (ra.failed > (this._raLastFailed || 0)) {
                this._raLastFailed = ra.failed;
                this._resetAllProgress.fail(ra.done + ra.failed, ra.current || '?', '');
              }
            }
          }
          if (data.type === 'ts_reset_all_done' && data.resetAll) {
            this._resetAllInFlight = false;
            this._raLastFailed = 0;
            this._updateTokensTabBadge();
            const ra = data.resetAll;
            if (this._resetAllProgress) {
              this._resetAllProgress.done({ ok: ra.done, failed: ra.failed });
              this._resetAllProgress = null;
            }
            this._loadBotTokens().then(() => {
              this._refreshBotTokensUI();
              if (this._libModal && this._libCurrentTab === 'tokens') this._renderLibraryTab();
              setTimeout(() => { this._switchLibraryTab('tokens'); sfx.ding?.(); }, 1200);
            });
          }
          this._renderLive();
        } catch (e) {}
      };
      this.sse.onerror = () => {};
    } catch (e) {}
  }

  // ── Manual captcha modal ────────────────────────────────────
  _maybeOpenCaptchaModal() {
    const pc = this.snapshot?.pendingCaptcha;
    if (pc && pc.id && (!this._captchaModal || this._captchaCurrentId !== pc.id)) {
      this._openCaptchaModal(pc);
    }
  }

  _ensureHcaptchaScript() {
    return new Promise((resolve) => {
      if (window.hcaptcha) { this._hcaptchaLoaded = true; return resolve(true); }
      // Use the explicit-render API so we control when widgets mount.
      const sc = document.createElement('script');
      sc.src = 'https://js.hcaptcha.com/1/api.js?render=explicit&recaptchacompat=off';
      sc.async = true; sc.defer = true;
      sc.onload = () => { this._hcaptchaLoaded = true; resolve(true); };
      sc.onerror = () => resolve(false);
      document.head.appendChild(sc);
    });
  }

  async _openCaptchaModal(challenge) {
    if (!challenge || !challenge.id) return;
    // If we already have a modal open for the same challenge, leave it alone.
    if (this._captchaModal && this._captchaCurrentId === challenge.id) return;
    this._closeCaptchaModal();

    this._captchaCurrentId = challenge.id;
    const ctx = challenge.context || 'discord';
    const sitekey = challenge.sitekey || '';
    // rqdata binds the produced hCaptcha token to Discord's specific request.
    // Without it, even a perfectly-solved captcha returns
    // {captcha_key:["invalid-response"]} from Discord's API.
    const rqdata = challenge.rqdata || null;

    const overlay = document.createElement('div');
    overlay.className = 'ts-captcha-overlay';
    overlay.innerHTML = `
      <div class="ts-captcha-modal">
        <div class="ts-captcha-head">
          <div class="ts-captcha-title">${escapeHtml(t('ts.captcha_modal_title') || 'Solve captcha challenge')}</div>
          <button class="ts-captcha-close" type="button" aria-label="close">×</button>
        </div>
        <div class="ts-captcha-body">
          <div class="ts-captcha-context">${escapeHtml(t('ts.captcha_context_label') || 'Context')}: <b>${escapeHtml(ctx)}</b></div>
          <div class="ts-captcha-hint">${escapeHtml(t('ts.captcha_hint') || 'Discord requested verification. Click the checkbox below to continue. The session is paused until you solve it (5 min timeout).')}</div>
          <div id="ts-hcaptcha-mount" class="ts-captcha-widget"></div>
          <div class="ts-captcha-loading">${escapeHtml(t('ts.captcha_loading') || 'Loading hCaptcha…')}</div>
          <div class="ts-captcha-fallback">
            ${escapeHtml(t('ts.captcha_fallback_hint') || 'Widget not loading?')}
            <a href="https://newassets.hcaptcha.com/captcha/v1/demo?sitekey=${encodeURIComponent(sitekey)}" target="_blank" rel="noopener">${escapeHtml(t('ts.captcha_open_external') || 'Open in new tab')}</a>
            <textarea id="ts-captcha-token" class="ts-input" rows="3" placeholder="${escapeHtml(t('ts.captcha_paste_token') || 'Paste captcha token here…')}"></textarea>
            <button class="ts-btn mint" id="ts-captcha-submit">${escapeHtml(t('ts.captcha_submit') || 'Submit token')}</button>
          </div>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);
    this._captchaModal = overlay;

    overlay.querySelector('.ts-captcha-close')?.addEventListener('click', () => this._cancelCaptcha());
    overlay.querySelector('#ts-captcha-submit')?.addEventListener('click', () => {
      const ta = overlay.querySelector('#ts-captcha-token');
      const tok = (ta?.value || '').trim();
      if (tok) this._submitCaptchaToken(tok);
      else showNotification(t('ts.captcha_paste_token') || 'Paste a token first', 'error');
    });

    // Try to render the widget. If hCaptcha can't load (network/CSP), the
    // fallback textarea + external link is always available.
    const ok = await this._ensureHcaptchaScript();
    if (ok && window.hcaptcha) {
      try {
        const mount = overlay.querySelector('#ts-hcaptcha-mount');
        const loading = overlay.querySelector('.ts-captcha-loading');
        if (loading) loading.style.display = 'none';
        const renderOpts = {
          sitekey,
          theme: 'dark',
          callback: (token) => this._submitCaptchaToken(token),
          'error-callback': () => {
            showNotification(t('ts.captcha_widget_error') || 'hCaptcha widget error — paste token manually', 'error');
          },
        };
        // Bind the solution to Discord's specific challenge. Required —
        // omitting this causes Discord to reject the captcha as "invalid-response".
        if (rqdata) renderOpts.rqdata = rqdata;
        window.hcaptcha.render(mount, renderOpts);
      } catch (e) {
        showNotification('hCaptcha render failed: ' + (e.message || e), 'error');
      }
    } else {
      const loading = overlay.querySelector('.ts-captcha-loading');
      if (loading) loading.textContent = t('ts.captcha_widget_blocked') || 'hCaptcha could not load — use the external link or paste a token.';
    }
  }

  async _submitCaptchaToken(token) {
    if (!this._captchaCurrentId) return;
    try {
      await window.electronAPI.tsResolveCaptcha(this._captchaCurrentId, token);
      showNotification(t('ts.captcha_submitted') || 'Captcha submitted ✓', 'success');
      this._closeCaptchaModal();
    } catch (e) {
      showNotification(e.message || 'Submit failed', 'error');
    }
  }

  async _cancelCaptcha() {
    if (!this._captchaCurrentId) { this._closeCaptchaModal(); return; }
    try { await window.electronAPI.tsCancelCaptcha(this._captchaCurrentId); } catch {}
    this._closeCaptchaModal();
  }

  _closeCaptchaModal() {
    if (this._captchaModal && this._captchaModal.parentNode) {
      this._captchaModal.parentNode.removeChild(this._captchaModal);
    }
    this._captchaModal = null;
    this._captchaCurrentId = null;
  }

  _startCountdownTicker() {
    if (this._countdownTimer) return;
    this._countdownTimer = setInterval(() => {
      // Re-render only the status card during a wait so the countdown updates smoothly
      const s = this.snapshot;
      if (s && s.state === 'waiting' && s.waitUntilTs > Date.now()) {
        const el = this.contentArea.querySelector('#ts-status-value');
        const bar = this.contentArea.querySelector('#ts-countdown-bar > span');
        if (el && bar) {
          const left = Math.max(0, s.waitUntilTs - Date.now());
          const total = Math.max(1, s.waitTotalMs || 1);
          const elapsedPct = Math.min(100, Math.max(0, ((total - left) / total) * 100));
          el.innerHTML = `${t('ts.state_waiting')} <span class="ts-stat-extra">(${this._fmtMs(left)})</span>`;
          bar.style.width = elapsedPct + '%';
        }
      }
      this.contentArea.querySelectorAll('[data-ts-account-hold-until]').forEach(node => {
        const until = Number(node.getAttribute('data-ts-account-hold-until') || 0);
        node.textContent = this._fmtMs(Math.max(0, until - Date.now()));
      });
    }, 500);
  }

  _fmtMs(ms) {
    const total = Math.max(0, Math.round(ms / 1000));
    const m = Math.floor(total / 60);
    const s = total % 60;
    return `${String(m).padStart(1, '0')}:${String(s).padStart(2, '0')}`;
  }

  _stateMeta(state) {
    const map = {
      idle:      { label: t('ts.state_idle'),      cls: '',       fmt: 'plain' },
      running:   { label: t('ts.state_running'),   cls: 'mint',   fmt: 'plain' },
      waiting:   { label: t('ts.state_waiting'),   cls: 'mint',   fmt: 'wait'  },
      done:      { label: t('ts.state_done'),      cls: 'mint',   fmt: 'plain' },
      cancelled: { label: t('ts.state_cancelled'), cls: 'warn',   fmt: 'plain' },
      error:     { label: t('ts.state_error'),     cls: 'danger', fmt: 'plain' },
    };
    return map[state] || map.idle;
  }

  // ── Render ───────────────────────────────────────────
  render() {
    const s = this.snapshot || { state: 'idle', total: 0, done: 0, failed: 0, bots: [], log: [] };
    const meta = this._stateMeta(s.state);
    const sel = this.accounts.find(a => a.email === this.selectedEmail) || null;

    this.contentArea.innerHTML = `
      <div class="ts-wrap" dir="rtl">
        <div class="ts-brand">
          <div class="ts-brand-main">
            <div class="ts-brand-pulse" title="online"></div>
            <div class="ts-brand-title">
              <div class="ts-brand-name">Bot-Studio</div>
              <div class="ts-brand-sub">Automation Ultra · v${VERSION}</div>
            </div>
          </div>
          <div class="ts-credit-panel" aria-label="Owner credit">
            <span class="ts-credit-kicker">OWNER</span>
            <span class="ts-credit-name">${escapeHtml(OWNER_NAME)}</span>
            <a class="ts-credit-link" href="${escapeAttr(DISCORD_INVITE)}" target="_blank" rel="noopener">${escapeHtml(DISCORD_LABEL)}</a>
          </div>
        </div>

        <div class="ts-stats">
          <div class="ts-stat">
            <div class="ts-stat-label">${t('ts.live_progress')}</div>
            <div class="ts-stat-value" id="ts-progress-value">${this._renderProgress(s)}</div>
          </div>
          <div class="ts-stat">
            <div class="ts-stat-label">${t('ts.automation_status')}</div>
            <div class="ts-stat-value ${meta.cls}" id="ts-status-value">${this._renderStatus(s, meta)}</div>
            ${s.state === 'waiting' ? `<div class="ts-countdown-bar" id="ts-countdown-bar"><span style="width:0%"></span></div>` : ''}
          </div>
        </div>
        ${this._renderAccountRateLimits(s)}

        <!-- Live account pool panel -->
        <div id="ts-account-pool">${this._renderAccountPool(s)}</div>

        <!-- Account picker -->
        <div class="ts-card">
          <div class="ts-card-head">
            <div class="ts-card-title ar">${t('ts.accounts_section')}</div>
          </div>
          <div class="ts-field">
            <div class="ts-field-label">${t('ts.active_account')}</div>
            <div class="ts-account-row">
              <button class="ts-btn danger" id="ts-acct-delete" ${sel ? '' : 'disabled'}>${t('ts.delete')}</button>
              <button class="ts-btn mint" id="ts-acct-save">${t('ts.save_account')}</button>
              <select class="ts-select" id="ts-acct-select">
                <option value="">${t('ts.choose_or_add')}</option>
                ${this.accounts.map(a => `
                  <option value="${escapeAttr(a.email)}" ${a.email === this.selectedEmail ? 'selected' : ''}>${this._optionLabel(a)}</option>
                `).join('')}
              </select>
            </div>
            <div class="ts-account-row" style="margin-top:8px;">
              <button class="ts-btn" id="ts-acct-test" ${sel ? '' : 'disabled'}>${t('ts.test_account')}</button>
              <div></div>
              <div id="ts-verify-info" class="ts-verify-info">${this._verifyLabel(sel)}</div>
            </div>
            ${this.accounts.length === 0 ? `<div class="ts-account-empty">${t('ts.no_accounts_yet')}</div>` : ''}
          </div>
        </div>

        <!-- Selected account credentials -->
        <div class="ts-card">
          <div class="ts-card-head">
            <div class="ts-card-title ar">${t('ts.account_data')}</div>
          </div>

          <!-- ── Method A: Direct Token ──────────────────── -->
          <div class="ts-method-banner">
            <span class="ts-method-badge token">${t('ts.method_a_badge')}</span>
            <span class="ts-method-hint">${t('ts.method_a_hint')}</span>
          </div>
          <div class="ts-field">
            <div class="ts-field-label">Discord User Token</div>
            <input type="password" id="ts-direct-token" class="ts-input ltr"
              value=""
              placeholder="${sel?.hasDirectToken ? `•••••••••••• ${t('ts.direct_token_saved_ph')}` : t('ts.direct_token_ph')}"
              autocomplete="off" />
            ${sel?.hasDirectToken ? `<div class="ts-field-hint ok">${t('ts.direct_token_saved_hint')}</div>` : `<div class="ts-field-hint">${t('ts.direct_token_how')}</div>`}
          </div>

          <!-- ── Method B: Email + Password ──────────────── -->
          <div class="ts-method-banner" style="margin-top:10px;">
            <span class="ts-method-badge email">${t('ts.method_b_badge')}</span>
            <span class="ts-method-hint">${t('ts.method_b_hint')}</span>
          </div>
          <div class="ts-form-grid">
            <div class="ts-field">
              <div class="ts-field-label">Email</div>
              <input type="email" id="ts-email" class="ts-input ltr" value="${escapeAttr(this.form.email)}" placeholder="account@example.com" autocomplete="off" />
            </div>
            <div class="ts-field">
              <div class="ts-field-label">Password</div>
              <input type="password" id="ts-password" class="ts-input ltr" value="" placeholder="${sel?.hasPassword ? '••••••••' : ''}" autocomplete="off" />
            </div>
          </div>
          <div class="ts-field">
            <div class="ts-field-label">2FA Auth Secret Key</div>
            <input type="text" id="ts-totp" class="ts-input totp" value="" placeholder="${sel?.hasTotp ? '•••• •••• •••• ••••' : 'BASE32 SECRET'}" autocomplete="off" />
          </div>
        </div>

        <!-- Bulk token import -->
        ${this._renderBulkTokenCard()}

        <!-- Automation rules -->
        <div class="ts-card">
          <div class="ts-card-head">
            <div class="ts-card-title">AUTOMATION RULES</div>
          </div>
          ${this._renderToggle('createTeams', t('ts.rule_create_teams'))}
          ${this._renderToggle('createBots', t('ts.rule_create_bots'))}
          ${this._renderToggle('linkBots', t('ts.rule_link_bots'))}
          ${this._renderTeamSelector()}
          ${this._renderRuleHint()}

          <div class="ts-form-grid" style="margin-top:14px;">
            <div class="ts-field${!this.form.rules.createBots ? ' ts-field-muted' : ''}">
              <div class="ts-field-label">${t('ts.quantity')}</div>
              <input type="number" id="ts-count" class="ts-input numeric" min="1" max="50"
                value="${this.form.count}" ${!this.form.rules.createBots ? 'disabled' : ''} />
            </div>
            <div class="ts-field${!this.form.rules.createBots ? ' ts-field-muted' : ''}">
              <div class="ts-field-label">${t('ts.bot_prefix')}</div>
              <input type="text" id="ts-prefix" class="ts-input"
                value="${escapeAttr(this.form.prefix)}" maxlength="24"
                ${!this.form.rules.createBots ? 'disabled' : ''} />
            </div>
          </div>
          <div class="ts-field${(!this.form.rules.createBots && !this.form.rules.createTeams) ? ' ts-field-muted' : ''}">
            <div class="ts-field-label">${t('ts.wait_minutes')}</div>
            <input type="number" id="ts-wait" class="ts-input numeric" min="0" max="60"
              value="${this.form.waitMinutes}"
              ${(!this.form.rules.createBots && !this.form.rules.createTeams) ? 'disabled' : ''} />
          </div>
          <div class="ts-field" style="margin-top:4px;">
            <div class="ts-field-label">${t('ts.session_budget_label')}</div>
            <input type="number" id="ts-session-budget" class="ts-input numeric" min="0" max="500"
              value="${this.form.sessionBudget}"
              title="${escapeAttr(t('ts.session_budget_hint'))}" />
            <div class="ts-field-hint">${t('ts.session_budget_hint')}</div>
          </div>
          ${this._renderAdvancedOptions()}
        </div>

        <!-- Saved bot profile media -->
        ${this._renderPfpSection()}

        <!-- Captcha solver settings -->
        ${this._renderCaptchaSettings()}

        <!-- Action buttons -->
        <div class="ts-actions">
          <button class="ts-btn danger big" id="ts-stop">${t('ts.stop')}</button>
          <button class="ts-btn mint big" id="ts-start">${t('ts.start_session')}</button>
        </div>

        <!-- Live log -->
        <div class="ts-log-wrap">
          ${this._renderLogToolbar(s.log || [])}
          <div class="ts-log" id="ts-log">${this._renderLog(s.log || [])}</div>
        </div>

        <!-- Library trigger button — opens a full-screen overlay with four
             tabs: Teams / Personal apps / Created bots / Bot Tokens. -->
        <div id="ts-lib-trigger">${this._renderLibraryTrigger(s)}</div>
      </div>
    `;
    this._bind();
  }

  _renderProgress(s) {
    if (!s.total) return `0/0`;
    const failPart = s.failed ? `· <span class="ts-fail-count">${s.failed} ✕</span>` : '';
    const eta = this._calcETA(s);
    const etaPart = eta ? ` <span class="ts-eta-badge" title="الوقت المتبقي المقدر">~${eta}</span>` : '';
    return `${s.done}/${s.total} <span class="ts-stat-extra">${failPart}${etaPart}</span>`;
  }

  _calcETA(s) {
    if (!s || s.state !== 'running') return null;
    const remaining = (s.total || 0) - (s.done || 0) - (s.failed || 0);
    if (remaining <= 0) return null;
    const stats = this._benchmarkStats(s.log || []);
    if (!stats || !stats.avg) return null;
    const ms = remaining * stats.avg;
    if (ms < 1000) return null;
    if (ms < 60000) return Math.round(ms / 1000) + 'ث';
    const m = Math.floor(ms / 60000);
    const sec = Math.round((ms % 60000) / 1000);
    return `${m}د${sec > 0 ? ' ' + sec + 'ث' : ''}`;
  }


  _renderPfpSection() {
    const hasAvatar = !!this.pfp?.avatar;
    const hasBanner = !!this.pfp?.banner;
    const hasSaved = hasAvatar || hasBanner;
    const stamp = this.pfp?.updatedAt
      ? new Date(this.pfp.updatedAt).toLocaleString(getLang() === 'ar' ? 'ar-SA' : 'en-GB', { dateStyle: 'short', timeStyle: 'short' })
      : 'غير محفوظ';
    const showPrev = this._pfpPreviewVisible;
    return `
      <div class="ts-card ts-pfp-card">
        <div class="ts-card-head ts-pfp-head">
          <div>
            <div class="ts-card-title ar"><span class="ts-drawn-icon brush" aria-hidden="true"><i></i></span> Pfp · صورة وبنر البوتات</div>
            <div class="ts-pfp-subtitle">احفظ هوية موحدة — أي بوت جديد يأخذها تلقائياً. Pfp all موجود في المكتبة.</div>
          </div>
          <button class="ts-btn ts-pfp-preview-toggle${showPrev ? ' active' : ''}" id="ts-pfp-preview-btn"
            title="${showPrev ? 'إخفاء المعاينة' : 'إظهار المعاينة'}">
            <span class="ts-drawn-icon ${showPrev ? 'eye_off' : 'eye'}" aria-hidden="true"><i></i></span>
            ${showPrev ? 'إخفاء' : 'معاينة'}
          </button>
        </div>
        <div class="ts-pfp-preview-wrap${showPrev ? ' open' : ''}">
          <div class="ts-pfp-preview">
            <div class="ts-pfp-banner">${hasBanner ? `<img src="${this.pfp.banner}" alt="banner">` : '<span><b class="ts-drawn-icon galaxy" aria-hidden="true"><i></i></b> Banner Preview</span>'}</div>
            <div class="ts-pfp-avatar">${hasAvatar ? `<img src="${this.pfp.avatar}" alt="avatar">` : '<span class="ts-drawn-bot" aria-hidden="true"><i></i></span>'}</div>
            <div class="ts-pfp-orbit one" aria-hidden="true"><i></i></div>
            <div class="ts-pfp-orbit two" aria-hidden="true"><i></i></div>
            <div class="ts-pfp-chip"><span class="ts-drawn-icon shield" aria-hidden="true"><i></i></span> Saved identity</div>
          </div>
        </div>
        <div class="ts-pfp-upload-grid">
          <label class="ts-pfp-drop">
            <span class="ts-pfp-drop-icon avatar" aria-hidden="true"><i></i></span>
            <span class="ts-pfp-drop-title">Avatar طبيعي للبوت</span>
            <span class="ts-pfp-drop-hint">PNG · JPG · GIF · WebP</span>
            <input type="file" id="ts-pfp-avatar" accept="image/png,image/jpeg,image/gif,image/webp" />
          </label>
          <label class="ts-pfp-drop banner">
            <span class="ts-pfp-drop-icon banner" aria-hidden="true"><i></i></span>
            <span class="ts-pfp-drop-title">Banner طبيعي للبوت</span>
            <span class="ts-pfp-drop-hint">يفضل مقاس واسع مثل دسكورد</span>
            <input type="file" id="ts-pfp-banner" accept="image/png,image/jpeg,image/gif,image/webp" />
          </label>
        </div>
        <div class="ts-pfp-actions">
          <button class="ts-btn ts-pfp-clear" id="ts-pfp-clear"><span class="ts-drawn-icon broom" aria-hidden="true"><i></i></span> مسح المحفوظ</button>
          <button class="ts-btn mint ts-pfp-save" id="ts-pfp-save"><span class="ts-drawn-icon save" aria-hidden="true"><i></i></span> حفظ Pfp</button>
          <span class="ts-field-hint ts-pfp-save-hint"><span class="ts-drawn-icon clock" aria-hidden="true"><i></i></span> آخر حفظ: ${escapeHtml(stamp)}</span>
        </div>
        <div class="ts-auto-intents-row">
          <span class="ts-auto-intents-label">
            <span class="ts-auto-intents-icon">⚡</span>
            تفعيل iNTeNT تلقائياً عند إنشاء أي بوت جديد
          </span>
          <button class="ts-btn${this._autoIntents ? ' mint' : ''}" id="ts-auto-intents-btn"
            title="${this._autoIntents ? 'مفعّل — كل بوت جديد سيحصل على Intents تلقائياً' : 'معطّل'}">
            ${this._autoIntents ? 'ON ✓' : 'OFF'}
          </button>
        </div>
      </div>
    `;
  }

  togglePfpPreview() {
    this._pfpPreviewVisible = !this._pfpPreviewVisible;
    const wrap = this.contentArea.querySelector('.ts-pfp-preview-wrap');
    const btn  = this.contentArea.querySelector('#ts-pfp-preview-btn');
    if (wrap) wrap.classList.toggle('open', this._pfpPreviewVisible);
    if (btn) {
      btn.classList.toggle('active', this._pfpPreviewVisible);
      btn.title = this._pfpPreviewVisible ? 'إخفاء المعاينة' : 'إظهار المعاينة';
      btn.innerHTML = `<span class="ts-drawn-icon ${this._pfpPreviewVisible ? 'eye_off' : 'eye'}" aria-hidden="true"><i></i></span> ${this._pfpPreviewVisible ? 'إخفاء' : 'معاينة'}`;
    }
  }

  async _fileToDataUrl(file) {
    if (!file) return null;
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result || ''));
      reader.onerror = () => reject(reader.error || new Error('file read failed'));
      reader.readAsDataURL(file);
    });
  }

  async _loadPfp() {
    try {
      const r = await window.electronAPI.tsGetPfp();
      this.pfp = r?.pfp || { avatar: null, banner: null, updatedAt: 0 };
    } catch (_) { this.pfp = { avatar: null, banner: null, updatedAt: 0 }; }
  }

  async _loadAutoIntents() {
    try {
      const r = await window.electronAPI.tsGetAutoIntents();
      this._autoIntents = !!r?.autoIntents;
    } catch (_) { this._autoIntents = false; }
  }

  async _toggleAutoIntents() {
    const next = !this._autoIntents;
    try {
      await window.electronAPI.tsSetAutoIntents(next);
      this._autoIntents = next;
      // Update button without re-rendering everything
      const btn = this.contentArea.querySelector('#ts-auto-intents-btn');
      if (btn) {
        btn.classList.toggle('mint', next);
        btn.textContent = next ? 'ON ✓' : 'OFF';
        btn.title = next ? 'مفعّل — كل بوت جديد سيحصل على Intents تلقائياً' : 'معطّل';
      }
      showNotification(next ? '⚡ Auto-intents مفعّل' : 'Auto-intents معطّل', next ? 'success' : 'info');
    } catch (e) { showNotification('فشل تغيير Auto-intents: ' + (e.message || e), 'error'); }
  }

  async _savePfpFromInputs(clear = false) {
    const saveBtn  = this.contentArea.querySelector('#ts-pfp-save');
    const clearBtn = this.contentArea.querySelector('#ts-pfp-clear');
    const activeBtn = clear ? clearBtn : saveBtn;

    // Guard: for clear, ask confirmation
    if (clear) {
      if (!this.pfp?.avatar && !this.pfp?.banner) {
        showNotification('لا يوجد Pfp محفوظ للمسح', 'error'); return;
      }
      const ok = await showConfirm('مسح الصورة والبنر المحفوظين نهائياً؟', { confirmText: 'مسح', cancelText: 'إلغاء' });
      if (!ok) return;
    } else {
      const avFile = this.contentArea.querySelector('#ts-pfp-avatar')?.files?.[0] || null;
      const bnFile = this.contentArea.querySelector('#ts-pfp-banner')?.files?.[0] || null;
      if (!avFile && !bnFile && !this.pfp?.avatar && !this.pfp?.banner) {
        showNotification('اختر صورة أو بانر أولاً', 'error'); return;
      }
    }

    if (activeBtn) { activeBtn.disabled = true; }
    try {
      const avFile = this.contentArea.querySelector('#ts-pfp-avatar')?.files?.[0] || null;
      const bnFile = this.contentArea.querySelector('#ts-pfp-banner')?.files?.[0] || null;
      const avatar = clear ? null : (avFile ? await this._fileToDataUrl(avFile) : (this.pfp?.avatar || null));
      const banner = clear ? null : (bnFile ? await this._fileToDataUrl(bnFile) : (this.pfp?.banner || null));
      const r = await window.electronAPI.tsSavePfp({ avatar, banner });
      if (!r?.success && r?.error) throw new Error(r.error);
      this.pfp = r?.pfp || { avatar, banner, updatedAt: Date.now() };
      showNotification(clear ? 'تم مسح Pfp المحفوظ' : 'تم حفظ Pfp — سيطبق على البوتات الجديدة', 'success');
      // Update the library modal pfp-all button live if it's already open
      const pfpAllBtn = this._libModal?.querySelector('#ts-lib-pfp-all');
      if (pfpAllBtn) {
        const hasPfp = !!(this.pfp?.avatar || this.pfp?.banner);
        pfpAllBtn.disabled = !hasPfp;
        pfpAllBtn.classList.toggle('mint', hasPfp);
        pfpAllBtn.title = hasPfp ? 'تطبيق Pfp المحفوظ على كل البوتات ✓' : 'احفظ Avatar أو Banner أولاً';
      }
      this.render();
    } catch (e) {
      showNotification('فشل حفظ Pfp: ' + (e.message || e), 'error');
    } finally {
      if (activeBtn) { activeBtn.disabled = false; }
    }
  }

  async _applyPfpAll() {
    if (!this.pfp?.avatar && !this.pfp?.banner) { showNotification('احفظ Avatar أو Banner أولاً', 'error'); return; }
    if (this._pfpAllRunning) { showNotification('Pfp all جاري التنفيذ بالفعل…', 'info'); return; }
    if (!this.selectedEmail) { showNotification('اختر حساباً أولاً لتطبيق Pfp all', 'error'); return; }
    const confirmed = await showConfirm('تطبيق الصورة والبنر المحفوظين على كل بوتات المكتبة؟\n(يُحدَّث البوت + أيقونة/بنر التطبيق في المكتبة)', { confirmText: 'Pfp all', cancelText: 'إلغاء' });
    if (!confirmed) return;

    this._pfpAllRunning = true;
    this._libModal?.querySelectorAll('#ts-lib-pfp-all').forEach(b => { b.disabled = true; });

    const prog = this._openBatchProgressModal('🖼 Pfp all', 'تطبيق الصورة والبنر على بوتات المكتبة…');
    prog.setIndeterminate(true);
    prog.setStatus('⏳ جاري تحميل قائمة البوتات…');

    let okCount = 0, failCount = 0;

    try {
      const resp = await fetch('/api/ts/pfp/apply-all', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: this.selectedEmail }),
      });

      // If server responded with a plain JSON error (e.g. no avatar saved)
      if (!resp.ok || !resp.headers.get('content-type')?.includes('text/event-stream')) {
        const body = await resp.json().catch(() => ({}));
        throw new Error(body.error || `HTTP ${resp.status}`);
      }

      const reader  = resp.body.getReader();
      const decoder = new TextDecoder();
      let   buf     = '';

      const parseLine = (line) => {
        if (!line.startsWith('data:')) return;
        let evt;
        try { evt = JSON.parse(line.slice(5).trim()); } catch { return; }

        if (evt.type === 'start') {
          prog.setIndeterminate(false);
          prog.setTotal(evt.total);
          prog.setStatus(`⏳ جاري التطبيق على ${evt.total} بوت…`);

        } else if (evt.type === 'progress') {
          okCount   = (evt.ok ? okCount + 1 : okCount);
          failCount = (evt.ok ? failCount   : failCount + 1);
          prog.setProgress(evt.index, evt.total);
          // Show per-bot line: bot result + app icon result
          const appNote = evt.appOk ? '(أيقونة ✓)' : evt.appError ? `(أيقونة ✗: ${evt.appError.slice(0,40)})` : '';
          prog.logLine(evt.ok ? '✓' : '✗', evt.name, (evt.error ? evt.error.slice(0,60) : '') + (appNote ? ' ' + appNote : ''));

        } else if (evt.type === 'done') {
          prog.done(evt.okCount, evt.failCount);

        } else if (evt.type === 'error') {
          throw new Error(evt.error);
        }
      };

      // Stream read loop
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const parts = buf.split('\n');
        buf = parts.pop();          // keep incomplete last chunk
        for (const line of parts) {
          const t = line.trim();
          if (t) try { parseLine(t); } catch (e) { prog.error(e.message || String(e)); break; }
        }
      }
    } catch (e) {
      prog.setIndeterminate(false);
      prog.error(e.message || String(e));
    } finally {
      this._pfpAllRunning = false;
      this._libModal?.querySelectorAll('#ts-lib-pfp-all').forEach(b => { b.disabled = false; });
    }
  }

  _renderStatus(s, meta) {
    if (meta.fmt === 'wait') {
      const left = Math.max(0, (s.waitUntilTs || 0) - Date.now());
      return `${meta.label} <span class="ts-stat-extra">(${this._fmtMs(left)})</span>`;
    }
    return meta.label;
  }

  _renderAccountRateLimits(s) {
    // Only Discord per-route bucket rate-limits (technical detail, separate from paused-account pool)
    const now = Date.now();
    const holds = Object.entries(s?.accountRateLimits || {})
      .filter(([, h]) => h && Number(h.waitUntilTs || 0) > now);
    if (!holds.length) return '';
    return `
      <div class="ts-account-holds">
        ${holds.map(([email, h]) => `
          <div class="ts-account-hold">
            <span class="ts-account-hold-main">${escapeHtml(email)} · rate limit</span>
            <span class="ts-account-hold-time" data-ts-account-hold-until="${Number(h.waitUntilTs || 0)}">${this._fmtMs(Math.max(0, Number(h.waitUntilTs || 0) - now))}</span>
          </div>
        `).join('')}
      </div>
    `;
  }

  _renderAccountPool(s) {
    // Only visible while a session is active or just finished
    if (!s || !['running', 'waiting', 'done', 'error', 'cancelled'].includes(s.state)) return '';
    const now = Date.now();
    const activeEmail = (s.account || '').toLowerCase();
    const paused = s.pausedAccounts || {};

    // Build display pool: active account first, then all other saved accounts
    const seen = new Set();
    const rows = [];
    if (activeEmail) { seen.add(activeEmail); rows.push({ email: activeEmail, isActive: true }); }
    for (const a of (this.accounts || [])) {
      const ae = (a.email || '').toLowerCase();
      if (!seen.has(ae)) { seen.add(ae); rows.push({ email: ae, isActive: false }); }
    }

    // Only render panel if we have at least 1 account to show
    if (rows.length === 0) return '';

    const cells = rows.map(({ email, isActive }) => {
      const p = paused[email];
      const until = p ? Number(p.waitUntilTs || 0) : 0;
      const isPaused = until > now;

      if (isActive) {
        return `
          <div class="ts-pool-row ts-pool-row--active">
            <span class="ts-pool-dot ts-pool-dot--active"></span>
            <span class="ts-pool-email">${escapeHtml(email)}</span>
            <span class="ts-pool-badge ts-pool-badge--active">نشط ●</span>
          </div>`;
      }
      if (isPaused) {
        return `
          <div class="ts-pool-row ts-pool-row--paused">
            <span class="ts-pool-dot ts-pool-dot--paused"></span>
            <span class="ts-pool-email">${escapeHtml(email)}</span>
            <span class="ts-pool-badge ts-pool-badge--paused" data-ts-account-hold-until="${until}">${this._fmtMs(Math.max(0, until - now))}</span>
          </div>`;
      }
      return `
        <div class="ts-pool-row ts-pool-row--ready">
          <span class="ts-pool-dot ts-pool-dot--ready"></span>
          <span class="ts-pool-email">${escapeHtml(email)}</span>
          <span class="ts-pool-badge ts-pool-badge--ready">متاح</span>
        </div>`;
    }).join('');

    return `
      <div class="ts-pool-panel">
        <div class="ts-pool-header">
          <span class="ts-pool-icon">⇄</span>
          <span class="ts-pool-title">حسابات الجلسة</span>
          <span class="ts-pool-count">${rows.length} حساب</span>
        </div>
        <div class="ts-pool-rows">${cells}</div>
      </div>`;
  }

  _renderBulkTokenCard() {
    const lines = this.bulkTokensText.split('\n').map(l => l.trim()).filter(l => l.length > 10);
    const pending = lines.length;
    const saved = (this.accounts || []).filter(a => /^tok-\d+@local$/.test(a.email || '')).length;
    return `
      <div class="ts-card">
        <div class="ts-card-head">
          <div class="ts-card-title ar">${t('ts.bulk_tokens_title')}</div>
          ${saved > 0 ? `<div class="ts-card-badge" style="background:var(--mint,#7ce0c4);color:#0a0e1a;font-size:11px;padding:2px 9px;border-radius:20px;font-weight:700;">${saved} محفوظ</div>` : ''}
        </div>
        <div class="ts-field">
          <div class="ts-field-hint">${t('ts.bulk_tokens_hint')}</div>
          <textarea id="ts-bulk-tokens"
            class="ts-input ltr"
            style="font-family:monospace;font-size:12px;resize:vertical;min-height:90px;line-height:1.5;"
            placeholder="${escapeAttr(t('ts.bulk_tokens_ph'))}"
            autocomplete="off" spellcheck="false">${escapeHtml(this.bulkTokensText)}</textarea>
        </div>
        <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:8px;">
          ${saved > 0 ? `<button class="ts-btn danger" id="ts-bulk-delete">${t('ts.bulk_tokens_delete')} (${saved})</button>` : ''}
          <button class="ts-btn mint" id="ts-bulk-save" ${pending === 0 ? 'disabled' : ''}>
            ${t('ts.bulk_tokens_save')}${pending > 0 ? ` (${pending})` : ''}
          </button>
        </div>
      </div>`;
  }

  _optionLabel(a) {
    const v = a.verify;
    let badge = '';
    if (a.hasDirectToken) badge += ' 🔑';
    if (v) badge += v.ok ? '  ✓' : '  !';
    return escapeHtml(a.email) + badge;
  }

  _verifyLabel(sel) {
    if (!sel) return '';
    const v = sel.verify;
    if (!v) return `<span class="ts-verify v-idle">${t('ts.verify_not_tested')}</span>`;
    const ago = Math.max(1, Math.round((Date.now() - (v.at || 0)) / 60000));
    if (v.ok) {
      const u = v.username ? ' · ' + escapeHtml(v.username) : '';
      return `<span class="ts-verify v-ok">✓ ${t('ts.verify_ok')} (${ago}m)${u}</span>`;
    }
    return `<span class="ts-verify v-bad" title="${escapeAttr(v.message || '')}">✕ ${t('ts.verify_failed')}: ${escapeHtml(v.status || '')}</span>`;
  }

  _renderToggle(key, label) {
    const on = !!this.form.rules[key];
    return `
      <div class="ts-toggle-row">
        <div class="ts-toggle-label">${label}</div>
        <div class="ts-toggle ${on ? 'on' : ''}" data-toggle="${key}" role="switch" aria-checked="${on}"></div>
      </div>
    `;
  }

  // Team dropdown — shown when linkBots ON and createTeams OFF
  _renderTeamSelector() {
    const r = this.form.rules;
    if (!r.linkBots || r.createTeams) return '';
    if (this._teamsLoading) {
      return `<div class="ts-rule-hint info" style="display:flex;align-items:center;gap:6px;">
        <span style="animation:spin 1s linear infinite;display:inline-block;">⟳</span>
        جاري تحميل التيمات…
      </div>`;
    }
    const teams = this.availableTeams || [];
    if (!teams.length) {
      return `<div class="ts-field" style="margin:8px 0 0;">
        <div class="ts-field-label">التيم المستهدف</div>
        <div class="ts-field-hint warn" style="color:#f5a623;">لا توجد تيمات — سيتم الإنشاء بدون تيم، أو أنشئ تيماً من المكتبة أولاً</div>
        <button class="ts-btn" id="ts-teams-reload" style="margin-top:6px;font-size:12px;">⟳ إعادة تحميل التيمات</button>
      </div>`;
    }
    return `
      <div class="ts-field" style="margin:8px 0 0;" id="ts-team-selector-field">
        <div class="ts-field-label">التيم المستهدف (للربط التلقائي)</div>
        <select class="ts-input" id="ts-team-select">
          <option value="">— أحدث تيم تلقائياً (Auto-rotate) —</option>
          ${teams.map(tm => `<option value="${escapeAttr(tm.id)}" ${tm.id === this.form.selectedTeamId ? 'selected' : ''}>${escapeHtml(tm.name)} (${tm.appCount || 0}/25)</option>`).join('')}
        </select>
        <div class="ts-field-hint">سيتم التبديل تلقائياً لتيم آخر أو إنشاء تيم Studio جديد عند امتلاء التيم (25 تطبيق)</div>
      </div>
    `;
  }

  // ── Bright Data preset definitions (from live Bright Data pricing, 2025) ──
  static BD_PRESETS = [
    {
      id: 'residential',
      name: 'Residential',
      nameAr: 'منزلي متغير',
      icon: '🏠',
      trustLabel: 'عالي',
      trustColor: '#3ba55d',
      costPer1000: '~$0.21',
      pricePerGB: '$4.20/GB',
      desc: 'IPs منزلية حقيقية من شركات الإنترنت — الأصعب كشفاً لـ Discord',
      recommended: true,
      protocol: 'http',
      batchSize: 3,
      speed: 'veryfast',
      zoneType: 'Residential',
      zoneHint: 'أنشئ Zone من نوع Residential (Pay As You Go)',
      bdUrl: 'https://brightdata.com/cp/zones',
    },
    {
      id: 'isp',
      name: 'ISP',
      nameAr: 'مزود خدمة',
      icon: '🏢',
      trustLabel: 'عالي جداً',
      trustColor: '#5865f2',
      costPer1000: '~$0.75',
      pricePerGB: '$15/GB',
      desc: 'IPs حقيقية من ISPs — أسرع من Residential ومستوى ثقة أعلى',
      recommended: false,
      protocol: 'http',
      batchSize: 4,
      speed: 'veryfast',
      zoneType: 'ISP',
      zoneHint: 'أنشئ Zone من نوع ISP Proxies',
      bdUrl: 'https://brightdata.com/cp/zones',
    },
    {
      id: 'datacenter',
      name: 'Datacenter',
      nameAr: 'مركز بيانات',
      icon: '⚡',
      trustLabel: 'متوسط',
      trustColor: '#faa61a',
      costPer1000: '~$0.03',
      pricePerGB: '$0.60/GB',
      desc: 'الأرخص والأسرع — Discord يعرف بعض نطاقات الـ Datacenter',
      recommended: false,
      protocol: 'http',
      batchSize: 5,
      speed: 'veryfast',
      zoneType: 'Datacenter',
      zoneHint: 'أنشئ Zone من نوع Datacenter (Shared)',
      bdUrl: 'https://brightdata.com/cp/zones',
    },
  ];

  // Speed + Proxy section — shown in automation rules card
  _renderAdvancedOptions() {
    const pr     = this._proxyTestResult;
    const bd     = this.form.brightData || {};
    const qsOpen = !!this._quickSetupOpen;
    const preset = TrueStudioManager.BD_PRESETS.find(p => p.id === this._bdPreset) || null;

    const proxyStatus = pr
      ? (pr.ok
          ? `<span style="color:#3ba55d;font-size:11px;">✓ يعمل — IP: ${escapeHtml(pr.ip || '?')}</span>`
          : `<span style="color:#ed4245;font-size:11px;">✕ ${escapeHtml(pr.error || 'فشل الاتصال')}</span>`)
      : '';

    // ── Quick Setup panel (3 preset cards) ──────────────────────────────────
    const quickSetupPanel = qsOpen ? `
      <div style="margin-top:8px;padding:10px;background:rgba(0,0,0,.25);border-radius:8px;border:1px solid rgba(255,255,255,.07);">
        <div style="font-size:11px;font-weight:600;margin-bottom:8px;color:var(--ts-muted,#7e8592);">
          اختر نوع الـ Zone المناسب لحالتك — السعر محسوب لكل 1000 بوت (3 طلبات/بوت × ~50KB)
        </div>
        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:6px;">
          ${TrueStudioManager.BD_PRESETS.map(p => `
            <div style="padding:9px 8px;background:rgba(255,255,255,.04);border-radius:7px;border:1px solid ${p.recommended ? 'rgba(59,165,93,.4)' : 'rgba(255,255,255,.06)'};display:flex;flex-direction:column;gap:4px;position:relative;">
              ${p.recommended ? `<div style="position:absolute;top:-7px;left:50%;transform:translateX(-50%);background:#3ba55d;color:#fff;font-size:9px;padding:1px 7px;border-radius:10px;white-space:nowrap;">موصى به</div>` : ''}
              <div style="font-size:13px;text-align:center;">${p.icon}</div>
              <div style="font-weight:700;font-size:12px;text-align:center;">${p.name}</div>
              <div style="font-size:10px;text-align:center;color:var(--ts-muted,#7e8592);">${p.nameAr}</div>
              <div style="display:flex;align-items:center;justify-content:center;gap:4px;margin:2px 0;">
                <span style="width:6px;height:6px;border-radius:50%;background:${p.trustColor};flex-shrink:0;"></span>
                <span style="font-size:10px;color:${p.trustColor};">${p.trustLabel}</span>
              </div>
              <div style="font-size:11px;font-weight:700;text-align:center;color:#fff;">${p.costPer1000}</div>
              <div style="font-size:9px;text-align:center;color:var(--ts-muted,#7e8592);">لكل 1000 بوت</div>
              <div style="font-size:9px;text-align:center;color:var(--ts-muted,#7e8592);line-height:1.4;margin-top:2px;">${p.desc}</div>
              <button class="ts-btn" data-qs-apply="${p.id}"
                style="margin-top:6px;font-size:11px;padding:4px 8px;${p.recommended ? 'background:#3ba55d;' : ''}">
                تطبيق
              </button>
            </div>
          `).join('')}
        </div>
        <div style="margin-top:8px;font-size:10px;color:var(--ts-muted,#7e8592);text-align:center;">
          الأسعار من Bright Data 2025 ·
          <a href="https://brightdata.com/cp/zones" target="_blank" rel="noopener"
            style="color:#5865f2;text-decoration:none;">افتح لوحة الـ Zones →</a>
        </div>
      </div>
    ` : '';

    // ── Applied preset strip ─────────────────────────────────────────────────
    const presetStrip = (!qsOpen && preset) ? `
      <div style="display:flex;align-items:center;gap:6px;padding:5px 8px;background:rgba(${preset.trustColor === '#3ba55d' ? '59,165,93' : preset.trustColor === '#5865f2' ? '88,101,242' : '250,166,26'},.12);border-radius:6px;border:1px solid ${preset.trustColor}33;margin-bottom:4px;">
        <span style="font-size:13px;">${preset.icon}</span>
        <span style="font-size:11px;font-weight:600;">${preset.name}</span>
        <span style="font-size:10px;color:var(--ts-muted,#7e8592);flex:1;">${preset.zoneHint}</span>
        <a href="${preset.bdUrl}" target="_blank" rel="noopener"
          style="font-size:10px;color:#5865f2;text-decoration:none;white-space:nowrap;">إنشاء Zone →</a>
      </div>
    ` : '';

    // ── Zone name placeholder (context-aware) ────────────────────────────────
    const zonePlaceholder = preset
      ? `اسم الـ Zone الذي أنشأته (نوع: ${preset.zoneType})`
      : 'Zone Name  (مثلاً: residential_rotating1)';

    // ── Bright Data credential form (shown when toggle is ON) ───────────────
    const bdForm = bd.enabled ? `
      <div style="margin-top:8px;display:grid;gap:6px;">
        ${presetStrip}
        ${quickSetupPanel}
        <input type="text" id="ts-bd-customer" class="ts-input ltr"
          placeholder="Account ID  (لوحة Bright Data → Settings → Account)"
          value="${escapeAttr(bd.customerId || '')}" autocomplete="off" />
        <div class="ts-account-row">
          <input type="text" id="ts-bd-zone" class="ts-input ltr"
            placeholder="${escapeAttr(zonePlaceholder)}"
            value="${escapeAttr(bd.zoneName || '')}" style="flex:1;" autocomplete="off" />
          <select id="ts-bd-proto" class="ts-input" style="flex:0 0 140px;">
            <option value="http"    ${bd.protocol !== 'socks5h' ? 'selected' : ''}>HTTP — 33335</option>
            <option value="socks5h" ${bd.protocol === 'socks5h' ? 'selected' : ''}>SOCKS5h — 22228</option>
          </select>
        </div>
        <div class="ts-account-row">
          <input type="password" id="ts-bd-pass" class="ts-input ltr"
            placeholder="Zone Password"
            value="${escapeAttr(bd.zonePassword || '')}" style="flex:1;" autocomplete="new-password" />
          <button class="ts-btn" id="ts-proxy-test" style="white-space:nowrap;">اختبار</button>
        </div>
        ${proxyStatus ? `<div>${proxyStatus}</div>` : ''}
        <div class="ts-field-hint" style="line-height:1.6;">
          كل بوت يحصل على <b>session ID عشوائي</b> → IP مختلف من نفس الاشتراك ✓<br>
          يدعم: Residential · Datacenter · ISP · Mobile
        </div>
      </div>
    ` : `
      <div class="ts-account-row" style="align-items:flex-start;margin-top:6px;">
        <textarea id="ts-proxy-url" class="ts-input ltr" rows="3"
          style="resize:vertical;font-size:11px;line-height:1.6;min-height:60px;font-family:monospace;"
          placeholder="بروكسي واحد لكل سطر — يتغير IP مع كل بوت&#10;socks5://user:pass@host:port&#10;http://user:pass@host:port">${escapeHtml(this.form.proxyUrl || '')}</textarea>
        <button class="ts-btn" id="ts-proxy-test" style="white-space:nowrap;align-self:flex-start;">اختبار</button>
      </div>
      ${proxyStatus ? `<div style="margin-top:4px;">${proxyStatus}</div>` : ''}
      <div class="ts-field-hint">http · https · socks · socks5h — كل بوت يستخدم IP مختلف عند وجود عدة بروكسيات</div>
    `;

    // ── Proxy header row with Bright Data toggle ────────────────────────────
    const proxyCountBadge = !bd.enabled && (this.form.proxyUrl || '').split(/\n/).filter(l => l.trim()).length > 1
      ? `<span style="font-size:10px;color:#3ba55d;margin-right:4px;">✓ ${(this.form.proxyUrl || '').split(/\n/).filter(l => l.trim()).length} بروكسي</span>`
      : '';

    return `
      <div class="ts-field" style="margin-top:12px;">
        <div class="ts-field-label">سرعة التنفيذ</div>
        <div class="ts-speed-pills">
          ${[
            { v:'medium',   label:'Medium',    sub:'×1.0 — آمن',          cls:'' },
            { v:'fast',     label:'Fast',      sub:'×0.4 — سريع',         cls:'' },
            { v:'veryfast', label:'Very Fast', sub:'×0.15 — أسرع',        cls:'warn' },
            { v:'ultra',    label:'Ultra',     sub:'×0.05 — أقصى ⚡',     cls:'danger' },
          ].map(s => `
            <label class="ts-speed-pill ${this.form.speed === s.v ? 'active' : ''} ${s.cls}">
              <input type="radio" name="ts-speed" value="${s.v}" ${this.form.speed === s.v ? 'checked' : ''} style="display:none">
              <span class="ts-speed-pill-label">${s.label}</span>
              <span class="ts-speed-pill-sub">${s.sub}</span>
            </label>`).join('')}
        </div>
        <div class="ts-field-hint">Ultra/Very Fast: تأخيرات صفرية — استخدم مع Proxy لتجنب الحظر</div>
      </div>

      <div class="ts-field" style="margin-top:8px;">
        <div class="ts-field-label" style="display:flex;align-items:center;justify-content:space-between;gap:6px;flex-wrap:wrap;">
          <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
            <span>${bd.enabled ? 'Bright Data Proxy' : 'Proxy للجلسة'}</span>
            ${!bd.enabled
              ? `<span style="font-size:10px;color:var(--ts-muted,#7e8592);">(اختياري)</span>${proxyCountBadge}`
              : `<span style="font-size:10px;color:#3ba55d;">IP rotation تلقائي ✓</span>`}
          </div>
          <div style="display:flex;align-items:center;gap:6px;flex-shrink:0;">
            ${bd.enabled ? `
              <button id="ts-quick-setup" class="ts-btn"
                style="font-size:10px;padding:3px 8px;${qsOpen ? 'background:#5865f2;' : ''}">
                ⚡ Quick Setup${qsOpen ? ' ▲' : ' ▼'}
              </button>
            ` : ''}
            <label style="display:flex;align-items:center;gap:5px;cursor:pointer;user-select:none;">
              <span style="font-size:10px;color:var(--ts-muted,#7e8592);">Bright Data</span>
              <div class="ts-toggle ${bd.enabled ? 'on' : ''}" id="ts-bd-toggle"
                role="switch" aria-checked="${bd.enabled}"
                title="استخدام Bright Data rotating proxy — IP جديد لكل بوت تلقائياً"></div>
            </label>
          </div>
        </div>
        ${bdForm}
      </div>

      ${(bd.enabled || (this.form.proxyUrl || '').split(/\n/).filter(l => l.trim()).length > 1) ? `
      <div class="ts-field" style="margin-top:8px;">
        <div class="ts-field-label" style="display:flex;align-items:center;gap:6px;">
          <span>حجم الدُّفعة المتوازية</span>
          <span style="font-size:10px;color:#3ba55d;background:rgba(59,165,93,.12);padding:1px 6px;border-radius:4px;">IP Rotation نشط ✓</span>
        </div>
        <select class="ts-input" id="ts-batch-size">
          <option value="1" ${(this.form.batchSize||1)===1?'selected':''}>1 — تسلسلي (الوضع الأصلي)</option>
          <option value="2" ${(this.form.batchSize||1)===2?'selected':''}>2 بوت في نفس الوقت</option>
          <option value="3" ${(this.form.batchSize||1)===3?'selected':''}>3 بوت في نفس الوقت</option>
          <option value="4" ${(this.form.batchSize||1)===4?'selected':''}>4 بوت في نفس الوقت</option>
          <option value="5" ${(this.form.batchSize||1)===5?'selected':''}>5 بوت في نفس الوقت — أقصى سرعة</option>
        </select>
        <div class="ts-field-hint">
          في وضع الدُّفعات: تأخيرات البشر تُحذف تلقائياً (كل بوت من IP مختلف) ·
          الكولداون بين الدُّفعات: 1s فقط · السرعة تتضاعف بعدد الدُّفعة
        </div>
      </div>
      ` : ''}
    `;
  }

  // Load teams from Discord for the linkBots dropdown
  async _loadTeamsForDropdown() {
    if (!this.selectedEmail) return;
    this._teamsLoading = true;
    this._patchTeamSelector();
    try {
      const r = await window.electronAPI.tsListTeams(this.selectedEmail);
      this.availableTeams = r?.teams || [];
    } catch (e) {
      this.availableTeams = [];
    } finally {
      this._teamsLoading = false;
      this._patchTeamSelector();
    }
  }

  // Re-render only the team selector in-place (no full re-render)
  _patchTeamSelector() {
    const existing = this.contentArea.querySelector('#ts-team-selector-field, .ts-rule-hint');
    if (!existing) return;
    // find the parent card and re-render only the selector portion
    this.render();
  }

  // Returns a contextual hint about the currently-selected rule combination.
  // Shown only when the combination might confuse the user or is invalid.
  _renderRuleHint() {
    const r = this.form.rules;
    // All three off → no valid pipeline
    if (!r.createTeams && !r.createBots && !r.linkBots) return '';
    // linkBots ON but nothing to link (no bots being created, no team to link into)
    if (r.linkBots && !r.createBots && !r.createTeams) {
      return `<div class="ts-rule-hint warn">
        ⚠ ${escapeHtml(t('ts.rule_hint_link_needs_bots') || 'Link Bots requires Create Bots or Create Teams to be enabled.')}
      </div>`;
    }
    // linkBots ON, createBots ON, but no team → bots won't be linked anywhere
    if (r.linkBots && r.createBots && !r.createTeams) {
      return `<div class="ts-rule-hint warn">
        ⚠ ${escapeHtml(t('ts.rule_hint_link_needs_team') || 'Link Bots will transfer created bots into an existing team. Enable Create Teams to create a new team first.')}
      </div>`;
    }
    // createTeams ON but nothing else → creates an empty team
    if (r.createTeams && !r.createBots && !r.linkBots) {
      return `<div class="ts-rule-hint info">
        ℹ ${escapeHtml(t('ts.rule_hint_team_only') || 'Only teams will be created — no bots will be added to them.')}
      </div>`;
    }
    // Full pipeline — all good
    if (r.createTeams && r.createBots && r.linkBots) {
      return `<div class="ts-rule-hint ok">
        ✓ ${escapeHtml(t('ts.rule_hint_full') || 'Full pipeline: create team → create bots → link bots into team.')}
      </div>`;
    }
    return '';
  }

  // Updates disabled state of bot-count / prefix / wait fields
  // to match the current rule toggles without re-rendering the full form.
  _updateRuleFieldStates() {
    const r = this.form.rules;
    const botsOn  = !!r.createBots;
    const batchOn = botsOn || !!r.createTeams;

    const setField = (id, enabled) => {
      const el = this.contentArea.querySelector(id);
      if (!el) return;
      el.disabled = !enabled;
      el.closest('.ts-field')?.classList.toggle('ts-field-muted', !enabled);
    };
    setField('#ts-count',  botsOn);
    setField('#ts-prefix', botsOn);
    setField('#ts-wait',   batchOn);

    // When linkBots is turned ON and createTeams is OFF → load teams dropdown
    const needsTeams = r.linkBots && !r.createTeams;
    if (needsTeams && !this.availableTeams.length && !this._teamsLoading) {
      this._loadTeamsForDropdown();
    }

    // Refresh the rule hint area without a full re-render
    const rulesCard = this.contentArea.querySelector('.ts-rule-hint')?.closest('.ts-card');
    // Faster: just replace the hint node in-place
    const existing = this.contentArea.querySelector('.ts-rule-hint');
    const hintHtml = this._renderRuleHint();
    if (existing) {
      if (hintHtml) {
        existing.outerHTML = hintHtml;
      } else {
        existing.remove();
      }
    } else if (hintHtml) {
      // Insert after the last toggle row
      const lastToggle = [...this.contentArea.querySelectorAll('.ts-toggle-row')].pop();
      lastToggle?.insertAdjacentHTML('afterend', hintHtml);
    }
  }

  _renderCaptchaSettings() {
    const c = this.captchaSettings || {};
    const hasKey = !!c.hasApiKey;
    // When an API key exists, manual mode is locked OFF — auto-solver is active.
    const fbLocked = hasKey;
    const fbOn = !fbLocked && (c.manualFallback !== false);
    const vr = this._captchaVerifyResult; // verify result state
    const verifyPopup = vr ? `
      <div class="ts-verify-popup ${vr.ok ? 'ok' : 'fail'}">
        <div class="ts-verify-popup-icon">${vr.ok ? '✓' : '✗'}</div>
        <div class="ts-verify-popup-body">
          <div class="ts-verify-popup-title">${vr.ok
            ? escapeHtml(t('ts.captcha_key_works').replace('{provider}', vr.provider))
            : escapeHtml(t('ts.captcha_key_fails').replace('{provider}', vr.provider))
          }</div>
          ${vr.ok
            ? `<div class="ts-verify-popup-bal">${escapeHtml(t('ts.captcha_balance').replace('{amount}', Number(vr.balance).toFixed(4)).replace('{currency}', vr.currency || 'USD'))}</div>`
            : `<div class="ts-verify-popup-err">${escapeHtml(vr.error || t('ts.captcha_unknown_error'))}</div>`
          }
        </div>
        <button class="ts-verify-popup-close" id="ts-captcha-verify-dismiss">×</button>
      </div>` : '';
    return `
      <div class="ts-card" id="ts-captcha-card" style="margin-top:14px;">
        <div class="ts-card-head">
          <div class="ts-card-title">${escapeHtml(t('ts.captcha_settings_title') || 'CAPTCHA SOLVER')}</div>
          <div class="ts-captcha-status ${hasKey ? 'on' : 'off'}">${hasKey
            ? (escapeHtml((c.providerLabel || '2Captcha') + ' key set — auto-solve on'))
            : (escapeHtml(t('ts.captcha_status_manual') || 'No key — manual fallback'))}</div>
        </div>
        <div class="ts-field">
          <div class="ts-field-label">${escapeHtml(t('ts.captcha_provider') || 'Provider')}</div>
          <select id="ts-captcha-provider" class="ts-input">
            <option value="2captcha"    ${(c.provider || '2captcha') === '2captcha'    ? 'selected' : ''}>2Captcha — 2captcha.com</option>
            <option value="capmonster"  ${c.provider === 'capmonster'                  ? 'selected' : ''}>${escapeHtml(t('ts.captcha_provider_capmonster'))}</option>
            <option value="capsolver"   ${c.provider === 'capsolver'                   ? 'selected' : ''}>CapSolver — capsolver.com</option>
          </select>
          <div class="ts-field-hint">
            ${ c.provider === 'capsolver'
              ? `${escapeHtml(t('ts.captcha_hint_capsolver'))} <a href="https://dashboard.capsolver.com" target="_blank" rel="noopener">dashboard.capsolver.com</a>`
              : c.provider === 'capmonster'
                ? `${escapeHtml(t('ts.captcha_hint_capmonster'))} <a href="https://capmonster.cloud" target="_blank" rel="noopener">capmonster.cloud</a>`
                : `${escapeHtml(t('ts.captcha_hint_2captcha'))} <a href="https://2captcha.com/?from=signup" target="_blank" rel="noopener">2captcha.com</a>`
            }
          </div>
        </div>
        <div class="ts-field">
          <div class="ts-field-label">${escapeHtml(t('ts.captcha_api_key') || 'API key')}</div>
          <div class="ts-account-row">
            <input type="password" id="ts-captcha-key" class="ts-input ltr"
              placeholder="${hasKey ? `•••••••••••• ${t('ts.captcha_key_set')}` : t('ts.captcha_key_ph')}"
              autocomplete="off" />
            <button class="ts-btn mint" id="ts-captcha-save">${escapeHtml(t('ts.save'))}</button>
            ${hasKey ? `<button class="ts-btn" id="ts-captcha-verify" style="background:rgba(124,224,196,0.1);border:1px solid rgba(124,224,196,0.3);color:#7ce0c4;">${escapeHtml(t('ts.captcha_verify_btn'))}</button>` : ''}
            ${hasKey ? `<button class="ts-btn danger" id="ts-captcha-clear">${escapeHtml(t('ts.captcha_clear'))}</button>` : ''}
          </div>
          ${verifyPopup}
        </div>
        <div class="ts-toggle-row ${fbLocked ? 'ts-toggle-locked' : ''}">
          <div class="ts-toggle-label">
            ${escapeHtml(t('ts.captcha_manual_fallback'))}
            ${fbLocked ? `<span class="ts-toggle-lock-hint">${escapeHtml(t('ts.captcha_fallback_locked'))}</span>` : ''}
          </div>
          <div class="ts-toggle ${fbOn ? 'on' : ''} ${fbLocked ? 'disabled' : ''}" id="ts-captcha-fallback" role="switch" aria-checked="${fbOn}" ${fbLocked ? 'aria-disabled="true"' : ''}></div>
        </div>
      </div>
    `;
  }

  _fmtDuration(ms) {
    if (!ms || ms <= 0) return null;
    if (ms < 1000) return ms + 'ms';
    return (ms / 1000).toFixed(1) + 's';
  }

  _benchmarkStats(log) {
    const durations = log.filter(e => e.level === 'success' && e.durationMs > 0).map(e => e.durationMs);
    if (!durations.length) return null;
    const avg  = durations.reduce((a, b) => a + b, 0) / durations.length;
    const min  = Math.min(...durations);
    const max  = Math.max(...durations);
    return { avg, min, max, count: durations.length };
  }

  _renderLogToolbar(log) {
    const filter = this._logFilter || 'all';
    const autoScroll = this._logAutoScroll !== false;
    const stats = this._benchmarkStats(log);
    const counts = { all: log.length, success: 0, info: 0, warn: 0, error: 0 };
    log.forEach(e => { if (counts[e.level] !== undefined) counts[e.level]++; });

    const SVG_LIGHTNING = `<svg class="ts-bench-lightning" viewBox="0 0 12 18" fill="none" xmlns="http://www.w3.org/2000/svg" width="10" height="15">
      <path class="ts-bench-bolt" d="M7 1L1 10h5l-1 7 6-9H6l1-7z" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/>
    </svg>`;

    const SVG_FILTER = {
      all:     `<svg class="ts-filter-svg" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><line x1="1" y1="3" x2="11" y2="3"/><line x1="3" y1="6" x2="9" y2="6"/><line x1="5" y1="9" x2="7" y2="9"/></svg>`,
      success: `<svg class="ts-filter-svg ts-filter-ok" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline class="ts-filter-check" points="1.5 6 4.5 9 10.5 2.5"/></svg>`,
      info:    `<svg class="ts-filter-svg ts-filter-info" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><circle class="ts-filter-circle" cx="6" cy="6" r="5"/><line x1="6" y1="5" x2="6" y2="8.5"/><circle cx="6" cy="3.2" r=".6" fill="currentColor" stroke="none"/></svg>`,
      warn:    `<svg class="ts-filter-svg ts-filter-warn" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path class="ts-filter-tri" d="M6 1L11.2 10H.8Z"/><line x1="6" y1="4.5" x2="6" y2="7"/><circle cx="6" cy="8.8" r=".5" fill="currentColor" stroke="none"/></svg>`,
      error:   `<svg class="ts-filter-svg ts-filter-err" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle class="ts-filter-xcircle" cx="6" cy="6" r="5"/><line class="ts-filter-xline" x1="4" y1="4" x2="8" y2="8"/><line class="ts-filter-xline" x1="8" y1="4" x2="4" y2="8"/></svg>`,
    };

    const FILTER_LABELS = { all: 'الكل', success: 'نجح', info: 'معلومة', warn: 'تحذير', error: 'خطأ' };

    const speedChip = stats ? `
      <div class="ts-log-bench" key="${stats.count}">
        <span class="ts-log-bench-icon">${SVG_LIGHTNING}</span>
        <span class="ts-log-bench-avg" title="متوسط وقت إنشاء البوت">${this._fmtDuration(stats.avg)}</span>
        <span class="ts-log-bench-sep">·</span>
        <span class="ts-log-bench-best" title="أسرع بوت">
          <svg viewBox="0 0 8 8" width="7" height="7" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="1 5 4 2 7 5"/></svg>
          ${this._fmtDuration(stats.min)}
        </span>
        <span class="ts-log-bench-sep">·</span>
        <span class="ts-log-bench-worst" title="أبطأ بوت">
          <svg viewBox="0 0 8 8" width="7" height="7" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="1 3 4 6 7 3"/></svg>
          ${this._fmtDuration(stats.max)}
        </span>
        <span class="ts-log-bench-sep">·</span>
        <span class="ts-log-bench-count">${stats.count} بوت</span>
      </div>` : '';

    const filterBtns = ['all','success','info','warn','error'].map(key => `
      <button class="ts-log-filter-btn ts-log-filter-${key} ${filter === key ? 'active' : ''}" data-log-filter="${key}" title="${FILTER_LABELS[key]}">
        ${SVG_FILTER[key]}<span class="ts-filter-label">${escapeHtml(FILTER_LABELS[key])}</span>${counts[key] ? `<span class="ts-log-filter-cnt">${counts[key]}</span>` : ''}
      </button>`).join('');

    return `
      <div class="ts-log-toolbar">
        <div class="ts-log-toolbar-left">
          <span class="ts-log-toolbar-title">Live Log</span>
          ${speedChip}
        </div>
        <div class="ts-log-toolbar-right">
          <div class="ts-log-filters">${filterBtns}</div>
          <button class="ts-log-ctrl-btn ${autoScroll ? 'active' : ''}" id="ts-log-autoscroll" title="تمرير تلقائي">
            <svg class="ts-ctrl-scroll-svg" viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
              <line x1="7" y1="1" x2="7" y2="10"/><polyline points="3.5 7 7 10.5 10.5 7"/>
            </svg>
          </button>
          <button class="ts-log-ctrl-btn" id="ts-log-copy" title="نسخ السجل">
            <svg viewBox="0 0 14 14" width="12" height="12" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <rect x="4" y="1" width="8" height="10" rx="1.5"/><path d="M1.5 4v8a1 1 0 0 0 1 1h8"/>
            </svg>
          </button>
          <button class="ts-log-ctrl-btn ts-log-ctrl-clear" id="ts-log-clear" title="مسح السجل">
            <svg viewBox="0 0 14 14" width="12" height="12" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <path d="M1.5 3.5h11M4.5 3.5V2h5v1.5M5.5 6.5v4M8.5 6.5v4M2.5 3.5l.8 9h7.4l.8-9"/>
            </svg>
          </button>
        </div>
      </div>`;
  }

  _renderLog(log) {
    const filter = this._logFilter || 'all';
    const filtered = filter === 'all' ? log : log.filter(e => e.level === filter);
    if (!filtered.length) {
      return `<div class="ts-log-empty">${filter === 'all' ? (t('ts.log_empty') || 'لا يوجد سجل بعد') : 'لا توجد إدخالات من هذا النوع'}</div>`;
    }

    const ICONS = {
      success: `<svg class="ts-log-icon ts-log-icon-success" viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
        <polyline class="ts-icon-check-path" points="2 7 5.5 10.5 12 3"/>
      </svg>`,
      info: `<svg class="ts-log-icon ts-log-icon-info" viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round">
        <circle class="ts-icon-info-ring" cx="7" cy="7" r="5.5"/>
        <line x1="7" y1="5.5" x2="7" y2="9"/>
        <circle cx="7" cy="3.8" r=".55" fill="currentColor" stroke="none"/>
      </svg>`,
      warn: `<svg class="ts-log-icon ts-log-icon-warn" viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <path class="ts-icon-warn-tri" d="M7 1.5L12.5 11.5H1.5Z"/>
        <line x1="7" y1="5.5" x2="7" y2="8.2"/>
        <circle cx="7" cy="10" r=".55" fill="currentColor" stroke="none"/>
      </svg>`,
      error: `<svg class="ts-log-icon ts-log-icon-error" viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round">
        <circle class="ts-icon-err-ring" cx="7" cy="7" r="5.5"/>
        <line class="ts-icon-err-x1" x1="4.5" y1="4.5" x2="9.5" y2="9.5"/>
        <line class="ts-icon-err-x2" x1="9.5" y1="4.5" x2="4.5" y2="9.5"/>
      </svg>`,
    };

    const SVG_BOLT = `<svg class="ts-speed-bolt" viewBox="0 0 10 16" fill="none" width="7" height="11">
      <path d="M6 1L1 9h4l-1 6 5-8H5l1-6z" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/>
    </svg>`;

    return filtered.map((e, idx) => {
      const time = new Date(e.ts).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
      const icon = ICONS[e.level] || ICONS.info;
      const durBadge = e.durationMs > 0
        ? `<span class="ts-log-speed-badge ts-log-speed-${this._speedClass(e.durationMs)}" title="وقت الإنشاء">${SVG_BOLT} ${this._fmtDuration(e.durationMs)}</span>`
        : '';
      const botBadge = e.botName
        ? `<span class="ts-log-bot-badge">${escapeHtml(e.botName)}</span>`
        : '';
      const msgText = e.durationMs
        ? escapeHtml(e.msg.replace(/ ⚡ [\d.]+[ms]+$/, ''))
        : escapeHtml(e.msg);

      return `<div class="ts-log-line ts-log-lv-${e.level} ts-log-entry-new" data-idx="${idx}">
        <span class="ts-log-row-icon">${icon}</span>
        <span class="ts-log-time">${time}</span>
        <span class="ts-log-msg">${msgText}</span>
        <span class="ts-log-badges">${botBadge}${durBadge}</span>
      </div>`;
    }).join('');
  }

  _speedClass(ms) {
    if (!ms) return 'mid';
    if (ms < 3000)  return 'fast';
    if (ms < 7000)  return 'mid';
    return 'slow';
  }

  // ── Inline Bot Tokens section (main page, below library button) ──────────
  _renderBotTokensSection() {
    const tokens = this.botTokens || [];
    const count = tokens.length;
    const inner = count === 0
      ? `<div class="ts-lib-empty" style="padding:18px 8px;">
           <div style="font-size:2rem;margin-bottom:10px;"><span class="ts-emoji-bob">🔑</span></div>
           <div>${escapeHtml(t('ts.bt_empty_title'))}</div>
           <div style="font-size:11px;color:var(--ts-muted);margin-top:5px;">
             ${escapeHtml(t('ts.bt_empty_hint'))}
           </div>
         </div>`
      : `<div class="ts-bt-header">
           <div class="ts-bt-count">${count} ${escapeHtml(t('ts.bt_count'))}</div>
           <div class="ts-bt-hint">${escapeHtml(t('ts.bt_hint'))}</div>
         </div>
         <div class="ts-bt-list">
           ${tokens.map(entry => {
             const iconUrl = entry.icon
               ? `https://cdn.discordapp.com/app-icons/${entry.appId}/${entry.icon}.png?size=64`
               : null;
             const initials = this._initialsFor(entry.name);
             const dateStr = entry.resetAt
               ? new Date(entry.resetAt).toLocaleString(getLang() === 'ar' ? 'ar-SA' : 'en-GB', { dateStyle: 'short', timeStyle: 'short' })
               : '';
             return `
               <div class="ts-bt-card" data-app-id="${escapeAttr(entry.appId)}">
                 <div class="ts-bt-avatar">
                   ${iconUrl
                     ? `<img src="${iconUrl}" alt="" onerror="this.replaceWith(Object.assign(document.createElement('span'),{textContent:'${escapeAttr(initials)}',className:'ts-bt-initials'}))">`
                     : `<span class="ts-bt-initials">${escapeHtml(initials)}</span>`}
                 </div>
                 <div class="ts-bt-info">
                   <div class="ts-bt-name">${escapeHtml(entry.name)}</div>
                   <div class="ts-bt-appid">${escapeHtml(entry.appId)}</div>
                   ${dateStr ? `<div class="ts-bt-date">${escapeHtml(t('ts.bt_last_reset'))}: ${escapeHtml(dateStr)}</div>` : ''}
                   <div class="ts-bt-token-row">
                     <div class="ts-bt-token-mask" data-token="${escapeAttr(entry.token)}" data-shown="0">
                       ${'•'.repeat(Math.min(entry.token.length, 32))}
                     </div>
                     <button class="ts-bt-show" data-show-token="${escapeAttr(entry.appId)}" title="${escapeAttr(t('ts.bt_show'))}">👁</button>
                     <button class="ts-btn mint ts-bt-copy" data-copy-token="${escapeAttr(entry.token)}" title="${escapeAttr(t('ts.bt_copy'))}">${escapeHtml(t('ts.bt_copy'))}</button>
                   </div>
                 </div>
                 <button class="ts-bt-delete" data-delete-token="${escapeAttr(entry.appId)}" title="${escapeAttr(t('ts.bt_delete'))}">✕</button>
               </div>`;
           }).join('')}
         </div>`;
    return `
      <div class="ts-card ts-bot-tokens-inline" style="margin-top:14px;">
        <div class="ts-card-head" style="margin-bottom:${count ? 16 : 0}px;">
          <div class="ts-card-title" style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
            <span class="ts-emoji-key">🔑</span> ${escapeHtml(t('ts.lib_tab_tokens'))}
            ${count ? `<span class="ts-tab-badge">${count}</span>` : ''}
          </div>
        </div>
        ${inner}
      </div>`;
  }

  _bindBotTokensSection(root) {
    root.querySelectorAll('[data-copy-token]').forEach(btn => {
      btn.addEventListener('click', async () => {
        _emojiPop(btn);
        try {
          await copyToClipboard(btn.dataset.copyToken);
          showNotification(t('ts.token_copied') || 'Token copied ✓', 'success');
        } catch (e) { showNotification(t('ts.copy_failed') || 'Copy failed', 'error'); }
      });
    });
    root.querySelectorAll('[data-show-token]').forEach(btn => {
      btn.addEventListener('click', () => {
        _emojiPop(btn);
        const appId = btn.dataset.showToken;
        const card = root.querySelector(`.ts-bt-card[data-app-id="${CSS.escape(appId)}"]`);
        const mask = card?.querySelector('.ts-bt-token-mask');
        if (!mask) return;
        const shown = mask.dataset.shown === '1';
        if (shown) {
          mask.textContent = '•'.repeat(Math.min(mask.dataset.token.length, 32));
          mask.dataset.shown = '0';
          btn.textContent = '👁';
        } else {
          mask.textContent = mask.dataset.token;
          mask.dataset.shown = '1';
          btn.textContent = '🙈';
        }
      });
    });
    root.querySelectorAll('[data-delete-token]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const appId = btn.dataset.deleteToken;
        try {
          const r = await window.electronAPI.tsDeleteBotToken(appId);
          this.botTokens = r?.tokens || this.botTokens.filter(x => x.appId !== appId);
          this._refreshBotTokensUI();
        } catch (e) { showNotification(t('ts.bt_delete_failed') + e.message, 'error'); }
      });
    });
  }

  _refreshBotTokensUI() {
    const section = this.contentArea.querySelector('#ts-bot-tokens-section');
    if (section) {
      section.innerHTML = this._renderBotTokensSection();
      this._bindBotTokensSection(section);
    }
    this._updateTokensTabBadge();
  }

  // ── Library trigger button ────────────────────────────
  // Compact button that lives on the main page and opens the full-screen
  // library overlay. Shows two badges so the user can see at a glance:
  //   • how many bots they've created in this session
  //   • how many teams/apps the loaded library has (when it's already loaded)
  _renderLibraryTrigger(s) {
    const sessionBots = (s?.bots || []).length;
    const lib = this.library;
    const libCount = lib ? ((lib.totals?.teams || 0) + (lib.totals?.apps || 0)) : null;
    const badges = [];
    if (sessionBots) badges.push(`<span class="ts-libbtn-badge mint">${sessionBots} ${t('ts.lib_btn_session_short') || 'جديد'}</span>`);
    if (libCount !== null) badges.push(`<span class="ts-libbtn-badge">${libCount} ${t('ts.lib_btn_total_short') || 'إجمالي'}</span>`);
    return `
      <div class="ts-libbtn-wrap" style="margin-top:14px;">
        <button class="ts-libbtn" id="ts-lib-open" type="button">
          <span class="ts-libbtn-icon" aria-hidden="true">
            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
              <rect x="3.5" y="4" width="6" height="16" rx="1.4"/>
              <rect x="10.5" y="4" width="4" height="16" rx="1.2"/>
              <path d="M16.6 5.2l3.3 .9a1 1 0 0 1 .7 1.22l-3 11.2a1 1 0 0 1 -1.22 .7l-1.38 -.37"/>
            </svg>
          </span>
          <span class="ts-libbtn-text">
            <span class="ts-libbtn-title">${t('ts.lib_btn_title') || 'فتح المكتبة'}</span>
            <span class="ts-libbtn-sub">${t('ts.lib_btn_sub') || 'التيمز · البوتات الحالية · البوتات المنشأة'}</span>
          </span>
          <span class="ts-libbtn-badges">${badges.join('')}</span>
        </button>
      </div>
    `;
  }

  // ── Full-screen library overlay ───────────────────────
  // Three tabs:
  //   teams    → all teams the account belongs to (with apps under each)
  //   personal → standalone apps not under any team
  //   created  → bots produced by the current TrueStudio session
  _openLibraryModal(initialTab = 'teams') {
    if (this._libModal) {
      this._switchLibraryTab(initialTab);
      return;
    }
    const savedCount = this.botTokens.length;
    const overlay = document.createElement('div');
    overlay.className = 'ts-lib-overlay';
    overlay.innerHTML = `
      <div class="ts-lib-page">
        <header class="ts-lib-page-head">
          <button class="ts-lib-back" id="ts-lib-close" aria-label="back">←</button>
          <div class="ts-lib-page-title">${t('ts.lib_btn_title') || 'فتح المكتبة'}</div>
          <div class="ts-lib-head-actions">
            <button class="ts-btn ts-intents-all-btn" id="ts-lib-intents-all"
              ${(!this.selectedEmail) ? 'disabled' : ''}
              title="تفعيل الثلاث Privileged Intents لكل بوتات المكتبة">
              <span class="ts-drawn-icon bolt" aria-hidden="true"><i></i></span> iNTeNT ALl
            </button>
            <button class="ts-btn${(this.pfp?.avatar || this.pfp?.banner) ? ' mint' : ''}" id="ts-lib-pfp-all"
              ${(!this.pfp?.avatar && !this.pfp?.banner) ? 'disabled' : ''}
              title="${(this.pfp?.avatar || this.pfp?.banner) ? 'تطبيق Pfp المحفوظ على كل البوتات ✓' : 'احفظ Avatar أو Banner أولاً'}">
              <span class="ts-drawn-icon image" aria-hidden="true"><i></i></span> Pfp all
            </button>
            <button class="ts-btn" id="ts-lib-bulk-invite"
              ${!this.library ? 'disabled' : ''}
              title="توليد روابط دعوة لكل البوتات وإضافتهم تلقائياً للسيرفرات">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" style="vertical-align:-1px"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg> Bulk Invite
            </button>
            <button class="ts-btn ts-reset-all-btn" id="ts-lib-reset-all"
              ${(!this.library || this._resetAllInFlight) ? 'disabled' : ''}
              title="${escapeAttr(t('ts.reset_all_title'))}"
              style="${this._resetAllInFlight ? 'display:none' : ''}">
              ⟳ Reset All
            </button>
            <button class="ts-btn ts-stop-btn" id="ts-lib-stop-all"
              title="${escapeAttr(t('ts.stop_reset_all_title'))}"
              style="${this._resetAllInFlight ? '' : 'display:none'}">
              ⏹ Stop
            </button>
            <button class="ts-btn" id="ts-lib-refresh-modal" ${this.libraryLoading || !this.selectedEmail ? 'disabled' : ''}>
              ${this.libraryLoading ? (t('ts.testing') || '...') : (t('ts.lib_refresh') || 'تحديث')}
            </button>
          </div>
        </header>
        <nav class="ts-lib-tabs" role="tablist">
          <button class="ts-lib-tab" data-tab="teams" role="tab">${t('ts.lib_tab_teams') || 'التيمز'}</button>
          <button class="ts-lib-tab" data-tab="personal" role="tab">${t('ts.lib_tab_personal') || 'البوتات الحالية'}</button>
          <button class="ts-lib-tab" data-tab="created" role="tab">${t('ts.lib_tab_created') || 'البوتات المنشأة'}</button>
          <button class="ts-lib-tab" data-tab="tokens" role="tab">
            <span class="ts-emoji-key">🔑</span> ${t('ts.lib_tab_tokens')}${savedCount ? ` <span class="ts-tab-badge">${savedCount}</span>` : ''}
          </button>
        </nav>
        <div class="ts-lib-page-body" id="ts-lib-page-body"></div>
      </div>
    `;
    document.body.appendChild(overlay);
    this._libModal = overlay;
    this._libCurrentTab = initialTab;

    overlay.querySelector('#ts-lib-close').addEventListener('click', () => this._closeLibraryModal());
    overlay.querySelector('#ts-lib-refresh-modal').addEventListener('click', () => this.loadLibrary());
    overlay.querySelector('#ts-lib-reset-all').addEventListener('click', () => this._resetAllBots());
    overlay.querySelector('#ts-lib-intents-all')?.addEventListener('click', () => this._applyIntentsAll(true));
    overlay.querySelector('#ts-lib-pfp-all')?.addEventListener('click', () => this._applyPfpAll());
    overlay.querySelector('#ts-lib-bulk-invite')?.addEventListener('click', () => this._openBulkInviteModal());
    overlay.querySelector('#ts-lib-stop-all').addEventListener('click', async () => {
      try {
        await window.electronAPI.tsResetAllStop();
        showNotification(t('ts.stop_reset_all_sent'), 'info');
      } catch (e) { showNotification(t('ts.stop_reset_all_failed') + e.message, 'error'); }
    });
    overlay.querySelectorAll('.ts-lib-tab').forEach(btn => {
      btn.addEventListener('click', () => this._switchLibraryTab(btn.dataset.tab));
    });

    this._switchLibraryTab(initialTab);
    if (!this.library && !this.libraryLoading && this.selectedEmail) {
      this.loadLibrary();
    }
  }

  _closeLibraryModal() {
    if (this._libModal && this._libModal.parentNode) {
      this._libModal.parentNode.removeChild(this._libModal);
    }
    this._libModal = null;
    this._libCurrentTab = null;
  }

  _switchLibraryTab(tab) {
    if (!this._libModal) return;
    this._libCurrentTab = tab;
    this._libModal.querySelectorAll('.ts-lib-tab').forEach(b => {
      b.classList.toggle('active', b.dataset.tab === tab);
    });
    this._renderLibraryTab();
  }

  _renderLibraryTab() {
    if (!this._libModal) return;
    const body = this._libModal.querySelector('#ts-lib-page-body');
    if (!body) return;
    const tab = this._libCurrentTab || 'teams';
    if (tab === 'created') {
      body.innerHTML = this._renderCreatedBotsTab();
      this._bindCreatedTab(body);
      return;
    }
    if (tab === 'tokens') {
      body.innerHTML = this._renderBotTokensTab();
      this._bindBotTokensTab(body);
      return;
    }
    // teams + personal share the loading/error/empty story since they come
    // from the same /api/ts/library response
    if (this.libraryLoading) {
      body.innerHTML = `<div class="ts-lib-empty">${t('ts.lib_loading') || 'جاري التحميل…'}</div>`;
      return;
    }
    if (this.libraryError) {
      body.innerHTML = `<div class="ts-lib-empty error">${escapeHtml(this.libraryError)}</div>`;
      return;
    }
    if (!this.selectedEmail) {
      body.innerHTML = `<div class="ts-lib-empty">${t('ts.pick_account_first') || 'اختر حساباً أولاً من الأعلى'}</div>`;
      return;
    }
    if (!this.library) {
      body.innerHTML = `<div class="ts-lib-empty">${t('ts.lib_hint') || 'اضغط تحديث لتحميل المكتبة'}</div>`;
      return;
    }
    if (tab === 'teams') {
      const teams = this.library.teams || [];
      // Header row: "Create Team" button always visible
      const createBtn = `<button class="ts-btn ts-create-team-btn" id="ts-lib-create-team"
        title="${escapeAttr(t('ts.team_create_title'))}">${escapeHtml(t('ts.team_create_btn'))}</button>`;
      if (!teams.length) {
        body.innerHTML = `
          <div class="ts-lib-teams-header">${createBtn}</div>
          <div class="ts-lib-empty">${t('ts.lib_no_teams') || 'لا توجد تيمز على هذا الحساب'}</div>`;
        body.querySelector('#ts-lib-create-team')?.addEventListener('click', () => this._openCreateTeamModal());
        return;
      }
      body.innerHTML = `
        <div class="ts-lib-teams-header">${createBtn}</div>
        ${teams.map(team => {
          const roleBadge = this._teamRoleBadge(team);
          return `
            <div class="ts-team">
              <div class="ts-team-head">
                <div class="ts-team-name">${escapeHtml(team.name)}${roleBadge}</div>
                <div class="ts-team-badge">${team.apps.length}/${team.appLimit || 25}</div>
              </div>
              ${team.apps.length
                ? `<div class="ts-cards">${team.apps.map(a => this._renderAppCard(a)).join('')}</div>`
                : `<div class="ts-team-empty">${t('ts.lib_team_empty') || 'لا تطبيقات'}</div>`}
            </div>
          `;
        }).join('')}
      `;
      this._bindResetButtons(body);
      this._bindIntentButtons(body);
      this._bindInviteButtons(body);
      body.querySelector('#ts-lib-create-team')?.addEventListener('click', () => this._openCreateTeamModal());
      return;
    }
    if (tab === 'personal') {
      const apps = this.library.personal || [];
      const teams = this.library.teams || [];
      if (!apps.length) {
        body.innerHTML = `<div class="ts-lib-empty">${t('ts.lib_no_personal') || 'لا توجد تطبيقات شخصية على هذا الحساب'}</div>`;
        return;
      }
      body.innerHTML = `<div class="ts-cards">${apps.map(a => this._renderAppCard(a, { showMoveToTeam: teams.length > 0 })).join('')}</div>`;
      this._bindResetButtons(body);
      this._bindIntentButtons(body);
      this._bindInviteButtons(body);
      this._bindMoveToTeamButtons(body);
      return;
    }
  }


  _bindIntentButtons(root) {
    root.querySelectorAll('[data-intents-bot]').forEach(btn => {
      if (btn._intentBound) return;
      btn._intentBound = true;
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const appId = btn.getAttribute('data-intents-bot');
        const name  = btn.getAttribute('data-bot-name') || appId;
        this._openIntentsModal(appId, name);
      });
    });
  }

  _bindInviteButtons(root) {
    root.querySelectorAll('[data-invite-bot]').forEach(btn => {
      if (btn._inviteBound) return;
      btn._inviteBound = true;
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const appId = btn.getAttribute('data-invite-bot');
        const name  = btn.getAttribute('data-bot-name') || appId;
        this._openInviteModal(appId, name);
      });
    });
  }

  /* SVG icon helpers — used by invite modals (no emojis) */
  _invIcons() {
    return {
      link:   `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>`,
      copy:   `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`,
      open:   `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>`,
      reload: `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 .49-4"/></svg>`,
      plus:   `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" aria-hidden="true"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>`,
      search: `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>`,
      crown:  `<svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor" stroke="none" aria-hidden="true"><path d="M3 19h18M4.5 9l3.5 4 4-7 4 7 3.5-4L21 19H3z"/></svg>`,
      check:  `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="20 6 9 17 4 12"/></svg>`,
      x:      `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.8" stroke-linecap="round" aria-hidden="true"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`,
      spin:   `<svg class="ts-icon-spin" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" aria-hidden="true"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg>`,
    };
  }

  _openInviteModal(appId, name) {
    document.querySelector('.ts-invite-overlay')?.remove();
    const overlay = document.createElement('div');
    overlay.className = 'ts-invite-overlay';

    const ic = this._invIcons();
    const _buildUrl = (perms) =>
      `https://discord.com/oauth2/authorize?client_id=${encodeURIComponent(appId)}&scope=bot+applications.commands&permissions=${encodeURIComponent(perms || '8')}`;

    overlay.innerHTML = `
      <div class="ts-invite-modal">
        <div class="ts-token-modal-head">
          <div class="ts-token-modal-title">
            ${ic.link}
            دعوة البوت · <span class="ts-invite-bot-name">${escapeHtml(name)}</span>
          </div>
          <button class="ts-token-modal-close" type="button" aria-label="close">×</button>
        </div>
        <div class="ts-invite-body">

          <div class="ts-invite-section">
            <div class="ts-invite-section-label">${ic.link} رابط الدعوة</div>
            <div class="ts-invite-perms-row">
              <label class="ts-invite-perms-label" for="ts-invite-perms">Permissions</label>
              <input type="number" id="ts-invite-perms" class="ts-invite-perms-input" value="8" min="0" title="8 = Administrator | 0 = بدون صلاحيات">
              <button class="ts-btn ts-btn-xs" id="ts-invite-regen" title="تحديث الرابط">${ic.reload}</button>
            </div>
            <div class="ts-invite-url-row">
              <input type="text" id="ts-invite-url" class="ts-invite-url-input" readonly value="${escapeAttr(_buildUrl('8'))}">
              <button class="ts-btn ts-btn-xs" id="ts-invite-copy" title="نسخ">${ic.copy}</button>
              <a class="ts-btn ts-btn-xs" id="ts-invite-open" href="${escapeAttr(_buildUrl('8'))}" target="_blank" rel="noopener" title="فتح">${ic.open}</a>
            </div>
          </div>

          <div class="ts-invite-divider"><span>إضافة تلقائية من الحساب</span></div>

          <div class="ts-invite-section">
            ${this.selectedEmail ? `
              <div class="ts-invite-search-wrap">${ic.search}<input type="text" id="ts-invite-guild-search" class="ts-invite-search" placeholder="ابحث عن سيرفر…"></div>
              <div class="ts-invite-guild-list" id="ts-invite-guild-list">
                <div class="ts-invite-guild-loading">${ic.spin} جاري التحميل…</div>
              </div>
              <button class="ts-btn mint ts-invite-add-btn" id="ts-invite-add-btn" disabled>
                ${ic.plus} إضافة للسيرفر المختار
              </button>
            ` : `<div class="ts-invite-no-account">اختر حساباً من القائمة الرئيسية لتفعيل الإضافة التلقائية</div>`}
          </div>

          <div class="ts-invite-log" id="ts-invite-log" style="display:none"></div>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);
    requestAnimationFrame(() => overlay.classList.add('open'));

    // Close
    overlay.querySelector('.ts-token-modal-close').addEventListener('click', () => {
      overlay.classList.remove('open');
      setTimeout(() => overlay.remove(), 260);
    });
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) { overlay.classList.remove('open'); setTimeout(() => overlay.remove(), 260); }
    });

    // Permissions regen
    const permsInput = overlay.querySelector('#ts-invite-perms');
    const urlInput   = overlay.querySelector('#ts-invite-url');
    const openLink   = overlay.querySelector('#ts-invite-open');
    const regenUrl   = () => {
      const u = _buildUrl(permsInput?.value || '8');
      if (urlInput)  urlInput.value = u;
      if (openLink) openLink.href  = u;
    };
    overlay.querySelector('#ts-invite-regen')?.addEventListener('click', regenUrl);
    permsInput?.addEventListener('input', regenUrl);

    // Copy
    overlay.querySelector('#ts-invite-copy')?.addEventListener('click', () => {
      const url = overlay.querySelector('#ts-invite-url')?.value || '';
      navigator.clipboard?.writeText(url).then(() => showNotification('تم نسخ الرابط ✓', 'success')).catch(() => showNotification('تعذّر النسخ', 'error'));
    });

    if (!this.selectedEmail) return;

    // Load guilds
    let allGuilds = [];
    let selectedGuildId = null;
    const listEl  = overlay.querySelector('#ts-invite-guild-list');
    const addBtn  = overlay.querySelector('#ts-invite-add-btn');
    const logEl   = overlay.querySelector('#ts-invite-log');
    const searchEl = overlay.querySelector('#ts-invite-guild-search');

    const _renderGuilds = (guilds) => {
      if (!listEl) return;
      if (!guilds.length) { listEl.innerHTML = '<div class="ts-invite-guild-empty">لا توجد سيرفرات بصلاحيات الإدارة</div>'; return; }
      listEl.innerHTML = guilds.map(g => `
        <div class="ts-invite-guild-item${g.id === selectedGuildId ? ' selected' : ''}" data-guild-id="${escapeAttr(g.id)}">
          ${g.icon
            ? `<img class="ts-invite-guild-icon" src="${escapeAttr(g.icon)}" alt="" loading="lazy" onerror="this.style.display='none';this.nextElementSibling.style.display='flex'"><span class="ts-invite-guild-icon ts-invite-guild-initials" style="display:none">${escapeHtml((g.name||'?')[0].toUpperCase())}</span>`
            : `<span class="ts-invite-guild-icon ts-invite-guild-initials">${escapeHtml((g.name||'?')[0].toUpperCase())}</span>`}
          <span class="ts-invite-guild-name">${escapeHtml(g.name)}</span>
          ${g.owner ? `<span class="ts-invite-guild-crown">${ic.crown}</span>` : ''}
        </div>
      `).join('');
      listEl.querySelectorAll('.ts-invite-guild-item').forEach(item => {
        item.addEventListener('click', () => {
          selectedGuildId = item.getAttribute('data-guild-id');
          listEl.querySelectorAll('.ts-invite-guild-item').forEach(i => i.classList.remove('selected'));
          item.classList.add('selected');
          if (addBtn) addBtn.disabled = false;
        });
      });
    };

    window.electronAPI.tsBotInviteGuilds(this.selectedEmail).then(r => {
      if (!r?.success) throw new Error(r?.error || 'فشل تحميل السيرفرات');
      allGuilds = r.guilds || [];
      _renderGuilds(allGuilds);
    }).catch(e => {
      if (listEl) listEl.innerHTML = `<div class="ts-invite-guild-empty" style="color:#ff6b7b">${ic.x} ${escapeHtml(e.message)}</div>`;
    });

    searchEl?.addEventListener('input', () => {
      const q = (searchEl.value || '').toLowerCase().trim();
      _renderGuilds(q ? allGuilds.filter(g => g.name.toLowerCase().includes(q)) : allGuilds);
    });

    /* addLog: type = 'ok' | 'fail' | 'info' */
    const addLog = (type, msg) => {
      if (!logEl) return;
      logEl.style.display = '';
      const d = document.createElement('div');
      d.className = `ts-invite-log-line ${type}`;
      const s = document.createElement('span');
      s.className = 'ts-ilog-icon';
      s.innerHTML = type === 'ok' ? ic.check : type === 'fail' ? ic.x : ic.spin;
      const t2 = document.createElement('span');
      t2.textContent = msg;
      d.append(s, t2);
      logEl.appendChild(d);
      logEl.scrollTop = logEl.scrollHeight;
    };

    addBtn?.addEventListener('click', async () => {
      if (!selectedGuildId || addBtn.disabled) return;
      addBtn.disabled = true;
      const guildName = allGuilds.find(g => g.id === selectedGuildId)?.name || selectedGuildId;
      addLog('info', `جاري إضافة البوت إلى "${guildName}"…`);
      try {
        const resp = await fetch('/api/ts/bot-add-to-guild', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: this.selectedEmail, appId, guildId: selectedGuildId, permissions: permsInput?.value || '8' }),
        });
        const reader = resp.body.getReader(); const decoder = new TextDecoder(); let buf = '';
        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          buf += decoder.decode(value, { stream: true });
          const parts = buf.split('\n'); buf = parts.pop();
          for (const ln of parts) {
            const raw = ln.trim();
            if (!raw.startsWith('data:')) continue;
            let evt; try { evt = JSON.parse(raw.slice(5)); } catch { continue; }
            if (evt.type === 'step')  addLog('info', evt.msg);
            else if (evt.type === 'done')  { addLog('ok',   `تم إضافة البوت إلى "${guildName}"`); addBtn.disabled = false; }
            else if (evt.type === 'error') { addLog('fail', evt.error); addBtn.disabled = false; }
          }
        }
      } catch (e) {
        addLog('fail', e.message || String(e));
        addBtn.disabled = false;
      }
    });
  }

  /* ═══════════════════════════════════════════════════════════════════
     Bulk Invite — shows ALL bots in a table with links + bulk auto-add
     ═══════════════════════════════════════════════════════════════════ */
  _openBulkInviteModal() {
    if (!this.library) { showNotification('افتح المكتبة أولاً', 'error'); return; }
    document.querySelector('.ts-bulk-invite-overlay')?.remove();

    const ic = this._invIcons();

    /* collect all bots from library, dedupe by id */
    const seen = new Set();
    const allBots = [
      ...(this.library.teams?.flatMap(t => t.apps || []) || []),
      ...(this.library.personal || []),
    ].filter(a => {
      if (!a.isBot || !a.id || seen.has(a.id)) return false;
      seen.add(a.id);
      return true;
    });

    if (!allBots.length) { showNotification('لا توجد بوتات في المكتبة', 'error'); return; }

    const buildUrl = (botId, perms) =>
      `https://discord.com/oauth2/authorize?client_id=${encodeURIComponent(botId)}&scope=bot+applications.commands&permissions=${encodeURIComponent(perms || '8')}`;

    const botRowHtml = (b, perms) => {
      const iconUrl = b.icon ? `https://cdn.discordapp.com/app-icons/${b.id}/${b.icon}.png?size=32` : null;
      const initials = (b.name || '?').slice(0, 2).toUpperCase();
      const url = buildUrl(b.id, perms);
      return `
        <tr data-bot-id="${escapeAttr(b.id)}">
          <td class="ts-bt-icon">
            ${iconUrl
              ? `<img class="ts-bt-icon-img" src="${escapeAttr(iconUrl)}" alt="" loading="lazy" onerror="this.style.display='none';this.nextElementSibling.style.display='flex'"><span class="ts-bt-icon-initials" style="display:none">${escapeHtml(initials)}</span>`
              : `<span class="ts-bt-icon-initials">${escapeHtml(initials)}</span>`}
          </td>
          <td class="ts-bt-name" title="${escapeAttr(b.id)}">${escapeHtml(b.name)}</td>
          <td class="ts-bt-url">
            <input type="text" class="ts-bt-url-input" readonly value="${escapeAttr(url)}" data-bot-id="${escapeAttr(b.id)}">
          </td>
          <td class="ts-bt-act">
            <button class="ts-btn ts-btn-xs ts-bt-copy-one" data-bot-id="${escapeAttr(b.id)}" title="نسخ">${ic.copy}</button>
            <a class="ts-btn ts-btn-xs ts-bt-open-one" href="${escapeAttr(url)}" target="_blank" rel="noopener" title="فتح" data-bot-id="${escapeAttr(b.id)}">${ic.open}</a>
            <span class="ts-bt-status" data-bot-id="${escapeAttr(b.id)}"></span>
          </td>
        </tr>`;
    };

    const overlay = document.createElement('div');
    overlay.className = 'ts-bulk-invite-overlay';
    overlay.innerHTML = `
      <div class="ts-bulk-invite-modal">
        <div class="ts-token-modal-head">
          <div class="ts-token-modal-title">${ic.link} Bulk Invite <span class="ts-bulk-count">· ${allBots.length} بوت</span></div>
          <button class="ts-token-modal-close" type="button" aria-label="close">×</button>
        </div>
        <div class="ts-bulk-invite-body">

          <!-- top row: permissions + copy-all -->
          <div class="ts-bulk-top-row">
            <div class="ts-invite-perms-row">
              <label class="ts-invite-perms-label" for="ts-bulk-perms">Permissions</label>
              <input type="number" id="ts-bulk-perms" class="ts-invite-perms-input" value="8" min="0" title="8=Admin | 0=None">
              <button class="ts-btn ts-btn-xs" id="ts-bulk-regen" title="تحديث كل الروابط">${ic.reload} تحديث</button>
            </div>
            <button class="ts-btn ts-btn-xs" id="ts-bulk-copy-all">${ic.copy} نسخ الكل</button>
          </div>

          <!-- bot table -->
          <div class="ts-bulk-table-wrap">
            <table class="ts-bulk-table">
              <thead>
                <tr>
                  <th class="ts-bt-icon"></th>
                  <th class="ts-bt-name">البوت</th>
                  <th class="ts-bt-url">رابط الدعوة</th>
                  <th class="ts-bt-act"></th>
                </tr>
              </thead>
              <tbody id="ts-bulk-tbody">
                ${allBots.map(b => botRowHtml(b, '8')).join('')}
              </tbody>
            </table>
          </div>

          ${this.selectedEmail ? `
            <!-- auto-add section -->
            <div class="ts-invite-divider"><span>إضافة تلقائية — كل البوتات للسيرفر المختار</span></div>
            <div class="ts-invite-search-wrap">${ic.search}<input type="text" id="ts-bulk-guild-search" class="ts-invite-search" placeholder="ابحث عن سيرفر…"></div>
            <div class="ts-invite-guild-list" id="ts-bulk-guild-list">
              <div class="ts-invite-guild-loading">${ic.spin} جاري تحميل السيرفرات…</div>
            </div>
            <div class="ts-bulk-add-row">
              <button class="ts-btn mint" id="ts-bulk-add-btn" disabled>${ic.plus} إضافة جميع البوتات</button>
              <span class="ts-bulk-progress-text" id="ts-bulk-prog-text"></span>
            </div>
          ` : `<div class="ts-invite-no-account">اختر حساباً لتفعيل الإضافة التلقائية لكل البوتات</div>`}

          <!-- live log -->
          <div class="ts-invite-log" id="ts-bulk-log" style="display:none"></div>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);
    requestAnimationFrame(() => overlay.classList.add('open'));

    const closeModal = () => { overlay.classList.remove('open'); setTimeout(() => overlay.remove(), 280); };
    overlay.querySelector('.ts-token-modal-close').addEventListener('click', closeModal);
    overlay.addEventListener('click', e => { if (e.target === overlay) closeModal(); });

    /* ── Permissions → regen all rows ── */
    const permsInput = overlay.querySelector('#ts-bulk-perms');
    const regenAll = () => {
      const p = permsInput?.value || '8';
      overlay.querySelectorAll('.ts-bt-url-input').forEach(inp => {
        const bid = inp.getAttribute('data-bot-id');
        if (bid) inp.value = buildUrl(bid, p);
      });
      overlay.querySelectorAll('.ts-bt-open-one').forEach(a => {
        const bid = a.getAttribute('data-bot-id');
        if (bid) a.href = buildUrl(bid, p);
      });
    };
    overlay.querySelector('#ts-bulk-regen')?.addEventListener('click', regenAll);
    permsInput?.addEventListener('input', regenAll);

    /* ── Copy all links ── */
    overlay.querySelector('#ts-bulk-copy-all')?.addEventListener('click', () => {
      const urls = [...overlay.querySelectorAll('.ts-bt-url-input')].map(i => i.value).join('\n');
      navigator.clipboard?.writeText(urls).then(
        () => showNotification(`تم نسخ ${allBots.length} رابط`, 'success'),
        () => showNotification('تعذّر النسخ', 'error')
      );
    });

    /* ── Per-row copy ── */
    overlay.addEventListener('click', e => {
      const btn = e.target.closest('.ts-bt-copy-one');
      if (!btn) return;
      const bid = btn.getAttribute('data-bot-id');
      const inp = overlay.querySelector(`.ts-bt-url-input[data-bot-id="${bid}"]`);
      if (inp) navigator.clipboard?.writeText(inp.value)
        .then(() => showNotification('تم النسخ', 'success'), () => {});
    });

    if (!this.selectedEmail) return;

    /* ── Guild loader ── */
    let allGuilds = [], selectedGuildId = null;
    const gListEl  = overlay.querySelector('#ts-bulk-guild-list');
    const addBtn   = overlay.querySelector('#ts-bulk-add-btn');
    const logEl    = overlay.querySelector('#ts-bulk-log');
    const progText = overlay.querySelector('#ts-bulk-prog-text');
    const gSearch  = overlay.querySelector('#ts-bulk-guild-search');

    const addLog = (type, msg) => {
      if (!logEl) return;
      logEl.style.display = '';
      const d = document.createElement('div');
      d.className = `ts-invite-log-line ${type}`;
      const s = document.createElement('span');
      s.className = 'ts-ilog-icon';
      s.innerHTML = type === 'ok' ? ic.check : type === 'fail' ? ic.x : ic.spin;
      const t2 = document.createElement('span');
      t2.textContent = msg;
      d.append(s, t2);
      logEl.appendChild(d);
      logEl.scrollTop = logEl.scrollHeight;
    };

    const renderGuilds = (guilds) => {
      if (!gListEl) return;
      if (!guilds.length) { gListEl.innerHTML = '<div class="ts-invite-guild-empty">لا توجد سيرفرات بصلاحيات الإدارة</div>'; return; }
      gListEl.innerHTML = guilds.map(g => `
        <div class="ts-invite-guild-item${g.id === selectedGuildId ? ' selected' : ''}" data-guild-id="${escapeAttr(g.id)}">
          ${g.icon
            ? `<img class="ts-invite-guild-icon" src="${escapeAttr(g.icon)}" alt="" loading="lazy" onerror="this.style.display='none';this.nextElementSibling.style.display='flex'"><span class="ts-invite-guild-icon ts-invite-guild-initials" style="display:none">${escapeHtml((g.name||'?')[0].toUpperCase())}</span>`
            : `<span class="ts-invite-guild-icon ts-invite-guild-initials">${escapeHtml((g.name||'?')[0].toUpperCase())}</span>`}
          <span class="ts-invite-guild-name">${escapeHtml(g.name)}</span>
          ${g.owner ? `<span class="ts-invite-guild-crown">${ic.crown}</span>` : ''}
        </div>
      `).join('');
      gListEl.querySelectorAll('.ts-invite-guild-item').forEach(item => {
        item.addEventListener('click', () => {
          selectedGuildId = item.getAttribute('data-guild-id');
          gListEl.querySelectorAll('.ts-invite-guild-item').forEach(i => i.classList.remove('selected'));
          item.classList.add('selected');
          if (addBtn) addBtn.disabled = false;
        });
      });
    };

    window.electronAPI.tsBotInviteGuilds(this.selectedEmail).then(r => {
      if (!r?.success) throw new Error(r?.error || 'فشل تحميل السيرفرات');
      allGuilds = r.guilds || [];
      renderGuilds(allGuilds);
    }).catch(e => {
      if (gListEl) gListEl.innerHTML = `<div class="ts-invite-guild-empty" style="color:#ff6b7b">${ic.x} ${escapeHtml(e.message)}</div>`;
    });

    gSearch?.addEventListener('input', () => {
      const q = (gSearch.value || '').toLowerCase().trim();
      renderGuilds(q ? allGuilds.filter(g => g.name.toLowerCase().includes(q)) : allGuilds);
    });

    /* ── Bulk add all bots via SSE ── */
    const setRowStatus = (botId, type) => {
      const el = overlay.querySelector(`.ts-bt-status[data-bot-id="${botId}"]`);
      if (!el) return;
      el.className = 'ts-bt-status ' + type;
      el.innerHTML = type === 'ok' ? ic.check : type === 'fail' ? ic.x : ic.spin;
    };

    addBtn?.addEventListener('click', async () => {
      if (!selectedGuildId || addBtn.disabled) return;
      addBtn.disabled = true;
      if (progText) progText.textContent = '';
      const guildName = allGuilds.find(g => g.id === selectedGuildId)?.name || selectedGuildId;
      const appIds = allBots.map(b => b.id);

      /* reset all status cells */
      overlay.querySelectorAll('.ts-bt-status').forEach(s => { s.innerHTML = ''; s.className = 'ts-bt-status'; });
      appIds.forEach(id => setRowStatus(id, 'pending'));

      addLog('info', `بدء إضافة ${appIds.length} بوت إلى "${guildName}"…`);

      try {
        const resp = await fetch('/api/ts/bot-bulk-add-to-guild', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: this.selectedEmail, appIds, guildId: selectedGuildId, permissions: permsInput?.value || '8' }),
        });

        if (!resp.ok) {
          const body = await resp.json().catch(() => ({}));
          throw new Error(body.error || `HTTP ${resp.status}`);
        }

        const reader = resp.body.getReader(); const decoder = new TextDecoder(); let buf = '';
        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          buf += decoder.decode(value, { stream: true });
          const parts = buf.split('\n'); buf = parts.pop();
          for (const ln of parts) {
            const raw = ln.trim();
            if (!raw.startsWith('data:')) continue;
            let evt; try { evt = JSON.parse(raw.slice(5)); } catch { continue; }

            if (evt.type === 'start') {
              if (progText) progText.textContent = `0 / ${evt.total}`;

            } else if (evt.type === 'progress') {
              const botName = allBots.find(b => b.id === evt.appId)?.name || evt.appId;
              if (progText) progText.textContent = `${evt.index} / ${evt.total}`;
              setRowStatus(evt.appId, evt.ok ? 'ok' : 'fail');
              if (evt.ok && !evt.skipped) addLog('ok',   `${botName} — تمت الإضافة`);
              else if (evt.skipped)        addLog('info', `${botName} — موجود بالفعل`);
              else                          addLog('fail', `${botName} — ${evt.error || 'فشل'}`);

            } else if (evt.type === 'retry') {
              const botName = allBots.find(b => b.id === evt.appId)?.name || evt.appId;
              addLog('info', `${botName} — rate limit، إعادة المحاولة بعد ${Math.round(evt.retryMs / 1000)}ث…`);

            } else if (evt.type === 'done') {
              addLog('ok', `اكتمل: ${evt.okCount} نجاح · ${evt.failCount} فشل · ${evt.skipCount} موجود`);
              if (progText) progText.textContent = `${evt.okCount} / ${allBots.length}`;
              addBtn.disabled = false;

            } else if (evt.type === 'error') {
              addLog('fail', evt.error);
              addBtn.disabled = false;
            }
          }
        }
      } catch (e) {
        addLog('fail', e.message || String(e));
        addBtn.disabled = false;
      }
    });
  }

  _intentRowsHtml(intents) {
    const st = intents?.state || {};
    const rows = [
      ['presence', 'Presence Intent'],
      ['guildMembers', 'Server Members Intent'],
      ['messageContent', 'Message Content Intent'],
    ];
    return rows.map(([key, label]) => {
      const v = st[key] || {};
      const on = !!v.enabled;
      const sub = v.approved ? 'approved/verified flag' : (v.limited ? 'limited flag enabled' : 'off');
      const icon = key === 'presence' ? 'presence' : (key === 'guildMembers' ? 'members' : 'message');
      return `<div class="ts-intent-row ${on ? 'on' : ''}">
        <span class="ts-intent-icon ${icon}" aria-hidden="true"><i></i></span>
        <span class="ts-intent-name">${escapeHtml(label)}</span>
        <b>${on ? 'ON' : 'OFF'}</b>
        <small>${escapeHtml(sub)}</small>
      </div>`;
    }).join('');
  }

  async _openIntentsModal(appId, name) {
    if (!this.selectedEmail) { showNotification(t('ts.pick_account_first'), 'error'); return; }
    document.querySelector('.ts-intents-overlay')?.remove();
    const overlay = document.createElement('div');
    overlay.className = 'ts-intents-overlay';
    overlay.innerHTML = `
      <div class="ts-intents-modal">
        <div class="ts-token-modal-head">
          <div class="ts-token-modal-title"><span class="ts-drawn-icon bolt" aria-hidden="true"><i></i></span> iNTeNT · ${escapeHtml(name)}</div>
          <button class="ts-token-modal-close" type="button" aria-label="close">×</button>
        </div>
        <div class="ts-token-modal-body">
          <div class="ts-token-modal-hint ts-intents-hint"><span class="ts-drawn-icon compass" aria-hidden="true"><i></i></span> الحالة الحالية للـ Privileged Intents الثلاثة. التفعيل/الإيقاف يتم عبر flags المحدودة القابلة للتعديل من API.</div>
          <div class="ts-intents-state" id="ts-intents-state">جاري القراءة…</div>
          <div class="ts-token-modal-actions">
            <button class="ts-btn mint" id="ts-intents-enable"><span class="ts-drawn-icon check" aria-hidden="true"><i></i></span> تفعيل الثلاثة</button>
            <button class="ts-btn danger" id="ts-intents-disable"><span class="ts-drawn-icon stop" aria-hidden="true"><i></i></span> إيقاف الثلاثة</button>
            <button class="ts-btn" id="ts-intents-refresh"><span class="ts-drawn-icon refresh" aria-hidden="true"><i></i></span> تحديث</button>
          </div>
        </div>
      </div>`;
    document.body.appendChild(overlay);
    const close = () => overlay.remove();
    overlay.querySelector('.ts-token-modal-close')?.addEventListener('click', close);
    overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });
    const stateEl = overlay.querySelector('#ts-intents-state');
    const load = async () => {
      stateEl.textContent = 'جاري القراءة…';
      try {
        const r = await window.electronAPI.tsGetIntents(appId, this.selectedEmail);
        if (!r?.success && r?.error) throw new Error(r.error);
        if (r.blocked) throw new Error(r.health?.message || 'Account blocked by health check');
        stateEl.innerHTML = this._intentRowsHtml(r.intents);
      } catch (e) { stateEl.innerHTML = `<div class="ts-lib-empty error">${escapeHtml(e.message || String(e))}</div>`; }
    };
    const set = async (enabled) => {
      stateEl.textContent = enabled ? 'جاري التفعيل…' : 'جاري الإيقاف…';
      try {
        const r = await window.electronAPI.tsSetIntents(appId, this.selectedEmail, enabled);
        if (!r?.success && r?.error) throw new Error(r.error);
        stateEl.innerHTML = this._intentRowsHtml(r.intents);
        showNotification(enabled ? 'تم تفعيل Intents' : 'تم إيقاف Intents', 'success');
      } catch (e) { stateEl.innerHTML = `<div class="ts-lib-empty error">${escapeHtml(e.message || String(e))}</div>`; }
    };
    overlay.querySelector('#ts-intents-refresh')?.addEventListener('click', load);
    overlay.querySelector('#ts-intents-enable')?.addEventListener('click', () => set(true));
    overlay.querySelector('#ts-intents-disable')?.addEventListener('click', () => set(false));
    load();
  }

  async _applyIntentsAll(enabled = true) {
    if (!this.selectedEmail) { showNotification(t('ts.pick_account_first'), 'error'); return; }
    if (this._intentsAllRunning) { showNotification('iNTeNT ALl جاري التنفيذ بالفعل…', 'info'); return; }
    const confirmed = await showConfirm(
      `${enabled ? 'تفعيل' : 'إيقاف'} الثلاث Privileged Intents لكل بوتات المكتبة؟ (البوتات المفعّلة بالفعل ستُتخطى تلقائياً)`,
      { confirmText: enabled ? 'iNTeNT ALl' : 'Disable all', cancelText: 'إلغاء' }
    );
    if (!confirmed) return;

    this._intentsAllRunning = true;
    const btn = this._libModal?.querySelector('#ts-lib-intents-all');
    if (btn) { btn.disabled = true; }

    const prog = this._openBatchProgressModal(
      `⚡ iNTeNT ALl`,
      `${enabled ? 'تفعيل' : 'إيقاف'} Privileged Intents — الخادم يعالج كل البوتات`
    );
    prog.setIndeterminate(true);
    prog.setStatus('⏳ جاري الاتصال بالخادم وقراءة المكتبة…');

    // Single server call: one health probe + process all bots with skip-already-enabled logic
    window.electronAPI.tsApplyIntentsAll(this.selectedEmail, enabled).then(r => {
      if (!r?.success && r?.error) throw new Error(r.error);
      prog.setIndeterminate(false);
      const ok       = r.okCount      || 0;
      const fail     = r.failCount    || 0;
      const skipped  = r.skippedCount || 0;
      const items = (r.results || []).map(x => ({
        name: x.name || x.appId, ok: x.ok, skipped: !!x.skipped, error: x.error,
      }));
      prog.done(ok, fail, items, skipped);
      if ((ok - skipped) > 0) this.loadLibrary().catch(() => {});
    }).catch(e => {
      prog.setIndeterminate(false);
      prog.error(e.message || String(e));
    }).finally(() => {
      this._intentsAllRunning = false;
      if (btn) { btn.disabled = false; }
    });
  }

  // ─── Generic batch progress modal (used by intents all + pfp all) ─────────
  _openBatchProgressModal(title, subtitle = '') {
    document.querySelector('.ts-batch-prog-overlay')?.remove();
    const wrap = document.createElement('div');
    wrap.className = 'ts-batch-prog-overlay';
    wrap.innerHTML = `
      <div class="ts-batch-prog-card">
        <div class="ts-batch-prog-header">
          <div class="ts-batch-prog-title">${title}</div>
          ${subtitle ? `<div class="ts-batch-prog-sub">${subtitle}</div>` : ''}
        </div>
        <div class="ts-batch-prog-bar-wrap">
          <div class="ts-batch-prog-bar" id="ts-bp-bar" style="width:0%"></div>
        </div>
        <div class="ts-batch-prog-counts" id="ts-bp-counts">جاري التحضير…</div>
        <div class="ts-batch-prog-status" id="ts-bp-status"></div>
        <div class="ts-batch-prog-log" id="ts-bp-log"></div>
        <button class="ts-btn ts-batch-prog-close" id="ts-bp-close" style="display:none">✓ إغلاق</button>
      </div>
    `;
    document.body.appendChild(wrap);
    requestAnimationFrame(() => wrap.classList.add('open'));

    let total = 0;
    const log = wrap.querySelector('#ts-bp-log');
    const addLogLine = (icon, name, note = '') => {
      const line = document.createElement('div');
      line.className = 'ts-bp-log-line' + (icon === '✓' ? ' ok' : icon === '✗' ? ' fail' : '');
      line.textContent = `${icon} ${name}${note ? ' — ' + note.slice(0, 90) : ''}`;
      log.prepend(line);
      if (log.children.length > 60) log.lastChild?.remove();
    };

    wrap.querySelector('#ts-bp-close').addEventListener('click', () => {
      wrap.classList.remove('open');
      setTimeout(() => wrap.remove(), 280);
    });

    return {
      setTotal(n) {
        total = n;
        wrap.querySelector('#ts-bp-counts').textContent = `0 / ${n}`;
      },
      setStatus(msg) {
        const el = wrap.querySelector('#ts-bp-status');
        if (el) el.textContent = msg;
      },
      setIndeterminate(on) {
        const bar = wrap.querySelector('#ts-bp-bar');
        if (!bar) return;
        if (on) {
          bar.classList.add('indeterminate');
          bar.style.width = '100%';
        } else {
          bar.classList.remove('indeterminate');
          bar.style.width = '0%';
        }
      },
      setProgress(done, tot) {
        total = tot || total;
        const pct = total ? Math.round((done / total) * 100) : 0;
        const bar = wrap.querySelector('#ts-bp-bar');
        if (bar) bar.style.width = pct + '%';
        wrap.querySelector('#ts-bp-counts').textContent = `${done} / ${total}`;
      },
      logLine(icon, name, note = '') { addLogLine(icon, name, note); },
      done(ok, fail, items = [], skipped = 0) {
        const bar = wrap.querySelector('#ts-bp-bar');
        if (bar) { bar.classList.remove('indeterminate'); bar.style.width = '100%'; bar.classList.add('done'); }
        const status = wrap.querySelector('#ts-bp-status');
        if (status) {
          const skippedPart = skipped > 0 ? `  <span class="ts-bp-skip">↷ ${skipped} تم تخطيه</span>` : '';
          status.innerHTML = `<span class="ts-bp-ok">✓ ${ok - skipped} نجاح</span>${skippedPart}  <span class="ts-bp-fail">✗ ${fail} فشل</span>`;
        }
        // Log results (only if not already populated)
        const logEl = wrap.querySelector('#ts-bp-log');
        if (logEl && !logEl.children.length) {
          [...items].reverse().forEach(x => {
            if (x.skipped) addLogLine('↷', x.name, 'مفعّل بالفعل');
            else addLogLine(x.ok ? '✓' : '✗', x.name, x.error);
          });
        }
        const closeBtn = wrap.querySelector('#ts-bp-close');
        if (closeBtn) closeBtn.style.display = '';
        // Auto-close after 5s only if nothing failed
        if (fail === 0) setTimeout(() => { wrap.classList.remove('open'); setTimeout(() => wrap.remove(), 280); }, 5000);
      },
      error(msg) {
        const bar = wrap.querySelector('#ts-bp-bar');
        if (bar) bar.classList.remove('indeterminate');
        const status = wrap.querySelector('#ts-bp-status');
        if (status) status.innerHTML = `<span class="ts-bp-fail">✗ ${msg}</span>`;
        const closeBtn = wrap.querySelector('#ts-bp-close');
        if (closeBtn) closeBtn.style.display = '';
      },
    };
  }

  // Wire up the per-card "Reset Token" buttons inside the library overlay.
  // Triggered after every render of the Teams/Personal tabs so freshly-rendered
  // cards always receive their handler.
  _bindResetButtons(root) {
    root.querySelectorAll('[data-reset-bot]').forEach(btn => {
      // Idempotent — never bind the same button twice. Without this guard,
      // re-rendering the library tab would stack click handlers on already-
      // rendered DOM nodes, causing one click to fire the reset N times and
      // freezing the UI while N parallel requests execute.
      if (btn._resetBound) return;
      btn._resetBound = true;
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        e.preventDefault();
        const appId = btn.getAttribute('data-reset-bot');
        const name  = btn.getAttribute('data-bot-name') || appId;
        this._resetBotToken(appId, name, btn);
      });
    });
  }

  async _resetBotToken(appId, name, btn) {
    if (!appId || !this.selectedEmail) {
      showNotification(t('ts.pick_account_first'), 'error');
      return;
    }
    // Hard click-protection: refuse to start a second reset while one is
    // already running anywhere in the app (the request can take 15-30s and
    // a panicked second click was previously firing a duplicate request).
    if (this._resetInFlight) {
      showNotification(t('ts.reset_in_progress') || 'Reset already in progress…', 'info');
      return;
    }
    if (btn?.disabled) return;

    const ok = await showConfirm(
      (t('ts.confirm_reset_token') || 'Reset the bot token for {name}?').replace('{name}', name),
      { confirmText: t('ts.reset_token') }
    );
    if (!ok) return;

    this._resetInFlight = true;
    const origText = btn?.querySelector('.ts-card-reset-label')?.textContent;
    if (btn) {
      btn.disabled = true;
      btn.classList.add('loading');
      const lbl = btn.querySelector('.ts-card-reset-label');
      if (lbl) lbl.textContent = t('ts.resetting_token') || 'Resetting…';
    }
    // Show a same-page progress overlay so the user gets immediate visual
    // feedback (the API call takes 15-30s — without this it looked frozen).
    const progress = this._openResetProgress(name);
    // Resolve icon BEFORE the API call so we can send it with the request
    const appEntry = [
      ...(this.library?.personal || []),
      ...(this.library?.teams || []).flatMap(tm => tm.apps || []),
    ].find(a => a.id === appId);
    try {
      const r = await window.electronAPI.tsResetBot(appId, this.selectedEmail, name, appEntry?.icon || null);
      const newToken = r?.token;
      if (!newToken) throw new Error('No token returned');
      // Server already saved to botTokensStore; client-side save is a best-effort duplicate
      await this._saveBotTokenPersistent({ appId, name, icon: appEntry?.icon || null, token: newToken });
      // Force-reload so Bot Tokens tab always reflects the new entry
      await this._loadBotTokens();
      this._updateTokensTabBadge();
      progress.success();
      showNotification(t('ts.token_reset_ok') || 'New bot token generated ✓', 'success');
      sfx.ding?.();
      // Token modal is rendered ON TOP of the library overlay (z-index handled
      // in CSS) so the user stays on the same page — no "press back" needed.
      this._openTokenModal({ name, appId, token: newToken, onClose: () => {
        // Auto-navigate to Bot Tokens tab after the user closes the token popup
        if (this._libModal) this._switchLibraryTab('tokens');
      } });
    } catch (e) {
      progress.fail(e?.message || String(e));
      const raw = (e && (e.message || String(e))) || '';
      // Discord rejects /bot/reset without an MFA header. Surface a clear,
      // actionable message instead of the cryptic "Two-factor required".
      const looksLikeMfa = /two[-\s]?factor|mfa|2fa|60003|enable.*2fa/i.test(raw);
      const msg = looksLikeMfa
        ? (t('ts.token_reset_needs_mfa') ||
           'Discord requires the account to have 2FA enabled and its TOTP secret saved here. Edit the account → add the 2FA secret → retry.')
        : (t('ts.token_reset_failed') || 'Token reset failed') + ': ' + raw;
      showNotification(msg, 'error');
    } finally {
      this._resetInFlight = false;
      if (btn) {
        btn.disabled = false;
        btn.classList.remove('loading');
        const lbl = btn.querySelector('.ts-card-reset-label');
        if (lbl && origText) lbl.textContent = origText;
      }
    }
  }

  // Lightweight progress overlay shown while a token reset is in flight.
  // Returns { success(), fail(msg) } — the overlay auto-dismisses shortly
  // after either is called so the user sees a final confirmed state.
  _openResetProgress(name) {
    document.querySelector('.ts-reset-progress')?.remove();
    const wrap = document.createElement('div');
    wrap.className = 'ts-reset-progress';
    wrap.setAttribute('role', 'status');
    wrap.setAttribute('aria-live', 'polite');
    wrap.innerHTML = `
      <div class="ts-reset-progress-card">
        <div class="ts-reset-progress-spinner" aria-hidden="true">
          <span></span><span></span><span></span>
        </div>
        <div class="ts-reset-progress-title">
          ${(t('ts.resetting_token_for') || 'Resetting bot token for')}
          <b>${this._escapeHtml(name)}</b>
        </div>
        <div class="ts-reset-progress-hint">
          ${t('ts.resetting_token_hint') || 'This usually takes 15–30 seconds. Please don’t close this window.'}
        </div>
        <div class="ts-reset-progress-bar"><i></i></div>
      </div>
    `;
    document.body.appendChild(wrap);
    requestAnimationFrame(() => wrap.classList.add('open'));
    return {
      success: () => {
        wrap.classList.add('done');
        const title = wrap.querySelector('.ts-reset-progress-title');
        if (title) title.textContent = t('ts.token_reset_ok') || 'New bot token generated ✓';
        setTimeout(() => { wrap.classList.remove('open'); setTimeout(() => wrap.remove(), 240); }, 600);
      },
      fail: (msg) => {
        wrap.classList.add('failed');
        const title = wrap.querySelector('.ts-reset-progress-title');
        if (title) title.textContent = t('ts.token_reset_failed') || 'Token reset failed';
        const hint = wrap.querySelector('.ts-reset-progress-hint');
        if (hint && msg) hint.textContent = String(msg).slice(0, 200);
        setTimeout(() => { wrap.classList.remove('open'); setTimeout(() => wrap.remove(), 240); }, 1400);
      },
    };
  }

  _escapeHtml(s = '') {
    return String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  }

  // Append a freshly-reset bot to the in-memory snapshot so the "Created bots"
  // tab and the token-export download include it. (Reset bots were not part
  // of the current automation session, but the user still wants them grouped.)
  _appendBotToSession({ name, appId, token }) {
    if (!this.snapshot) this.snapshot = { bots: [], log: [] };
    if (!Array.isArray(this.snapshot.bots)) this.snapshot.bots = [];
    // Replace any existing entry for this appId so we always have the latest token.
    this.snapshot.bots = this.snapshot.bots.filter(b => b.appId !== appId);
    this.snapshot.bots.unshift({
      name, appId,
      botUserId: '',
      hasToken: true,
      token, // local-only — server snapshot omits the raw token from /state
    });
    // Live-refresh the trigger badge + "Created bots" tab if it's open
    const trig = this.contentArea.querySelector('#ts-lib-trigger');
    if (trig) trig.innerHTML = this._renderLibraryTrigger(this.snapshot);
    if (this._libModal && this._libCurrentTab === 'created') this._renderLibraryTab();
  }

  // Modal that surfaces a freshly-generated bot token. The token is rendered
  // ONCE — Discord won't return it again — with a prominent Copy button.
  _openTokenModal({ name, appId, token, onClose }) {
    // Tear down any previous instance
    document.querySelector('.ts-token-modal-overlay')?.remove();
    const overlay = document.createElement('div');
    overlay.className = 'ts-token-modal-overlay';
    overlay.innerHTML = `
      <div class="ts-token-modal">
        <div class="ts-token-modal-head">
          <div class="ts-token-modal-title">${escapeHtml(t('ts.new_token_modal_title') || 'New bot token')}</div>
          <button class="ts-token-modal-close" type="button" aria-label="close">×</button>
        </div>
        <div class="ts-token-modal-body">
          <div class="ts-token-modal-bot">${escapeHtml(name)} <span class="ts-token-modal-id">${escapeHtml(appId)}</span></div>
          <div class="ts-token-modal-hint">${escapeHtml(t('ts.new_token_modal_hint') || 'Copy this token now — it will not be shown again.')}</div>
          <div class="ts-token-box" id="ts-token-value">${escapeHtml(token)}</div>
          <div class="ts-token-modal-actions">
            <button class="ts-btn mint" id="ts-token-copy">${escapeHtml(t('ts.copy_token') || 'Copy Token')}</button>
            <button class="ts-btn" id="ts-token-close-btn">${escapeHtml(t('ts.close') || 'Close')}</button>
          </div>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);
    const close = () => { overlay.remove(); onClose?.(); };
    overlay.querySelector('.ts-token-modal-close').addEventListener('click', close);
    overlay.querySelector('#ts-token-close-btn').addEventListener('click', close);
    overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });
    overlay.querySelector('#ts-token-copy').addEventListener('click', async () => {
      try {
        await copyToClipboard(token);
        showNotification(t('ts.token_copied') || 'Token copied ✓', 'success');
      } catch (e) {
        showNotification(t('ts.copy_failed') || 'Copy failed', 'error');
      }
    });
  }

  // ── Bot Tokens tab ────────────────────────────────────
  // Persistent storage of all revealed/reset bot tokens across sessions.
  _renderBotTokensTab() {
    const tokens = this.botTokens || [];
    if (!tokens.length) {
      return `
        <div class="ts-lib-empty">
          <div style="font-size:2rem;margin-bottom:10px;"><span class="ts-emoji-bob">🔑</span></div>
          <div>${escapeHtml(t('ts.bt_empty_title'))}</div>
          <div style="font-size:11px;color:var(--ts-muted,#7e8592);margin-top:6px;">
            ${escapeHtml(t('ts.bt_empty_hint'))}
          </div>
        </div>`;
    }
    return `
      <div class="ts-bt-header">
        <div class="ts-bt-count">${tokens.length} ${escapeHtml(t('ts.bt_count'))}</div>
        <button class="ts-btn mint" id="ts-bt-copy-all"
          title="${escapeAttr(t('ts.bt_copy_all'))}"
          style="font-size:12px;padding:5px 14px;display:flex;align-items:center;gap:6px;">
          <span style="font-size:14px;">📋</span> ${escapeHtml(t('ts.bt_copy_all'))}
        </button>
      </div>
      <div class="ts-bt-list">
        ${tokens.map(entry => {
          const iconUrl = entry.icon
            ? `https://cdn.discordapp.com/app-icons/${entry.appId}/${entry.icon}.png?size=64`
            : null;
          const initials = this._initialsFor(entry.name);
          const dateStr = entry.resetAt
            ? new Date(entry.resetAt).toLocaleString(getLang() === 'ar' ? 'ar-SA' : 'en-GB', { dateStyle: 'short', timeStyle: 'short' })
            : '';
          return `
            <div class="ts-bt-card" data-app-id="${escapeAttr(entry.appId)}">
              <div class="ts-bt-avatar">
                ${iconUrl
                  ? `<img src="${iconUrl}" alt="" onerror="this.replaceWith(Object.assign(document.createElement('span'),{textContent:'${escapeAttr(initials)}',className:'ts-bt-initials'}))">`
                  : `<span class="ts-bt-initials">${escapeHtml(initials)}</span>`}
              </div>
              <div class="ts-bt-info">
                <div class="ts-bt-name">${escapeHtml(entry.name)}</div>
                <div class="ts-bt-appid">${escapeHtml(entry.appId)}</div>
                ${dateStr ? `<div class="ts-bt-date">${escapeHtml(t('ts.bt_last_reset'))}: ${escapeHtml(dateStr)}</div>` : ''}
                <div class="ts-bt-token-row">
                  <div class="ts-bt-token-mask" data-token="${escapeAttr(entry.token)}" data-shown="0">
                    ${'•'.repeat(Math.min(entry.token.length, 32))}
                  </div>
                  <button class="ts-bt-show" data-show-token="${escapeAttr(entry.appId)}" title="${escapeAttr(t('ts.bt_show'))}">👁</button>
                  <button class="ts-btn mint ts-bt-copy" data-copy-token="${escapeAttr(entry.token)}" title="${escapeAttr(t('ts.bt_copy'))}">${escapeHtml(t('ts.bt_copy'))}</button>
                </div>
              </div>
              <button class="ts-bt-delete" data-delete-token="${escapeAttr(entry.appId)}" title="${escapeAttr(t('ts.bt_delete'))}">✕</button>
            </div>
          `;
        }).join('')}
      </div>
    `;
  }

  _bindBotTokensTab(root) {
    const copyAllBtn = root.querySelector('#ts-bt-copy-all');
    if (copyAllBtn) {
      copyAllBtn.addEventListener('click', async () => {
        _emojiPop(copyAllBtn);
        const lines = (this.botTokens || []).map(e => `${e.name} | ${e.token}`).join('\n');
        try {
          await copyToClipboard(lines);
          const orig = copyAllBtn.innerHTML;
          copyAllBtn.innerHTML = `<span style="font-size:14px;">✅</span> ${escapeHtml(t('ts.bt_copy_all_done'))}`;
          setTimeout(() => { copyAllBtn.innerHTML = orig; }, 1800);
        } catch (e) { showNotification(t('ts.copy_failed') || 'Copy failed', 'error'); }
      });
    }
    root.querySelectorAll('[data-copy-token]').forEach(btn => {
      btn.addEventListener('click', async () => {
        _emojiPop(btn);
        try {
          await copyToClipboard(btn.dataset.copyToken);
          showNotification(t('ts.token_copied') || 'Token copied ✓', 'success');
        } catch (e) { showNotification(t('ts.copy_failed') || 'Copy failed', 'error'); }
      });
    });
    root.querySelectorAll('[data-show-token]').forEach(btn => {
      btn.addEventListener('click', () => {
        _emojiPop(btn);
        const appId = btn.dataset.showToken;
        const card = root.querySelector(`.ts-bt-card[data-app-id="${CSS.escape(appId)}"]`);
        const mask = card?.querySelector('.ts-bt-token-mask');
        if (!mask) return;
        const shown = mask.dataset.shown === '1';
        if (shown) {
          mask.textContent = '•'.repeat(Math.min(mask.dataset.token.length, 32));
          mask.dataset.shown = '0';
          btn.textContent = '👁';
        } else {
          mask.textContent = mask.dataset.token;
          mask.dataset.shown = '1';
          btn.textContent = '🙈';
        }
      });
    });
    root.querySelectorAll('[data-delete-token]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const appId = btn.dataset.deleteToken;
        try {
          const r = await window.electronAPI.tsDeleteBotToken(appId);
          this.botTokens = r?.tokens || this.botTokens.filter(t => t.appId !== appId);
          this._renderLibraryTab();
          this._updateTokensTabBadge();
        } catch (e) { showNotification(t('ts.bt_delete_failed') + e.message, 'error'); }
      });
    });
  }

  _updateTokensTabBadge() {
    if (this._libModal) {
      const tab = this._libModal.querySelector('.ts-lib-tab[data-tab="tokens"]');
      if (tab) {
        const count = this.botTokens.length;
        tab.innerHTML = `<span class="ts-emoji-key">🔑</span> ${escapeHtml(t('ts.lib_tab_tokens'))}${count ? ` <span class="ts-tab-badge">${count}</span>` : ''}`;
      }
      const resetAllBtn = this._libModal.querySelector('#ts-lib-reset-all');
      const stopAllBtn  = this._libModal.querySelector('#ts-lib-stop-all');
      if (resetAllBtn) {
        resetAllBtn.disabled = !this.library || this._resetAllInFlight;
        resetAllBtn.style.display = this._resetAllInFlight ? 'none' : '';
      }
      if (stopAllBtn) {
        stopAllBtn.style.display = this._resetAllInFlight ? '' : 'none';
      }
    }
  }

  async _loadBotTokens() {
    try {
      const r = await window.electronAPI.tsBotTokens();
      this.botTokens = r?.tokens || [];
    } catch (e) { this.botTokens = []; }
  }

  async _saveBotTokenPersistent({ appId, name, icon, token }) {
    try {
      const r = await window.electronAPI.tsSaveBotToken({
        appId, name, icon: icon || null, token,
        email: this.selectedEmail || '',
      });
      this.botTokens = r?.tokens || this.botTokens;
      this._updateTokensTabBadge();
      this._refreshBotTokensUI();
      if (this._libModal && this._libCurrentTab === 'tokens') {
        this._renderLibraryTab();
      }
    } catch (e) { /* non-fatal */ }
  }

  // ── Reset All Bots ─────────────────────────────────
  // Sends all bots to the SERVER for background processing so it continues
  // even when the user navigates away. Progress is streamed via SSE.
  async _resetAllBots() {
    if (!this.selectedEmail) { showNotification(t('ts.pick_account_first'), 'error'); return; }
    if (!this.library) { showNotification(t('ts.reset_all_load_first'), 'error'); return; }
    if (this._resetAllInFlight) {
      showNotification(t('ts.reset_all_in_flight'), 'info');
      return;
    }

    // Check if already running on server (e.g. user re-opened the page)
    try {
      const state = await window.electronAPI.tsResetAllState();
      if (state.state === 'running') {
        showNotification(t('ts.reset_all_server_running'), 'info');
        this._resetAllInFlight = true;
        this._updateTokensTabBadge();
        return;
      }
    } catch (_) {}

    // Collect all bots across teams + personal
    const allBots = [
      ...(this.library.personal || []),
      ...(this.library.teams || []).flatMap(tm => tm.apps || []),
    ].filter(a => a.isBot);

    if (!allBots.length) {
      showNotification(t('ts.reset_all_no_bots'), 'info');
      return;
    }

    const confirmed = await showConfirm(
      t('ts.reset_all_confirm').replace('{n}', allBots.length),
      { confirmText: t('ts.reset_all_confirm_btn') }
    );
    if (!confirmed) return;

    try {
      // Send bot list to server — it runs entirely in the background
      await window.electronAPI.tsResetAllStart(
        this.selectedEmail,
        allBots.map(b => ({ id: b.id, name: b.name, icon: b.icon || null }))
      );
      this._resetAllInFlight = true;
      this._raLastFailed = 0;
      this._updateTokensTabBadge();
      // Open progress overlay — it will be updated by SSE events
      this._resetAllProgress = this._openResetAllProgress(allBots.length);
    } catch (e) {
      showNotification(t('ts.reset_all_start_failed') + (e?.message || String(e)), 'error');
    }
  }

  // Progress overlay for Reset All — shows which bot is being reset + counts.
  _openResetAllProgress(total) {
    document.querySelector('.ts-reset-all-overlay')?.remove();
    const wrap = document.createElement('div');
    wrap.className = 'ts-reset-all-overlay';
    wrap.innerHTML = `
      <div class="ts-reset-all-card">
        <div class="ts-reset-all-title">⟳ Reset All Bots</div>
        <div class="ts-reset-all-current" id="ts-ra-current">${t('ts.reset_all_starting')}</div>
        <div class="ts-reset-all-bar-wrap">
          <div class="ts-reset-all-bar" id="ts-ra-bar" style="width:0%"></div>
        </div>
        <div class="ts-reset-all-counts" id="ts-ra-counts">0 / ${total}</div>
        <div class="ts-reset-all-log" id="ts-ra-log"></div>
      </div>
    `;
    document.body.appendChild(wrap);
    requestAnimationFrame(() => wrap.classList.add('open'));

    let doneCount = 0;
    const addLog = (icon, name, note = '') => {
      const log = wrap.querySelector('#ts-ra-log');
      if (!log) return;
      const line = document.createElement('div');
      line.className = 'ts-ra-log-line';
      line.textContent = `${icon} ${name}${note ? ' — ' + note.slice(0, 80) : ''}`;
      log.prepend(line);
      if (log.children.length > 30) log.lastChild?.remove();
    };

    return {
      update(idx, name) {
        const el = wrap.querySelector('#ts-ra-current');
        if (el) el.textContent = t('ts.reset_all_progress').replace('{idx}', idx).replace('{total}', total).replace('{name}', name);
        const bar = wrap.querySelector('#ts-ra-bar');
        if (bar) bar.style.width = (((idx - 1) / total) * 100) + '%';
      },
      success(idx, name) {
        doneCount++;
        const ct = wrap.querySelector('#ts-ra-counts');
        if (ct) ct.textContent = `✓ ${doneCount} / ${total}`;
        addLog('✓', name);
      },
      fail(idx, name, msg) {
        addLog('✗', name, msg);
      },
      done(results) {
        const el = wrap.querySelector('#ts-ra-current');
        if (el) el.textContent = t('ts.reset_all_done_label').replace('{ok}', results.ok).replace('{failed}', results.failed);
        const bar = wrap.querySelector('#ts-ra-bar');
        if (bar) { bar.style.width = '100%'; bar.classList.add('done'); }
        setTimeout(() => {
          wrap.classList.remove('open');
          setTimeout(() => wrap.remove(), 300);
        }, 3000);
      },
    };
  }

  _renderCreatedBotsTab() {
    const bots = this.snapshot?.bots || [];
    if (!bots.length) {
      return `
        <div class="ts-lib-empty">
          <div style="font-size:2rem;margin-bottom:10px;">🤖</div>
          <div>${escapeHtml(t('ts.lib_no_created'))}</div>
          <div style="font-size:11px;color:var(--ts-muted,#7e8592);margin-top:6px;">
            ${escapeHtml(t('ts.lib_no_created_hint'))}
          </div>
        </div>`;
    }
    const exportHref = window.electronAPI.tsExportUrl('text');
    return `
      <div class="ts-bt-header">
        <div class="ts-bt-count">${bots.length} ${escapeHtml(t('ts.lib_created_count_label') || 'بوت')}</div>
        <a class="ts-btn" href="${exportHref}" download style="font-size:12px;padding:5px 12px;">
          ⬇ ${escapeHtml(t('ts.export_tokens') || 'تصدير التوكنات')}
        </a>
      </div>
      <div class="ts-bt-list">
        ${bots.map(b => {
          // Cross-reference with persistent botTokens store by appId
          const stored = (this.botTokens || []).find(tk => tk.appId === b.appId);
          const token = stored?.token || null;
          const icon = stored?.icon || null;
          const iconUrl = icon
            ? `https://cdn.discordapp.com/app-icons/${b.appId}/${icon}.png?size=64`
            : null;
          const initials = this._initialsFor(b.name);
          const createdAt = stored?.createdAt || stored?.resetAt;
          const dateStr = createdAt
            ? new Date(createdAt).toLocaleString(getLang() === 'ar' ? 'ar-SA' : 'en-GB', { dateStyle: 'short', timeStyle: 'short' })
            : '';
          return `
            <div class="ts-bt-card" data-app-id="${escapeAttr(b.appId)}">
              <div class="ts-bt-avatar">
                ${iconUrl
                  ? `<img src="${iconUrl}" alt="" onerror="this.replaceWith(Object.assign(document.createElement('span'),{textContent:'${escapeAttr(initials)}',className:'ts-bt-initials'}))">`
                  : `<span class="ts-bt-initials">${escapeHtml(initials)}</span>`}
              </div>
              <div class="ts-bt-info">
                <div class="ts-bt-name">${escapeHtml(b.name)}</div>
                <div class="ts-bt-appid">App ID: ${escapeHtml(b.appId)}</div>
                ${b.botUserId ? `<div class="ts-bt-date">Bot ID: ${escapeHtml(b.botUserId)}</div>` : ''}
                ${dateStr ? `<div class="ts-bt-date">${escapeHtml(t('ts.created_at_label'))}: ${escapeHtml(dateStr)}</div>` : ''}
                ${token
                  ? `<div class="ts-bt-token-row">
                       <div class="ts-bt-token-mask" data-token="${escapeAttr(token)}" data-shown="0">
                         ${'•'.repeat(Math.min(token.length, 32))}
                       </div>
                       <button class="ts-bt-show" data-show-token="${escapeAttr(b.appId)}" title="${escapeAttr(t('ts.bt_show'))}">👁</button>
                       <button class="ts-btn mint ts-bt-copy" data-copy-token="${escapeAttr(token)}" title="${escapeAttr(t('ts.bt_copy'))}">
                         ${escapeHtml(t('ts.bt_copy'))}
                       </button>
                     </div>`
                  : `<div class="ts-bt-date" style="color:var(--ts-muted,#7e8592);font-style:italic;">
                       ${escapeHtml(t('ts.token_unavailable'))}
                     </div>`}
              </div>
              <button class="ts-bt-copy-id ts-btn" data-copy-id="${escapeAttr(b.appId)}" title="${escapeAttr(t('ts.copy_id'))}" style="font-size:11px;padding:4px 9px;white-space:nowrap;">
                ${escapeHtml(t('ts.copy_id'))}
              </button>
            </div>
          `;
        }).join('')}
      </div>
    `;
  }

  _bindCreatedTab(root) {
    // Copy App ID
    root.querySelectorAll('[data-copy-id]').forEach(btn => {
      btn.addEventListener('click', async () => {
        _emojiPop(btn);
        try {
          await copyToClipboard(btn.dataset.copyId);
          showNotification(t('ts.copied'), 'success');
        } catch (_) { showNotification('Copy failed', 'error'); }
      });
    });
    // Copy token
    root.querySelectorAll('[data-copy-token]').forEach(btn => {
      btn.addEventListener('click', async () => {
        _emojiPop(btn);
        try {
          await copyToClipboard(btn.dataset.copyToken);
          showNotification(t('ts.token_copied') || 'Token copied ✓', 'success');
        } catch (e) { showNotification(t('ts.copy_failed') || 'Copy failed', 'error'); }
      });
    });
    // Show/hide token
    root.querySelectorAll('[data-show-token]').forEach(btn => {
      btn.addEventListener('click', () => {
        _emojiPop(btn);
        const appId = btn.dataset.showToken;
        const card = root.querySelector(`.ts-bt-card[data-app-id="${CSS.escape(appId)}"]`);
        const mask = card?.querySelector('.ts-bt-token-mask');
        if (!mask) return;
        const shown = mask.dataset.shown === '1';
        if (shown) {
          mask.textContent = '•'.repeat(Math.min(mask.dataset.token.length, 32));
          mask.dataset.shown = '0';
          btn.textContent = '👁';
        } else {
          mask.textContent = mask.dataset.token;
          mask.dataset.shown = '1';
          btn.textContent = '🙈';
        }
      });
    });
  }

  _renderLibrary() {
    const lib = this.library;
    const refreshBtn = `<button class="ts-btn" id="ts-lib-refresh" ${this.libraryLoading || !this.selectedEmail ? 'disabled' : ''}>${this.libraryLoading ? t('ts.testing') : t('ts.lib_refresh')}</button>`;
    let body = '';
    if (this.libraryLoading) {
      body = `<div class="ts-lib-empty">${t('ts.lib_loading')}</div>`;
    } else if (this.libraryError) {
      body = `<div class="ts-lib-empty error">${escapeHtml(this.libraryError)}</div>`;
    } else if (!lib) {
      body = `<div class="ts-lib-empty">${t('ts.lib_hint')}</div>`;
    } else if ((lib.teams || []).length === 0 && (lib.personal || []).length === 0) {
      body = `<div class="ts-lib-empty">${t('ts.lib_no_apps')}</div>`;
    } else {
      const teamsHtml = (lib.teams || []).map(team => `
        <div class="ts-team">
          <div class="ts-team-head">
            <div class="ts-team-name">${escapeHtml(team.name)}</div>
            <div class="ts-team-badge">${team.apps.length}/${team.appLimit || 25}</div>
          </div>
          ${team.apps.length ? `<div class="ts-cards">${team.apps.map(a => this._renderAppCard(a)).join('')}</div>` :
            `<div class="ts-team-empty">${t('ts.lib_team_empty')}</div>`}
        </div>
      `).join('');
      const personalHtml = (lib.personal || []).length ? `
        <div class="ts-team">
          <div class="ts-team-head">
            <div class="ts-team-name">${t('ts.lib_personal')}</div>
            <div class="ts-team-badge personal">${lib.personal.length}</div>
          </div>
          <div class="ts-cards">${lib.personal.map(a => this._renderAppCard(a)).join('')}</div>
        </div>
      ` : '';
      body = teamsHtml + personalHtml;
    }
    return `
      <div class="ts-card" style="margin-top:14px;">
        <div class="ts-card-head">
          <div class="ts-card-title ar">${t('ts.lib_title')}</div>
          ${refreshBtn}
        </div>
        ${lib ? `<div class="ts-lib-summary">${t('ts.lib_summary').replace('{teams}', lib.totals?.teams || 0).replace('{apps}', lib.totals?.apps || 0)}</div>` : ''}
        <div class="ts-lib-body">${body}</div>
      </div>
    `;
  }

  _renderAppCard(a, opts = {}) {
    const initials = this._initialsFor(a.name);
    const iconUrl = a.icon ? `https://cdn.discordapp.com/app-icons/${a.id}/${a.icon}.png?size=128` : null;
    const tag = a.isBot ? '<span class="ts-card-tag bot">BOT</span>' : '<span class="ts-card-tag app">APP</span>';
    const resetBtn = a.isBot ? `
      <button class="ts-card-reset" type="button"
        data-reset-bot="${escapeAttr(a.id)}"
        data-bot-name="${escapeAttr(a.name)}"
        title="${escapeAttr(t('ts.reset_token'))}">
        <span class="ts-card-reset-icon" aria-hidden="true">⟳</span>
        <span class="ts-card-reset-label">${escapeHtml(t('ts.reset_token'))}</span>
      </button>` : '';
    // Check if all 3 privileged intents are already enabled (limited or approved flags)
    const _INTENT_LIMITED = (1 << 13) | (1 << 15) | (1 << 19); // 8192|32768|524288
    const _INTENT_APPROVED = (1 << 12) | (1 << 14) | (1 << 18); // 4096|16384|262144
    const _flags = Number(a.flags_new || a.flags || 0);
    const _hasAllIntents = a.isBot && (
      (_flags & _INTENT_LIMITED) === _INTENT_LIMITED ||
      ((_flags & 4096) && (_flags & 16384) && (_flags & 262144))
    );
    const intentBtn = a.isBot ? `
      <button class="ts-card-intents${_hasAllIntents ? ' intents-on' : ''}" type="button"
        data-intents-bot="${escapeAttr(a.id)}"
        data-bot-name="${escapeAttr(a.name)}"
        title="${_hasAllIntents ? 'Intents مفعّلة ✓ — اضغط للتفاصيل' : 'رؤية/تفعيل/إيقاف Privileged Intents الثلاثة'}">
        <span class="ts-card-intents-icon">⚡</span> iNTeNT${_hasAllIntents ? ' <span class="ts-intent-on-dot"></span>' : ''}
      </button>` : '';
    const inviteBtn = a.isBot ? `
      <button class="ts-card-invite" type="button"
        data-invite-bot="${escapeAttr(a.id)}"
        data-bot-name="${escapeAttr(a.name)}"
        title="رابط دعوة البوت / إضافة تلقائية للسيرفر">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
        دعوة
      </button>` : '';
    const moveBtn = opts.showMoveToTeam ? `
      <button class="ts-card-move-team" type="button"
        data-move-app="${escapeAttr(a.id)}"
        data-app-name="${escapeAttr(a.name)}"
        title="${escapeAttr(t('ts.move_to_team_title'))}">
        ↗ ${escapeHtml(t('ts.move_to_team_btn'))}
      </button>` : '';
    return `
      <div class="ts-app-card${a.isBot ? ' has-reset' : ''}${opts.showMoveToTeam ? ' has-move' : ''}${_hasAllIntents ? ' intents-live' : ''}" title="${escapeAttr(a.id)}">
        <div class="ts-app-thumb">
          ${iconUrl ? `<img src="${iconUrl}" alt="" onerror="this.replaceWith(Object.assign(document.createElement('span'),{textContent:'${escapeAttr(initials)}',className:'ts-thumb-text'}))">` : `<span class="ts-thumb-text">${escapeHtml(initials)}</span>`}
          ${_hasAllIntents ? '<span class="ts-card-intent-badge" title="Privileged Intents مفعّلة ✓"></span>' : ''}
        </div>
        <div class="ts-app-name">${escapeHtml(a.name)}</div>
        ${tag}
        ${resetBtn}
        ${intentBtn}
        ${inviteBtn}
        ${moveBtn}
      </div>
    `;
  }

  // Returns an HTML badge string for the user's role in a team.
  _teamRoleBadge(team) {
    const role = team.myRole || (team.isOwner ? 'owner' : 'member');
    const labels = {
      owner:     t('ts.team_owner_badge')    || 'Owner',
      admin:     t('ts.team_role_admin')     || 'Admin',
      developer: t('ts.team_role_developer') || 'Developer',
      read_only: t('ts.team_role_read_only') || 'Read-only',
      member:    t('ts.team_member_badge')   || 'Member',
    };
    const label = labels[role] || labels.member;
    const cls   = role === 'owner' ? 'owner' : 'member';
    return ` <span class="ts-team-role-badge ${cls}">${escapeHtml(label)}</span>`;
  }

  // Bind "Move to Team" action buttons on personal-app cards.
  _bindMoveToTeamButtons(root) {
    root.querySelectorAll('[data-move-app]').forEach(btn => {
      if (btn._moveBound) return;
      btn._moveBound = true;
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const appId   = btn.getAttribute('data-move-app');
        const appName = btn.getAttribute('data-app-name') || appId;
        this._openMoveToTeamModal(appId, appName);
      });
    });
  }

  // ── Create Team modal ──────────────────────────────────────────────────
  _openCreateTeamModal() {
    document.querySelector('.ts-create-team-overlay')?.remove();
    const wrap = document.createElement('div');
    wrap.className = 'ts-create-team-overlay';
    wrap.innerHTML = `
      <div class="ts-create-team-card" role="dialog" aria-modal="true">
        <div class="ts-cteam-title">${escapeHtml(t('ts.team_create_title'))}</div>
        <label class="ts-cteam-label">${escapeHtml(t('ts.team_name_label'))}</label>
        <input class="ts-cteam-input" id="ts-cteam-name" type="text"
          maxlength="32"
          placeholder="${escapeAttr(t('ts.team_name_placeholder'))}" />
        <div class="ts-cteam-actions">
          <button class="ts-btn" id="ts-cteam-cancel">${escapeHtml(t('ts.close'))}</button>
          <button class="ts-btn primary" id="ts-cteam-confirm">${escapeHtml(t('ts.team_create_confirm'))}</button>
        </div>
      </div>
    `;
    document.body.appendChild(wrap);
    requestAnimationFrame(() => wrap.classList.add('open'));
    const input   = wrap.querySelector('#ts-cteam-name');
    const confirm = wrap.querySelector('#ts-cteam-confirm');
    const cancel  = wrap.querySelector('#ts-cteam-cancel');
    const close = () => { wrap.classList.remove('open'); setTimeout(() => wrap.remove(), 220); };
    cancel.addEventListener('click', close);
    wrap.addEventListener('click', (e) => { if (e.target === wrap) close(); });
    confirm.addEventListener('click', async () => {
      const name = (input?.value || '').trim();
      if (!name) { input?.focus(); return; }
      confirm.disabled = true;
      confirm.textContent = t('ts.team_creating');
      try {
        const result = await window.electronAPI.tsCreateTeam(this.selectedEmail, name);
        showNotification(t('ts.team_created_ok'), 'success');
        sfx.ding?.();
        // Immediately inject the new team into the local library so the tab
        // shows it right away without waiting for a slow API round-trip.
        if (!this.library) this.library = { teams: [], personal: [], totals: {}, currentUserId: null };
        if (!Array.isArray(this.library.teams)) this.library.teams = [];
        const newTeam = result?.team || {};
        this.library.teams.unshift({
          id: newTeam.id || String(Date.now()),
          name: newTeam.name || name,
          icon: newTeam.icon || null,
          apps: [],
          isOwner: true,
          myRole: 'owner',
          memberCount: 1,
          appsFromTeamEndpoint: false,
        });
        this.library.totals = this.library.totals || {};
        this.library.totals.teams = (this.library.totals.teams || 0) + 1;
        close();
        // Switch to teams tab immediately to show the new team
        this._switchLibraryTab('teams');
        // Refresh in background to get the real data
        this.loadLibrary().catch(() => {});
      } catch (e) {
        showNotification((t('ts.team_create_failed') || 'Failed') + ': ' + (e.message || e), 'error');
        confirm.disabled = false;
        confirm.textContent = t('ts.team_create_confirm');
      }
    });
    input?.focus();
  }

  // ── Move to Team modal ──────────────────────────────────────────────────
  _openMoveToTeamModal(appId, appName) {
    const teams = (this.library?.teams || []).filter(t => t.isOwner);
    if (!teams.length) {
      // No owned teams — offer to create one first
      showNotification(t('ts.lib_no_teams') || 'No teams — create one first', 'info');
      this._openCreateTeamModal();
      return;
    }
    document.querySelector('.ts-move-team-overlay')?.remove();
    const wrap = document.createElement('div');
    wrap.className = 'ts-move-team-overlay';
    wrap.innerHTML = `
      <div class="ts-move-team-card" role="dialog" aria-modal="true">
        <div class="ts-mteam-title">${escapeHtml(t('ts.move_to_team_title'))}</div>
        <div class="ts-mteam-app-name">${escapeHtml(appName)}</div>
        <label class="ts-cteam-label">${escapeHtml(t('ts.move_to_team_pick'))}</label>
        <select class="ts-mteam-select" id="ts-mteam-pick">
          ${teams.map(tm => `<option value="${escapeAttr(tm.id)}">${escapeHtml(tm.name)}</option>`).join('')}
        </select>
        <div class="ts-mteam-warn">⚠ ${escapeHtml(t('ts.move_to_team_warn'))}</div>
        <div class="ts-cteam-actions">
          <button class="ts-btn" id="ts-mteam-cancel">${escapeHtml(t('ts.close'))}</button>
          <button class="ts-btn primary danger" id="ts-mteam-confirm">${escapeHtml(t('ts.move_to_team_confirm'))}</button>
        </div>
      </div>
    `;
    document.body.appendChild(wrap);
    requestAnimationFrame(() => wrap.classList.add('open'));
    const select  = wrap.querySelector('#ts-mteam-pick');
    const confirm = wrap.querySelector('#ts-mteam-confirm');
    const cancel  = wrap.querySelector('#ts-mteam-cancel');
    const close = () => { wrap.classList.remove('open'); setTimeout(() => wrap.remove(), 220); };
    cancel.addEventListener('click', close);
    wrap.addEventListener('click', (e) => { if (e.target === wrap) close(); });
    confirm.addEventListener('click', async () => {
      const teamId = select?.value;
      if (!teamId) return;
      const ok = await showConfirm(
        `${t('ts.move_to_team_warn') || 'This is permanent'}\n\n"${appName}" → "${teams.find(x => x.id === teamId)?.name || teamId}"`,
        { confirmText: t('ts.move_to_team_confirm') }
      );
      if (!ok) return;
      confirm.disabled = true;
      confirm.textContent = t('ts.moving_to_team');
      try {
        await window.electronAPI.tsAddAppToTeam(this.selectedEmail, appId, teamId);
        showNotification(t('ts.move_ok'), 'success');
        sfx.ding?.();
        close();
        await this.loadLibrary();
        this._switchLibraryTab('teams');
      } catch (e) {
        showNotification((t('ts.move_failed') || 'Move failed') + ': ' + (e.message || e), 'error');
        confirm.disabled = false;
        confirm.textContent = t('ts.move_to_team_confirm');
      }
    });
  }

  _initialsFor(name) {
    const s = String(name || '').trim();
    if (!s) return '?';
    // "True-Studio7035" → "T-S"; "MyBot" → "MB"; "alpha beta" → "AB"
    const parts = s.split(/[\s\-_]+/).filter(Boolean);
    if (parts.length >= 2) return (parts[0][0] + '-' + parts[1][0]).toUpperCase();
    return s.slice(0, 2).toUpperCase();
  }

  _renderBots(bots) {
    if (!bots.length) return '';
    return `
      <div class="ts-card" style="margin-top:6px;">
        <div class="ts-card-head">
          <div class="ts-card-title">${t('ts.created_bots')} (${bots.length})</div>
          <a class="ts-btn" href="${window.electronAPI.tsExportUrl('text')}" download>${t('ts.export_tokens')}</a>
        </div>
        <div class="ts-bots-list">
          ${bots.map(b => `
            <div class="ts-bot-row">
              <span class="name">${escapeHtml(b.name)}</span>
              <span class="token">${b.hasToken ? (b.appId.slice(0, 6) + '… · ' + (b.botUserId || '').slice(0, 8)) : ''}</span>
              <button data-copy-id="${escapeAttr(b.appId)}">${t('ts.copy_id')}</button>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }

  _renderLive() {
    const s = this.snapshot;
    if (!s) return;
    const prog = this.contentArea.querySelector('#ts-progress-value');
    if (prog) prog.innerHTML = this._renderProgress(s);
    const stat = this.contentArea.querySelector('#ts-status-value');
    if (stat) {
      const meta = this._stateMeta(s.state);
      stat.className = 'ts-stat-value ' + meta.cls;
      stat.innerHTML = this._renderStatus(s, meta);
    }
    const log = this.contentArea.querySelector('#ts-log');
    const toolbar = this.contentArea.querySelector('.ts-log-toolbar');
    const logData = s.log || [];
    if (toolbar) toolbar.outerHTML = this._renderLogToolbar(logData);
    if (log) {
      log.innerHTML = this._renderLog(logData);
      if (this._logAutoScroll !== false) log.scrollTop = log.scrollHeight;
    }
    this._bindLogToolbar();
    // Refresh the "open library" trigger button so its session-bots badge
    // updates as new bots are produced. (The old inline #ts-bots / #ts-library
    // sections were replaced by this single trigger.)
    const trig = this.contentArea.querySelector('#ts-lib-trigger');
    if (trig) {
      trig.innerHTML = this._renderLibraryTrigger(s);
      // CRITICAL: rebuilding innerHTML wipes the click handler that _bind()
      // attached to #ts-lib-open. Without re-attaching here, the library
      // button stops responding after the very first SSE update — that's the
      // "hang" the user reported. Same goes for the inline refresh button.
      trig.querySelector('#ts-lib-open')
          ?.addEventListener('click', () => this._openLibraryModal('teams'));
      trig.querySelector('#ts-lib-refresh')
          ?.addEventListener('click', () => this.loadLibrary());
    }
    // If the library overlay is open AND the user is on the "created" tab,
    // re-render its body so newly-created bots appear live.
    if (this._libModal && this._libCurrentTab === 'created') {
      this._renderLibraryTab();
    }
    // Live account pool panel — refresh on every SSE update
    const poolWrap = this.contentArea.querySelector('#ts-account-pool');
    if (poolWrap) poolWrap.innerHTML = this._renderAccountPool(s);

    // Add or remove the countdown bar dynamically
    const stats = this.contentArea.querySelector('.ts-stats .ts-stat:nth-child(2)');
    if (stats) {
      const existing = stats.querySelector('#ts-countdown-bar');
      if (s.state === 'waiting' && !existing) {
        stats.insertAdjacentHTML('beforeend', `<div class="ts-countdown-bar" id="ts-countdown-bar"><span style="width:0%"></span></div>`);
      } else if (s.state !== 'waiting' && existing) {
        existing.remove();
      }
    }
  }

  _bindLogToolbar() {
    const area = this.contentArea;
    area.querySelectorAll('[data-log-filter]').forEach(btn => {
      if (btn._lfBound) return;
      btn._lfBound = true;
      btn.addEventListener('click', () => {
        this._logFilter = btn.dataset.logFilter;
        const log = area.querySelector('#ts-log');
        const toolbar = area.querySelector('.ts-log-toolbar');
        const logData = this.snapshot?.log || [];
        if (toolbar) {
          const newToolbar = document.createElement('div');
          newToolbar.innerHTML = this._renderLogToolbar(logData);
          toolbar.replaceWith(newToolbar.firstElementChild);
        }
        if (log) {
          log.innerHTML = this._renderLog(logData);
          if (this._logAutoScroll !== false) log.scrollTop = log.scrollHeight;
        }
        this._bindLogToolbar();
      });
    });

    const autoScrollBtn = area.querySelector('#ts-log-autoscroll');
    if (autoScrollBtn && !autoScrollBtn._asBound) {
      autoScrollBtn._asBound = true;
      autoScrollBtn.addEventListener('click', () => {
        this._logAutoScroll = !this._logAutoScroll;
        autoScrollBtn.classList.toggle('active', this._logAutoScroll);
        if (this._logAutoScroll) {
          const log = area.querySelector('#ts-log');
          if (log) log.scrollTop = log.scrollHeight;
        }
      });
    }

    const copyBtn = area.querySelector('#ts-log-copy');
    if (copyBtn && !copyBtn._cpBound) {
      copyBtn._cpBound = true;
      copyBtn.addEventListener('click', async () => {
        const log = this.snapshot?.log || [];
        const text = log.map(e => {
          const time = new Date(e.ts).toLocaleTimeString([], { hour12: false });
          const dur = e.durationMs ? ` [⚡${this._fmtDuration(e.durationMs)}]` : '';
          return `[${time}] [${e.level.toUpperCase()}]${dur} ${e.msg}`;
        }).join('\n');
        try {
          await navigator.clipboard.writeText(text);
          copyBtn.classList.add('flash');
          setTimeout(() => copyBtn.classList.remove('flash'), 600);
        } catch {}
      });
    }

    const clearBtn = area.querySelector('#ts-log-clear');
    if (clearBtn && !clearBtn._clBound) {
      clearBtn._clBound = true;
      clearBtn.addEventListener('click', async () => {
        try {
          await window.electronAPI?.tsClearLog?.();
        } catch {}
        if (this.snapshot) this.snapshot.log = [];
        const log = area.querySelector('#ts-log');
        const toolbar = area.querySelector('.ts-log-toolbar');
        if (toolbar) {
          const newT = document.createElement('div');
          newT.innerHTML = this._renderLogToolbar([]);
          toolbar.replaceWith(newT.firstElementChild);
        }
        if (log) log.innerHTML = this._renderLog([]);
        this._bindLogToolbar();
      });
    }
  }

  // ── Bindings ──────────────────────────────────────────
  _bind() {
    const $ = (sel) => this.contentArea.querySelector(sel);
    this._bindLogToolbar();

    $('#ts-acct-select')?.addEventListener('change', (e) => {
      this.selectedEmail = e.target.value || null;
      this.form.email = this.selectedEmail || '';
      this.form.password = '';
      this.form.totpSecret = '';
      this.form.directToken = '';
      // Clear library if it belongs to a different account
      if (this.libraryEmail && this.libraryEmail !== this.selectedEmail) {
        this.library = null; this.libraryEmail = null; this.libraryError = '';
      }
      this.render();
    });
    $('#ts-lib-refresh')?.addEventListener('click', () => this.loadLibrary());
    // Open the full-screen library overlay (Teams / Personal / Created tabs)
    $('#ts-lib-open')?.addEventListener('click', () => this._openLibraryModal('teams'));
    $('#ts-acct-save')?.addEventListener('click', () => this.saveAccount());
    $('#ts-acct-delete')?.addEventListener('click', () => this.deleteAccount());
    $('#ts-acct-test')?.addEventListener('click', () => this.testAccount());

    $('#ts-email')?.addEventListener('input', (e) => this.form.email = e.target.value.trim());
    $('#ts-password')?.addEventListener('input', (e) => this.form.password = e.target.value);
    $('#ts-totp')?.addEventListener('input', (e) => this.form.totpSecret = e.target.value.replace(/\s+/g, ''));
    $('#ts-direct-token')?.addEventListener('input', (e) => this.form.directToken = e.target.value.trim());

    $('#ts-bulk-tokens')?.addEventListener('input', (e) => {
      this.bulkTokensText = e.target.value;
      const n = this.bulkTokensText.split('\n').map(l => l.trim()).filter(l => l.length > 10).length;
      const btn = this.contentArea.querySelector('#ts-bulk-save');
      if (btn) {
        btn.disabled = n === 0;
        btn.textContent = t('ts.bulk_tokens_save') + (n > 0 ? ` (${n})` : '');
      }
    });
    $('#ts-bulk-save')?.addEventListener('click', () => this.saveBulkTokens());
    $('#ts-bulk-delete')?.addEventListener('click', () => this.deleteBulkTokens());
    $('#ts-session-budget')?.addEventListener('input', (e) => {
      this.form.sessionBudget = Math.max(0, Math.min(500, parseInt(e.target.value) || 0));
    });

    this.contentArea.querySelectorAll('[data-toggle]').forEach(el => {
      el.addEventListener('click', () => {
        const key = el.dataset.toggle;
        this.form.rules[key] = !this.form.rules[key];
        sfx.click?.();
        el.classList.toggle('on');
        el.setAttribute('aria-checked', String(this.form.rules[key]));
        this._updateRuleFieldStates();
      });
    });

    $('#ts-count')?.addEventListener('input', (e) => {
      this.form.count = Math.max(1, Math.min(50, parseInt(e.target.value) || 1));
    });
    $('#ts-prefix')?.addEventListener('input', (e) => this.form.prefix = e.target.value);
    $('#ts-wait')?.addEventListener('input', (e) => {
      this.form.waitMinutes = Math.max(0, Math.min(60, parseInt(e.target.value) || 0));
    });

    // Speed pills (radio buttons)
    this.contentArea.querySelectorAll('[name="ts-speed"]').forEach(radio => {
      radio.addEventListener('change', () => {
        this.form.speed = radio.value || 'medium';
        this.contentArea.querySelectorAll('.ts-speed-pill').forEach(p => {
          p.classList.toggle('active', p.querySelector('input')?.value === this.form.speed);
        });
      });
    });

    // Proxy URL textarea (one proxy per line)
    $('#ts-proxy-url')?.addEventListener('input', (e) => {
      this.form.proxyUrl = e.target.value;
      this._proxyTestResult = null;
    });

    // ── Bright Data toggle ──────────────────────────────────────────
    $('#ts-bd-toggle')?.addEventListener('click', () => {
      if (!this.form.brightData) this.form.brightData = { enabled: false, customerId: '', zoneName: '', zonePassword: '', protocol: 'http' };
      this.form.brightData.enabled = !this.form.brightData.enabled;
      this._proxyTestResult = null;
      this.render();
    });

    // ── Bright Data credential inputs ───────────────────────────────
    $('#ts-bd-customer')?.addEventListener('input', (e) => {
      if (!this.form.brightData) return;
      this.form.brightData.customerId = e.target.value.trim();
      this._proxyTestResult = null;
    });
    $('#ts-bd-zone')?.addEventListener('input', (e) => {
      if (!this.form.brightData) return;
      this.form.brightData.zoneName = e.target.value.trim();
      this._proxyTestResult = null;
    });
    $('#ts-bd-pass')?.addEventListener('input', (e) => {
      if (!this.form.brightData) return;
      this.form.brightData.zonePassword = e.target.value;
      this._proxyTestResult = null;
    });
    $('#ts-bd-proto')?.addEventListener('change', (e) => {
      if (!this.form.brightData) return;
      this.form.brightData.protocol = e.target.value || 'http';
    });

    // Batch size selector (shown when IP rotation is active)
    $('#ts-batch-size')?.addEventListener('change', (e) => {
      this.form.batchSize = Math.max(1, Math.min(5, parseInt(e.target.value) || 1));
    });

    // ── Quick Setup toggle button ────────────────────────────────────
    $('#ts-quick-setup')?.addEventListener('click', () => {
      this._quickSetupOpen = !this._quickSetupOpen;
      this.render();
    });

    // ── Quick Setup preset apply buttons (delegated via data-qs-apply) ──
    this.contentArea.querySelectorAll('[data-qs-apply]').forEach(btn => {
      btn.addEventListener('click', () => {
        const presetId = btn.dataset.qsApply;
        const preset   = TrueStudioManager.BD_PRESETS.find(p => p.id === presetId);
        if (!preset) return;
        // Apply preset settings to the form
        if (!this.form.brightData) this.form.brightData = { enabled: true, customerId: '', zoneName: '', zonePassword: '', protocol: 'http' };
        this.form.brightData.protocol = preset.protocol;
        this.form.batchSize = preset.batchSize;
        this.form.speed     = preset.speed;
        this._bdPreset      = preset.id;
        this._quickSetupOpen = false;
        this.render();
        showNotification(`تم تطبيق إعدادات ${preset.name} — أدخل Zone Name وPassword`, 'success');
      });
    });

    // Proxy test button — handles both manual proxy list and Bright Data mode
    $('#ts-proxy-test')?.addEventListener('click', async () => {
      const bd = this.form.brightData;
      let url = '';
      if (bd?.enabled) {
        // Build a test URL from Bright Data credentials (using a fixed test session)
        if (!bd.customerId || !bd.zoneName || !bd.zonePassword) {
          showNotification('أدخل Customer ID وZone Name وPassword أولاً', 'error'); return;
        }
        const host = 'brd.superproxy.io';
        const user = encodeURIComponent(`brd-customer-${bd.customerId}-zone-${bd.zoneName}-session-test`);
        const pass = encodeURIComponent(bd.zonePassword);
        url = bd.protocol === 'socks5h'
          ? `socks5h://${user}:${pass}@${host}:22228`
          : `http://${user}:${pass}@${host}:33335`;
      } else {
        url = (this.form.proxyUrl || '').split(/[\n,]+/).map(s => s.trim()).filter(Boolean)[0] || '';
        if (!url) { showNotification('أدخل رابط Proxy أولاً', 'error'); return; }
      }
      const btn = $('#ts-proxy-test');
      if (btn) { btn.disabled = true; btn.textContent = '…'; }
      try {
        const r = await window.electronAPI.tsVerifyProxy(url);
        this._proxyTestResult = r?.ok ? { ok: true, ip: r.ip } : { ok: false, error: r?.error || 'فشل' };
      } catch (e) {
        this._proxyTestResult = { ok: false, error: e.message || 'فشل الاتصال' };
      } finally {
        if (btn) { btn.disabled = false; btn.textContent = 'اختبار'; }
        this.render();
      }
    });

    // Team select dropdown
    $('#ts-team-select')?.addEventListener('change', (e) => {
      this.form.selectedTeamId = e.target.value || '';
    });

    // Teams reload button (shown when no teams available)
    $('#ts-teams-reload')?.addEventListener('click', () => this._loadTeamsForDropdown());

    $('#ts-start')?.addEventListener('click', () => this.startSession());
    $('#ts-stop')?.addEventListener('click', () => this.stopSession());
    $('#ts-pfp-save')?.addEventListener('click', () => this._savePfpFromInputs(false));
    $('#ts-pfp-clear')?.addEventListener('click', () => this._savePfpFromInputs(true));
    $('#ts-pfp-preview-btn')?.addEventListener('click', () => this.togglePfpPreview());
    $('#ts-auto-intents-btn')?.addEventListener('click', () => this._toggleAutoIntents());

    // Captcha settings
    $('#ts-captcha-save')?.addEventListener('click', () => this.saveCaptchaSettings());
    $('#ts-captcha-clear')?.addEventListener('click', () => this.clearCaptchaKey());
    $('#ts-captcha-verify')?.addEventListener('click', () => this.verifyCaptchaKey());
    $('#ts-captcha-verify-dismiss')?.addEventListener('click', () => {
      this._captchaVerifyResult = null;
      this._renderCaptchaSection();
    });
    $('#ts-captcha-fallback')?.addEventListener('click', () => this.toggleCaptchaFallback());

    this.contentArea.querySelectorAll('[data-copy-id]').forEach(el => {
      el.addEventListener('click', async () => {
        try { await copyToClipboard(el.dataset.copyId); showNotification(t('ts.copied'), 'success'); }
        catch (e) { showNotification(t('ts.copy_failed'), 'error'); }
      });
    });
  }

  // ── Actions ───────────────────────────────────────────
  async saveAccount() {
    const email = (this.form.email || '').trim().toLowerCase();
    if (!email || !email.includes('@')) {
      showNotification(t('ts.invalid_email'), 'error');
      return;
    }
    const payload = { email };
    // Only send fields if user typed them (so editing doesn't wipe existing creds)
    if (this.form.password) payload.password = this.form.password;
    if (this.form.totpSecret) payload.totpSecret = this.form.totpSecret;
    if (this.form.directToken) payload.directToken = this.form.directToken;
    try {
      await window.electronAPI.tsSaveAccount(payload);
      showNotification(t('ts.account_saved'), 'success');
      this.selectedEmail = email;
      this.form.password = '';
      this.form.totpSecret = '';
      this.form.directToken = '';
      await this.refresh();
      this.render();
    } catch (e) {
      showNotification(e.message || 'Save failed', 'error');
    }
  }

  async saveBulkTokens() {
    const tokens = this.bulkTokensText
      .split('\n')
      .map(l => l.trim())
      .filter(l => l.length > 10);
    if (tokens.length === 0) {
      showNotification('لا توجد توكنات صالحة', 'error');
      return;
    }
    try {
      const r = await window.electronAPI.tsSaveBulkTokens(tokens);
      if (!r.success) throw new Error(r.error || 'Save failed');
      const first = r.added[0];
      const last  = r.added[r.added.length - 1];
      const msg = t('ts.bulk_tokens_saved_range')
        .replace('{n}', r.count)
        .replace('{from}', first.email)
        .replace('{to}', last.email);
      showNotification(msg, 'success');
      this.bulkTokensText = '';
      await this.refresh();
      this.render();
    } catch (e) {
      showNotification(e.message || 'فشل الحفظ', 'error');
    }
  }

  async deleteBulkTokens() {
    const saved = (this.accounts || []).filter(a => /^tok-\d+@local$/.test(a.email || '')).length;
    if (saved === 0) { showNotification('لا توجد توكنات مرقمة', 'warn'); return; }
    if (!confirm(`هل أنت متأكد؟ سيتم حذف ${saved} توكن مرقم نهائياً.`)) return;
    try {
      const r = await window.electronAPI.tsDeleteBulkTokens();
      if (!r.success) throw new Error(r.error || 'Delete failed');
      showNotification(t('ts.bulk_tokens_deleted').replace('{n}', r.removed), 'success');
      await this.refresh();
      this.render();
    } catch (e) {
      showNotification(e.message || 'فشل الحذف', 'error');
    }
  }

  async loadLibrary() {
    if (!this.selectedEmail) { showNotification(t('ts.pick_account_first'), 'error'); return; }
    this.libraryLoading = true;
    this.libraryError = '';
    this._patchLibrary();
    try {
      const r = await window.electronAPI.tsLibrary(this.selectedEmail);
      this.library = {
        teams: r.teams || [],
        personal: r.personal || [],
        totals: r.totals || {},
        currentUserId: r.currentUserId || null,
      };
      this.currentUserId = r.currentUserId || null;
      this.libraryEmail = this.selectedEmail;
    } catch (e) {
      this.libraryError = e.message || 'Failed to load library';
      this.library = null;
    } finally {
      this.libraryLoading = false;
      this._patchLibrary();
    }
  }

  _patchLibrary() {
    // Trigger button shows the live "loaded apps" badge
    const trig = this.contentArea.querySelector('#ts-lib-trigger');
    if (trig) trig.innerHTML = this._renderLibraryTrigger(this.snapshot);
    // If the overlay is open, refresh its body and the refresh-button state
    if (this._libModal) {
      const refreshBtn = this._libModal.querySelector('#ts-lib-refresh-modal');
      if (refreshBtn) {
        refreshBtn.disabled = !!(this.libraryLoading || !this.selectedEmail);
        refreshBtn.textContent = this.libraryLoading
          ? (t('ts.testing') || '...')
          : (t('ts.lib_refresh') || 'تحديث');
      }
      // Always sync Reset All / Stop button states after library load/clear
      const resetAllBtn = this._libModal.querySelector('#ts-lib-reset-all');
      const stopAllBtn  = this._libModal.querySelector('#ts-lib-stop-all');
      if (resetAllBtn) {
        resetAllBtn.disabled = !this.library || this._resetAllInFlight;
        resetAllBtn.style.display = this._resetAllInFlight ? 'none' : '';
      }
      if (stopAllBtn) {
        stopAllBtn.style.display = this._resetAllInFlight ? '' : 'none';
      }
      this._renderLibraryTab();
    }
  }

  async testAccount() {
    if (!this.selectedEmail) { showNotification(t('ts.pick_account_first'), 'error'); return; }
    const btn = this.contentArea.querySelector('#ts-acct-test');
    const info = this.contentArea.querySelector('#ts-verify-info');
    if (btn) { btn.disabled = true; btn.textContent = t('ts.testing'); }
    if (info) info.innerHTML = `<span class="ts-verify v-idle">${t('ts.testing')}</span>`;
    try {
      const r = await window.electronAPI.tsTestAccount(this.selectedEmail);
      this.accounts = r?.accounts || this.accounts;
      const ok = r?.verify?.ok;
      showNotification(ok ? t('ts.verify_ok') : (t('ts.verify_failed') + ': ' + (r?.verify?.message || '')), ok ? 'success' : 'error');
    } catch (e) {
      showNotification(e.message || 'Test failed', 'error');
    } finally {
      this.render();
    }
  }

  async deleteAccount() {
    if (!this.selectedEmail) return;
    const target = this.selectedEmail;
    const confirmed = await showConfirm(
      t('ts.confirm_delete_msg').replace('{email}', target),
      { confirmText: t('ts.delete') }
    );
    if (!confirmed) return;
    try {
      await window.electronAPI.tsDeleteAccount(target);
      showNotification(t('ts.account_deleted'), 'success');
      this.selectedEmail = null;
      this.form.email = '';
      await this.refresh();
      this.render();
    } catch (e) {
      showNotification(e.message || 'Delete failed', 'error');
    }
  }

  async startSession() {
    if (!this.selectedEmail) {
      showNotification(t('ts.pick_account_first'), 'error');
      return;
    }
    const r = this.form.rules;
    if (!r.createTeams && !r.createBots && !r.linkBots) {
      showNotification(t('ts.pick_at_least_one_rule'), 'error');
      return;
    }
    try {
      await window.electronAPI.tsStart({
        email: this.selectedEmail,
        rules: r,
        count: this.form.count,
        prefix: this.form.prefix,
        waitMinutes: this.form.waitMinutes,
        proxyUrl: this.form.proxyUrl || '',
        speed: this.form.speed || 'medium',
        selectedTeamId: this.form.selectedTeamId || '',
        brightData: this.form.brightData || null,
        batchSize: this.form.batchSize || 1,
        sessionBudget: this.form.sessionBudget || 0,
      });
      showNotification(t('ts.session_started'), 'success');
      sfx.ding?.();
      await this.refresh();
      this._renderLive();
    } catch (e) {
      showNotification(e.message || 'Start failed', 'error');
    }
  }

  async stopSession() {
    try {
      await window.electronAPI.tsStop();
      showNotification(t('ts.session_stopping'), 'warn');
      await this.refresh();
      this._renderLive();
    } catch (e) {
      showNotification(e.message || 'Stop failed', 'error');
    }
  }

  // ── Captcha settings actions ──────────────────────────────
  async saveCaptchaSettings() {
    const provEl = this.contentArea.querySelector('#ts-captcha-provider');
    const keyEl = this.contentArea.querySelector('#ts-captcha-key');
    const provider = provEl?.value || '2captcha';
    const apiKey = (keyEl?.value || '').trim();
    const payload = { provider };
    if (apiKey) payload.apiKey = apiKey;
    try {
      const r = await window.electronAPI.tsSaveCaptchaSettings(payload);
      if (r?.settings) this.captchaSettings = r.settings;
      showNotification(t('ts.captcha_saved') || 'Captcha settings saved ✓', 'success');
      this.render();
    } catch (e) {
      showNotification(e.message || 'Save failed', 'error');
    }
  }

  async clearCaptchaKey() {
    const ok = await showConfirm(t('ts.captcha_clear_confirm') || 'Remove the saved API key?', { confirmText: t('ts.captcha_clear') || 'Clear' });
    if (!ok) return;
    try {
      const r = await window.electronAPI.tsSaveCaptchaSettings({ clearKey: true });
      if (r?.settings) this.captchaSettings = r.settings;
      showNotification(t('ts.captcha_cleared') || 'API key removed', 'success');
      this.render();
    } catch (e) {
      showNotification(e.message || 'Clear failed', 'error');
    }
  }

  async toggleCaptchaFallback() {
    // Locked when an API key is present — manual fallback can't be toggled on
    if (this.captchaSettings?.hasApiKey) return;
    const next = !(this.captchaSettings?.manualFallback !== false);
    try {
      const r = await window.electronAPI.tsSaveCaptchaSettings({ manualFallback: next });
      if (r?.settings) this.captchaSettings = r.settings;
      this.render();
    } catch (e) {
      showNotification(e.message || 'Toggle failed', 'error');
    }
  }

  // Re-render only the captcha card section without a full page re-render.
  _renderCaptchaSection() {
    const el = this.contentArea?.querySelector('#ts-captcha-card');
    if (!el) { this.render(); return; }
    el.outerHTML = this._renderCaptchaSettings();
    // Re-bind the newly injected buttons
    const $ = id => this.contentArea.querySelector(id);
    $('#ts-captcha-save')?.addEventListener('click', () => this.saveCaptchaSettings());
    $('#ts-captcha-clear')?.addEventListener('click', () => this.clearCaptchaKey());
    $('#ts-captcha-verify')?.addEventListener('click', () => this.verifyCaptchaKey());
    $('#ts-captcha-verify-dismiss')?.addEventListener('click', () => {
      this._captchaVerifyResult = null;
      this._renderCaptchaSection();
    });
    $('#ts-captcha-fallback')?.addEventListener('click', () => this.toggleCaptchaFallback());
  }

  async verifyCaptchaKey() {
    const btn = this.contentArea?.querySelector('#ts-captcha-verify');
    if (btn) { btn.textContent = '…'; btn.disabled = true; }
    try {
      const r = await window.electronAPI.tsCaptchaVerify();
      if (!r || !r.success) throw new Error(r?.error || 'فشل التحقق');
      this._captchaVerifyResult = r;
    } catch (e) {
      this._captchaVerifyResult = { ok: false, provider: this.captchaSettings?.providerLabel || 'API', error: e.message || 'فشل الاتصال' };
    }
    this.render();
  }
}

// ─── Local helpers ────────────────────────────────────
function escapeHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function escapeAttr(s) { return escapeHtml(s); }

// Triggers the ts-emoji-pop CSS animation once on an element.
// Removes and re-adds the class so rapid clicks always replay it.
function _emojiPop(el) {
  if (!el) return;
  el.classList.remove('ts-emoji-pop');
  void el.offsetWidth; // force reflow to restart animation
  el.classList.add('ts-emoji-pop');
  el.addEventListener('animationend', () => el.classList.remove('ts-emoji-pop'), { once: true });
}
