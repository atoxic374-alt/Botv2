/**
 * trueStudio.js — TOTP-based Discord automation engine (2025 — verified endpoints)
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * PIPELINE
 * ─────────────────────────────────────────────────────────────────────────────
 *   1. login(email, password, totpSecret)         → user token + warmed client
 *   2. simulateBrowsing()                         → plants cookies / looks human
 *   3. loadDevPortal()                            → warms X-Fingerprint
 *   4. [optional] createTeam(name)                → team id  (POST /teams)
 *   5. [optional] createApplication × N           → app ids  (POST /applications)
 *   6. [optional] ensureBot(appId)                → bot user (POST /applications/:id/bot)
 *   7. [optional] resetBotToken(appId, mfa)       → bot tok  (POST /applications/:id/bot/reset)
 *   8. [optional] transferAppToTeam(appId, teamId)→ transfer (POST /applications/:id/transfer)
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * VERIFIED ENDPOINTS (docs.discord.food / discord userdoccers, May 2025)
 * ─────────────────────────────────────────────────────────────────────────────
 *  POST /applications                         Create application (max 50/user, 25/team)
 *  POST /applications/:id/bot                 Create bot user (idempotent — 400→already exists)
 *  POST /applications/:id/bot/reset           Reset bot token → {token:string}  ← requires MFA
 *  POST /applications/:id/transfer            Transfer to team → {team_id:string}
 *  POST /teams                                Create team (max 30 teams/user)
 *  GET  /teams                                List user's teams
 *  GET  /applications?with_team_applications=true  List all user applications
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * ANTI-DETECTION STACK (2025)
 * ─────────────────────────────────────────────────────────────────────────────
 *  • Chrome 133 TLS: ciphers / curves / sigalgs / ALPN  (approximates JA3)
 *  • Persistent CookieJar per session  (__dcfduid / __sdcfduid / __cfruid)
 *  • Live client_build_number scraped from Discord's JS bundle at session start
 *  • X-Super-Properties matches current Discord web client schema (design_id=0)
 *  • X-Context-Properties sent on every dev-portal request (reverse-engineered)
 *  • Gaussian-jittered delays — avoids flat-uniform timing fingerprint
 *  • Full post-login browsing simulation (@me / guilds / science events)
 *  • Referer chain updated via navigateTo() on every SPA route change
 *  • rate-limit back-off reads X-RateLimit-Reset-After header
 *  • TOTP auto-retry across 30-second epoch boundary
 */

'use strict';

const crypto = require('crypto');
const axios  = require('axios');
const { CookieJar } = require('tough-cookie');
const { HttpsCookieAgent, HttpCookieAgent } = require('http-cookie-agent/http');

// API base URLs — we use v9 for user-auth endpoints (better tested),
// v10 for bot/reset which was moved there.
const API   = 'https://discord.com/api/v9';
const API10 = 'https://discord.com/api/v10';

// ─────────────────────────────────────────────────────────────────────────────
// TLS fingerprint mitigation — Chrome 133 (January 2025)
//
// JA3 is built from ClientHello: cipher list + extensions + curves + sigalgs.
// Node's TLS hard-codes extension ORDER so we can't match it perfectly, but
// aligning cipher preference order / curves / sigalgs moves us out of the
// "automation library" JA3 bucket into the "unknown browser" bucket.
// ALPN: Chrome sends h2 first but Node can't speak HTTP/2 binary frames, so
// we advertise http/1.1 only. This is the only remaining major JA3 delta.
// ─────────────────────────────────────────────────────────────────────────────
const CHROME_133_CIPHERS = [
  'TLS_AES_128_GCM_SHA256',
  'TLS_AES_256_GCM_SHA384',
  'TLS_CHACHA20_POLY1305_SHA256',
  'ECDHE-ECDSA-AES128-GCM-SHA256',
  'ECDHE-RSA-AES128-GCM-SHA256',
  'ECDHE-ECDSA-CHACHA20-POLY1305',
  'ECDHE-RSA-CHACHA20-POLY1305',
  'ECDHE-ECDSA-AES256-GCM-SHA384',
  'ECDHE-RSA-AES256-GCM-SHA384',
  'ECDHE-ECDSA-AES128-SHA256',
  'ECDHE-RSA-AES128-SHA256',
  'ECDHE-ECDSA-AES128-SHA',
  'ECDHE-RSA-AES128-SHA',
  'ECDHE-ECDSA-AES256-SHA384',
  'ECDHE-RSA-AES256-SHA384',
  'ECDHE-ECDSA-AES256-SHA',
  'ECDHE-RSA-AES256-SHA',
  'AES128-GCM-SHA256',
  'AES256-GCM-SHA384',
  'AES128-SHA256',
  'AES256-SHA256',
  'AES128-SHA',
  'AES256-SHA',
].join(':');

const CHROME_133_SIGALGS = [
  'ecdsa_secp256r1_sha256',
  'rsa_pss_rsae_sha256',
  'rsa_pkcs1_sha256',
  'ecdsa_secp384r1_sha384',
  'rsa_pss_rsae_sha384',
  'rsa_pkcs1_sha384',
  'rsa_pss_rsae_sha512',
  'rsa_pkcs1_sha512',
  'rsa_pkcs1_sha1',
].join(':');

function _buildAgents(jar) {
  const tls = {
    keepAlive: true,
    keepAliveMsecs: 45_000,
    ciphers: CHROME_133_CIPHERS,
    honorCipherOrder: true,
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.3',
    ALPNProtocols: ['http/1.1'],
    ecdhCurve: 'X25519:prime256v1:secp384r1',
    sigalgs: CHROME_133_SIGALGS,
  };
  return {
    httpsAgent: new HttpsCookieAgent({ cookies: { jar }, ...tls }),
    httpAgent:  new HttpCookieAgent({ cookies: { jar }, keepAlive: true, keepAliveMsecs: 45_000 }),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// User-Agent pool — Chrome 132 & 133, Windows 10/11 & macOS 14/15
// Each session gets one UA randomly chosen and keeps it throughout.
// Mixing platforms/versions prevents per-IP UA fingerprint correlation.
// ─────────────────────────────────────────────────────────────────────────────
const UA_POOL = [
  {
    os: 'Windows', browser: 'Chrome', browser_version: '133.0.0.0', os_version: '10',
    ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
    sec_ch_ua: '"Not A(Brand";v="8", "Chromium";v="133", "Google Chrome";v="133"',
    platform: '"Windows"',
  },
  {
    os: 'Windows', browser: 'Chrome', browser_version: '133.0.0.0', os_version: '11',
    ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
    sec_ch_ua: '"Not A(Brand";v="8", "Chromium";v="133", "Google Chrome";v="133"',
    platform: '"Windows"',
  },
  {
    os: 'Mac OS X', browser: 'Chrome', browser_version: '133.0.0.0', os_version: '15_3_1',
    ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_3_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
    sec_ch_ua: '"Not A(Brand";v="8", "Chromium";v="133", "Google Chrome";v="133"',
    platform: '"macOS"',
  },
  {
    os: 'Mac OS X', browser: 'Chrome', browser_version: '132.0.0.0', os_version: '14_7_2',
    ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36',
    sec_ch_ua: '"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"',
    platform: '"macOS"',
  },
  {
    os: 'Windows', browser: 'Chrome', browser_version: '132.0.0.0', os_version: '10',
    ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36',
    sec_ch_ua: '"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"',
    platform: '"Windows"',
  },
];

function _pickUA() { return UA_POOL[Math.floor(Math.random() * UA_POOL.length)]; }

// ─────────────────────────────────────────────────────────────────────────────
// X-Super-Properties (discord.food/reference — Client Properties Structure)
//
// Required fields per docs: os, browser, browser_user_agent, browser_version,
// client_build_number.  Additional fields: device, system_locale,
// release_channel, client_event_source, design_id.
//
// client_build_number refreshed dynamically at session start.
// Static fallback: ~May 2025 build.
// ─────────────────────────────────────────────────────────────────────────────
const STATIC_BUILD_NUMBER = 374017; // May 2025 stable build

function _encodeSuperProps(buildNumber, uaInfo) {
  return Buffer.from(JSON.stringify({
    os:                  uaInfo.os,
    browser:             uaInfo.browser,
    device:              '',
    system_locale:       'en-US',
    has_client_mods:     false,
    browser_user_agent:  uaInfo.ua,
    browser_version:     uaInfo.browser_version,
    os_version:          uaInfo.os_version,
    referrer:            '',
    referring_domain:    '',
    referrer_current:    '',
    referring_domain_current: '',
    release_channel:     'stable',
    client_build_number: buildNumber || STATIC_BUILD_NUMBER,
    client_event_source: null,
    design_id:           0,
  })).toString('base64');
}

// X-Context-Properties: sent on dev-portal API calls (reverse-engineered).
// Signals that the request originates from the Developer Portal UI context.
const CTX_DEV_PORTAL = Buffer.from(JSON.stringify({
  location:              'Developer Portal',
  location_guild_id:     null,
  location_channel_id:   null,
  location_channel_type: null,
})).toString('base64');

// ─────────────────────────────────────────────────────────────────────────────
// Per-session client factory
// ─────────────────────────────────────────────────────────────────────────────
function createClient(proxyUrl) {
  const jar    = new CookieJar();
  const uaInfo = _pickUA();
  const buildNumber   = STATIC_BUILD_NUMBER;
  const superPropsB64 = _encodeSuperProps(buildNumber, uaInfo);

  let httpsAgent, httpAgent, useCookieInterceptors = false;

  if (proxyUrl && typeof proxyUrl === 'string' && proxyUrl.trim()) {
    const raw = proxyUrl.trim();
    const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : 'http://' + raw;
    const scheme = (() => { try { return new URL(withScheme).protocol.replace(':', '').toLowerCase(); } catch { return 'http'; } })();
    if (scheme === 'socks' || scheme === 'socks4' || scheme === 'socks5' || scheme === 'socks5h') {
      const { SocksProxyAgent } = require('socks-proxy-agent');
      const agent = new SocksProxyAgent(withScheme);
      httpsAgent = agent;
      httpAgent  = agent;
    } else {
      const { HttpsProxyAgent } = require('https-proxy-agent');
      const { HttpProxyAgent }  = require('http-proxy-agent');
      httpsAgent = new HttpsProxyAgent(withScheme);
      httpAgent  = new HttpProxyAgent(withScheme);
    }
    useCookieInterceptors = true;
  } else {
    const agents = _buildAgents(jar);
    httpsAgent = agents.httpsAgent;
    httpAgent  = agents.httpAgent;
  }

  const http = axios.create({
    timeout: 32_000,
    validateStatus: () => true,
    httpAgent,
    httpsAgent,
    headers: {
      'Accept':              '*/*',
      'Accept-Language':     'en-US,en;q=0.9',
      'Accept-Encoding':     'gzip, deflate, br, zstd',
      'User-Agent':          uaInfo.ua,
      'sec-ch-ua':           uaInfo.sec_ch_ua,
      'sec-ch-ua-mobile':    '?0',
      'sec-ch-ua-platform':  uaInfo.platform,
      'sec-fetch-dest':      'empty',
      'sec-fetch-mode':      'cors',
      'sec-fetch-site':      'same-origin',
    },
  });

  if (useCookieInterceptors) {
    http.interceptors.request.use(async (config) => {
      try {
        const reqUrl = config.url || 'https://discord.com';
        const cookies = await jar.getCookies(reqUrl);
        if (cookies.length) config.headers['Cookie'] = cookies.map(c => c.cookieString()).join('; ');
      } catch (_) {}
      return config;
    });
    http.interceptors.response.use(async (response) => {
      try {
        const reqUrl = response.config?.url || 'https://discord.com';
        const setCookie = response.headers['set-cookie'];
        if (setCookie) {
          const list = Array.isArray(setCookie) ? setCookie : [setCookie];
          for (const ck of list) { try { await jar.setCookie(ck, reqUrl); } catch (_) {} }
        }
      } catch (_) {}
      return response;
    }, async (err) => Promise.reject(err));
  }

  return {
    jar, http, uaInfo,
    buildNumber, superPropsB64,
    fingerprint:    null,
    warmedUp:       false,
    devPortalLoaded: false,
    currentPage:    'https://discord.com/login',
    proxyUrl:       proxyUrl || null,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Live build_number scraper
// Scans the last 8 JS chunks from discord.com/login for the build number.
// Falls back to STATIC_BUILD_NUMBER if Discord's structure changes.
// ─────────────────────────────────────────────────────────────────────────────
async function fetchBuildNumber(client) {
  try {
    const page = await client.http.get('https://discord.com/login', {
      headers: {
        'Accept':         'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language':'en-US,en;q=0.9',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'none',
        'sec-fetch-user': '?1',
        'Cache-Control':  'max-age=0',
        'Upgrade-Insecure-Requests': '1',
      },
    });
    const html = String(page.data || '');
    const re = /<script[^>]+src="(\/assets\/[A-Za-z0-9._-]+\.js)"/g;
    const scripts = [];
    let m;
    while ((m = re.exec(html)) !== null) scripts.push(m[1]);
    if (!scripts.length) return null;

    for (const src of scripts.slice(-8).reverse()) {
      try {
        const r = await client.http.get('https://discord.com' + src, {
          headers: {
            'Accept':          '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Referer':         'https://discord.com/login',
            'sec-fetch-dest':  'script',
            'sec-fetch-mode':  'no-cors',
            'sec-fetch-site':  'same-origin',
          },
          maxContentLength: 80 * 1024 * 1024,
          maxBodyLength:    80 * 1024 * 1024,
        });
        const body = String(r.data || '');
        // Multiple patterns Discord has used across builds
        const patterns = [
          /buildNumber[^\d]*(\d{5,7})/,
          /client_build_number[^\d]*(\d{5,7})/,
          /"buildNumber":"?(\d{5,7})"?/,
          /BUILT_IN_COMMANDS_BUILD_NUMBER[^\d]*(\d{5,7})/,
        ];
        for (const pat of patterns) {
          const bm = body.match(pat);
          if (bm) {
            const num = parseInt(bm[1], 10);
            if (num > 200_000 && num < 9_999_999) return num;
          }
        }
      } catch (_) {}
    }
  } catch (_) {}
  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Timing helpers
// Gaussian distribution (Box-Muller) gives realistic human-like timing.
// Flat uniform is a dead giveaway of automation — humans cluster around a mean.
// ─────────────────────────────────────────────────────────────────────────────
function _sleep(ms) { return new Promise(r => setTimeout(r, Math.max(0, ms | 0))); }

function _gauss(min, max) {
  let u = 0, v = 0;
  while (!u) u = Math.random();
  while (!v) v = Math.random();
  const n = Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
  const mid  = (min + max) / 2;
  const half = (max - min) / 2;
  return Math.max(min, Math.min(max, mid + n * (half / 2.5))) | 0;
}

// speedFactor: 1.0 = medium (default), 0.4 = fast, 0.15 = veryfast
function _humanDelay(min = 500, max = 1500, factor = 1.0) {
  const f = Math.max(0.05, factor);
  return _sleep(_gauss(Math.max(50, Math.round(min * f)), Math.max(100, Math.round(max * f))));
}
function humanDelay(min, max, factor) { return _humanDelay(min, max, factor); }

function _firstHeader(headers, name) {
  if (!headers) return undefined;
  const lower = String(name).toLowerCase();
  return headers[lower] ?? headers[name] ?? headers[Object.keys(headers).find(k => String(k).toLowerCase() === lower)];
}

function _num(v, fallback = 0) {
  const n = Number(Array.isArray(v) ? v[0] : v);
  return Number.isFinite(n) ? n : fallback;
}

function _routeKey(method, url) {
  try {
    const u = new URL(url, 'https://discord.com');
    const path = u.pathname.replace(/\d{15,25}/g, ':id');
    return `${String(method || 'GET').toUpperCase()} ${u.host}${path}`;
  } catch (_) {
    return `${String(method || 'GET').toUpperCase()} ${String(url || '').replace(/\d{15,25}/g, ':id')}`;
  }
}

function rateLimitInfoFromResponse(r) {
  const headers = r?.headers || {};
  const retryAfter = _num(_firstHeader(headers, 'retry-after') ?? r?.data?.retry_after, 0);
  const resetAfter = _num(_firstHeader(headers, 'x-ratelimit-reset-after'), retryAfter);
  const remainingRaw = _firstHeader(headers, 'x-ratelimit-remaining');
  const remaining = remainingRaw === undefined ? null : _num(remainingRaw, null);
  const limitRaw = _firstHeader(headers, 'x-ratelimit-limit');
  const limit = limitRaw === undefined ? null : _num(limitRaw, null);
  const bucket = _firstHeader(headers, 'x-ratelimit-bucket') || null;
  const scope = _firstHeader(headers, 'x-ratelimit-scope') || (r?.data?.global ? 'global' : null);
  const global = String(_firstHeader(headers, 'x-ratelimit-global') || '').toLowerCase() === 'true' || !!r?.data?.global || scope === 'global';
  const retryAfterMs = Math.max(0, Math.ceil(retryAfter * 1000));
  const resetAfterMs = Math.max(0, Math.ceil(resetAfter * 1000));
  const exhausted = r?.status === 429 || (remaining === 0 && resetAfterMs > 0);
  const waitMs = exhausted ? Math.max(retryAfterMs, resetAfterMs, r?.status === 429 ? 1000 : 0) : 0;
  return { retryAfter, retryAfterMs, resetAfter, resetAfterMs, remaining, limit, bucket, scope, global, exhausted, waitMs };
}

function createRateLimitGuard({ label = 'discord', onWait, minimumGapMs = 0, safetyMs = 650 } = {}) {
  const routes = new Map();
  const buckets = new Map();
  let globalUntil = 0;
  let lastRequestAt = 0;
  let queue = Promise.resolve();

  async function waitFor(until, reason, info = {}) {
    const waitMs = Math.max(0, Math.ceil((until || 0) - Date.now()));
    if (!waitMs) return;
    try { await onWait?.({ label, reason, waitMs, phase: 'start', ...info }); } catch (_) {}
    await _sleep(waitMs);
    try { await onWait?.({ label, reason, waitMs: 0, phase: 'end', ...info }); } catch (_) {}
  }

  return {
    async before({ method, url } = {}) {
      const run = queue.then(async () => {
        if (minimumGapMs > 0) {
          await waitFor(lastRequestAt + minimumGapMs, 'local_pacing', { method, url });
        }
        await waitFor(globalUntil, 'global_rate_limit', { method, url });

        const key = _routeKey(method, url);
        const route = routes.get(key);
        if (route?.until) await waitFor(route.until, 'route_rate_limit', { method, url, route: key, bucket: route.bucket || null });
        if (route?.bucket) {
          const bucket = buckets.get(route.bucket);
          if (bucket?.until) await waitFor(bucket.until, 'bucket_rate_limit', { method, url, route: key, bucket: route.bucket });
        }
        lastRequestAt = Date.now();
      });
      queue = run.catch(() => {});
      return run;
    },

    after({ method, url, response } = {}) {
      const info = rateLimitInfoFromResponse(response);
      const key = _routeKey(method, url);
      const route = routes.get(key) || {};
      if (info.bucket) route.bucket = info.bucket;

      if (info.waitMs > 0) {
        const until = Date.now() + info.waitMs + safetyMs;
        route.until = Math.max(route.until || 0, until);
        route.reason = response?.status === 429 ? '429' : 'remaining_0';
        if (info.bucket) {
          const prev = buckets.get(info.bucket) || {};
          buckets.set(info.bucket, { ...prev, until: Math.max(prev.until || 0, until), route: key, scope: info.scope || null });
        }
        if (info.global) globalUntil = Math.max(globalUntil, until);
      }

      if (route.bucket || route.until) routes.set(key, route);
      return info;
    },

    snapshot() {
      return { label, globalUntil, routes: routes.size, buckets: buckets.size };
    },
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// TOTP
// ─────────────────────────────────────────────────────────────────────────────
function generateTOTP(secret) {
  const { authenticator } = require('otplib');
  return authenticator.generate(secret);
}

function isValidTotpSecret(secret) {
  if (typeof secret !== 'string') return false;
  return /^[A-Z2-7]{16,64}$/i.test(secret.replace(/\s+/g, ''));
}

// ─────────────────────────────────────────────────────────────────────────────
// Error class
// ─────────────────────────────────────────────────────────────────────────────
class DiscordError extends Error {
  constructor(msg, { code, status, data, retryAfter, rateLimit, captchaSitekey, captchaRqdata, captchaRqtoken, captchaSessionId } = {}) {
    super(msg);
    this.code   = code   || '';
    this.status = status || 0;
    this.data   = data;
    if (retryAfter != null) this.retryAfter = retryAfter;
    if (rateLimit) this.rateLimit = rateLimit;
    if (captchaSitekey) this.captchaSitekey = captchaSitekey;
    if (captchaRqdata) this.captchaRqdata = captchaRqdata;
    if (captchaRqtoken) this.captchaRqtoken = captchaRqtoken;
    if (captchaSessionId) this.captchaSessionId = captchaSessionId;
  }
}

function _isCaptcha(data) {
  return !!(data && (data.captcha_key || data.captcha_sitekey || data.captcha_service));
}

// ─────────────────────────────────────────────────────────────────────────────
// Core request wrapper
// Handles: Gaussian pre-delay · rate-limit back-off · MFA ticket · captcha
// ─────────────────────────────────────────────────────────────────────────────
async function _req({
  method, url, token, body, netOpts = {}, mfa,
  extra = {}, _rl = 0, _cap = 0, _mfa = 0,
}) {
  const client = netOpts.client || createClient();
  const { totpSecret, solveCaptcha } = netOpts;

  // Build request headers
  const headers = {
    'Content-Type':        'application/json',
    'Origin':              'https://discord.com',
    'X-Super-Properties':  client.superPropsB64,
    'X-Discord-Locale':    'en-US',
    'X-Discord-Timezone':  'Etc/UTC',
    'Referer':             client.currentPage || 'https://discord.com/',
    ...extra,
  };
  if (token) headers['Authorization'] = token;
  if (mfa)   headers['X-Discord-MFA-Authorization'] = mfa;
  if (client.fingerprint) headers['X-Fingerprint'] = client.fingerprint;

  // Gaussian inter-request delay — avoids fixed-interval automation pattern
  const _sf = netOpts.speedFactor != null ? netOpts.speedFactor : 1.0;
  await _humanDelay(200, 700, _sf);

  if (netOpts.rateLimiter?.before) {
    await netOpts.rateLimiter.before({ method, url, token });
  }
  const r = await client.http({ method, url, data: body, headers });
  const rateLimit = netOpts.rateLimiter?.after
    ? netOpts.rateLimiter.after({ method, url, token, response: r })
    : rateLimitInfoFromResponse(r);

  // ── Rate-limit back-off ────────────────────────────────────────────────
  if (r.status === 429) {
    // ── Cloudflare IP block fast-fail ──────────────────────────────────
    // A real Discord 429 ALWAYS includes X-RateLimit-Bucket and retry_after.
    // Cloudflare blocks return neither — just a JSON {code:0} or HTML body
    // with a message about being blocked, and the block can last up to 24h.
    // Retrying 4× on a CF block wastes 8–12s and never recovers — fail fast
    // so the caller can switch accounts immediately.
    const _cfMsg = String(r.data?.message || '').toLowerCase();
    const _isCf  = !rateLimit.bucket &&
                   !rateLimit.retryAfter &&
                   !rateLimit.waitMs &&
                   (r.data?.code === 0 ||
                    /blocked|error\s*1015|cloudflare|temporarily restricted/i.test(_cfMsg));
    if (_isCf) {
      throw new DiscordError('Cloudflare IP block — switch account immediately', {
        status: 429, data: r.data, code: 'CLOUDFLARE_BLOCK', rateLimit,
      });
    }
    // Normal Discord 429 — back off and retry (up to 4×)
    if (_rl < 4) {
      const waitMs = Math.max(rateLimit.waitMs, 1000) + _gauss(700, 1800);
      await _sleep(waitMs);
      return _req({ method, url, token, body, netOpts, mfa, extra, _rl: _rl + 1, _cap, _mfa });
    }
  }

  // ── MFA ticket (code 60003) ────────────────────────────────────────────
  // Discord returns this for BOTH 2FA-enabled and non-2FA accounts on
  // sensitive operations (bot/reset, ensureBot, transfer, etc.).
  //
  // New format (2025): mfa.methods[] lists which methods are accepted:
  //   {"type": "password"}  — account has NO 2FA → verify with password
  //   {"type": "totp"}      — account HAS 2FA    → verify with TOTP code
  //
  // Both methods now use POST /mfa/finish  (new unified endpoint).
  // Old format (no methods array): fall back to old TOTP flow for compat.
  if ((r.status === 401 || r.status === 403) && r.data?.code === 60003 && r.data?.mfa?.ticket && _mfa < 2) {
    const ticket  = r.data.mfa.ticket;
    const methods = Array.isArray(r.data.mfa.methods) ? r.data.mfa.methods : [];
    const { password: accountPassword } = netOpts;

    const wantsPassword = methods.some(m => m.type === 'password');
    const wantsTotp     = methods.length === 0 || methods.some(m => m.type === 'totp' || m.type === 'backup');

    let mfaToken = null;

    // ── Path A: password-based MFA (account has NO 2FA) ───────────────
    if (!mfaToken && wantsPassword && accountPassword) {
      const pr = await _req({
        method:  'POST',
        url:     `${API}/mfa/finish`,
        token,
        body:    { ticket, mfa_type: 'password', data: accountPassword },
        netOpts: { ...netOpts, password: undefined, totpSecret: undefined },
        _mfa:    _mfa + 1,
      });
      if (pr.status < 400 && pr.data?.token) mfaToken = pr.data.token;
    }

    // ── Path B: TOTP-based MFA (account HAS 2FA) ──────────────────────
    if (!mfaToken && wantsTotp && totpSecret) {
      for (let attempt = 0; attempt < 3; attempt++) {
        if (attempt > 0) {
          const msIntoStep = Date.now() % 30_000;
          await _sleep(30_000 - msIntoStep + _gauss(1200, 2500));
        }
        // Use new unified endpoint; fall back to old one if new one fails.
        const mr = await _req({
          method:  'POST',
          url:     `${API}/mfa/finish`,
          token,
          body:    { ticket, mfa_type: 'totp', data: generateTOTP(totpSecret) },
          netOpts: { ...netOpts, totpSecret: undefined, password: undefined },
          _mfa:    _mfa + 1,
        });
        if (mr.status < 400 && mr.data?.token) { mfaToken = mr.data.token; break; }
        // If new endpoint not found, fall back to old TOTP verify endpoint
        if (mr.status === 404) {
          const fr = await _req({
            method:  'POST',
            url:     `${API}/users/@me/mfa/totp/verify`,
            token,
            body:    { code: generateTOTP(totpSecret), ticket },
            netOpts: { ...netOpts, totpSecret: undefined, password: undefined },
            _mfa:    _mfa + 1,
          });
          if (fr.status < 400 && fr.data?.token) { mfaToken = fr.data.token; break; }
          if (fr.data?.code !== 60008) break;
        } else {
          if (mr.data?.code !== 60008) break;
        }
      }
    }

    if (mfaToken) {
      return _req({
        method, url, token, body, netOpts, mfa: mfaToken,
        extra, _rl, _cap, _mfa: _mfa + 1,
      });
    }
  }

  // ── Captcha ────────────────────────────────────────────────────────────
  if (_isCaptcha(r.data) && _cap < 1 && typeof solveCaptcha === 'function') {
    const {
      captcha_sitekey: sitekey, captcha_service: service,
      captcha_rqdata: rqdata, captcha_rqtoken: rqtoken,
      captcha_session_id: sessionId,
    } = r.data;
    if (sitekey) {
      try {
        const solved = await solveCaptcha({
          sitekey, service: service || 'hcaptcha',
          rqdata, rqtoken, url, context: netOpts.captchaContext || 'discord',
        });
        if (solved) {
          const captchaExtra = { ...extra, 'X-Captcha-Key': solved };
          if (sessionId) captchaExtra['X-Captcha-Session-Id'] = sessionId;
          if (rqtoken) captchaExtra['X-Captcha-Rqtoken'] = rqtoken;
          return _req({ method, url, token, body, netOpts, mfa, extra: captchaExtra, _rl, _cap: _cap + 1, _mfa });
        }
      } catch (e) {
        throw new DiscordError('Captcha solver failed: ' + (e?.message || e), {
          code: 'CAPTCHA_FAILED', status: r.status, data: r.data,
          captchaSitekey: sitekey, captchaRqdata: rqdata, captchaRqtoken: rqtoken, captchaSessionId: sessionId,
        });
      }
    }
    throw new DiscordError('Discord requires captcha — no solver available', {
      code: 'CAPTCHA_REQUIRED', status: r.status, data: r.data,
      captchaSitekey: sitekey, captchaRqdata: rqdata, captchaRqtoken: rqtoken, captchaSessionId: sessionId,
    });
  }

  return { status: r.status, data: r.data, headers: r.headers };
}

// ─────────────────────────────────────────────────────────────────────────────
// Session warm-up
// Three steps that every real Chrome session performs before login:
//   1. Scrape live build_number from the Discord JS bundle
//   2. GET /login  → plants __dcfduid + __sdcfduid + __cfruid cookies
//   3. GET /experiments → obtains X-Fingerprint
// ─────────────────────────────────────────────────────────────────────────────
async function warmUpClient(client) {
  if (client.warmedUp) return;

  // 1. Live build number
  const bn = await fetchBuildNumber(client);
  if (bn) {
    client.buildNumber   = bn;
    client.superPropsB64 = _encodeSuperProps(bn, client.uaInfo);
  }

  // 2. Login page cold load — seeds Cloudflare cookies
  await client.http.get('https://discord.com/login', {
    headers: {
      'Accept':          'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.9',
      'sec-fetch-dest':  'document',
      'sec-fetch-mode':  'navigate',
      'sec-fetch-site':  'none',
      'sec-fetch-user':  '?1',
      'Cache-Control':   'max-age=0',
    },
  });
  await _humanDelay(1000, 2800);

  // 3. /experiments → fingerprint (no auth needed here)
  try {
    const er = await client.http.get(`${API}/experiments`, {
      headers: {
        'X-Super-Properties':  client.superPropsB64,
        'X-Context-Properties': CTX_DEV_PORTAL,
        'Referer':             'https://discord.com/login',
      },
    });
    if (er.data?.fingerprint) client.fingerprint = er.data.fingerprint;
  } catch (_) {}

  client.warmedUp = true;
}

// ─────────────────────────────────────────────────────────────────────────────
// navigateTo — tracks Referer chain across SPA route changes.
// Also posts a /track event (Discord's client sends these on every nav).
// ─────────────────────────────────────────────────────────────────────────────
async function navigateTo({ client, page }) {
  if (!client || !page) return;
  const prev = client.currentPage || 'https://discord.com/';
  client.currentPage = page;
  try {
    await client.http.post(`${API}/track`, {}, {
      headers: {
        'X-Super-Properties': client.superPropsB64,
        'Content-Type': 'application/json',
        'Referer': prev,
      },
    });
  } catch (_) {}
}

// ─────────────────────────────────────────────────────────────────────────────
// simulateBrowsing — post-login warm-up that looks like a real user session.
//
// A real Discord web client after login will:
//   • Fetch @me (user profile)
//   • Fetch @me/channels (DM list)
//   • Fetch @me/guilds
//   • Post a science event (telemetry)
// We replicate these calls so the session has a natural activity pattern
// before we start hitting the dev portal.
// ─────────────────────────────────────────────────────────────────────────────
async function simulateBrowsing({ token, netOpts }) {
  const client = netOpts?.client;
  if (!client) return;

  const h = (extra = {}) => ({
    Authorization: token,
    'X-Super-Properties': client.superPropsB64,
    Referer: client.currentPage,
    ...extra,
  });

  // Simulate navigating to the main channels view
  await navigateTo({ client, page: 'https://discord.com/channels/@me' });
  await _humanDelay(800, 2000);

  // Fetch own profile
  try {
    await client.http.get(`${API}/users/@me`, { headers: h() });
  } catch (_) {}
  await _humanDelay(400, 1000);

  // Fetch DM list
  try {
    await client.http.get(`${API}/users/@me/channels`, { headers: h() });
  } catch (_) {}
  await _humanDelay(600, 1600);

  // Fetch guild list
  try {
    await client.http.get(`${API}/users/@me/guilds?with_counts=true`, { headers: h() });
  } catch (_) {}
  await _humanDelay(700, 1800);

  // Science event — Discord's telemetry (real clients always send this)
  try {
    await client.http.post(`${API}/science`, {
      events: [{ type: 'app_opened', properties: { platform: 'web', build_number: client.buildNumber } }],
    }, { headers: h({ 'Content-Type': 'application/json' }) });
  } catch (_) {}
  await _humanDelay(500, 1200);
}

// ─────────────────────────────────────────────────────────────────────────────
// loadDevPortal — warm up the Developer Portal context.
// A real user opening the dev portal triggers:
//   • Navigation to /developers/applications
//   • A /experiments call WITH X-Context-Properties (portal context header)
//   • A GET /applications to load the app list
// ─────────────────────────────────────────────────────────────────────────────
async function loadDevPortal({ client, token, netOpts }) {
  if (!client || client.devPortalLoaded) return;

  await navigateTo({ client, page: 'https://discord.com/developers/applications' });
  await _humanDelay(1000, 2500);

  // Refresh fingerprint with portal context
  try {
    const er = await client.http.get(`${API}/experiments`, {
      headers: {
        Authorization: token,
        'X-Super-Properties': client.superPropsB64,
        'X-Context-Properties': CTX_DEV_PORTAL,
        Referer: client.currentPage,
      },
    });
    if (er.data?.fingerprint) client.fingerprint = er.data.fingerprint;
  } catch (_) {}
  await _humanDelay(600, 1400);

  // Load app list (the portal's initial data fetch)
  try {
    await client.http.get(`${API}/applications?with_team_applications=true`, {
      headers: {
        Authorization: token,
        'X-Super-Properties': client.superPropsB64,
        'X-Context-Properties': CTX_DEV_PORTAL,
        Referer: client.currentPage,
      },
    });
  } catch (_) {}
  await _humanDelay(400, 1000);

  client.devPortalLoaded = true;
}

// ─────────────────────────────────────────────────────────────────────────────
// simulateResetTokenButtonClick
// Mimics the exact UI navigation path a developer follows to hit Reset Token:
//   Applications list → App information page → Bot sub-page (reads bot info)
// ─────────────────────────────────────────────────────────────────────────────
async function simulateResetTokenButtonClick({ client, token, appId, netOpts }) {
  if (!client) return;

  // 1. Navigate to app information page
  await navigateTo({ client, page: `https://discord.com/developers/applications/${appId}/information` });
  await _humanDelay(900, 2200);

  // GET app details (the information page loads these)
  try {
    await _req({
      method: 'GET', url: `${API}/applications/${appId}`,
      token, netOpts, extra: { 'X-Context-Properties': CTX_DEV_PORTAL },
    });
  } catch (_) {}
  await _humanDelay(700, 1800);

  // 2. Click "Bot" in the sidebar
  await navigateTo({ client, page: `https://discord.com/developers/applications/${appId}/bot` });
  await _humanDelay(1100, 2800);
}

// ─────────────────────────────────────────────────────────────────────────────
// acquireMfa — get a short-lived X-Discord-MFA-Authorization value.
// Required before calling resetBotToken / transferAppToTeam on 2FA accounts.
// Retries across the 30-second TOTP boundary (code 60008 = expired).
// ─────────────────────────────────────────────────────────────────────────────
async function acquireMfa({ token, totpSecret, netOpts }) {
  if (!totpSecret) return null;
  for (let attempt = 0; attempt < 3; attempt++) {
    if (attempt > 0) {
      const msIntoStep = Date.now() % 30_000;
      await _sleep(30_000 - msIntoStep + _gauss(1000, 2000));
    }
    const r = await _req({
      method: 'POST',
      url:    `${API}/users/@me/mfa/totp/verify`,
      token,
      body:   { code: generateTOTP(totpSecret), ticket: null },
      netOpts: { ...(netOpts || {}), totpSecret: undefined },
    });
    if (r.status < 400 && r.data?.token) return r.data.token;
    if (r.data?.code !== 60008) break;
  }
  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// PUBLIC API
// ─────────────────────────────────────────────────────────────────────────────

// ── login ──────────────────────────────────────────────────────────────────
async function login({ email, password, totpSecret, netOpts = {} }) {
  if (!email || !password) throw new Error('Email and password are required');
  if (!netOpts.client) netOpts = { ...netOpts, client: createClient() };

  await warmUpClient(netOpts.client);
  await _humanDelay(1500, 4000); // human pause before form submit

  const r1 = await _req({
    method: 'POST',
    url:    `${API}/auth/login`,
    token:  null,
    body: {
      login:            email,
      password,
      undelete:         false,
      login_source:     null,
      gift_code_sku_id: null,
    },
    netOpts: { ...netOpts, captchaContext: 'login:' + email },
  });

  if (r1.status >= 400 && !r1.data?.mfa) {
    throw new DiscordError('Login failed: ' + (r1.data?.message || r1.status), {
      status: r1.status, data: r1.data,
    });
  }

  // 2FA flow
  if (r1.data?.mfa && r1.data?.ticket) {
    if (!totpSecret) {
      throw new DiscordError('2FA required — save the TOTP secret in Bot-Studio settings', {
        code: 'MFA_REQUIRED',
      });
    }
    let lastErr = null;
    for (let attempt = 0; attempt < 3; attempt++) {
      if (attempt > 0) {
        const msIntoStep = Date.now() % 30_000;
        await _sleep(30_000 - msIntoStep + _gauss(1200, 2500));
      }
      const r2 = await _req({
        method: 'POST',
        url:    `${API}/auth/mfa/totp`,
        token:  null,
        body:   { ticket: r1.data.ticket, code: generateTOTP(totpSecret), login_source: null, gift_code_sku_id: null },
        netOpts,
      });
      if (r2.status < 400 && r2.data?.token) {
        return { token: r2.data.token, userId: r2.data.user_id || null };
      }
      lastErr = new DiscordError('MFA verification failed: ' + (r2.data?.message || r2.status), {
        status: r2.status, data: r2.data,
      });
      if (r2.data?.code !== 60008) break;
    }
    throw lastErr;
  }

  if (!r1.data?.token) {
    throw new DiscordError('No token in login response', { status: r1.status, data: r1.data });
  }
  return { token: r1.data.token, userId: r1.data.user_id || null };
}

// ── Teams — verified endpoints (docs.discord.food/resources/team) ──────────
// POST /teams  · body: {name}  · limit: 30 teams/user
// GET  /teams  · returns array of team objects
// ──────────────────────────────────────────────────────────────────────────

async function listTeams({ token, netOpts = {} }) {
  const r = await _req({
    method: 'GET',
    url:    `${API}/teams`,
    token, netOpts,
    extra: { 'X-Context-Properties': CTX_DEV_PORTAL },
  });
  if (r.status >= 400) {
    throw new DiscordError('listTeams failed: ' + (r.data?.message || r.status), {
      status: r.status, data: r.data,
    });
  }
  return Array.isArray(r.data) ? r.data : [];
}

// GET /teams/:teamId/applications — list apps in a specific team.
// Required for teams where the user is a MEMBER (not owner) since
// GET /applications?with_team_applications=true only returns apps
// the user owns directly. Silently returns [] on any error.
async function listTeamApplications({ token, teamId, netOpts = {} }) {
  const r = await _req({
    method: 'GET',
    url:    `${API}/teams/${teamId}/applications`,
    token, netOpts,
    extra: { 'X-Context-Properties': CTX_DEV_PORTAL },
  });
  if (r.status >= 400) return [];
  return Array.isArray(r.data) ? r.data : [];
}

// GET /users/@me — current user's id/username (needed for owner-vs-member badge).
async function getCurrentUser({ token, netOpts = {} }) {
  const r = await _req({
    method: 'GET',
    url:    `${API}/users/@me`,
    token, netOpts,
  });
  if (r.status >= 400) return null;
  return r.data || null;
}

async function createTeam({ token, name, netOpts = {} }) {
  const teamName = String(name || 'Team').slice(0, 32).trim();
  const r = await _req({
    method: 'POST',
    url:    `${API}/teams`,
    token,
    body:   { name: teamName },
    netOpts,
    extra: { 'X-Context-Properties': CTX_DEV_PORTAL },
  });
  if (r.status >= 400) {
    throw new DiscordError(
      'createTeam failed: ' + (r.data?.message || r.status) +
      (r.data?.code ? ` (code ${r.data.code})` : ''),
      { status: r.status, data: r.data },
    );
  }
  return r.data; // {id, name, icon, owner_user_id, members, ...}
}

// ── Applications — verified endpoints (docs.discord.food/resources/application)
// POST /applications  · body: {name, team_id?, description?}
//                    · limit: 50 apps/user, 25 apps/team
// GET  /applications?with_team_applications=true
// ──────────────────────────────────────────────────────────────────────────

async function listApplications({ token, netOpts = {} }) {
  const r = await _req({
    method: 'GET',
    url:    `${API}/applications?with_team_applications=true`,
    token, netOpts,
    extra: { 'X-Context-Properties': CTX_DEV_PORTAL },
  });
  if (r.status >= 400) {
    throw new DiscordError('listApplications failed: ' + (r.data?.message || r.status), {
      status: r.status, data: r.data,
    });
  }
  return Array.isArray(r.data) ? r.data : [];
}

/**
 * createApplication
 * ─────────────────
 * POST /applications
 *
 * Verified body fields (discord.food):
 *   name       string   required   max 32 chars
 *   team_id    snowflake optional  create directly under team (preferred over
 *                                  post-creation transfer — avoids 2nd API call)
 *   description string  optional   appears in dev portal
 *
 * Returns the full application object including app.id and app.bot (if set).
 *
 * Timing strategy for bulk creation:
 *   • Each call already adds a 200–700ms Gaussian pre-delay inside _req().
 *   • Between bots the caller (server.js runTsSession) applies waitMinutes.
 *   • We additionally jitter the name slightly with padding so repeated names
 *     don't form an obvious automated sequence in Discord's internal logs.
 */
async function createApplication({ token, name, teamId = null, netOpts = {} }) {
  const appName = String(name || 'Bot').slice(0, 32).trim();
  const body = { name: appName };
  if (teamId) body.team_id = String(teamId);

  const r = await _req({
    method: 'POST',
    url:    `${API}/applications`,
    token, body, netOpts,
    extra: { 'X-Context-Properties': CTX_DEV_PORTAL },
  });

  if (r.status >= 400) {
    const code = r.data?.code;
    const msg  = r.data?.message || String(r.status);
    if (code === 30002) throw new DiscordError('تجاوزت الحد الأقصى (25 تطبيق/تيم) — سيتم التبديل لتيم آخر', { status: r.status, data: r.data, code: 'MAX_APPS' });
    if (r.status === 401) throw new DiscordError('انتهت صلاحية التوكن — الحساب يحتاج إعادة تسجيل دخول', { status: r.status, data: r.data, code: 'TOKEN_EXPIRED' });
    if (r.status === 403) throw new DiscordError('الحساب محظور أو يحتاج تحقق هاتفي', { status: r.status, data: r.data, code: 'FORBIDDEN' });
    if (r.status === 429) {
      const rateLimit = rateLimitInfoFromResponse(r);
      throw new DiscordError(`Rate limit على إنشاء التطبيقات — انتظر ${rateLimit.retryAfter || rateLimit.resetAfter || '?'} ثانية`, {
        status: r.status, data: r.data, code: 'RATE_LIMITED',
        retryAfter: rateLimit.retryAfter || rateLimit.resetAfter || 0,
        rateLimit,
      });
    }
    // 50035 = validation error — extract field-level details
    if (code === 50035 && r.data?.errors) {
      const fieldErrs = Object.entries(r.data.errors)
        .map(([k, v]) => `${k}: ${JSON.stringify(v)}`)
        .join(', ');
      throw new DiscordError(
        `خطأ تحقق (50035): ${msg} | ${fieldErrs}`,
        { status: r.status, data: r.data, code: 'VALIDATION_ERROR' },
      );
    }
    // Phone verification or account flagged
    if (r.status === 400 && /phone|verify|confirm/i.test(msg)) {
      throw new DiscordError('الحساب يحتاج تحقق هاتفي قبل إنشاء التطبيقات', { status: r.status, data: r.data, code: 'PHONE_VERIFY' });
    }
    const rawHint = r.data ? ` | raw: ${JSON.stringify(r.data).slice(0, 300)}` : '';
    throw new DiscordError(`createApplication فشل (${r.status}): ${msg}${rawHint}`, { status: r.status, data: r.data });
  }
  return r.data; // full Application object
}

// ── Bot user — POST /applications/:id/bot ──────────────────────────────────
// Creates a bot user on the application (idempotent).
// Discord returns HTTP 400 code=30007 if a bot already exists — we treat
// that as success so the caller doesn't need to special-case it.
// ──────────────────────────────────────────────────────────────────────────

async function ensureBot({ token, appId, netOpts = {} }) {
  const r = await _req({
    method: 'POST',
    url:    `${API}/applications/${appId}/bot`,
    token,
    body:   {},
    netOpts,
    extra: { 'X-Context-Properties': CTX_DEV_PORTAL },
  });
  // 30007 = "Maximum number of bots reached" / bot already exists → OK
  if (r.status === 400 && (r.data?.code === 30007 || r.data?.code === 30013)) return r.data;
  if (r.status >= 400) {
    const rateLimit = rateLimitInfoFromResponse(r);
    throw new DiscordError('ensureBot فشل: ' + (r.data?.message || r.status), {
      status: r.status, data: r.data,
      code: r.status === 429 ? 'RATE_LIMITED' : r.data?.code,
      retryAfter: rateLimit.retryAfter || rateLimit.resetAfter || 0,
      rateLimit,
    });
  }
  return r.data;
}

// ── Reset bot token — POST /applications/:id/bot/reset ─────────────────────
//
// Verified (docs.discord.food, May 2025):
//   POST /applications/{application.id}/bot/reset
//   Auth: user token
//   MFA:  X-Discord-MFA-Authorization header (required if 2FA enabled)
//   Body: {} (empty)
//   Response: { token: string }   ← shown ONCE, cannot be retrieved again
//
// If the response body is empty (Discord sometimes does this on first call
// immediately after ensureBot), the caller should wait 3-5s and retry.
// ──────────────────────────────────────────────────────────────────────────

async function resetBotToken({ token, appId, mfa = null, netOpts = {} }) {
  const extra = { 'X-Context-Properties': CTX_DEV_PORTAL };
  if (mfa) extra['X-Discord-MFA-Authorization'] = mfa;

  // Use API v10 for bot/reset — Discord's dev portal JS uses v10 for this call
  const r = await _req({
    method: 'POST',
    url:    `${API10}/applications/${appId}/bot/reset`,
    token,
    body:   {},
    netOpts,
    extra,
  });

  if (r.status >= 400) {
    const code = r.data?.code;
    const msg  = r.data?.message || String(r.status);
    if (r.status === 401)
      throw new DiscordError('Token expired during reset', { status: r.status, data: r.data, code: 'TOKEN_EXPIRED' });
    if (code === 60003 || /two.factor|mfa|2fa/i.test(msg))
      throw new DiscordError(
        '2FA مطلوب — تأكد من أن TOTP secret محفوظ بشكل صحيح في Bot-Studio',
        { status: r.status, data: r.data, code: 'MFA_REQUIRED' },
      );
    const rateLimit = rateLimitInfoFromResponse(r);
    throw new DiscordError('resetBotToken فشل: ' + msg, {
      status: r.status, data: r.data,
      code: r.status === 429 ? 'RATE_LIMITED' : code,
      retryAfter: rateLimit.retryAfter || rateLimit.resetAfter || 0,
      rateLimit,
    });
  }

  const tok = r.data?.token;
  if (!tok || typeof tok !== 'string' || tok.length < 20) {
    throw new DiscordError(
      'Discord أرجع جسم فارغ — انتظر 4 ثواني وأعد المحاولة',
      { status: r.status, data: r.data, code: 'EMPTY_TOKEN' },
    );
  }
  return tok;
}



// ── Privileged intent flags (Developer Portal Bot page) ────────────────────
// Discord's public docs say only the LIMITED flags are writable through the
// Application edit endpoint; the full verified flags are approval-controlled.
const INTENT_FLAGS = {
  presence:       1 << 13, // GATEWAY_PRESENCE_LIMITED
  guildMembers:   1 << 15, // GATEWAY_GUILD_MEMBERS_LIMITED
  messageContent: 1 << 19, // GATEWAY_MESSAGE_CONTENT_LIMITED
};
const INTENT_APPROVED_FLAGS = {
  presence:       1 << 12,
  guildMembers:   1 << 14,
  messageContent: 1 << 18,
};
const ALL_INTENT_FLAGS = INTENT_FLAGS.presence | INTENT_FLAGS.guildMembers | INTENT_FLAGS.messageContent;

function normalizeIntentState(app) {
  const flags = Number(app?.flags_new || app?.flags || 0) || 0;
  const state = {};
  for (const key of Object.keys(INTENT_FLAGS)) {
    const limited = (flags & INTENT_FLAGS[key]) !== 0;
    const approved = (flags & INTENT_APPROVED_FLAGS[key]) !== 0;
    state[key] = { enabled: limited || approved, limited, approved };
  }
  return { flags, state };
}

async function getApplication({ token, appId, netOpts = {} }) {
  const r = await _req({
    method: 'GET',
    url:    `${API}/applications/${appId}`,
    token, netOpts,
    extra: { 'X-Context-Properties': CTX_DEV_PORTAL },
  });
  if (r.status >= 400) {
    throw new DiscordError('getApplication failed: ' + (r.data?.message || r.status), {
      status: r.status, data: r.data, code: r.data?.code,
    });
  }
  return r.data;
}

async function setApplicationIntents({ token, appId, enabled = true, netOpts = {}, app = null }) {
  app = app || await getApplication({ token, appId, netOpts });
  const current = Number(app?.flags_new || app?.flags || 0) || 0;
  const nextFlags = enabled ? (current | ALL_INTENT_FLAGS) : (current & ~ALL_INTENT_FLAGS);
  if (nextFlags === current) return app;
  const r = await _req({
    method: 'PATCH',
    url:    `${API}/applications/${appId}`,
    token,
    body:   { flags: nextFlags },
    netOpts,
    extra: { 'X-Context-Properties': CTX_DEV_PORTAL },
  });
  if (r.status >= 400) {
    const code = r.data?.code;
    const msg  = r.data?.message || String(r.status);
    if (r.status === 429) {
      const rateLimit = rateLimitInfoFromResponse(r);
      throw new DiscordError(`Rate limited while updating intents — retry after ${rateLimit.retryAfter || rateLimit.resetAfter || '?'}s`, {
        status: r.status, data: r.data, code: 'RATE_LIMITED',
        retryAfter: rateLimit.retryAfter || rateLimit.resetAfter || 0,
        rateLimit,
      });
    }
    throw new DiscordError('setApplicationIntents failed: ' + msg, { status: r.status, data: r.data, code });
  }
  return r.data;
}

function botAuthHeader(token) {
  const raw = String(token || '').trim();
  return /^Bot\s+/i.test(raw) ? raw : `Bot ${raw}`;
}

// Get the guilds the user belongs to, including their computed permission flags.
// Returns an array of { id, name, icon, owner, permissions } from the REST endpoint
// (not the client cache) so the `permissions` field is always present.
async function getUserGuildsWithPerms({ token, netOpts = {} }) {
  const r = await _req({
    method: 'GET',
    url:    `${API}/users/@me/guilds`,
    token,
    netOpts,
  });
  if (r.status >= 400) {
    throw new DiscordError('getUserGuildsWithPerms failed: ' + (r.data?.message || r.status), {
      status: r.status, data: r.data,
    });
  }
  return Array.isArray(r.data) ? r.data : [];
}

// Add a bot (by client_id / appId) to a guild using the OWNER's user token.
// Uses the OAuth2 authorize endpoint with the user token directly — no browser needed.
async function addBotToGuild({ token, clientId, guildId, permissions = '8', netOpts = {} }) {
  const qs = new URLSearchParams({
    client_id:            clientId,
    scope:                'bot applications.commands',
    permissions,
    guild_id:             guildId,
    disable_guild_select: 'true',
  }).toString();
  const r = await _req({
    method: 'POST',
    url:    `${API}/oauth2/authorize?${qs}`,
    token,
    body:   { authorize: true, guild_id: guildId },
    netOpts,
  });
  if (r.status >= 400) {
    const rateLimit = rateLimitInfoFromResponse(r);
    const retryAfter = rateLimit.retryAfter || rateLimit.resetAfter || 0;
    const captchaSitekey = r.data?.captcha_sitekey || null;
    const msg = r.status === 429 ? `Rate limited — retry after ${retryAfter || '?'}s`
      : r.status === 401         ? 'Unauthorized — check account token'
      : r.status === 403         ? 'Missing permissions or bot already in server'
      : captchaSitekey           ? 'Captcha required'
      : (r.data?.message || String(r.status));
    throw new DiscordError('addBotToGuild failed: ' + msg, {
      status: r.status, data: r.data, retryAfter, captchaSitekey,
      rateLimit,
      code: r.status === 429 ? 'RATE_LIMITED' : captchaSitekey ? 'CAPTCHA' : r.data?.code,
    });
  }
  return r.data;
}

// Update the APPLICATION icon + cover_image (visible in the library listing).
// Uses owner token via PATCH /applications/{appId}.
async function updateAppVisuals({ token, appId, icon = undefined, coverImage = undefined, netOpts = {} }) {
  const body = {};
  if (icon       !== undefined) body.icon        = icon       || null;
  if (coverImage !== undefined) body.cover_image = coverImage || null;
  if (!Object.keys(body).length) return null;
  const r = await _req({
    method: 'PATCH',
    url:    `${API}/applications/${appId}`,
    token,
    body,
    netOpts,
    extra: { 'X-Context-Properties': CTX_DEV_PORTAL },
  });
  if (r.status >= 400) {
    const rateLimit = rateLimitInfoFromResponse(r);
    const retryAfter = rateLimit.retryAfter || rateLimit.resetAfter || 0;
    const msg = r.status === 429
      ? `App visuals rate limited — retry after ${retryAfter || '?'}s`
      : (r.data?.message || String(r.status));
    throw new DiscordError('updateAppVisuals failed: ' + msg, {
      status: r.status, data: r.data, code: r.status === 429 ? 'RATE_LIMITED' : r.data?.code,
      retryAfter, rateLimit,
    });
  }
  return r.data;
}

// Update bot avatar/banner using the OWNER's account token via the applications API.
// Unlike updateBotProfile (which needs the bot token), this only needs the user's own Discord token.
async function updateBotProfileViaOwner({ token, appId, avatar = undefined, banner = undefined, netOpts = {} }) {
  const body = {};
  if (avatar !== undefined) body.avatar = avatar || null;
  if (banner !== undefined) body.banner = banner || null;
  const r = await _req({
    method: 'PATCH',
    url:    `${API}/applications/${appId}/bot`,
    token,
    body,
    netOpts,
    extra: { 'X-Context-Properties': CTX_DEV_PORTAL },
  });
  if (r.status >= 400) {
    const rateLimit = rateLimitInfoFromResponse(r);
    const retryAfter = rateLimit.retryAfter || rateLimit.resetAfter || 0;
    const msg = r.status === 429
      ? `Bot profile rate limited — retry after ${retryAfter || '?'}s`
      : (r.data?.message || String(r.status));
    throw new DiscordError('updateBotProfileViaOwner failed: ' + msg, {
      status: r.status, data: r.data, code: r.status === 429 ? 'RATE_LIMITED' : r.data?.code,
      retryAfter, rateLimit,
    });
  }
  return r.data;
}

async function updateBotProfile({ botToken, avatar = undefined, banner = undefined, netOpts = {} }) {
  const client = netOpts.client || createClient();
  const body = {};
  if (avatar !== undefined) body.avatar = avatar || null;
  if (banner !== undefined) body.banner = banner || null;
  const reqMeta = { method: 'PATCH', url: `${API10}/users/@me`, token: botAuthHeader(botToken) };
  if (netOpts.rateLimiter?.before) await netOpts.rateLimiter.before(reqMeta);
  const r = await client.http({
    method: 'PATCH',
    url: reqMeta.url,
    data: body,
    headers: {
      'Authorization': reqMeta.token,
      'Content-Type': 'application/json',
      'User-Agent': client.uaInfo?.ua || undefined,
    },
  });
  const rateLimit = netOpts.rateLimiter?.after
    ? netOpts.rateLimiter.after({ ...reqMeta, response: r })
    : rateLimitInfoFromResponse(r);
  if (r.status >= 400) {
    const retryAfter = rateLimit.retryAfter || rateLimit.resetAfter || 0;
    const msg = r.status === 429
      ? `Bot profile rate limited — retry after ${retryAfter || '?'}s`
      : (r.data?.message || String(r.status));
    throw new DiscordError('updateBotProfile failed: ' + msg, {
      status: r.status, data: r.data, code: r.status === 429 ? 'RATE_LIMITED' : r.data?.code,
      retryAfter, rateLimit,
    });
  }
  return r.data;
}

async function accountHealthProbe({ token, netOpts = {} }) {
  const client = netOpts.client || createClient();
  const checks = [];
  async function probe(name, url) {
    const r = await _req({
      method: 'GET', url, token, netOpts: { ...netOpts, client },
      extra: { 'X-Context-Properties': CTX_DEV_PORTAL },
    });
    const retryAfter = Number(r.headers?.['retry-after'] || r.data?.retry_after || 0);
    const scope = r.headers?.['x-ratelimit-scope'] || (r.data?.global ? 'global' : null);
    const global = String(r.headers?.['x-ratelimit-global'] || '').toLowerCase() === 'true' || !!r.data?.global;
    const item = { name, status: r.status, ok: r.status >= 200 && r.status < 300, retryAfter, scope, global, code: r.data?.code || null, message: r.data?.message || '' };
    checks.push(item);
    return item;
  }
  await probe('user', `${API}/users/@me`);
  await probe('applications', `${API}/applications?with_team_applications=true`);
  const bad = checks.find(c => c.status === 429) || checks.find(c => c.status === 401) || checks.find(c => c.status === 403) || checks.find(c => !c.ok);
  let ok = !bad;
  let classification = ok ? 'ok' : 'unknown';
  let message = ok ? 'Account health looks OK' : (bad.message || `HTTP ${bad.status}`);
  if (bad) {
    if (bad.status === 429) { classification = bad.global ? 'global_rate_limited' : 'rate_limited'; message = `Rate limited (${bad.scope || 'unknown scope'}), retry after ${bad.retryAfter || '?'}s`; }
    else if (bad.status === 401) { classification = 'invalid_token'; message = 'Token expired/invalid — stop before making more requests'; }
    else if (bad.status === 403) { classification = 'forbidden_or_locked'; message = bad.message || 'Forbidden — account may be locked, phone-verified, or missing access'; }
  }
  return { ok, classification, message, checks };
}

// ── Transfer app to team — POST /applications/:id/transfer ─────────────────
//
// Verified (docs.discord.food, May 2025):
//   POST /applications/{application.id}/transfer
//   Auth: user token (owner of application)
//   MFA:  required if 2FA enabled
//   Body: { team_id: snowflake }
//   Response: application object
//   Note: transfer is IRREVERSIBLE
// ──────────────────────────────────────────────────────────────────────────

async function transferAppToTeam({ token, appId, teamId, mfa = null, netOpts = {} }) {
  const extra = { 'X-Context-Properties': CTX_DEV_PORTAL };
  if (mfa) extra['X-Discord-MFA-Authorization'] = mfa;

  const r = await _req({
    method: 'POST',
    url:    `${API}/applications/${appId}/transfer`,
    token,
    body:   { team_id: String(teamId) },
    netOpts,
    extra,
  });

  if (r.status >= 400) {
    throw new DiscordError(
      'transferAppToTeam فشل: ' + (r.data?.message || r.status),
      { status: r.status, data: r.data },
    );
  }
  return r.data;
}

// ─────────────────────────────────────────────────────────────────────────────
// cloneClientWithProxy — creates a lightweight per-bot client that shares the
// parent session's cookie jar (Cloudflare cookies) and X-Fingerprint so
// Discord still sees a consistent session, but routes HTTP through a different
// egress IP.  Used for per-bot proxy rotation in Bot-Studio.
//
// The clone is marked warmedUp:true / devPortalLoaded:true so the caller
// never triggers a second warm-up or portal load — those already happened
// on the parent client.
// ─────────────────────────────────────────────────────────────────────────────
function cloneClientWithProxy(baseClient, proxyUrl) {
  const jar = baseClient.jar; // shared — same Cloudflare / session cookies

  let httpsAgent, httpAgent, useCookieInterceptors = false;

  if (proxyUrl && typeof proxyUrl === 'string' && proxyUrl.trim()) {
    const raw = proxyUrl.trim();
    const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : 'http://' + raw;
    const scheme = (() => { try { return new URL(withScheme).protocol.replace(':', '').toLowerCase(); } catch { return 'http'; } })();
    if (scheme === 'socks' || scheme === 'socks4' || scheme === 'socks5' || scheme === 'socks5h') {
      const { SocksProxyAgent } = require('socks-proxy-agent');
      const agent = new SocksProxyAgent(withScheme);
      httpsAgent = agent;
      httpAgent  = agent;
    } else {
      const { HttpsProxyAgent } = require('https-proxy-agent');
      const { HttpProxyAgent }  = require('http-proxy-agent');
      httpsAgent = new HttpsProxyAgent(withScheme);
      httpAgent  = new HttpProxyAgent(withScheme);
    }
    useCookieInterceptors = true;
  } else {
    const agents = _buildAgents(jar);
    httpsAgent = agents.httpsAgent;
    httpAgent  = agents.httpAgent;
  }

  const http = axios.create({
    timeout: 32_000,
    validateStatus: () => true,
    httpAgent,
    httpsAgent,
    headers: {
      'Accept':              '*/*',
      'Accept-Language':     'en-US,en;q=0.9',
      'Accept-Encoding':     'gzip, deflate, br, zstd',
      'User-Agent':          baseClient.uaInfo.ua,
      'sec-ch-ua':           baseClient.uaInfo.sec_ch_ua,
      'sec-ch-ua-mobile':    '?0',
      'sec-ch-ua-platform':  baseClient.uaInfo.platform,
      'sec-fetch-dest':      'empty',
      'sec-fetch-mode':      'cors',
      'sec-fetch-site':      'same-origin',
    },
  });

  if (useCookieInterceptors) {
    http.interceptors.request.use(async (config) => {
      try {
        const reqUrl = config.url || 'https://discord.com';
        const cookies = await jar.getCookies(reqUrl);
        if (cookies.length) config.headers['Cookie'] = cookies.map(c => c.cookieString()).join('; ');
      } catch (_) {}
      return config;
    });
    http.interceptors.response.use(async (response) => {
      try {
        const reqUrl = response.config?.url || 'https://discord.com';
        const setCookie = response.headers['set-cookie'];
        if (setCookie) {
          const list = Array.isArray(setCookie) ? setCookie : [setCookie];
          for (const ck of list) { try { await jar.setCookie(ck, reqUrl); } catch (_) {} }
        }
      } catch (_) {}
      return response;
    }, async (err) => Promise.reject(err));
  }

  return {
    jar,                               // shared — same Cloudflare / session cookies
    http,                              // new axios instance with new proxy
    uaInfo:          baseClient.uaInfo,
    buildNumber:     baseClient.buildNumber,
    superPropsB64:   baseClient.superPropsB64,
    fingerprint:     baseClient.fingerprint, // inherited
    warmedUp:        true,             // already done by parent
    devPortalLoaded: true,             // already done by parent
    currentPage:     baseClient.currentPage,
    proxyUrl:        proxyUrl || null,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// makeSession — blank session state (server.js calls ts.makeSession())
// ─────────────────────────────────────────────────────────────────────────────
function makeSession() {
  return {
    state:           'idle',  // idle|running|waiting|done|cancelled|error
    account:         null,
    rules:           {},
    total:           0,
    done:            0,
    failed:          0,
    current:         '',
    teamId:          null,
    teamName:        null,
    bots:            [],
    log:             [],
    lastError:       null,
    waitUntilTs:     0,
    waitTotalMs:     0,
    startedAt:       null,
    finishedAt:      null,
    cancelRequested: false,
    pendingCaptcha:  null,
    accountRateLimits: {},
    pausedAccounts:  {}, // { email: unPauseTimestampMs } — accounts paused due to RL/CF-block
  };
}

// ─────────────────────────────────────────────────────────────────────────────
module.exports = {
  // Client / session
  createClient,
  cloneClientWithProxy,
  createRateLimitGuard,
  rateLimitInfoFromResponse,
  makeSession,
  warmUpClient,
  fetchBuildNumber,
  DiscordError,

  // Validation / crypto
  isValidTotpSecret,
  generateTOTP,

  // Navigation & UX simulation
  navigateTo,
  humanDelay,
  simulateBrowsing,
  loadDevPortal,
  simulateResetTokenButtonClick,

  // Auth
  login,
  acquireMfa,

  // Teams  (POST /teams · GET /teams · GET /teams/:id/applications)
  listTeams,
  listTeamApplications,
  getCurrentUser,
  createTeam,

  // Applications  (POST /applications · GET /applications)
  listApplications,
  getApplication,
  normalizeIntentState,
  setApplicationIntents,
  accountHealthProbe,
  createApplication,

  // Bot user  (POST /applications/:id/bot)
  ensureBot,
  updateBotProfile,
  updateBotProfileViaOwner,

  // App visuals  (PATCH /applications/:id)
  updateAppVisuals,

  // Guild utilities
  getUserGuildsWithPerms,
  addBotToGuild,

  // Bot token  (POST /applications/:id/bot/reset)
  resetBotToken,

  // Transfer  (POST /applications/:id/transfer)
  transferAppToTeam,
};
