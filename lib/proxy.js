// lib/proxy.js
// ───────────────────────────────────────────────────────────────────
// Build the agent object that discord.js-selfbot-v13 expects for a
// given proxy URL. Supports http://, https://, socks://, socks4://,
// socks5:// (with optional user:pass@host:port).
//
// discord.js-selfbot-v13 expects the SAME agent object for both:
//   REST  : client.options.http.agent → agent instance
//   WS    : client.options.ws.agent   → agent instance (NOT {httpAgent, httpsAgent})
//
// Returns { agent } where agent is an HttpsProxyAgent or SocksProxyAgent.
// Call buildProxyAgents() once per Client — never share agent instances between clients.
// Throws Error('Unsupported proxy scheme: …') for invalid input.
// ───────────────────────────────────────────────────────────────────

const { HttpsProxyAgent } = require('https-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');

function normalize(url) {
  if (!url || typeof url !== 'string') return null;
  const v = url.trim();
  if (!v) return null;
  // Be forgiving: bare "host:port" → assume http
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) return 'http://' + v;
  return v;
}

/**
 * Build a proxy agent suitable for both REST and WebSocket in discord.js-selfbot-v13.
 * Returns { agent } or null if no proxy URL is provided.
 * Always creates a NEW agent instance — never share between clients.
 */
function buildProxyAgents(rawUrl) {
  const url = normalize(rawUrl);
  if (!url) return null;

  let parsed;
  try { parsed = new URL(url); } catch (e) {
    throw new Error('Invalid proxy URL: ' + e.message);
  }

  const scheme = parsed.protocol.toLowerCase().replace(':', '');

  if (scheme === 'socks' || scheme === 'socks4' || scheme === 'socks5' || scheme === 'socks5h') {
    const agent = new SocksProxyAgent(url);
    return { agent };
  }

  if (scheme === 'http' || scheme === 'https') {
    const agent = new HttpsProxyAgent(url);
    return { agent };
  }

  throw new Error('Unsupported proxy scheme: ' + scheme);
}

// Quick reachability test. Hits a small endpoint THROUGH the proxy and
// returns the egress IP so the user gets immediate confirmation.
// Times out at 8s — Discord will fail well before that anyway.
async function testProxy(rawUrl) {
  const agents = buildProxyAgents(rawUrl);
  if (!agents) throw new Error('Empty proxy URL');
  const https = require('https');
  return await new Promise((resolve, reject) => {
    const to = setTimeout(() => {
      req.destroy(new Error('Proxy timeout (8s) — host unreachable or wrong port'));
    }, 8000);
    const req = https.get('https://api.ipify.org?format=json', { agent: agents.agent }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c.toString(); });
      res.on('end', () => {
        clearTimeout(to);
        if (res.statusCode !== 200) return reject(new Error('Proxy returned HTTP ' + res.statusCode));
        try {
          const j = JSON.parse(body);
          resolve({ ok: true, ip: j.ip || null });
        } catch (e) { resolve({ ok: true, ip: null }); }
      });
    });
    req.on('error', (e) => { clearTimeout(to); reject(e); });
  });
}

// Mask credentials for safe display in the UI / logs.
function maskProxy(rawUrl) {
  const url = normalize(rawUrl);
  if (!url) return '';
  try {
    const u = new URL(url);
    if (u.username) u.username = '***';
    if (u.password) u.password = '***';
    return u.toString().replace(/\/$/, '');
  } catch (e) { return '***'; }
}

module.exports = { buildProxyAgents, testProxy, maskProxy, normalize };
