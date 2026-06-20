'use strict';

/**
 * tlsProxyAgent.js — Chrome 133 TLS fingerprint preserved through proxy tunnels
 *
 * Problem: Standard HttpsProxyAgent / SocksProxyAgent create the TLS socket
 *   internally with Node defaults — our custom ciphers/sigalgs/curves are lost.
 *
 * Solution: Build the tunnel manually (HTTP CONNECT or SOCKS) then call
 *   tls.connect() ourselves with the exact Chrome 133 options on the raw socket.
 *
 * Result: Discord's TLS inspector sees the same ClientHello fingerprint whether
 *   a proxy is used or not.
 */

const net   = require('net');
const tls   = require('tls');
const https = require('https');

// ─── Chrome 133 TLS options (mirrors trueStudio.js _buildAgents) ─────────────
const CHROME_133_TLS = {
  ciphers: [
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
  ].join(':'),
  sigalgs: [
    'ecdsa_secp256r1_sha256',
    'rsa_pss_rsae_sha256',
    'rsa_pkcs1_sha256',
    'ecdsa_secp384r1_sha384',
    'rsa_pss_rsae_sha384',
    'rsa_pkcs1_sha384',
    'rsa_pss_rsae_sha512',
    'rsa_pkcs1_sha512',
    'rsa_pkcs1_sha1',
  ].join(':'),
  ecdhCurve:        'X25519:prime256v1:secp384r1',
  honorCipherOrder: true,
  minVersion:       'TLSv1.2',
  maxVersion:       'TLSv1.3',
  ALPNProtocols:    ['http/1.1'],
  rejectUnauthorized: false,
};

// ─── HTTP/HTTPS proxy → CONNECT tunnel → Chrome 133 TLS ──────────────────────
class TlsFingerprintHttpProxyAgent extends https.Agent {
  constructor(proxyUrl) {
    super({ keepAlive: true, keepAliveMsecs: 45_000 });
    this._proxy = new URL(proxyUrl);
  }

  createConnection(options, callback) {
    const proxyHost  = this._proxy.hostname;
    const proxyPort  = parseInt(this._proxy.port) || 80;
    const targetHost = options.host || options.hostname || 'discord.com';
    const targetPort = options.port || 443;

    const socket = net.connect(proxyPort, proxyHost, () => {
      let connectReq =
        `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\n` +
        `Host: ${targetHost}:${targetPort}\r\n`;

      if (this._proxy.username) {
        const raw = `${decodeURIComponent(this._proxy.username)}:${decodeURIComponent(this._proxy.password || '')}`;
        connectReq += `Proxy-Authorization: Basic ${Buffer.from(raw).toString('base64')}\r\n`;
      }
      connectReq += '\r\n';
      socket.write(connectReq);

      let buf = Buffer.alloc(0);
      const onData = (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        const str = buf.toString('binary');
        if (str.includes('\r\n\r\n')) {
          socket.removeListener('data', onData);
          if (/^HTTP\/1\.[01] 200/i.test(str)) {
            const tlsSock = tls.connect({
              ...CHROME_133_TLS,
              socket,
              servername: targetHost,
            });
            tlsSock.once('secureConnect', () => callback(null, tlsSock));
            tlsSock.once('error', callback);
          } else {
            socket.destroy();
            callback(new Error('Proxy CONNECT failed: ' + str.split('\r\n')[0]));
          }
        }
      };
      socket.on('data', onData);
    });

    socket.once('error', callback);
  }
}

// ─── SOCKS proxy → socket → Chrome 133 TLS ───────────────────────────────────
class TlsFingerprintSocksProxyAgent extends https.Agent {
  constructor(proxyUrl) {
    super({ keepAlive: true, keepAliveMsecs: 45_000 });
    const u      = new URL(proxyUrl);
    const scheme = u.protocol.replace(':', '').toLowerCase();
    this._proxy  = {
      host:     u.hostname,
      port:     parseInt(u.port) || 1080,
      type:     scheme === 'socks4' ? 4 : 5,
      userId:   u.username ? decodeURIComponent(u.username)         : undefined,
      password: u.password ? decodeURIComponent(u.password)         : undefined,
    };
  }

  createConnection(options, callback) {
    const targetHost = options.host || options.hostname || 'discord.com';
    const targetPort = options.port || 443;
    const { SocksClient } = require('socks');

    SocksClient.createConnection({
      proxy:       this._proxy,
      command:     'connect',
      destination: { host: targetHost, port: targetPort },
    }).then(({ socket }) => {
      const tlsSock = tls.connect({
        ...CHROME_133_TLS,
        socket,
        servername: targetHost,
      });
      tlsSock.once('secureConnect', () => callback(null, tlsSock));
      tlsSock.once('error', callback);
    }).catch(callback);
  }
}

// ─── Factory ─────────────────────────────────────────────────────────────────
function buildTlsFingerprintAgent(proxyUrl) {
  if (!proxyUrl || typeof proxyUrl !== 'string' || !proxyUrl.trim()) return null;

  const raw        = proxyUrl.trim();
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : 'http://' + raw;
  const scheme     = (() => {
    try { return new URL(withScheme).protocol.replace(':', '').toLowerCase(); }
    catch { return 'http'; }
  })();

  if (scheme === 'socks' || scheme === 'socks4' || scheme === 'socks5' || scheme === 'socks5h') {
    return new TlsFingerprintSocksProxyAgent(withScheme);
  }
  return new TlsFingerprintHttpProxyAgent(withScheme);
}

module.exports = { buildTlsFingerprintAgent };
