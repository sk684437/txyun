import { createHash } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import net from 'node:net';
import tls from 'node:tls';

/**
 * EdgeOne Makers / Pages —— Trojan over WebSocket 服务端
 *
 * 环境变量（在 Makers 控制台配置）：
 *   UUID        节点密码（不配则用 DEFAULT_UUID）
 *   PROXYIP     上游出口，支持 socks5:// http:// https:// 或 host:port
 *   DOMAIN      对外访问域名（强烈建议配置！见下方说明）
 *
 * 关于 DOMAIN：
 *   EdgeOne 的函数运行在内部后端（*.qcloudteo.com）上，request.url / Host 头
 *   可能拿到的是内部域名而不是你的公开域名。若不配置 DOMAIN，函数会用请求头
 *   推断；推断失败时生成的节点地址会指向内部域名，客户端将无法连接。
 *   所以请务必设置 DOMAIN=你的域名（如 tx.he110.dpdns.org）。
 *   部署后访问 /{UUID}/debug 可以看到实际解析到的域名和全部请求头，
 *   访问 /{UUID}/diag 可以自检出站连通性（DNS + TCP 探测），
 *   用 WebSocket 连 /{UUID}/wstest 可自检 WS 通道是否打通（会回一条 trojan-hello）。
 */

const DEFAULT_UUID = 'e904d6c0-01fd-4f2a-8874-eb92acfb720a';
const DEFAULT_PROXY_IP = 'ProxyIP.CA.CMLiussss.net';
const WS_PATH = '/ws?ed=2560';

let yourUUID = DEFAULT_UUID;
let proxyIP = DEFAULT_PROXY_IP;
let forcedHost = '';
let runtimeProxyIP = '';

const speedTestDomains = [
  'speedtest.net',
  'fast.com',
  'speedtest.cn',
  'speed.cloudflare.com',
  'ovo.speedtestcustom.com',
];

const INTERNAL_HOST_MARKERS = ['qcloudteo.com', 'pages-scf'];

function log(...args) {
  console.log('[trojan]', ...args);
}

function applyEnv(env = {}) {
  const envProxyIP = env.PROXYIP || env.proxyip || env.proxyIP;
  if (envProxyIP) {
    const servers = String(envProxyIP).split(',').map((s) => s.trim()).filter(Boolean);
    if (servers.length) proxyIP = servers[0];
  }

  const envUUID = env.UUID || env.uuid;
  if (envUUID) yourUUID = String(envUUID).trim();

  const envHost = env.DOMAIN || env.domain || env.PUBLIC_HOST || env.public_host;
  if (envHost) forcedHost = String(envHost).trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '');

  // 运行时通过 /proxyip= 设置过就不再被环境变量覆盖
  if (runtimeProxyIP) proxyIP = runtimeProxyIP;
}

function toBuffer(message) {
  if (Buffer.isBuffer(message)) return message;
  if (message instanceof ArrayBuffer) return Buffer.from(message);
  if (ArrayBuffer.isView(message)) {
    return Buffer.from(message.buffer, message.byteOffset, message.byteLength);
  }
  if (typeof message === 'string') return Buffer.from(message);
  if (message && typeof message === 'object' && 'data' in message) return toBuffer(message.data);
  return Buffer.from(message || []);
}

function base64ToBuffer(b64Str) {
  if (!b64Str) return null;
  try {
    return Buffer.from(b64Str.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  } catch {
    return null;
  }
}

function isInternalHost(host) {
  if (!host) return true;
  return INTERNAL_HOST_MARKERS.some((m) => host === m || host.endsWith(`.${m}`));
}

/** 解析对外访问域名：环境变量 > 请求头 > request.url */
function getPublicHost(request) {
  if (forcedHost) return forcedHost;

  const headers = request.headers;
  const candidates = [
    // EdgeOne 会把公开访问域名放在 eo-pages-host 里
    headers.get('eo-pages-host'),
    headers.get('x-forwarded-host'),
    headers.get('x-original-host'),
    headers.get('x-real-host'),
    headers.get('host'),
  ];

  for (const raw of candidates) {
    if (!raw) continue;
    const host = raw.split(',')[0].trim().replace(/:\d+$/, '');
    if (host && !isInternalHost(host)) return host;
  }

  try {
    const host = new URL(request.url).hostname;
    if (host && !isInternalHost(host)) return host;
  } catch {
    // ignore
  }

  log('WARN: 无法推断公开域名，请配置环境变量 DOMAIN。');
  return '';
}

function buildTrojanLink(host, uuid) {
  const query = [
    'security=tls',
    `sni=${host}`,
    'fp=firefox',
    'allowInsecure=0',
    'type=ws',
    `host=${host}`,
    `path=${encodeURIComponent(WS_PATH)}`,
  ].join('&');
  return `trojan://${uuid}@${host}:443?${query}#${host}-trojan`;
}

/* ------------------------------- 出站连接 ------------------------------- */

function parseProxyAddress(serverStr) {
  if (!serverStr) return null;
  const str = serverStr.trim();

  if (str.startsWith('socks://') || str.startsWith('socks5://')) {
    try {
      const url = new URL(str.replace(/^socks:\/\//, 'socks5://'));
      return {
        type: 'socks5',
        host: url.hostname,
        port: parseInt(url.port, 10) || 1080,
        username: url.username ? decodeURIComponent(url.username) : '',
        password: url.password ? decodeURIComponent(url.password) : '',
      };
    } catch {
      return null;
    }
  }

  if (str.startsWith('http://') || str.startsWith('https://')) {
    try {
      const url = new URL(str);
      return {
        type: url.protocol === 'https:' ? 'https' : 'http',
        host: url.hostname,
        port: parseInt(url.port, 10) || (url.protocol === 'https:' ? 443 : 80),
        username: url.username ? decodeURIComponent(url.username) : '',
        password: url.password ? decodeURIComponent(url.password) : '',
      };
    } catch {
      return null;
    }
  }

  if (str.startsWith('[')) {
    const close = str.indexOf(']');
    if (close > 0) {
      const host = str.substring(1, close);
      const rest = str.substring(close + 1);
      if (rest.startsWith(':')) {
        const port = parseInt(rest.substring(1), 10);
        if (!Number.isNaN(port) && port > 0 && port <= 65535) return { type: 'direct', host, port };
      }
      return { type: 'direct', host, port: 443 };
    }
  }

  const idx = str.lastIndexOf(':');
  if (idx > 0) {
    const host = str.substring(0, idx);
    const port = parseInt(str.substring(idx + 1), 10);
    if (!Number.isNaN(port) && port > 0 && port <= 65535) return { type: 'direct', host, port };
  }

  return { type: 'direct', host: str, port: 443 };
}

function isSpeedTestSite(hostname) {
  return speedTestDomains.some((d) => hostname === d || hostname.endsWith(`.${d}`));
}

function sha224(text) {
  return createHash('sha224').update(text).digest('hex');
}

const PASSWORD_HEX_LEN = 56;

/**
 * 解析 Trojan 请求头（Trojan 的请求体是去掉 VER/RSV 的 SOCKS5 请求）。
 * 返回 { need } 表示数据还不够；返回 { error } 表示格式错误；返回 { result } 表示成功。
 */
function parseTrojanHeader(buffer, passwordPlainText) {
  const minLen = PASSWORD_HEX_LEN + 2;
  if (buffer.byteLength < minLen) return { need: minLen };

  if (buffer[PASSWORD_HEX_LEN] !== 0x0d || buffer[PASSWORD_HEX_LEN + 1] !== 0x0a) {
    return { error: 'invalid header format (missing CRLF after password)' };
  }

  const password = buffer.subarray(0, PASSWORD_HEX_LEN).toString();
  if (password !== sha224(passwordPlainText)) return { error: 'invalid password' };

  const rest = buffer.subarray(PASSWORD_HEX_LEN + 2);
  if (rest.byteLength < 2) return { need: minLen + 2 };

  const cmd = rest[0];
  if (cmd !== 1) return { error: 'unsupported command, only TCP is allowed' };

  const atype = rest[1];
  let addressIndex = 2;
  let addressLength = 0;

  if (atype === 1) {
    addressLength = 4;
  } else if (atype === 3) {
    if (rest.byteLength < 3) return { need: minLen + 3 };
    addressLength = rest[2];
    addressIndex = 3;
  } else if (atype === 4) {
    addressLength = 16;
  } else {
    return { error: `invalid addressType is ${atype}` };
  }

  const portIndex = addressIndex + addressLength;
  const needForPort = minLen + portIndex + 2;
  if (buffer.byteLength < needForPort) return { need: needForPort };

  let hostname = '';
  if (atype === 1) {
    hostname = Array.from(rest.subarray(2, 6)).join('.');
  } else if (atype === 3) {
    hostname = rest.subarray(3, 3 + addressLength).toString();
  } else {
    const parts = [];
    for (let i = 0; i < 8; i += 1) parts.push(rest.readUInt16BE(2 + i * 2).toString(16));
    hostname = parts.join(':');
  }

  if (!hostname) return { error: `address is empty, addressType is ${atype}` };

  const port = rest.readUInt16BE(portIndex);

  // 端口之后允许跟一个 CRLF，再往后才是真正的业务数据
  let payloadStart = minLen + portIndex + 2;
  if (buffer.byteLength >= payloadStart + 2 && buffer[payloadStart] === 0x0d && buffer[payloadStart + 1] === 0x0a) {
    payloadStart += 2;
  }

  return {
    result: {
      addressType: atype,
      port,
      hostname,
      rawClientData: buffer.subarray(payloadStart),
    },
  };
}

function connectSocket(host, port, secure = false) {
  return new Promise((resolve, reject) => {
    const socket = secure ? tls.connect({ host, port, servername: host }) : net.connect({ host, port });

    const cleanup = () => {
      socket.off('connect', onConnect);
      socket.off('secureConnect', onConnect);
      socket.off('error', onError);
    };
    const onConnect = () => {
      cleanup();
      resolve(socket);
    };
    const onError = (error) => {
      cleanup();
      socket.destroy();
      reject(error);
    };

    socket.once(secure ? 'secureConnect' : 'connect', onConnect);
    socket.once('error', onError);
    socket.setNoDelay(true);
  });
}

function readOnce(socket) {
  return new Promise((resolve, reject) => {
    const onData = (chunk) => cleanup(resolve, chunk);
    const onError = (error) => cleanup(reject, error);
    const onClose = () => cleanup(reject, new Error('socket closed'));
    const cleanup = (done, value) => {
      socket.off('data', onData);
      socket.off('error', onError);
      socket.off('close', onClose);
      done(value);
    };

    socket.once('data', onData);
    socket.once('error', onError);
    socket.once('close', onClose);
  });
}

async function connect2Socks5(proxyConfig, targetHost, targetPort, initialData) {
  const { host, port, username, password } = proxyConfig;
  const socket = await connectSocket(host, port);

  const authMethods = username && password
    ? Buffer.from([0x05, 0x02, 0x00, 0x02])
    : Buffer.from([0x05, 0x01, 0x00]);

  socket.write(authMethods);
  const methodResponse = await readOnce(socket);
  if (methodResponse.byteLength < 2) {
    socket.destroy();
    throw new Error('S5 method selection failed');
  }

  const selectedMethod = methodResponse[1];
  if (selectedMethod === 0x02) {
    if (!username || !password) {
      socket.destroy();
      throw new Error('S5 requires authentication');
    }
    const userBytes = Buffer.from(username);
    const passBytes = Buffer.from(password);
    const authPacket = Buffer.alloc(3 + userBytes.length + passBytes.length);
    authPacket[0] = 0x01;
    authPacket[1] = userBytes.length;
    userBytes.copy(authPacket, 2);
    authPacket[2 + userBytes.length] = passBytes.length;
    passBytes.copy(authPacket, 3 + userBytes.length);

    socket.write(authPacket);
    const authResponse = await readOnce(socket);
    if (authResponse.byteLength < 2 || authResponse[1] !== 0x00) {
      socket.destroy();
      throw new Error('S5 authentication failed');
    }
  } else if (selectedMethod !== 0x00) {
    socket.destroy();
    throw new Error(`S5 unsupported auth method: ${selectedMethod}`);
  }

  const hostBytes = Buffer.from(targetHost);
  const connectPacket = Buffer.alloc(7 + hostBytes.length);
  connectPacket[0] = 0x05;
  connectPacket[1] = 0x01;
  connectPacket[2] = 0x00;
  connectPacket[3] = 0x03;
  connectPacket[4] = hostBytes.length;
  hostBytes.copy(connectPacket, 5);
  connectPacket.writeUInt16BE(targetPort, 5 + hostBytes.length);

  socket.write(connectPacket);
  const connectResponse = await readOnce(socket);
  if (connectResponse.byteLength < 2 || connectResponse[1] !== 0x00) {
    socket.destroy();
    throw new Error('S5 connection failed');
  }

  if (initialData.byteLength > 0) socket.write(initialData);
  return socket;
}

async function connect2Http(proxyConfig, targetHost, targetPort, initialData) {
  const { host, port, username, password, type } = proxyConfig;
  const socket = await connectSocket(host, port, type === 'https');

  let request = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\n`;
  request += `Host: ${targetHost}:${targetPort}\r\n`;
  if (username && password) {
    request += `Proxy-Authorization: Basic ${Buffer.from(`${username}:${password}`).toString('base64')}\r\n`;
  }
  request += 'User-Agent: Mozilla/5.0\r\n';
  request += 'Connection: keep-alive\r\n\r\n';
  socket.write(request);

  let responseBuffer = Buffer.alloc(0);
  while (responseBuffer.byteLength < 8192 && !responseBuffer.includes('\r\n\r\n')) {
    responseBuffer = Buffer.concat([responseBuffer, await readOnce(socket)]);
  }

  const headerEndIndex = responseBuffer.indexOf('\r\n\r\n');
  if (headerEndIndex < 0) {
    socket.destroy();
    throw new Error('Invalid HTTP response');
  }

  const statusLine = responseBuffer.subarray(0, headerEndIndex).toString().split('\r\n')[0];
  const statusMatch = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/);
  const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : 0;
  if (statusCode < 200 || statusCode >= 300) {
    socket.destroy();
    throw new Error(`Connection failed: ${statusLine}`);
  }

  if (initialData.byteLength > 0) socket.write(initialData);
  return socket;
}

async function connectDirect(host, port, initialData) {
  const socket = await connectSocket(host, port);
  if (initialData.byteLength > 0) socket.write(initialData);
  return socket;
}

async function openRemoteSocket(host, port, rawData, customProxyIP) {
  const configuredProxy = customProxyIP || proxyIP;
  const proxyConfig = parseProxyAddress(configuredProxy) || { type: 'direct', host: configuredProxy, port: 443 };

  if (proxyConfig.type === 'socks5') {
    return { socket: await connect2Socks5(proxyConfig, host, port, rawData), fallback: null };
  }

  if (proxyConfig.type === 'http' || proxyConfig.type === 'https') {
    return { socket: await connect2Http(proxyConfig, host, port, rawData), fallback: null };
  }

  try {
    return {
      socket: await connectDirect(host, port, rawData),
      fallback: () => connectDirect(proxyConfig.host, proxyConfig.port, rawData),
    };
  } catch (error) {
    log(`直连 ${host}:${port} 失败（${error.message}），回退到 ${proxyConfig.host}:${proxyConfig.port}`);
    return { socket: await connectDirect(proxyConfig.host, proxyConfig.port, rawData), fallback: null };
  }
}

/* ------------------------------ WebSocket ------------------------------ */

function closeWebSocket(ws) {
  try {
    ws.close?.();
  } catch {
    // ignore
  }
}

/** 安全发送（失败忽略） */
function safeSend(ws, data) {
  try {
    ws.send(data);
  } catch {
    // ignore
  }
}

/** 把失败原因回传给客户端，便于用脚本排查（连接随后会关闭） */
function safeSendError(ws, message) {
  safeSend(ws, `trojan-error: ${message}`);
}

function attachRemoteSocket(state, socket, ws, fallback) {
  state.remoteSocket = socket;
  state.fallback = fallback;
  state.hasRemoteData = false;
  state.usingFallback = !fallback;

  socket.on('data', (chunk) => {
    state.hasRemoteData = true;
    try {
      ws.send(chunk);
    } catch (error) {
      log('ws.send 失败:', error?.message || error);
      socket.destroy();
      closeWebSocket(ws);
    }
  });

  socket.on('error', (error) => {
    log('远端 socket 错误:', error?.message || error);
    socket.destroy();
    closeWebSocket(ws);
  });

  socket.on('close', async () => {
    if (!state.closed && !state.hasRemoteData && state.fallback && !state.usingFallback) {
      state.usingFallback = true;
      try {
        const fallbackSocket = await state.fallback();
        attachRemoteSocket(state, fallbackSocket, ws, null);
        return;
      } catch (error) {
        log('回退连接失败:', error?.message || error);
      }
    }
    closeWebSocket(ws);
  });
}

async function handleTrojanChunk(state, ws, chunk) {
  if (state.remoteSocket) {
    state.remoteSocket.write(chunk);
    return;
  }

  state.pending = state.pending ? Buffer.concat([state.pending, chunk]) : chunk;
  const parsed = parseTrojanHeader(state.pending, yourUUID);

  if (parsed.need) return;
  if (parsed.error) throw new Error(parsed.error);

  const { port, hostname, rawClientData } = parsed.result;
  state.pending = null;

  if (isSpeedTestSite(hostname)) throw new Error('Speedtest site is blocked');

  log(`转发 ${hostname}:${port}`);
  const { socket, fallback } = await openRemoteSocket(hostname, port, rawClientData, state.customProxyIP);
  attachRemoteSocket(state, socket, ws, fallback);
}

function getCustomProxyIP(request) {
  const url = new URL(request.url);
  if (url.pathname.startsWith('/proxyip=')) {
    try {
      return decodeURIComponent(url.pathname.substring(9)).trim();
    } catch {
      return null;
    }
  }
  return url.searchParams.get('proxyip') || request.headers.get('proxyip');
}

function createWebSocketHandler(request, options = {}) {
  const earlyData = base64ToBuffer(request.headers.get('sec-websocket-protocol') || '');
  const customProxyIP = getCustomProxyIP(request);
  const state = {
    closed: false,
    customProxyIP,
    pending: null,
    remoteSocket: null,
    fallback: null,
    hasRemoteData: false,
    usingFallback: false,
  };

  return {
    async onopen(ws) {
      log('WS 已连接', customProxyIP ? `(proxyip=${customProxyIP})` : '');
      if (options.hello) safeSend(ws, 'trojan-hello');
      if (!earlyData || earlyData.byteLength === 0) return;
      try {
        await handleTrojanChunk(state, ws, earlyData);
      } catch (error) {
        const reason = error?.message || String(error);
        log('early-data 处理失败:', reason);
        safeSendError(ws, reason);
        closeWebSocket(ws);
      }
    },

    async onmessage(ws, message) {
      try {
        await handleTrojanChunk(state, ws, toBuffer(message));
      } catch (error) {
        const reason = error?.message || String(error);
        log('消息处理失败:', reason);
        safeSendError(ws, reason);
        closeWebSocket(ws);
      }
    },

    onclose(ws, code, reason) {
      state.closed = true;
      state.remoteSocket?.destroy();
      log('WS 已关闭', code, reason?.toString?.() || '');
    },

    onerror(ws, error) {
      state.closed = true;
      state.remoteSocket?.destroy();
      log('WS 错误:', error?.message || error);
    },
  };
}

/* -------------------------------- 页面 -------------------------------- */

const PAGE_HTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Trojan 节点信息</title>
<style>
:root{color-scheme:light}
*{box-sizing:border-box}
body{margin:0;padding:24px;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f5f6f8;color:#1f2328;display:flex;justify-content:center}
.card{background:#fff;border:1px solid #e3e6ea;border-radius:14px;max-width:760px;width:100%;padding:24px}
h1{font-size:20px;margin:0 0 4px}
p.sub{color:#6b7280;font-size:13px;margin:0 0 18px}
label{display:block;font-size:13px;font-weight:600;margin:18px 0 6px}
input{width:100%;padding:10px 12px;border:1px solid #d0d5dd;border-radius:8px;font-size:14px;font-family:inherit}
button{cursor:pointer;border:1px solid #d0d5dd;background:#fff;border-radius:8px;padding:8px 14px;font-size:13px;font-family:inherit}
button.primary{background:#2563eb;border-color:#2563eb;color:#fff}
.row{display:flex;gap:8px;margin-top:8px;flex-wrap:wrap}
code{display:block;word-break:break-all;background:#f3f4f6;border:1px solid #e5e7eb;border-radius:8px;padding:10px;font-size:12px;margin-top:8px;line-height:1.6}
table{width:100%;border-collapse:collapse;margin-top:8px;font-size:13px}
td{border-bottom:1px solid #eef0f2;padding:8px 4px;vertical-align:top}
td:first-child{color:#6b7280;width:36%}
.hide{display:none}
.tip{font-size:12px;color:#6b7280;margin-top:18px;line-height:1.8}
</style>
</head>
<body>
<div class="card">
  <h1>Trojan over WebSocket</h1>
  <p class="sub">EdgeOne 云函数代理节点</p>
  <div id="gate">
    <label for="uuid">输入节点 UUID（即密码）</label>
    <input id="uuid" value="__UUID__" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" autocomplete="off">
    <div class="row"><button class="primary" id="go">生成节点信息</button></div>
  </div>
  <div id="info" class="hide">
    <label>订阅地址</label>
    <code id="sub"></code>
    <div class="row"><button id="copy-sub">复制订阅地址</button></div>
    <label>节点链接（手动导入用）</label>
    <code id="link"></code>
    <div class="row"><button id="copy-link">复制节点链接</button></div>
    <label>手动填写参数</label>
    <table>
      <tr><td>协议</td><td>Trojan</td></tr>
      <tr><td>服务器地址</td><td id="c-host"></td></tr>
      <tr><td>端口</td><td>443</td></tr>
      <tr><td>密码</td><td id="c-pw"></td></tr>
      <tr><td>传输方式</td><td>WebSocket</td></tr>
      <tr><td>路径</td><td>/ws?ed=2560</td></tr>
      <tr><td>Host / SNI</td><td id="c-sni"></td></tr>
      <tr><td>TLS</td><td>开启，指纹 firefox，allowInsecure=0</td></tr>
    </table>
  </div>
  <p class="tip">把「订阅地址」填进 Clash / v2rayN / Shadowrocket 的订阅导入即可。客户端不支持订阅时，用「节点链接」或按上表手动填写。</p>
</div>
<script>
(function () {
  var host = location.hostname;
  function build(uuid) {
    var q = 'security=tls&sni=' + host + '&fp=firefox&allowInsecure=0&type=ws&host=' + host + '&path=' + encodeURIComponent('/ws?ed=2560');
    return {
      sub: 'https://' + host + '/sub/' + uuid,
      link: 'trojan://' + uuid + '@' + host + ':443?' + q + '#' + host + '-trojan'
    };
  }
  function show(uuid) {
    var r = build(uuid);
    document.getElementById('sub').textContent = r.sub;
    document.getElementById('link').textContent = r.link;
    document.getElementById('c-host').textContent = host;
    document.getElementById('c-sni').textContent = host;
    document.getElementById('c-pw').textContent = uuid;
    document.getElementById('gate').className = 'hide';
    document.getElementById('info').className = '';
  }
  function copy(btn, text) {
    navigator.clipboard.writeText(text).then(function () {
      var old = btn.textContent;
      btn.textContent = '已复制';
      setTimeout(function () { btn.textContent = old; }, 1200);
    });
  }
  document.getElementById('go').onclick = function () {
    var v = document.getElementById('uuid').value.trim();
    if (v) show(v);
  };
  document.getElementById('copy-sub').onclick = function () {
    copy(this, document.getElementById('sub').textContent);
  };
  document.getElementById('copy-link').onclick = function () {
    copy(this, document.getElementById('link').textContent);
  };
  var preset = document.getElementById('uuid').value.trim();
  if (preset) show(preset);
})();
</script>
</body>
</html>`;

function htmlResponse(body, status = 200) {
  return new Response(body, {
    status,
    headers: {
      'Content-Type': 'text/html;charset=utf-8',
      'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
    },
  });
}

function textResponse(body, status = 200) {
  return new Response(body, {
    status,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
    },
  });
}

function homePage(uuid) {
  return htmlResponse(PAGE_HTML.replace('__UUID__', uuid || ''));
}

function subscriptionResponse(request) {
  const host = getPublicHost(request);
  if (!host) {
    return textResponse('未解析到公开域名，请配置环境变量 DOMAIN 后重试。', 500);
  }
  const link = buildTrojanLink(host, yourUUID);
  return new Response(Buffer.from(link, 'utf8').toString('base64'), {
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
    },
  });
}

function debugResponse(request) {
  const headers = {};
  for (const [key, value] of request.headers.entries()) headers[key] = value;
  return new Response(
    JSON.stringify(
      {
        requestUrl: request.url,
        resolvedHost: getPublicHost(request),
        forcedHost: forcedHost || null,
        proxyIP,
        wsPath: WS_PATH,
        headers,
      },
      null,
      2
    ),
    {
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
      },
    }
  );
}

/* ------------------------------ 出站自检 ------------------------------ */

function tcpProbe(host, port, timeoutMs = 8000) {
  return new Promise((resolve) => {
    const started = Date.now();
    const socket = net.connect({ host, port });
    let settled = false;
    const done = (ok, error) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ target: `${host}:${port}`, ok, error: error || null, ms: Date.now() - started });
    };
    socket.setTimeout(timeoutMs, () => done(false, 'timeout'));
    socket.once('connect', () => done(true));
    socket.once('error', (e) => done(false, e.code || e.message));
  });
}

async function diagResponse(context) {
  const proxyConfig = parseProxyAddress(proxyIP);

  const dnsTest = await (async () => {
    const started = Date.now();
    try {
      const record = await lookup('example.com');
      return { ok: true, address: record.address, ms: Date.now() - started };
    } catch (error) {
      return { ok: false, error: error.code || error.message, ms: Date.now() - started };
    }
  })();

  const targets = [
    ['example.com', 80],
    ['cp.cloudflare.com', 80],
    ['www.baidu.com', 80],
    ['1.1.1.1', 443],
  ];
  if (proxyConfig && proxyConfig.type === 'direct') targets.push([proxyConfig.host, proxyConfig.port]);

  const tcp = await Promise.all(targets.map(([h, p]) => tcpProbe(h, p)));

  // WebSocket 运行时能力自检
  let wsModule;
  try {
    const mod = await import('ws');
    wsModule = { ok: true, keys: Object.keys(mod).slice(0, 10) };
  } catch (error) {
    wsModule = { ok: false, error: error.message };
  }

  const runtime = {
    node: process.version,
    platform: process.platform,
    hasWebSocketPair: typeof WebSocketPair !== 'undefined',
    hasGlobalWebSocket: typeof WebSocket !== 'undefined',
    envKeys: Object.keys(context?.env || {}),
    wsModule,
  };

  return new Response(
    JSON.stringify({ proxyIP, proxyConfig, runtime, dns: dnsTest, tcp }, null, 2),
    {
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
      },
    }
  );
}

/* ------------------------------- 入口 ------------------------------- */
export async function onRequest(context) {
  applyEnv(context.env || {});

  const request = context.request;
  const url = new URL(request.url);
  const pathname = url.pathname;
  const lowerPath = pathname.toLowerCase();
  const uuidLower = yourUUID.toLowerCase();

  // WebSocket 升级
  if (request.headers.get('upgrade')?.toLowerCase() === 'websocket') {
    return { websocket: createWebSocketHandler(request, { hello: lowerPath === `/${uuidLower}/wstest` }) };
  }

  // 运行时切换出口 IP
  if (pathname.startsWith('/proxyip=')) {
    const pathProxyIP = getCustomProxyIP(request);
    if (pathProxyIP) {
      runtimeProxyIP = pathProxyIP;
      proxyIP = pathProxyIP;
    }
    return textResponse(`set proxyIP to: ${proxyIP}\n\n`);
  }

  if (request.method !== 'GET') {
    return textResponse('Not Found', 404);
  }

  if (pathname === '/') {
    return homePage('');
  }

  if (lowerPath === `/${uuidLower}`) {
    return homePage(yourUUID);
  }

  if (lowerPath === `/${uuidLower}/debug`) {
    return debugResponse(request);
  }

  if (lowerPath === `/${uuidLower}/diag`) {
    return diagResponse(context);
  }

  if (lowerPath === `/sub/${uuidLower}`) {
    return subscriptionResponse(request);
  }

  return textResponse('Not Found', 404);
}

export default onRequest;
