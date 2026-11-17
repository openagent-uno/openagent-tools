// Loopback relay for authenticated egress proxies.
//
// Chromium's --proxy-server accepts no credentials, and it cannot authenticate
// to SOCKS5 at all. When OPENAGENT_CHROME_PROXY carries userinfo
// (http://user:pass@host:port or socks5://user:pass@host:port) the browser is
// pointed at this relay instead: a no-auth HTTP proxy on 127.0.0.1 that opens
// every tunnel through the configured upstream with its credentials. Only the
// owning process can reach it (loopback, random port) and credentials never
// appear in the browser's command line or in logs.

import http from "node:http";
import net from "node:net";
import tls from "node:tls";

const CONNECT_TIMEOUT_MS = 20000;

/** Parse an egress proxy URL. Returns null for an empty value. */
export function parseProxy(raw) {
  const value = (raw || "").trim();
  if (!value) return null;
  let url;
  try { url = new URL(value); } catch { throw new Error("OPENAGENT_CHROME_PROXY is not a valid proxy URL"); }
  const scheme = url.protocol.replace(/:$/, "");
  if (!["http", "https", "socks5", "socks5h"].includes(scheme)) {
    throw new Error("OPENAGENT_CHROME_PROXY must use http, https or socks5");
  }
  const port = Number(url.port || (scheme === "https" ? 443 : scheme === "http" ? 80 : 1080));
  if (!url.hostname || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("OPENAGENT_CHROME_PROXY needs a host and port");
  }
  return {
    scheme: scheme === "socks5h" ? "socks5" : scheme,
    host: url.hostname.replace(/^\[|\]$/g, ""),
    port,
    username: decodeURIComponent(url.username),
    password: decodeURIComponent(url.password),
  };
}

/** Value for --proxy-server, without credentials. */
export function chromeProxyServer(proxy) {
  const host = proxy.host.includes(":") ? `[${proxy.host}]` : proxy.host;
  return `${proxy.scheme}://${host}:${proxy.port}`;
}

function withTimeout(socket, label) {
  socket.setTimeout(CONNECT_TIMEOUT_MS, () => socket.destroy(new Error(`${label} timed out`)));
  return socket;
}

function connectUpstream(proxy) {
  return new Promise((resolve, reject) => {
    const options = { host: proxy.host, port: proxy.port };
    const socket = proxy.scheme === "https"
      ? tls.connect({ ...options, servername: net.isIP(proxy.host) ? undefined : proxy.host })
      : net.connect(options);
    withTimeout(socket, "upstream proxy");
    socket.once(proxy.scheme === "https" ? "secureConnect" : "connect", () => resolve(socket));
    socket.once("error", reject);
  });
}

function readUntil(socket, predicate) {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    const onData = (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      const result = predicate(buffer);
      if (result) {
        socket.off("data", onData);
        socket.off("error", reject);
        resolve(result);
      } else if (buffer.length > 65536) {
        socket.destroy(new Error("upstream proxy reply too large"));
      }
    };
    socket.on("data", onData);
    socket.once("error", reject);
  });
}

async function httpTunnel(proxy, host, port) {
  const socket = await connectUpstream(proxy);
  const auth = proxy.username || proxy.password
    ? `Proxy-Authorization: Basic ${Buffer.from(`${proxy.username}:${proxy.password}`).toString("base64")}\r\n`
    : "";
  const target = host.includes(":") ? `[${host}]:${port}` : `${host}:${port}`;
  socket.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n${auth}\r\n`);
  const { status, rest } = await readUntil(socket, (buffer) => {
    const end = buffer.indexOf("\r\n\r\n");
    if (end < 0) return null;
    const line = buffer.subarray(0, buffer.indexOf("\r\n")).toString("latin1");
    return { status: Number(line.split(" ")[1]), rest: buffer.subarray(end + 4) };
  });
  if (status !== 200) {
    socket.destroy();
    throw new Error(`upstream proxy refused CONNECT (${status})`);
  }
  return { socket, rest };
}

async function socksTunnel(proxy, host, port) {
  const socket = await connectUpstream(proxy);
  const wantsAuth = Boolean(proxy.username || proxy.password);
  socket.write(Buffer.from(wantsAuth ? [5, 1, 2] : [5, 1, 0]));
  const method = await readUntil(socket, (b) => (b.length >= 2 ? b : null));
  if (method[0] !== 5 || method[1] !== (wantsAuth ? 2 : 0)) throw new Error("SOCKS5 method refused");
  if (wantsAuth) {
    const user = Buffer.from(proxy.username), pass = Buffer.from(proxy.password);
    if (user.length > 255 || pass.length > 255) throw new Error("SOCKS5 credentials too long");
    socket.write(Buffer.concat([Buffer.from([1, user.length]), user, Buffer.from([pass.length]), pass]));
    const reply = await readUntil(socket, (b) => (b.length >= 2 ? b : null));
    if (reply[1] !== 0) throw new Error("SOCKS5 authentication failed");
  }
  const ipVersion = net.isIP(host);
  const address = ipVersion === 4
    ? Buffer.from([1, ...host.split(".").map(Number)])
    : ipVersion === 6
      ? Buffer.concat([Buffer.from([4]), ipv6Bytes(host)])
      : Buffer.concat([Buffer.from([3, Buffer.byteLength(host)]), Buffer.from(host)]);
  socket.write(Buffer.concat([Buffer.from([5, 1, 0]), address, Buffer.from([port >> 8, port & 255])]));
  const { ok, rest } = await readUntil(socket, (b) => {
    if (b.length < 5) return null;
    const length = b[3] === 1 ? 4 : b[3] === 4 ? 16 : b[3] === 3 ? 1 + b[4] : -1;
    if (length < 0) return { ok: false, rest: Buffer.alloc(0) };
    const total = 4 + length + 2;
    return b.length >= total ? { ok: b[1] === 0, rest: b.subarray(total) } : null;
  });
  if (!ok) {
    socket.destroy();
    throw new Error("SOCKS5 connect refused");
  }
  return { socket, rest };
}

function ipv6Bytes(host) {
  const [head, tail = ""] = host.split("::");
  const parts = (s) => (s ? s.split(":") : []);
  const groups = [...parts(head), ...Array(8 - parts(head).length - parts(tail).length).fill("0"), ...parts(tail)];
  return Buffer.from(groups.flatMap((g) => { const v = parseInt(g, 16); return [v >> 8, v & 255]; }));
}

function tunnel(proxy, host, port) {
  return proxy.scheme === "socks5" ? socksTunnel(proxy, host, port) : httpTunnel(proxy, host, port);
}

/**
 * Start the loopback relay for `proxy`. Resolves to { url, close }, where url
 * is the credential-free http://127.0.0.1:<port> value for --proxy-server.
 * A stable `preferredPort` lets a browser that survived an MCP restart keep
 * using the relay the new process binds; a busy port falls back to a random one.
 */
export async function startProxyRelay(proxy, preferredPort = 0) {
  try { return await listenRelay(proxy, preferredPort); }
  catch (error) {
    if (preferredPort && error && error.code === "EADDRINUSE") return listenRelay(proxy, 0);
    throw error;
  }
}

function listenRelay(proxy, port) {
  const server = http.createServer(async (request, response) => {
    // Plain-HTTP requests arrive with an absolute URI; tunnel them like CONNECT.
    let target;
    try { target = new URL(request.url); } catch { response.writeHead(400).end(); return; }
    if (target.protocol !== "http:") { response.writeHead(400).end(); return; }
    try {
      const { socket, rest } = await tunnel(proxy, target.hostname, Number(target.port || 80));
      socket.setTimeout(0);
      const path = target.pathname + target.search;
      const headers = Object.entries(request.headers)
        .filter(([name]) => !/^proxy-/i.test(name))
        .map(([name, value]) => `${name}: ${value}`).join("\r\n");
      socket.write(`${request.method} ${path} HTTP/1.1\r\n${headers}\r\n\r\n`);
      if (rest.length) response.socket.write(rest);
      request.pipe(socket);
      socket.pipe(response.socket);
      socket.on("error", () => response.socket.destroy());
    } catch {
      if (!response.headersSent) response.writeHead(502).end();
    }
  });
  server.on("connect", async (request, client, head) => {
    const separator = request.url.lastIndexOf(":");
    const host = request.url.slice(0, separator).replace(/^\[|\]$/g, "");
    const port = Number(request.url.slice(separator + 1));
    client.on("error", () => {});
    try {
      if (!host || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error("bad target");
      const { socket, rest } = await tunnel(proxy, host, port);
      socket.setTimeout(0);
      client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (rest.length) client.write(rest);
      if (head.length) socket.write(head);
      socket.pipe(client);
      client.pipe(socket);
      socket.on("error", () => client.destroy());
      client.on("close", () => socket.destroy());
    } catch {
      client.end("HTTP/1.1 502 Bad Gateway\r\n\r\n");
    }
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({ url: `http://127.0.0.1:${port}`, close: () => new Promise((r) => server.close(() => r())) });
    });
  });
}
