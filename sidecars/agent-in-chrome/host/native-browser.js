// Generic CDP process/pipe transport. Hosts supply confinement and environment
// adapters explicitly; no client identity or deployment is selected here.
import { spawn } from 'node:child_process';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';

async function launchWindowsBrowser(binary, profile, flags, errorLog) {
  // libuv's generated stdio pipe names use the global namespace, which Windows
  // denies inside AppContainer. The explicit LOCAL endpoint belongs to this
  // box identity and never exposes a TCP debugger.
  const pipe = '\\\\.\\pipe\\LOCAL\\OpenAgent-CDP-' + randomBytes(24).toString('hex');
  // Separate synchronous Windows file objects avoid serializing a pending
  // read against a write on the same duplex named-pipe handle.
  const inputServer = net.createServer(), outputServer = net.createServer();
  inputServer.maxConnections = 1; outputServer.maxConnections = 1;
  for (const [server, suffix] of [[inputServer, '-input'], [outputServer, '-output']])
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(pipe + suffix, resolve); });
  const here = path.dirname(fileURLToPath(import.meta.url));
  let child, readyTimer;
  try {
    const connection = Promise.all([inputServer, outputServer].map(server => new Promise((resolve, reject) => {
      server.once('connection', resolve); server.once('error', reject);
    })));
    const readiness = new Promise((resolve, reject) => {
      readyTimer = setTimeout(() => reject(new Error('Native Windows browser pipe readiness timed out')), 15000);
    });
    // libuv also opens \\.\NUL for ignored standard handles; AppContainer
    // denies that global device path. Inherit an empty file owned by this box.
    const empty = fs.openSync(path.join(profile, 'native-browser-input'), 'a+', 0o600);
    try {
      child = spawn(process.env.OPENAGENT_CHROME_PYTHON || 'python',
        [path.join(here, 'windows-browser.py'), pipe, binary, JSON.stringify(flags)],
        // libuv's non-detached spawn adds a job with breakaway flags. Detached
        // skips that additional job without CREATE_BREAKAWAY_FROM_JOB: the
        // bridge retains the inherited nonbreakaway host/MCP cleanup jobs.
        { stdio: [empty, errorLog, errorLog], windowsHide: true, detached: true });
    } finally { fs.closeSync(empty); }
    const failed = new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('exit', (code, signal) => reject(new Error(`Native Windows browser bridge exited (${code ?? signal})`)));
    });
    const [inputSocket, outputSocket] = await Promise.race([connection, failed, readiness]);
    child.stdio[3] = inputSocket; child.stdio[4] = outputSocket;
    return child;
  } catch (error) {
    if (child) child.kill();
    throw error;
  } finally { clearTimeout(readyTimer); inputServer.close(); outputServer.close(); }
}

export async function launchNativeBrowser(binary, profile, args) {
  if (process.env.OPENAGENT_CHROME_TRANSPORT !== 'pipe') throw new Error('Native box authority required');
  if (!binary || !fs.statSync(binary).isFile()) throw new Error('Bundled browser unavailable');
  const flags = args.filter(arg => !arg.startsWith('--remote-debugging-') &&
    arg !== '--no-sandbox' && !arg.startsWith('--no-sandbox=') && !arg.startsWith('--disable-setuid-sandbox'));
  flags.push('--remote-debugging-pipe');
  // Windows Chrome's crashpad DLL opens a global pipe before startup. The
  // bundled official headless shell supports CDP without that external service.
  if (['chrome-headless-shell', 'chrome-headless-shell.exe'].includes(path.basename(binary))) {
    // The standalone shell implements the old headless engine. Do not select
    // Chrome's separate unified headless engine inside this executable.
    for (let index = flags.length - 1; index >= 0; index--)
      if (flags[index].startsWith('--headless')) flags.splice(index, 1);
    flags.push('--headless=old', '--disable-crash-reporter', '--disable-gpu');
  }
  if (process.env.OPENAGENT_CHROME_DIAGNOSTICS === 'true')
    flags.push('--enable-logging=stderr', '--v=1');
  // macOS rejects a second seatbelt installation. The inherited host policy
  // remains active in Chrome and every descendant; this does not affect Client.
  if (process.platform === 'darwin' && process.env.OPENAGENT_CHROME_INHERITED_SANDBOX === '1') flags.push('--no-sandbox');
  let browserEnvironment;
  if (process.platform === 'linux') {
    const adapter = process.env.OPENAGENT_CHROME_ENVIRONMENT_ADAPTER;
    if (adapter) {
      if (!path.isAbsolute(adapter)) throw new Error('Browser environment adapter must be absolute');
      const { linuxBrowserEnvironment } = await import(pathToFileURL(adapter).href);
      browserEnvironment = linuxBrowserEnvironment(profile, process.env, path.dirname(adapter));
    }
  }
  const errorLog = fs.openSync(path.join(profile, 'native-browser.log'), 'a', 0o600);
  let child;
  try {
    child = process.platform === 'win32' ? await launchWindowsBrowser(binary, profile, flags, errorLog) :
      spawn(binary, flags, { detached: true, env: browserEnvironment, stdio: ['ignore', 'ignore', errorLog, 'pipe', 'pipe'] });
  } finally { fs.closeSync(errorLog); }
  return { wsUrl: { child }, ownsBrowser: true, pid: child.pid };
}

export function createPipeSocket(endpoint) {
  const { child } = endpoint;
  const socket = new EventEmitter();
  const input = child.stdio[3], output = child.stdio[4];
  let buffer = Buffer.alloc(0), closed = false;
  socket.readyState = 1;
  const close = () => {
    if (closed) return;
    closed = true; socket.readyState = 3;
    input.destroy(); output.destroy(); socket.emit('close');
  };
  socket.send = message => {
    if (closed) throw new Error('Native CDP pipe closed');
    input.write(Buffer.from(message + '\0'), error => { if (error) close(); });
  };
  socket.close = close;
  output.on('data', chunk => {
    buffer = Buffer.concat([buffer, chunk]);
    if (buffer.length > 128 * 1024 * 1024) return close();
    for (;;) {
      const end = buffer.indexOf(0);
      if (end < 0) break;
      const message = buffer.subarray(0, end);
      buffer = buffer.subarray(end + 1);
      socket.emit('message', message);
    }
  });
  input.on('error', close); output.on('error', close); output.on('end', close);
  child.on('error', error => { socket.emit('error', error); close(); });
  child.on('exit', close);
  queueMicrotask(() => closed ? socket.emit('error', new Error('Native browser exited')) : socket.emit('open'));
  return socket;
}
