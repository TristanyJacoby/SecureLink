import { createRequire } from "node:module";
import WebSocket from "ws";
import { SecureLinkClient, CHUNK_SIZE } from "../src/protocol.mjs";

const require = createRequire(import.meta.url);
export const { createSecureLinkServer } = require("../server/app.js");

export async function startServer(options = {}) {
  const sl = createSecureLinkServer({ log: () => {}, ...options });
  await new Promise((r) => sl.server.listen(0, "127.0.0.1", r));
  const { port } = sl.server.address();
  const scheme = options.tls ? "s" : "";
  return { ...sl, port, httpUrl: `http${scheme}://127.0.0.1:${port}`, wsUrl: `ws${scheme}://127.0.0.1:${port}` };
}

/** A raw WebSocket that records server messages. */
export function rawClient(url, opts = {}) {
  const ws = new WebSocket(url, opts);
  ws.msgs = [];
  ws.bins = [];
  ws.waiters = [];
  ws.on("message", (data, isBinary) => {
    if (isBinary) ws.bins.push(data);
    else ws.msgs.push(JSON.parse(data.toString()));
    for (const w of [...ws.waiters]) w();
  });
  ws.opened = new Promise((res, rej) => { ws.on("open", res); ws.on("error", rej); ws.on("unexpected-response", (_, r) => rej(new Error(`HTTP ${r.statusCode}`))); });
  ws.closed = new Promise((res) => ws.on("close", (code) => res(code)));
  ws.json = (o) => ws.send(JSON.stringify(o));
  ws.next = (type, timeout = 2000) => new Promise((resolve, reject) => {
    const seen = new Set();
    const check = () => {
      const m = ws.msgs.find((x) => x.type === type && !x._taken);
      if (m) { m._taken = true; ws.waiters = ws.waiters.filter((w) => w !== check); clearTimeout(t); resolve(m); }
    };
    const t = setTimeout(() => { ws.waiters = ws.waiters.filter((w) => w !== check); reject(new Error(`timeout waiting for ${type}`)); }, timeout);
    seen.add(check);
    ws.waiters.push(check);
    check();
  });
  return ws;
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Node WebSocket that accepts the self-signed test certificate. */
export class InsecureWS extends WebSocket {
  constructor(url) { super(url, { rejectUnauthorized: false }); }
}

/** A SecureLinkClient plus an event log and promise helpers. */
export function makeClient({ url, role, name, qrSecret, WebSocketImpl = WebSocket }) {
  const events = [];
  const waiters = [];
  const client = new SecureLinkClient({
    url, role, name, qrSecret, WebSocketImpl,
    onEvent: (type, payload) => {
      events.push({ type, payload });
      for (const w of [...waiters]) w();
    },
  });
  client.events = events;
  client.next = (type, timeout = 5000) => new Promise((resolve, reject) => {
    const check = () => {
      const e = events.find((x) => x.type === type && !x.taken);
      if (e) { e.taken = true; waiters.splice(waiters.indexOf(check), 1); clearTimeout(t); resolve(e.payload); }
    };
    const t = setTimeout(() => {
      const i = waiters.indexOf(check); if (i >= 0) waiters.splice(i, 1);
      reject(new Error(`timeout waiting for ${type}; saw ${events.map((e) => e.type).join(", ")}`));
    }, timeout);
    waiters.push(check);
    check();
  });
  client.all = (type) => events.filter((e) => e.type === type).map((e) => e.payload);
  return client;
}

/** In-memory "file" for SecureLinkClient.sendFiles. */
export function memFile(name, bytes, type = "application/octet-stream") {
  return { name, size: bytes.length, type, read: async (s, e) => bytes.slice(s, e) };
}

export function randomData(n) {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i += 65536) globalThis.crypto.getRandomValues(out.subarray(i, Math.min(n, i + 65536)));
  return out;
}

export function joined(parts) {
  const n = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export { CHUNK_SIZE };
