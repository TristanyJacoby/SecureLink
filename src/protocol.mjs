// SecureLink protocol v2: pairing, key agreement, verification and chunked
// encrypted file transfer. Runs unchanged in browsers and in Node 18+
// (it only needs globalThis.crypto.subtle, TextEncoder and a WebSocket class).
//
// Security summary
// - The 6-digit pairing code is only a routing ticket on the relay server.
//   It is never used as key material.
// - Each session runs an ephemeral ECDH (P-256) key agreement. The creator
//   (sender, "A") first commits to its public key, so a relay or network
//   attacker cannot grind keys to make the verification numbers match.
// - The people verify the session by comparing a 6-digit Short
//   Authentication String (SAS) shown on both screens, or automatically when
//   the receiver opened the sender's QR code, which carries a secret the
//   server never sees.
// - Keys come from HKDF with a per-session salt; each direction has its own
//   AES-256-GCM key. File metadata is encrypted. Every 64 KiB chunk is
//   authenticated together with its file id, position and chunk count, so
//   changed, dropped, reordered or truncated data is rejected.
// - The sender reports a file as delivered only after an encrypted receipt
//   from the receiver, so a relay cannot fake a successful delivery.

export const PROTOCOL_VERSION = 2;
export const CHUNK_SIZE = 64 * 1024;
export const MAX_FILE_BYTES = 250 * 1024 * 1024;
export const FRAME_HEADER_BYTES = 21; // version(1) + file id(16) + index(4)

const WINDOW_CHUNKS = 16;
const ACK_EVERY = 4;
const te = new TextEncoder();
const td = new TextDecoder();
const subtle = () => globalThis.crypto.subtle;

// ---------- byte helpers ----------

export function randomBytes(n) {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export function b64u(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function unb64u(str) {
  if (typeof str !== "string" || !/^[A-Za-z0-9_-]*$/.test(str)) throw new Error("bad base64");
  const pad = str.length % 4 ? "=".repeat(4 - (str.length % 4)) : "";
  const bin = atob(str.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

async function sha256(bytes) {
  return new Uint8Array(await subtle().digest("SHA-256", bytes));
}

export function u32(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n);
  return b;
}

// ---------- crypto building blocks (exported for tests and tools) ----------

export async function generateKeyPair() {
  const kp = await subtle().generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const pub = new Uint8Array(await subtle().exportKey("raw", kp.publicKey));
  return { privateKey: kp.privateKey, pub };
}

export async function computeSas(pkA, pkB) {
  const h = await sha256(concat(te.encode("SecureLink v2 SAS|"), pkA, pkB));
  const n = new DataView(h.buffer).getUint32(0);
  return String(n % 1000000).padStart(6, "0");
}

export async function deriveSessionKeys(privateKey, peerPub, pkA, pkB) {
  const peerKey = await subtle().importKey("raw", peerPub, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = await subtle().deriveBits({ name: "ECDH", public: peerKey }, privateKey, 256);
  const ikm = await subtle().importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const salt = await sha256(concat(te.encode("SecureLink v2 salt|"), pkA, pkB));
  const make = (info) => subtle().deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: te.encode(info) },
    ikm, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
  );
  return { ab: await make("SecureLink v2 key A->B"), ba: await make("SecureLink v2 key B->A") };
}

export async function qrMac(secret, role, pkA, pkB) {
  const key = await subtle().importKey("raw", secret, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const msg = concat(te.encode(`SecureLink v2 QR|${role}|`), pkA, pkB);
  return new Uint8Array(await subtle().sign("HMAC", key, msg));
}

export function chunkAad(idB64, index, chunks) {
  return te.encode(`SL2|chunk|${idB64}|${index}|${chunks}`);
}

export function chunkCount(size) {
  return Math.max(1, Math.ceil(size / CHUNK_SIZE));
}

export function parseJoinFragment(hash) {
  // "#join=123456.<base64url secret>"
  const m = /^#?join=(\d{6})\.([A-Za-z0-9_-]{43})$/.exec(hash || "");
  return m ? { code: m[1], secret: unb64u(m[2]) } : null;
}

export function buildJoinUrl(origin, code, secret) {
  return `${origin}/#join=${code}.${b64u(secret)}`;
}

export function cleanFileName(name) {
  const s = String(name || "").replace(/[\u0000-\u001f\u007f/\\]/g, "_").trim().slice(0, 200);
  return s || "file";
}

function cleanType(type) {
  const t = String(type || "").toLowerCase().slice(0, 100);
  if (!/^[a-z0-9.+-]+\/[a-z0-9.+-]+$/.test(t)) return "application/octet-stream";
  // Never hand active content back to the page's origin.
  if (/html|xml|svg|javascript|ecmascript/.test(t)) return "application/octet-stream";
  return t;
}

// ---------- the client ----------

export class SecureLinkError extends Error {
  constructor(code, message) { super(message || code); this.code = code; }
}

/**
 * One device's side of a session.
 * role: "send" (creates the session, shows the code/QR) or "receive" (joins).
 * onEvent(type, payload) receives everything the UI needs; see README.
 */
export class SecureLinkClient {
  constructor({ url, role, name, WebSocketImpl, onEvent, qrSecret } = {}) {
    if (role !== "send" && role !== "receive") throw new Error("role must be send or receive");
    this.url = url;
    this.role = role;
    this.isA = role === "send";
    this.name = name || "";
    this.WS = WebSocketImpl || globalThis.WebSocket;
    this.emit = onEvent || (() => {});
    // The sender makes the QR secret; a receiver gets it from the QR link.
    this.qrSecret = this.isA ? randomBytes(32) : (qrSecret || null);
    this.state = "idle";
    this.dead = false;
    this.verified = false;
    this.localConfirmed = false;
    this.peerConfirmed = false;
    this.peerName = "";
    this._chain = Promise.resolve();
    this._waiters = new Set();
    this._out = [];
    this._pumping = false;
    this._outgoing = new Map();
    this._incoming = null;
  }

  // ----- public API -----

  connect() {
    return new Promise((resolve, reject) => {
      let opened = false;
      const ws = new this.WS(this.url);
      ws.binaryType = "arraybuffer";
      ws.onopen = () => {
        opened = true;
        this.state = "connected";
        if (this.isA) this._send({ type: "create", name: this.name });
        resolve();
      };
      ws.onerror = () => { if (!opened) reject(new SecureLinkError("unreachable", "Could not reach the SecureLink server.")); };
      ws.onclose = (ev) => {
        if (!opened) reject(new SecureLinkError("unreachable", "Could not reach the SecureLink server."));
        this._onClose(ev);
      };
      ws.onmessage = (ev) => {
        const data = ev.data;
        this._chain = this._chain
          .then(() => (typeof data === "string" ? this._onServer(data) : this._onChunk(new Uint8Array(data))))
          .catch((err) => this._fail(err.code || "protocol", err.message));
      };
      this.ws = ws;
    });
  }

  join(code) {
    if (this.isA) throw new Error("only the receiver joins");
    this._send({ type: "join", code: String(code), name: this.name });
  }

  renewCode() {
    if (!this.isA || this.state !== "waiting") return;
    this.qrSecret = randomBytes(32);
    this._send({ type: "renew" });
  }

  async confirmSas(match) {
    if (this.dead || this.state !== "verify") return;
    if (!match) {
      this._relay({ t: "cancel", reason: "mismatch" });
      this._fail("sas-mismatch", "You said the numbers don't match, so SecureLink stopped the connection.");
      return;
    }
    this.localConfirmed = true;
    await this._sendEnc({ k: "ready" });
    this.emit("local-confirmed", {});
    this._maybeVerified("sas");
  }

  /** files: [{ name, size, type, read(start, end) => Promise<Uint8Array> }] */
  sendFiles(files) {
    if (!this.isA) throw new Error("only the sender sends files");
    const ids = [];
    for (const f of files) {
      const id = b64u(randomBytes(16));
      ids.push(id);
      const item = { id, file: f, name: cleanFileName(f.name), size: f.size, type: cleanType(f.type) };
      this._out.push(item);
      this.emit("file-queued", { id, name: item.name, size: item.size, type: item.type });
    }
    this._pump();
    return ids;
  }

  close() {
    if (this.ws && this.ws.readyState <= 1) {
      try { this._send({ type: "leave" }); } catch {}
      this.ws.close(1000);
    }
    this.dead = true;
    this._notify();
  }

  // ----- transport -----

  _send(obj) {
    if (this.ws && this.ws.readyState === 1) this.ws.send(JSON.stringify(obj));
  }

  _relay(body) { this._send({ type: "relay", body }); }

  async _sendEnc(inner) {
    const key = this.isA ? this.keys.ab : this.keys.ba;
    const iv = randomBytes(12);
    const ct = new Uint8Array(await subtle().encrypt(
      { name: "AES-GCM", iv, additionalData: te.encode("SL2|ctl") }, key, te.encode(JSON.stringify(inner))
    ));
    this._relay({ t: "enc", iv: b64u(iv), ct: b64u(ct) });
  }

  async _openEnc(body) {
    if (!this.keys) throw new SecureLinkError("protocol", "Encrypted message arrived before keys were agreed.");
    const key = this.isA ? this.keys.ba : this.keys.ab;
    let pt;
    try {
      pt = await subtle().decrypt(
        { name: "AES-GCM", iv: unb64u(body.iv), additionalData: te.encode("SL2|ctl") }, key, unb64u(body.ct)
      );
    } catch {
      throw new SecureLinkError("tampered", "A message from the other device failed its security check.");
    }
    return JSON.parse(td.decode(pt));
  }

  _fail(code, message) {
    if (this.dead) return;
    this.dead = true;
    this.state = "failed";
    for (const t of this._outgoing.values()) t.failed = true;
    this.emit("error", { code, message });
    try { this.ws && this.ws.close(1000); } catch {}
    this._notify();
  }

  _onClose(ev) {
    const wasDead = this.dead;
    this.dead = true;
    this._notify();
    if (!wasDead) this.emit("closed", { code: ev && ev.code, reason: (ev && ev.reason) || "" });
  }

  _wait(pred) {
    if (pred()) return Promise.resolve();
    return new Promise((resolve, reject) => {
      const w = () => {
        if (this.dead) { this._waiters.delete(w); reject(new SecureLinkError("closed", "The connection closed.")); }
        else if (pred()) { this._waiters.delete(w); resolve(); }
      };
      this._waiters.add(w);
    });
  }

  _notify() { for (const w of [...this._waiters]) w(); }

  // ----- server messages -----

  async _onServer(text) {
    if (this.dead) return;
    let msg;
    try { msg = JSON.parse(text); } catch { return; }
    switch (msg.type) {
      case "created":
        this.state = "waiting";
        this.emit("code", { code: msg.code, ttl: msg.ttl, secret: this.qrSecret });
        break;
      case "code-expired":
        this.emit("code-expired", {});
        break;
      case "join-failed":
        this.emit("join-failed", { reason: msg.reason, attemptsLeft: msg.attemptsLeft, retryAfter: msg.retryAfter });
        break;
      case "error":
        this.emit("server-error", { reason: msg.reason });
        break;
      case "paired":
        await this._onPaired(msg);
        break;
      case "peer-left":
        this._onPeerLeft();
        break;
      case "relay":
        if (msg.body && typeof msg.body === "object") await this._onRelay(msg.body);
        break;
      default:
        break;
    }
  }

  async _onPaired(msg) {
    if (this.state !== "waiting" && this.state !== "connected") return;
    this.peerName = typeof msg.peerName === "string" ? msg.peerName : "";
    this.state = "exchanging";
    this.kp = await generateKeyPair();
    this.emit("peer-joined", { peerName: this.peerName });
    if (this.isA) {
      this.commitSent = true;
      this._relay({ t: "commit", v: PROTOCOL_VERSION, h: b64u(await sha256(this.kp.pub)) });
    }
  }

  _onPeerLeft() {
    if (this.dead) return;
    const pending = [...this._outgoing.values()].some((t) => !t.done && !t.failed) || (this._incoming && !this._incoming.done);
    this.dead = true;
    this.emit("peer-left", { duringTransfer: !!pending, wasVerified: this.verified });
    this._notify();
    try { this.ws.close(1000); } catch {}
  }

  // ----- peer messages (via relay) -----

  async _onRelay(body) {
    switch (body.t) {
      case "commit": {
        if (this.isA || this.state !== "exchanging" || this.commit) throw new SecureLinkError("protocol", "Unexpected key commitment.");
        if (body.v !== PROTOCOL_VERSION) throw new SecureLinkError("version", "The other device runs a different SecureLink version.");
        this.commit = unb64u(body.h);
        this._relay({ t: "pk", pk: b64u(this.kp.pub), qr: !!this.qrSecret });
        break;
      }
      case "pk": {
        if (!this.isA || this.state !== "exchanging" || !this.commitSent || this.pkB) throw new SecureLinkError("protocol", "Unexpected key.");
        this.pkA = this.kp.pub;
        this.pkB = unb64u(body.pk);
        this.peerUsesQr = body.qr === true;
        this._relay({ t: "reveal", pk: b64u(this.pkA) });
        await this._establish();
        break;
      }
      case "reveal": {
        if (this.isA || this.state !== "exchanging" || !this.commit) throw new SecureLinkError("protocol", "Unexpected key reveal.");
        const pkA = unb64u(body.pk);
        if (!equalBytes(await sha256(pkA), this.commit)) {
          throw new SecureLinkError("commit-mismatch", "The other device's key did not match what it promised. Someone may be interfering.");
        }
        this.pkA = pkA;
        this.pkB = this.kp.pub;
        await this._establish();
        break;
      }
      case "qrmac": {
        if (this.state !== "qr-wait" || !this.qrSecret) throw new SecureLinkError("protocol", "Unexpected QR proof.");
        const expected = await qrMac(this.qrSecret, this.isA ? "B" : "A", this.pkA, this.pkB);
        if (!equalBytes(unb64u(body.mac), expected)) {
          throw new SecureLinkError("qr-mismatch", "This device did not prove it scanned your QR code. Someone may be interfering.");
        }
        if (this.isA) this._relay({ t: "qrmac", mac: b64u(await qrMac(this.qrSecret, "A", this.pkA, this.pkB)) });
        this.localConfirmed = true;
        this.peerConfirmed = true;
        this._maybeVerified("qr");
        break;
      }
      case "cancel":
        this._fail("peer-cancelled", "The other device said the numbers didn't match, so the connection was stopped.");
        break;
      case "ack": {
        const t = this._outgoing.get(body.id);
        if (t && Number.isInteger(body.n) && body.n > t.acked && body.n <= t.chunks) {
          t.acked = body.n;
          this.emit("file-progress", { id: t.id, bytes: Math.min(t.acked * CHUNK_SIZE, t.size), size: t.size });
          this._notify();
        }
        break;
      }
      case "enc":
        await this._onEncrypted(await this._openEnc(body));
        break;
      default:
        break;
    }
  }

  async _establish() {
    const peerPub = this.isA ? this.pkB : this.pkA;
    this.keys = await deriveSessionKeys(this.kp.privateKey, peerPub, this.pkA, this.pkB);
    this.sas = await computeSas(this.pkA, this.pkB);
    const qrPath = this.isA ? this.peerUsesQr : !!this.qrSecret;
    if (qrPath) {
      this.state = "qr-wait";
      this.emit("checking-qr", { peerName: this.peerName });
      if (!this.isA) this._relay({ t: "qrmac", mac: b64u(await qrMac(this.qrSecret, "B", this.pkA, this.pkB)) });
    } else {
      this.state = "verify";
      this.emit("sas", { sas: this.sas, peerName: this.peerName });
    }
  }

  _maybeVerified(mode) {
    if (this.verified || !this.localConfirmed || !this.peerConfirmed) return;
    this.verified = true;
    this.state = "verified";
    this.emit("verified", { mode, sas: this.sas, peerName: this.peerName });
    this._notify();
    this._pump();
  }

  async _onEncrypted(m) {
    switch (m.k) {
      case "ready":
        if (this.state !== "verify" && this.state !== "verified") throw new SecureLinkError("protocol", "Unexpected confirmation.");
        this.peerConfirmed = true;
        this.emit("peer-confirmed", {});
        this._maybeVerified("sas");
        break;
      case "meta":
        if (this.isA || !this.verified) throw new SecureLinkError("protocol", "File offered before the devices were verified.");
        this._startIncoming(m);
        break;
      case "receipt": {
        const t = this._outgoing.get(m.id);
        if (!this.isA || !t) break;
        t.done = true;
        t.ok = m.ok === true;
        this._notify();
        break;
      }
      default:
        break;
    }
  }

  // ----- sending -----

  async _pump() {
    if (this._pumping || !this.verified || this.dead) return;
    this._pumping = true;
    try {
      while (this._out.length && !this.dead) {
        const item = this._out.shift();
        await this._sendOne(item);
      }
    } catch (err) {
      if (!this.dead) this._fail(err.code || "send-failed", err.message);
    } finally {
      this._pumping = false;
    }
  }

  async _sendOne(item) {
    if (item.size > MAX_FILE_BYTES) {
      this.emit("file-failed", { id: item.id, reason: "too-large", message: "This file is larger than the 250 MB limit." });
      return;
    }
    const idBytes = unb64u(item.id);
    const prefix = randomBytes(8);
    const chunks = chunkCount(item.size);
    const t = { id: item.id, size: item.size, chunks, acked: 0, done: false, ok: false, failed: false };
    this._outgoing.set(item.id, t);
    this.emit("file-start", { id: item.id, name: item.name, size: item.size, type: item.type });
    await this._sendEnc({ k: "meta", id: item.id, np: b64u(prefix), name: item.name, size: item.size, type: item.type, chunks });

    for (let i = 0; i < chunks; i++) {
      await this._wait(() => t.done || i - t.acked < WINDOW_CHUNKS);
      if (t.done) break; // the receiver already rejected this file
      const start = i * CHUNK_SIZE;
      const plain = item.size === 0 ? new Uint8Array(0) : await item.file.read(start, Math.min(start + CHUNK_SIZE, item.size));
      const expectedLen = Math.min(CHUNK_SIZE, item.size - start);
      if (plain.length !== Math.max(0, expectedLen)) throw new SecureLinkError("read-failed", `Could not read ${item.name}.`);
      const ct = new Uint8Array(await subtle().encrypt(
        { name: "AES-GCM", iv: concat(prefix, u32(i)), additionalData: chunkAad(item.id, i, chunks) }, this.keys.ab, plain
      ));
      if (this.dead) return;
      this.ws.send(concat(new Uint8Array([PROTOCOL_VERSION]), idBytes, u32(i), ct));
    }
    this.emit("file-sent", { id: item.id });
    await this._wait(() => t.done);
    if (t.ok) this.emit("file-delivered", { id: item.id, name: item.name, size: item.size });
    else this.emit("file-failed", { id: item.id, reason: "rejected", message: "The receiver could not verify this file, so it was discarded." });
  }

  // ----- receiving -----

  _startIncoming(m) {
    if (this._incoming && !this._incoming.done) throw new SecureLinkError("protocol", "A new file started before the last one finished.");
    if (typeof m.id !== "string" || typeof m.np !== "string") throw new SecureLinkError("protocol", "Bad file description.");
    const size = m.size;
    if (!Number.isSafeInteger(size) || size < 0) throw new SecureLinkError("protocol", "Bad file size.");
    if (m.chunks !== chunkCount(size)) throw new SecureLinkError("protocol", "Bad chunk count.");
    const prefix = unb64u(m.np);
    if (prefix.length !== 8 || unb64u(m.id).length !== 16) throw new SecureLinkError("protocol", "Bad file description.");
    const inc = {
      id: m.id, prefix, size, chunks: m.chunks, next: 0, bytes: 0, parts: [],
      name: cleanFileName(m.name), type: cleanType(m.type), done: false, failed: false,
    };
    this._incoming = inc;
    if (size > MAX_FILE_BYTES) {
      this._rejectIncoming(inc, "too-large", "The file is larger than the 250 MB limit, so it was refused.");
      return;
    }
    this.emit("file-start", { id: inc.id, name: inc.name, size: inc.size, type: inc.type });
  }

  async _rejectIncoming(inc, reason, message) {
    inc.failed = true;
    inc.done = true;
    inc.parts = [];
    this.emit("file-failed", { id: inc.id, name: inc.name, reason, message });
    await this._sendEnc({ k: "receipt", id: inc.id, ok: false });
  }

  async _onChunk(frame) {
    if (this.dead) return;
    if (this.isA || !this.verified) return; // nothing should arrive here; ignore
    if (frame.length < FRAME_HEADER_BYTES || frame[0] !== PROTOCOL_VERSION) throw new SecureLinkError("protocol", "Malformed data.");
    const inc = this._incoming;
    const idB64 = b64u(frame.subarray(1, 17));
    if (!inc || inc.id !== idB64) throw new SecureLinkError("protocol", "Data arrived for an unknown file.");
    if (inc.failed) return; // rest of a rejected file
    const index = new DataView(frame.buffer, frame.byteOffset + 17, 4).getUint32(0);
    if (index !== inc.next || index >= inc.chunks) {
      await this._rejectIncoming(inc, "integrity", "Parts of this file arrived out of order or were missing, so it was discarded.");
      return;
    }
    let plain;
    try {
      plain = new Uint8Array(await subtle().decrypt(
        { name: "AES-GCM", iv: concat(inc.prefix, u32(index)), additionalData: chunkAad(inc.id, index, inc.chunks) },
        this.keys.ab, frame.subarray(FRAME_HEADER_BYTES)
      ));
    } catch {
      await this._rejectIncoming(inc, "integrity", "This file was changed on the way, so it failed its security check and was discarded.");
      return;
    }
    const expectedLen = Math.max(0, Math.min(CHUNK_SIZE, inc.size - index * CHUNK_SIZE));
    if (plain.length !== expectedLen) {
      await this._rejectIncoming(inc, "integrity", "This file's size didn't match what was announced, so it was discarded.");
      return;
    }
    inc.parts.push(plain);
    inc.bytes += plain.length;
    inc.next = index + 1;
    const last = inc.next === inc.chunks;
    if (last || inc.next % ACK_EVERY === 0) {
      this._relay({ t: "ack", id: inc.id, n: inc.next });
      this.emit("file-progress", { id: inc.id, bytes: inc.bytes, size: inc.size });
    }
    if (last) {
      inc.done = true;
      const parts = inc.parts;
      inc.parts = [];
      this.emit("file-received", { id: inc.id, name: inc.name, size: inc.size, type: inc.type, parts });
      await this._sendEnc({ k: "receipt", id: inc.id, ok: true });
    }
  }
}
