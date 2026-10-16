// SecureLink relay server.
// It pairs two devices with a short-lived, single-use code and then forwards
// their messages. It never sees keys or file contents: the browsers agree on
// keys with ECDH and verify each other themselves (see src/protocol.mjs).
const http = require("http");
const https = require("https");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const express = require("express");
const WebSocket = require("ws");

const PUBLIC_DIR = path.join(__dirname, "..", "public");

const DEFAULTS = {
  codeTtlMs: 3 * 60 * 1000, // a code works for 3 minutes, once
  maxJoinFailuresPerSocket: 5, // then that connection is closed
  maxJoinFailuresPerIp: 10, // per ipWindowMs, then the address is locked out
  ipWindowMs: 10 * 60 * 1000,
  ipLockMs: 10 * 60 * 1000,
  maxCreatesPerIpPerMinute: 10,
  maxConnectionsPerIp: 20,
  maxRooms: 200,
  maxPayloadBytes: 256 * 1024, // one encrypted 64 KiB chunk plus headroom
  maxRelayJsonBytes: 16 * 1024,
  heartbeatMs: 30 * 1000,
  tamperNextChunk: false, // demo: corrupt one forwarded chunk (shows the integrity check)
  interceptor: null, // demo/tests only: { relay(ctx), binary(ctx) } acting as a man in the middle
  log: (...a) => console.log(...a),
};

function lanAddresses() {
  return Object.values(os.networkInterfaces())
    .flat()
    .filter((a) => a && (a.family === "IPv4" || a.family === 4) && !a.internal)
    .map((a) => a.address);
}

function cleanName(name) {
  const s = typeof name === "string" ? name.replace(/[\u0000-\u001f\u007f]/g, "").trim().slice(0, 40) : "";
  return s || "Unnamed device";
}

function securityHeaders(req, res, next) {
  const host = String(req.headers.host || "").replace(/[^A-Za-z0-9.:[\]-]/g, "");
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self'",
      "img-src 'self' data: blob:",
      `connect-src 'self' wss://${host} ws://${host}`,
      "object-src 'none'",
      "base-uri 'none'",
      "form-action 'none'",
      "frame-ancestors 'none'",
    ].join("; ")
  );
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader("Cache-Control", "no-store");
  next();
}

function createSecureLinkServer(options = {}) {
  const opt = { ...DEFAULTS, ...options };
  const log = opt.log;

  // ---------- HTTP ----------
  const app = express();
  app.disable("x-powered-by");
  app.use(securityHeaders);
  app.get("/api/info", (req, res) => {
    const port = server.address() && server.address().port;
    const scheme = opt.tls ? "https" : "http";
    res.json({ version: 2, secure: !!opt.tls, lanUrls: lanAddresses().map((ip) => `${scheme}://${ip}:${port}`) });
  });
  const sendApp = (req, res) => res.sendFile(path.join(PUBLIC_DIR, "app.html"));
  app.get("/", sendApp);
  app.use(express.static(PUBLIC_DIR, { index: false }));

  const server = opt.tls ? https.createServer(opt.tls, app) : http.createServer(app);

  // ---------- state ----------
  const rooms = new Map(); // id -> room
  const codes = new Map(); // code -> room
  const ipStats = new Map(); // ip -> { conns, failures: [times], lockedUntil, creates: [times] }
  let tamperArmed = !!opt.tamperNextChunk;

  const statFor = (ip) => {
    let s = ipStats.get(ip);
    if (!s) { s = { conns: 0, failures: [], lockedUntil: 0, creates: [] }; ipStats.set(ip, s); }
    return s;
  };

  const send = (ws, obj) => {
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
  };

  function newCode() {
    for (let i = 0; i < 50; i++) {
      const c = String(crypto.randomInt(0, 1000000)).padStart(6, "0");
      if (!codes.has(c)) return c;
    }
    return null;
  }

  function issueCode(room) {
    if (room.code) codes.delete(room.code);
    clearTimeout(room.timer);
    const code = newCode();
    if (!code) return false;
    room.code = code;
    codes.set(code, room);
    room.timer = setTimeout(() => {
      if (room.code === code) {
        codes.delete(code);
        room.code = null;
        send(room.sender, { type: "code-expired" });
      }
    }, opt.codeTtlMs);
    if (room.timer.unref) room.timer.unref();
    send(room.sender, { type: "created", code, ttl: Math.round(opt.codeTtlMs / 1000) });
    return true;
  }

  function teardown(ws, notifyPeer = true) {
    const room = ws.room;
    if (!room) return;
    clearTimeout(room.timer);
    if (room.code) codes.delete(room.code);
    rooms.delete(room.id);
    const peer = room.sender === ws ? room.receiver : room.sender;
    if (peer) {
      peer.room = null;
      if (notifyPeer) send(peer, { type: "peer-left" });
    }
    ws.room = null;
    log(`[session] ended (${rooms.size} active)`);
  }

  function recordFailure(ws, stat) {
    const now = Date.now();
    ws.failures += 1;
    stat.failures = stat.failures.filter((t) => now - t < opt.ipWindowMs);
    stat.failures.push(now);
    if (stat.failures.length >= opt.maxJoinFailuresPerIp) {
      stat.lockedUntil = now + opt.ipLockMs;
      stat.failures = [];
      log(`[security] ${ws.ip} locked out after repeated wrong codes`);
    }
  }

  // ---------- handlers ----------
  function onCreate(ws, msg) {
    if (ws.room) return send(ws, { type: "error", reason: "already-in-session" });
    const stat = statFor(ws.ip);
    const now = Date.now();
    stat.creates = stat.creates.filter((t) => now - t < 60 * 1000);
    if (stat.creates.length >= opt.maxCreatesPerIpPerMinute) return send(ws, { type: "error", reason: "rate-limited" });
    if (rooms.size >= opt.maxRooms) return send(ws, { type: "error", reason: "busy" });
    stat.creates.push(now);
    const room = { id: crypto.randomUUID(), code: null, timer: null, sender: ws, receiver: null };
    ws.name = cleanName(msg.name);
    ws.room = room;
    ws.role = "sender";
    rooms.set(room.id, room);
    if (!issueCode(room)) { teardown(ws, false); return send(ws, { type: "error", reason: "busy" }); }
    log(`[session] created (${rooms.size} active)`);
  }

  function onRenew(ws) {
    const room = ws.room;
    if (!room || ws.role !== "sender" || room.receiver) return;
    issueCode(room);
  }

  function onJoin(ws, msg) {
    if (ws.room) return send(ws, { type: "join-failed", reason: "already-in-session" });
    const stat = statFor(ws.ip);
    const now = Date.now();
    if (stat.lockedUntil > now) {
      return send(ws, { type: "join-failed", reason: "locked", retryAfter: Math.ceil((stat.lockedUntil - now) / 1000) });
    }
    const code = typeof msg.code === "string" ? msg.code : "";
    const room = /^\d{6}$/.test(code) ? codes.get(code) : null;
    if (!room || room.receiver) {
      recordFailure(ws, stat);
      const attemptsLeft = Math.max(0, opt.maxJoinFailuresPerSocket - ws.failures);
      if (stat.lockedUntil > Date.now()) {
        send(ws, { type: "join-failed", reason: "locked", retryAfter: Math.ceil(opt.ipLockMs / 1000) });
      } else {
        send(ws, { type: "join-failed", reason: "invalid", attemptsLeft });
      }
      if (attemptsLeft === 0) ws.close(1008, "too many wrong codes");
      return;
    }
    // Single use: the code stops working the moment someone joins.
    codes.delete(code);
    clearTimeout(room.timer);
    room.code = null;
    room.receiver = ws;
    ws.room = room;
    ws.role = "receiver";
    ws.name = cleanName(msg.name);
    send(room.sender, { type: "paired", peerName: ws.name });
    send(ws, { type: "paired", peerName: room.sender.name });
    log("[session] devices paired");
  }

  function onRelay(ws, msg, rawLength) {
    const room = ws.room;
    if (!room || !room.receiver) return;
    if (!msg.body || typeof msg.body !== "object" || Array.isArray(msg.body)) return;
    if (rawLength > opt.maxRelayJsonBytes) return;
    const peer = room.sender === ws ? room.receiver : room.sender;
    if (opt.interceptor) return intercept(room, () => opt.interceptor.relay({ room, from: ws.role, body: msg.body, send: (b) => send(peer, { type: "relay", body: b }) }));
    send(peer, { type: "relay", body: msg.body });
  }

  // Keeps intercepted messages in order (the interceptor is async).
  function intercept(room, fn) {
    room.chain = (room.chain || Promise.resolve()).then(fn).catch((err) => log("[interceptor]", err && err.message));
  }

  function onBinary(ws, data) {
    const room = ws.room;
    if (!room || !room.receiver) return; // unpaired clients cannot push data
    const peer = room.sender === ws ? room.receiver : room.sender;
    if (!peer || peer.readyState !== WebSocket.OPEN) return;
    if (opt.interceptor) {
      return intercept(room, () => opt.interceptor.binary({ room, from: ws.role, data, send: (buf) => peer.readyState === WebSocket.OPEN && peer.send(buf, { binary: true }) }));
    }
    let out = data;
    if (tamperArmed && data.length > 22) {
      out = Buffer.from(data);
      out[22] ^= 0x01; // flip one bit of the ciphertext
      tamperArmed = false;
      log("[demo] tampered with one forwarded chunk");
    }
    peer.send(out, { binary: true });
  }

  // ---------- WebSocket ----------
  const wss = new WebSocket.Server({
    server,
    maxPayload: opt.maxPayloadBytes,
    verifyClient: (info, done) => {
      // Browsers always send Origin; refuse pages from other sites (cross-site WebSocket hijacking).
      const origin = info.origin || info.req.headers.origin;
      if (origin) {
        let originHost = "";
        try { originHost = new URL(origin).host; } catch {}
        if (originHost !== info.req.headers.host) return done(false, 403, "Forbidden origin");
      }
      const ip = info.req.socket.remoteAddress || "unknown";
      if (statFor(ip).conns >= opt.maxConnectionsPerIp) return done(false, 429, "Too many connections");
      done(true);
    },
  });

  wss.on("connection", (ws, req) => {
    ws.ip = req.socket.remoteAddress || "unknown";
    ws.failures = 0;
    ws.room = null;
    ws.isAlive = true;
    statFor(ws.ip).conns += 1;

    ws.on("pong", () => { ws.isAlive = true; });

    ws.on("message", (data, isBinary) => {
      try {
        if (isBinary) return onBinary(ws, data);
        let msg;
        try { msg = JSON.parse(data.toString()); } catch { return; }
        if (!msg || typeof msg !== "object" || typeof msg.type !== "string") return;
        switch (msg.type) {
          case "create": return onCreate(ws, msg);
          case "renew": return onRenew(ws);
          case "join": return onJoin(ws, msg);
          case "relay": return onRelay(ws, msg, data.length);
          case "leave": return teardown(ws);
          default: return;
        }
      } catch (err) {
        log("[error] message handler:", err && err.message);
      }
    });

    ws.on("error", () => {}); // e.g. payload too large: ws closes the socket itself
    ws.on("close", () => {
      statFor(ws.ip).conns -= 1;
      teardown(ws);
    });
  });

  const heartbeat = setInterval(() => {
    for (const ws of wss.clients) {
      if (!ws.isAlive) { ws.terminate(); continue; }
      ws.isAlive = false;
      try { ws.ping(); } catch {}
    }
  }, opt.heartbeatMs);
  if (heartbeat.unref) heartbeat.unref();
  wss.on("close", () => clearInterval(heartbeat));

  return {
    server,
    wss,
    stats: () => ({ rooms: rooms.size, codes: codes.size }),
    armTamper: () => { tamperArmed = true; },
    close: () => new Promise((resolve) => {
      clearInterval(heartbeat);
      for (const ws of wss.clients) ws.terminate();
      wss.close(() => server.close(() => resolve()));
    }),
  };
}

module.exports = { createSecureLinkServer, lanAddresses };
