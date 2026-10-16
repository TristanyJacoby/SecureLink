import { test } from "node:test";
import assert from "node:assert/strict";
import { startServer, rawClient, sleep } from "./helpers.mjs";

async function pair(s) {
  const a = rawClient(s.wsUrl); await a.opened;
  a.json({ type: "create", name: "Laptop" });
  const { code } = await a.next("created");
  const b = rawClient(s.wsUrl); await b.opened;
  b.json({ type: "join", code, name: "Phone" });
  await a.next("paired"); await b.next("paired");
  return { a, b, code };
}

test("pairing code is 6 digits, pairs both sides, and works only once", async () => {
  const s = await startServer();
  const a = rawClient(s.wsUrl); await a.opened;
  a.json({ type: "create", name: "Laptop" });
  const created = await a.next("created");
  assert.match(created.code, /^\d{6}$/);
  assert.equal(created.ttl, 180);

  const b = rawClient(s.wsUrl); await b.opened;
  b.json({ type: "join", code: created.code, name: "Phone" });
  assert.equal((await a.next("paired")).peerName, "Phone");
  assert.equal((await b.next("paired")).peerName, "Laptop");

  const c = rawClient(s.wsUrl); await c.opened;
  c.json({ type: "join", code: created.code, name: "Intruder" });
  assert.equal((await c.next("join-failed")).reason, "invalid");
  await s.close();
});

test("wrong codes are limited per connection, then the connection is closed", async () => {
  const s = await startServer();
  const a = rawClient(s.wsUrl); await a.opened;
  a.json({ type: "create" });
  const { code } = await a.next("created");
  const wrong = code === "000000" ? "000001" : "000000";
  const g = rawClient(s.wsUrl); await g.opened;
  const left = [];
  for (let i = 0; i < 5; i++) {
    g.json({ type: "join", code: wrong });
    left.push((await g.next("join-failed")).attemptsLeft);
  }
  assert.deepEqual(left, [4, 3, 2, 1, 0]);
  assert.equal(await g.closed, 1008);
  await s.close();
});

test("an address that keeps guessing is locked out, even across connections", async () => {
  const s = await startServer({ maxJoinFailuresPerIp: 6 });
  let last;
  for (let conn = 0; conn < 2 && !(last && last.reason === "locked"); conn++) {
    const g = rawClient(s.wsUrl); await g.opened;
    for (let i = 0; i < 3; i++) {
      g.json({ type: "join", code: "123456" });
      last = await g.next("join-failed");
    }
  }
  assert.equal(last.reason, "locked");
  // Even the right code is refused while locked.
  const a = rawClient(s.wsUrl); await a.opened;
  a.json({ type: "create" });
  const { code } = await a.next("created");
  const g2 = rawClient(s.wsUrl); await g2.opened;
  g2.json({ type: "join", code });
  const r = await g2.next("join-failed");
  assert.equal(r.reason, "locked");
  assert.ok(r.retryAfter > 0);
  await s.close();
});

test("codes expire, and renewing replaces the old code", async () => {
  const s = await startServer({ codeTtlMs: 150 });
  const a = rawClient(s.wsUrl); await a.opened;
  a.json({ type: "create" });
  const first = await a.next("created");
  await a.next("code-expired");
  const b = rawClient(s.wsUrl); await b.opened;
  b.json({ type: "join", code: first.code });
  assert.equal((await b.next("join-failed")).reason, "invalid");

  a.json({ type: "renew" });
  const second = await a.next("created");
  b.json({ type: "join", code: second.code });
  await b.next("paired");
  await s.close();
});

test("a connected device cannot hijack a session by creating again", async () => {
  const s = await startServer();
  const { a, b } = await pair(s);
  a.json({ type: "create" });
  assert.equal((await a.next("error")).reason, "already-in-session");
  b.json({ type: "create" });
  assert.equal((await b.next("error")).reason, "already-in-session");
  await s.close();
});

test("unpaired clients cannot send or receive data", async () => {
  const s = await startServer();
  const { a, b } = await pair(s);
  const lurker = rawClient(s.wsUrl); await lurker.opened;
  lurker.send(Buffer.from([2, 1, 2, 3]));
  lurker.json({ type: "relay", body: { t: "enc", iv: "x", ct: "y" } });
  a.send(Buffer.from([2, 9, 9, 9]));
  await sleep(100);
  assert.equal(lurker.bins.length, 0);
  assert.equal(lurker.msgs.length, 0);
  assert.equal(b.bins.length, 1);
  assert.equal(b.msgs.filter((m) => m.type === "relay").length, 0);
  await s.close();
});

test("two sessions are kept apart", async () => {
  const s = await startServer();
  const one = await pair(s);
  const two = await pair(s);
  assert.notEqual(one.code, two.code);
  one.a.send(Buffer.from([2, 1]));
  one.a.json({ type: "relay", body: { t: "ack", id: "x", n: 1 } });
  await sleep(100);
  assert.equal(one.b.bins.length, 1);
  assert.equal(one.b.msgs.filter((m) => m.type === "relay").length, 1);
  assert.equal(two.a.bins.length + two.b.bins.length, 0);
  assert.equal(two.b.msgs.filter((m) => m.type === "relay").length, 0);
  await s.close();
});

test("malformed and oversized messages do not crash the server", async () => {
  const s = await startServer();
  const x = rawClient(s.wsUrl); await x.opened;
  x.send("not json");
  x.send("[]");
  x.send(JSON.stringify({ type: "file", filename: "crash" })); // the message that crashed v1
  x.send(JSON.stringify({ type: "relay" }));
  x.send(JSON.stringify({ type: "join", code: { $ne: 1 } }));
  x.send(JSON.stringify({ type: 42 }));
  await sleep(50);
  const big = rawClient(s.wsUrl); await big.opened;
  big.send(Buffer.alloc(300 * 1024));
  await big.closed; // ws closes it with 1009
  const { b } = await pair(s); // still works
  assert.ok(b);
  await s.close();
});

test("pages from another site cannot open a WebSocket to the server", async () => {
  const s = await startServer();
  const evil = rawClient(s.wsUrl, { origin: "https://evil.example" });
  await assert.rejects(evil.opened, /403/);
  const same = rawClient(s.wsUrl, { origin: s.httpUrl });
  await same.opened;
  await s.close();
});

test("closing one side tells the other and frees the session", async () => {
  const s = await startServer();
  const { a, b } = await pair(s);
  a.close();
  await b.next("peer-left");
  await sleep(50);
  assert.deepEqual(s.stats(), { rooms: 0, codes: 0 });
  b.json({ type: "create" }); // b can start fresh
  await b.next("created");
  await s.close();
});

test("pages are served with security headers, and codes are never logged", async () => {
  const lines = [];
  const s = await startServer({ log: (...a) => lines.push(a.join(" ")) });
  const res = await fetch(`${s.httpUrl}/`);
  assert.equal(res.status, 200);
  const csp = res.headers.get("content-security-policy");
  assert.match(csp, /script-src 'self'/);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.equal(res.headers.get("x-content-type-options"), "nosniff");
  assert.equal(res.headers.get("referrer-policy"), "no-referrer");
  const info = await (await fetch(`${s.httpUrl}/api/info`)).json();
  assert.equal(info.version, 2);
  const { code } = await pair(s);
  assert.ok(!lines.join("\n").includes(code));
  await s.close();
});
