import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import selfsignedPkg from "selfsigned";
import { startServer, makeClient, memFile, randomData, joined, InsecureWS, CHUNK_SIZE } from "./helpers.mjs";
import { MAX_FILE_BYTES, b64u, unb64u, buildJoinUrl, parseJoinFragment, randomBytes } from "../src/protocol.mjs";
import { createMitmInterceptor } from "../tools/mitm-relay.mjs";

const require = createRequire(import.meta.url);
const selfsigned = selfsignedPkg.generate ? selfsignedPkg : require("selfsigned");

/** Pair a sender and receiver. mode: "sas" (people compare numbers) or "qr". */
async function connectPair(s, { mode = "sas", qrSecret, WebSocketImpl } = {}) {
  const sender = makeClient({ url: s.wsUrl, role: "send", name: "Laptop", WebSocketImpl });
  await sender.connect();
  const { code, secret } = await sender.next("code");
  const receiver = makeClient({
    url: s.wsUrl, role: "receive", name: "Phone", WebSocketImpl,
    qrSecret: mode === "qr" ? (qrSecret || secret) : null,
  });
  await receiver.connect();
  receiver.join(code);
  return { sender, receiver, code, secret };
}

async function verifyBySas(sender, receiver) {
  const [a, b] = await Promise.all([sender.next("sas"), receiver.next("sas")]);
  await sender.confirmSas(true);
  await receiver.confirmSas(true);
  await Promise.all([sender.next("verified"), receiver.next("verified")]);
  return [a.sas, b.sas];
}

test("people see the same 6-digit number, and files arrive byte-for-byte", async () => {
  const s = await startServer();
  const { sender, receiver } = await connectPair(s);
  const [sasA, sasB] = await verifyBySas(sender, receiver);
  assert.match(sasA, /^\d{6}$/);
  assert.equal(sasA, sasB);

  const files = [
    memFile("hello.txt", new TextEncoder().encode("This is a test file for SecureLink."), "text/plain"),
    memFile("empty.bin", new Uint8Array(0)),
    memFile("exact.bin", randomData(CHUNK_SIZE * 3)),
    memFile("photo.jpg", randomData(3 * 1024 * 1024 + 123), "image/jpeg"),
  ];
  const ids = sender.sendFiles(files);
  for (let i = 0; i < files.length; i++) {
    const got = await receiver.next("file-received", 15000);
    assert.equal(got.id, ids[i]);
    assert.equal(got.name, files[i].name);
    assert.equal(got.size, files[i].size);
    assert.deepEqual(joined(got.parts), await files[i].read(0, files[i].size));
    const delivered = await sender.next("file-delivered", 15000);
    assert.equal(delivered.id, ids[i]);
  }
  // Progress on the sender comes from the receiver's acknowledgements.
  const progress = sender.all("file-progress").filter((p) => p.id === ids[3]);
  assert.ok(progress.length > 3);
  assert.equal(progress.at(-1).bytes, files[3].size);
  // Dangerous types are neutralised before they reach the page.
  sender.sendFiles([memFile("x.html", new Uint8Array([60]), "text/html")]);
  assert.equal((await receiver.next("file-received")).type, "application/octet-stream");
  sender.close();
  await receiver.next("peer-left");
  await s.close();
});

test("scanning the QR code verifies the devices without comparing numbers", async () => {
  const s = await startServer();
  const { sender, receiver } = await connectPair(s, { mode: "qr" });
  const [a, b] = await Promise.all([sender.next("verified"), receiver.next("verified")]);
  assert.equal(a.mode, "qr");
  assert.equal(b.mode, "qr");
  assert.equal(sender.all("sas").length, 0);
  sender.sendFiles([memFile("a.txt", new TextEncoder().encode("hi"))]);
  assert.equal((await receiver.next("file-received")).name, "a.txt");
  await s.close();
});

test("a QR link with the wrong secret is rejected", async () => {
  const s = await startServer();
  const { sender, receiver } = await connectPair(s, { mode: "qr", qrSecret: randomBytes(32) });
  const err = await sender.next("error");
  assert.equal(err.code, "qr-mismatch");
  await receiver.next("peer-left");
  assert.equal(receiver.verified, false);
  await s.close();
});

test("saying the numbers don't match stops both devices", async () => {
  const s = await startServer();
  const { sender, receiver } = await connectPair(s);
  await Promise.all([sender.next("sas"), receiver.next("sas")]);
  await receiver.confirmSas(false);
  assert.equal((await receiver.next("error")).code, "sas-mismatch");
  assert.equal((await sender.next("error")).code, "peer-cancelled");
  assert.equal(sender.verified, false);
  await s.close();
});

test("nothing is sent until both people confirm", async () => {
  const s = await startServer();
  const { sender, receiver } = await connectPair(s);
  await Promise.all([sender.next("sas"), receiver.next("sas")]);
  sender.sendFiles([memFile("wait.txt", new Uint8Array([1, 2, 3]))]);
  await sender.confirmSas(true);
  await receiver.next("peer-confirmed");
  await new Promise((r) => setTimeout(r, 150));
  assert.equal(receiver.all("file-start").length, 0);
  await receiver.confirmSas(true);
  assert.equal((await receiver.next("file-received")).name, "wait.txt");
  await s.close();
});

test("a chunk changed in transit is detected; the next file still goes through", async () => {
  const s = await startServer({ tamperNextChunk: true });
  const { sender, receiver } = await connectPair(s);
  await verifyBySas(sender, receiver);
  sender.sendFiles([memFile("bad.bin", randomData(CHUNK_SIZE * 40)), memFile("good.txt", new TextEncoder().encode("ok"))]);
  const failed = await receiver.next("file-failed", 10000);
  assert.equal(failed.reason, "integrity");
  assert.equal((await sender.next("file-failed", 10000)).reason, "rejected");
  assert.equal(receiver.all("file-received").length, 0);
  const good = await receiver.next("file-received", 10000);
  assert.equal(good.name, "good.txt");
  assert.equal((await sender.next("file-delivered")).name, "good.txt");
  await s.close();
});

test("files over the size limit are refused before reading", async () => {
  const s = await startServer();
  const { sender, receiver } = await connectPair(s);
  await verifyBySas(sender, receiver);
  let reads = 0;
  sender.sendFiles([{ name: "huge.iso", size: MAX_FILE_BYTES + 1, type: "", read: async () => { reads++; return new Uint8Array(0); } }]);
  assert.equal((await sender.next("file-failed")).reason, "too-large");
  assert.equal(reads, 0);
  await s.close();
});

test("a man-in-the-middle relay is exposed by the numbers and by the QR proof", async () => {
  const seen = [];
  const captured = [];
  const s = await startServer({ interceptor: createMitmInterceptor({ log: () => {}, onSas: (x) => seen.push(x), onCapture: (c) => captured.push(c) }) });

  // 1. Comparing numbers: they differ, so careful people stop here.
  const p1 = await connectPair(s);
  const [a, b] = await Promise.all([p1.sender.next("sas"), p1.receiver.next("sas")]);
  assert.notEqual(a.sas, b.sas);
  assert.deepEqual(seen[0], { sender: a.sas, receiver: b.sas });

  // 2. Ignoring the mismatch lets the attacker read the file (why the check matters).
  await p1.sender.confirmSas(true);
  await p1.receiver.confirmSas(true);
  await Promise.all([p1.sender.next("verified"), p1.receiver.next("verified")]);
  const secretText = new TextEncoder().encode("exam answers");
  p1.sender.sendFiles([memFile("secret.txt", secretText)]);
  await p1.receiver.next("file-received");
  assert.deepEqual(captured[0].bytes, secretText);

  // 3. With the QR code, the attack is detected automatically.
  const p2 = await connectPair(s, { mode: "qr" });
  assert.equal((await p2.sender.next("error")).code, "qr-mismatch");
  assert.equal(p2.sender.verified, false);
  await s.close();
});

test("works over HTTPS (wss://) with a self-signed certificate", async () => {
  const pems = selfsigned.generate([{ name: "commonName", value: "test" }], { keySize: 2048, days: 1 });
  const s = await startServer({ tls: { key: pems.private, cert: pems.cert } });
  const { sender, receiver } = await connectPair(s, { mode: "qr", WebSocketImpl: InsecureWS });
  await Promise.all([sender.next("verified"), receiver.next("verified")]);
  sender.sendFiles([memFile("tls.txt", new TextEncoder().encode("over tls"))]);
  assert.equal((await receiver.next("file-received")).name, "tls.txt");
  await s.close();
});

test("QR join links round-trip and reject anything malformed", () => {
  const secret = randomBytes(32);
  const url = buildJoinUrl("https://192.168.1.5:3443", "012345", secret);
  const parsed = parseJoinFragment(new URL(url).hash);
  assert.equal(parsed.code, "012345");
  assert.deepEqual(parsed.secret, secret);
  assert.equal(parseJoinFragment("#join=12345.abc"), null);
  assert.equal(parseJoinFragment("#join=123456." + b64u(randomBytes(16))), null);
  assert.equal(parseJoinFragment(""), null);
  assert.deepEqual(unb64u(b64u(new Uint8Array([0, 255, 128]))), new Uint8Array([0, 255, 128]));
});
