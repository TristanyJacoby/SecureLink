// Creates (once) a self-signed HTTPS certificate for this computer's local
// addresses, so phones on the same Wi-Fi get a secure page. Browsers only
// allow the Web Crypto API on secure (https or localhost) pages.
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const selfsigned = require("selfsigned");

const CERT_DIR = path.join(__dirname, "..", "certs");

function loadOrCreateCert(ips) {
  const keyPath = path.join(CERT_DIR, "key.pem");
  const certPath = path.join(CERT_DIR, "cert.pem");
  const metaPath = path.join(CERT_DIR, "meta.json");
  try {
    const meta = JSON.parse(fs.readFileSync(metaPath, "utf8"));
    const fresh = Date.now() - meta.created < 300 * 24 * 3600 * 1000;
    const coversIps = ips.every((ip) => meta.ips.includes(ip));
    if (fresh && coversIps && fs.existsSync(keyPath) && fs.existsSync(certPath)) {
      const cert = fs.readFileSync(certPath, "utf8");
      return { key: fs.readFileSync(keyPath, "utf8"), cert, fingerprint: fingerprint(cert), created: false };
    }
  } catch {}

  const allIps = Array.from(new Set(["127.0.0.1", ...ips]));
  const pems = selfsigned.generate([{ name: "commonName", value: "SecureLink local server" }], {
    keySize: 2048,
    days: 365,
    algorithm: "sha256",
    extensions: [
      { name: "basicConstraints", cA: false },
      { name: "keyUsage", digitalSignature: true, keyEncipherment: true },
      { name: "extKeyUsage", serverAuth: true },
      { name: "subjectAltName", altNames: [{ type: 2, value: "localhost" }, ...allIps.map((ip) => ({ type: 7, ip }))] },
    ],
  });
  fs.mkdirSync(CERT_DIR, { recursive: true });
  fs.writeFileSync(keyPath, pems.private, { mode: 0o600 });
  fs.writeFileSync(certPath, pems.cert);
  fs.writeFileSync(metaPath, JSON.stringify({ ips: allIps, created: Date.now() }));
  return { key: pems.private, cert: pems.cert, fingerprint: fingerprint(pems.cert), created: true };
}

function fingerprint(certPem) {
  try { return new crypto.X509Certificate(certPem).fingerprint256; } catch { return ""; }
}

module.exports = { loadOrCreateCert };
