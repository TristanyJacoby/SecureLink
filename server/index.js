// Starts SecureLink.
//   npm start                 HTTPS on port 3443 (+ redirect from http://…:3000)
//   npm start -- --http       plain HTTP on port 3000 (works only on this computer)
//   npm run demo:tamper       HTTPS, and the relay corrupts one file chunk in transit
const http = require("http");
const { createSecureLinkServer, lanAddresses } = require("./app");
const { loadOrCreateCert } = require("./cert");

const args = process.argv.slice(2);
const has = (f) => args.includes(f);
const val = (f, d) => { const i = args.indexOf(f); return i >= 0 && args[i + 1] ? Number(args[i + 1]) : d; };

const useHttp = has("--http");
const httpPort = val("--port", Number(process.env.PORT) || 3000);
const httpsPort = val("--https-port", Number(process.env.HTTPS_PORT) || 3443);
const tamper = has("--demo-tamper");

const ips = lanAddresses();
let tls = null;
let fingerprint = "";
if (!useHttp) {
  const c = loadOrCreateCert(ips);
  tls = { key: c.key, cert: c.cert };
  fingerprint = c.fingerprint;
  if (c.created) console.log("Created a new self-signed certificate in certs/.");
}

const sl = createSecureLinkServer({ tls, tamperNextChunk: tamper });
const port = useHttp ? httpPort : httpsPort;

sl.server.listen(port, () => {
  const scheme = useHttp ? "http" : "https";
  console.log("");
  console.log("SecureLink is running.");
  console.log(`  On this computer:  ${scheme}://localhost:${port}`);
  if (useHttp) {
    console.log("  Plain HTTP mode: other devices can't use encryption here. Run `npm start` for HTTPS.");
  } else {
    for (const ip of ips) console.log(`  On your phone:     ${scheme}://${ip}:${port}   (same Wi-Fi)`);
    console.log("");
    console.log("  The first visit shows a certificate warning because this certificate is");
    console.log("  self-signed. To check it is really this computer, its SHA-256 fingerprint is:");
    console.log(`  ${fingerprint}`);
  }
  if (tamper) console.log("\n  DEMO: the next file chunk relayed will be corrupted on purpose.");
  console.log("");
});

if (!useHttp) {
  // Anyone who types the old http://…:3000 address gets sent to HTTPS.
  const redirect = http.createServer((req, res) => {
    const host = String(req.headers.host || "localhost").split(":")[0].replace(/[^A-Za-z0-9.-]/g, "") || "localhost";
    res.writeHead(301, { Location: `https://${host}:${httpsPort}${req.url && req.url.startsWith("/") ? req.url : "/"}` });
    res.end();
  });
  redirect.on("error", (err) => console.log(`(Redirect from port ${httpPort} not started: ${err.code})`));
  redirect.listen(httpPort);
}

const stop = () => sl.close().then(() => process.exit(0));
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
