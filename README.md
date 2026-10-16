# SecureLink

Send files between your own devices on the same Wi-Fi, end-to-end encrypted.
IT 021 Usable Security, Group 4 (IT31S4).

## Run it

Requires Node.js 18.17 or newer.

```bash
npm install
npm start
```

The terminal prints the addresses to open:

```
SecureLink is running.
  On this computer:  https://localhost:3443
  On your phone:     https://192.168.1.23:3443   (same Wi-Fi)
```

1. Open the **On your phone** address on both devices (the laptop can use either address).
2. The first visit shows a certificate warning because the certificate is self-signed.
   The terminal prints its SHA-256 fingerprint so you can check it is really your computer,
   then choose "Advanced", then "Proceed" (Chrome) or "Show details", then "visit this website" (Safari).
3. On the sending device tap **Send**, pick files, then **Continue**.
4. On the receiving device either scan the QR code with the camera, or tap **Receive** and type the code.
5. If you typed the code, check that both screens show the same 6-digit number and tap
   **The numbers match** on both. With the QR code this check happens automatically.

If a phone can't open the page, allow port 3443 through the computer's firewall.
The old address `http://…:3000` redirects to HTTPS.

## How it protects a transfer

| Threat | Protection |
| --- | --- |
| Someone on the Wi-Fi reads the traffic | HTTPS/WSS to the server, and every file is encrypted on the sending device with AES-256-GCM |
| The relay server reads files | Keys are agreed between the two browsers with ECDH (P-256). The pairing code is only a routing ticket and is never used as a key |
| Man in the middle swaps keys | Both screens show a verification number derived from both keys. The sender commits to its key first, so an attacker can't search for matching numbers (1 in a million chance per try). Scanning the QR code verifies automatically, using a secret in the link that the server never sees |
| Guessing the code | Codes are random, single-use and expire after 3 minutes. 5 wrong codes close the connection; 10 from one address lock it out for 10 minutes |
| Changing a file in transit | Every 64 KiB piece is authenticated with its file ID, position and piece count. Changed, missing, reordered or truncated data is rejected and the file is discarded |
| A fake "sent" message | The sender shows **Delivered** only after an encrypted receipt from the receiver |
| Another site's page connecting to the server | The server rejects WebSocket connections from other origins |
| Crashing the server | Every message is validated; oversized messages close only that connection |

File names and types are encrypted too. Received HTML, SVG and script files are saved as plain downloads and never opened in the page.

## Demos for the presentation

```bash
npm run demo:tamper   # the relay corrupts one piece of the next file: the receiver rejects it
npm run demo:mitm     # a malicious relay swaps keys: the two screens show different numbers
```

In the man-in-the-middle demo, tapping **They're different** stops everything. If both people tap
**The numbers match** without looking, the relay can read the file and saves it in `mitm-captured/`,
which shows why the check matters. Joining with the QR code defeats the attack automatically.

## Development

```bash
npm run build   # rebuilds public/tailwind.output.css and public/app.bundle.js
npm test        # 21 tests: server limits, end-to-end transfers, tampering, MITM, HTTPS
npm run start:http   # plain HTTP, for this computer only (browsers block encryption elsewhere)
```

| Path | Contents |
| --- | --- |
| `server/app.js` | Express + WebSocket relay: sessions, codes, limits, security headers |
| `server/index.js` | Command-line start, HTTPS and the redirect from port 3000 |
| `server/cert.js` | Creates the self-signed certificate in `certs/` |
| `src/protocol.mjs` | Pairing, key agreement, verification and encrypted transfer (browser and Node) |
| `src/main.jsx` | The interface (React + Tailwind) |
| `tools/mitm-relay.mjs` | The malicious relay for the demo and tests |
| `test/` | Automated tests (`node --test`) |

## Known limits

- The certificate is self-signed, so each device shows a warning once per certificate.
- The verification number protects you only if people actually compare it. The QR code avoids that step.
- Device names are labels chosen by each device. The verification number, not the name, proves who is connected.
- The server can still see when a transfer happens and roughly how large it is.
- Files are limited to 250 MB each, because the receiving browser keeps them in memory until saved.
