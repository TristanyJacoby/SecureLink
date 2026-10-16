import React, { useEffect, useReducer, useRef, useState, useCallback } from "react";
import { createRoot } from "react-dom/client";
import QRCode from "qrcode";
import {
  ShieldCheck, Lock, Upload, FileText, Check, ArrowLeft, TriangleAlert, Download, LoaderCircle,
  Smartphone, X, RefreshCw, Pencil, Send, Inbox, Plus, ShieldAlert, CircleCheck, ScanLine,
} from "lucide-react";
import {
  SecureLinkClient, MAX_FILE_BYTES, buildJoinUrl, parseJoinFragment,
} from "./protocol.mjs";

// ---------- helpers ----------

function formatBytes(bytes) {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  const v = bytes / Math.pow(1024, i);
  return `${i === 0 ? v : v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`;
}

function guessDeviceName() {
  const ua = navigator.userAgent;
  if (/iPhone/.test(ua)) return "iPhone";
  if (/iPad/.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1)) return "iPad";
  if (/Android/.test(ua)) return /Mobile/.test(ua) ? "Android phone" : "Android tablet";
  if (/Macintosh/.test(ua)) return "Mac";
  if (/Windows/.test(ua)) return "Windows PC";
  if (/CrOS/.test(ua)) return "Chromebook";
  if (/Linux/.test(ua)) return "Linux computer";
  return "This device";
}

const store = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch {} },
};

function fromBrowserFile(file) {
  return {
    name: file.name, size: file.size, type: file.type,
    read: (start, end) => file.slice(start, end).arrayBuffer().then((b) => new Uint8Array(b)),
  };
}

const isLocalHost = (h) => h === "localhost" || h === "127.0.0.1" || h === "[::1]";
const splitCode = (c) => (c ? `${c.slice(0, 3)} ${c.slice(3)}` : "");
const cryptoAvailable = () => !!(window.isSecureContext && window.crypto && window.crypto.subtle);

// ---------- state ----------

const initialState = {
  step: "home", // home | pick | host | join | connecting | verify | transfer | error
  role: null,
  code: null,
  codeExpiresAt: 0,
  codeExpired: false,
  qrSrc: null,
  joinUrl: null,
  peerName: "",
  sas: null,
  connectingText: "",
  localConfirmed: false,
  peerConfirmed: false,
  verifyMode: null,
  files: [],
  joinError: null,
  ended: null,
  fatal: null,
};

function updateFile(files, id, patch) {
  return files.map((f) => (f.id === id ? { ...f, ...patch } : f));
}

function reducer(s, a) {
  switch (a.type) {
    case "reset": return { ...initialState };
    case "go": return { ...s, step: a.step, role: a.role ?? s.role, joinError: null };
    case "code": return { ...s, step: "host", code: a.code, codeExpiresAt: a.expiresAt, codeExpired: false, qrSrc: a.qrSrc, joinUrl: a.joinUrl };
    case "code-expired": return { ...s, codeExpired: true };
    case "join-error": return { ...s, step: "join", joinError: a.text };
    case "connecting": return { ...s, step: "connecting", connectingText: a.text, peerName: a.peerName ?? s.peerName, joinError: null };
    case "sas": return { ...s, step: "verify", sas: a.sas, peerName: a.peerName };
    case "local-confirmed": return { ...s, localConfirmed: true };
    case "peer-confirmed": return { ...s, peerConfirmed: true };
    case "verified": return { ...s, step: "transfer", verifyMode: a.mode, sas: a.sas || s.sas, peerName: a.peerName || s.peerName };
    case "file-add":
      return s.files.some((f) => f.id === a.file.id) ? s : { ...s, files: [...s.files, a.file] };
    case "file-update": return { ...s, files: updateFile(s.files, a.id, a.patch) };
    case "ended": {
      const files = s.files.map((f) => (["waiting", "active", "confirming"].includes(f.status)
        ? { ...f, status: "failed", message: "The connection closed before this file finished." } : f));
      return { ...s, files, ended: a.ended };
    }
    case "fatal": return { ...s, step: "error", fatal: a.fatal };
    default: return s;
  }
}

const FATAL = {
  "sas-mismatch": ["Connection stopped", "You said the numbers were different. That can mean someone on this network tried to get between your devices, so nothing was sent. Start again, and if the numbers differ again, switch to another network."],
  "peer-cancelled": ["The other device saw different numbers", "The other person said the numbers didn't match, so the connection was stopped before anything was sent. Start again, and if it happens again, switch to another network."],
  "qr-mismatch": ["The QR check failed", "The device that joined couldn't prove it scanned your QR code, so nothing was sent. Start again. If it keeps happening, someone may be interfering with this network."],
  "commit-mismatch": ["Security check failed", "The other device's key didn't match what it promised, so nothing was sent. Someone may be interfering with this network."],
  tampered: ["Security check failed", "A message from the other device was changed on the way, so the connection was stopped."],
  version: ["Different SecureLink versions", "Both devices need to load SecureLink from the same server. Reload the page on both and try again."],
  unreachable: ["Can't reach SecureLink", "Check that SecureLink is still running on the computer and that this device is on the same Wi-Fi, then try again."],
  closed: ["Connection lost", "The connection to SecureLink closed. Check that it is still running on the computer and try again."],
  "peer-left": ["The other device left", "The connection closed before both devices were verified. Nothing was sent."],
  "rate-limited": ["Too many attempts", "This device started too many sessions in a short time. Wait a minute and try again."],
  busy: ["SecureLink is busy", "The server has too many sessions open right now. Try again in a moment."],
  "too-many-codes": ["Too many wrong codes", "This connection entered too many wrong codes. Ask the sender for a new code and start again."],
};
const fatalFor = (code, message) => {
  const [title, body] = FATAL[code] || ["Something went wrong", message || "Start again to try once more."];
  return { title, body };
};

// ---------- layout ----------

const FLOW = {
  send: ["Choose", "Pair", "Verify", "Send"],
  receive: ["Pair", "Verify", "Receive"],
};
const STEP_INDEX = {
  send: { pick: 0, host: 1, connecting: 1, verify: 2, transfer: 3 },
  receive: { join: 0, connecting: 0, verify: 1, transfer: 2 },
};

function Progress({ role, step }) {
  const labels = FLOW[role];
  const at = STEP_INDEX[role] ? STEP_INDEX[role][step] : undefined;
  if (!labels || at === undefined) return null;
  return (
    <ol className="flex gap-1.5 px-5 pb-1" aria-label="Progress">
      {labels.map((label, i) => (
        <li key={label} className="flex-1" aria-current={i === at ? "step" : undefined}>
          <div className={`h-1 rounded-full ${i <= at ? "bg-seal" : "bg-line"}`} />
          <div className={`mt-1.5 text-[0.75rem] ${i === at ? "font-semibold text-ink" : "text-muted"}`}>{label}</div>
        </li>
      ))}
    </ol>
  );
}

function Screen({ title, onBack, onClose, role, step, badge, children, actions }) {
  return (
    <div className="flex min-h-dvh w-full justify-center sm:items-center sm:px-6 sm:py-10">
      <main className="flex min-h-dvh w-full flex-col bg-surface sm:min-h-[44rem] sm:max-w-[27.5rem] sm:rounded-[2rem] sm:border sm:border-line sm:shadow-[0_24px_60px_-24px_rgba(16,35,28,0.25)]">
        <header className="pt-[max(0.5rem,env(safe-area-inset-top))]">
          <div className="flex h-14 items-center gap-1 px-2">
            {onBack ? (
              <button className="icon-btn" onClick={onBack} aria-label="Back"><ArrowLeft size={22} /></button>
            ) : <span className="w-11" />}
            <h1 className="flex-1 truncate text-center text-[1.0625rem] font-semibold">{title}</h1>
            {onClose ? (
              <button className="icon-btn" onClick={onClose} aria-label="Cancel and start over"><X size={22} /></button>
            ) : badge || <span className="w-11" />}
          </div>
          <Progress role={role} step={step} />
        </header>
        <div className="flex flex-1 flex-col px-5 pb-6 pt-5">{children}</div>
        {actions && (
          <footer className="sticky bottom-0 space-y-2.5 border-t border-line/70 bg-surface/95 px-5 pb-[max(1rem,env(safe-area-inset-bottom))] pt-3 backdrop-blur sm:rounded-b-[2rem]">
            {actions}
          </footer>
        )}
      </main>
    </div>
  );
}

function Spinner({ label }) {
  return (
    <div className="flex items-center gap-2.5 text-[0.9375rem] text-muted" role="status">
      <LoaderCircle size={18} className="animate-spin text-seal" aria-hidden="true" /> {label}
    </div>
  );
}

function Notice({ tone = "caution", icon: Icon = TriangleAlert, children }) {
  const cls = tone === "alert" ? "bg-alert-tint text-alert" : tone === "seal" ? "bg-mint text-ink" : "bg-caution-tint text-caution";
  return (
    <div className={`flex gap-3 rounded-2xl p-4 text-[0.9375rem] leading-snug ${cls}`} role={tone === "alert" ? "alert" : "status"}>
      <Icon size={20} className="mt-0.5 shrink-0" aria-hidden="true" />
      <div>{children}</div>
    </div>
  );
}

// ---------- screens ----------

function Home({ deviceName, onRename, onSend, onReceive, cryptoOk }) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(deviceName);
  return (
    <Screen title="">
      <div className="flex flex-1 flex-col">
        <div className="mb-8 mt-2 flex items-center gap-3">
          <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-seal text-seal-ink">
            <ShieldCheck size={26} strokeWidth={2.2} aria-hidden="true" />
          </div>
          <div className="text-[1.75rem] font-bold tracking-tight">SecureLink</div>
        </div>
        <p className="mb-8 max-w-[22rem] text-[1.125rem] leading-relaxed text-muted">
          Send files between your own devices on the same Wi-Fi. Files go straight to the other device, encrypted, and are never stored on a server.
        </p>

        {!cryptoOk && (
          <div className="mb-6">
            <Notice tone="alert" icon={ShieldAlert}>
              <strong className="font-semibold">This address can't encrypt files.</strong> Browsers only allow encryption on secure pages. Open the <span className="font-semibold">https://</span> address shown where SecureLink is running.
            </Notice>
          </div>
        )}

        <div className="grid grid-cols-2 gap-3">
          <button onClick={onSend} disabled={!cryptoOk}
            className="flex min-h-[8.5rem] flex-col justify-between rounded-3xl bg-seal p-4 text-left text-seal-ink transition hover:brightness-110 disabled:opacity-40 focus-visible:outline focus-visible:outline-[3px] focus-visible:outline-offset-2 focus-visible:outline-seal">
            <Send size={26} aria-hidden="true" />
            <span><span className="block text-[1.1875rem] font-semibold">Send</span><span className="text-[0.875rem] opacity-80">Choose files to share</span></span>
          </button>
          <button onClick={onReceive} disabled={!cryptoOk}
            className="flex min-h-[8.5rem] flex-col justify-between rounded-3xl bg-mint p-4 text-left text-ink transition hover:brightness-[0.97] disabled:opacity-40 focus-visible:outline focus-visible:outline-[3px] focus-visible:outline-offset-2 focus-visible:outline-seal">
            <Inbox size={26} className="text-seal" aria-hidden="true" />
            <span><span className="block text-[1.1875rem] font-semibold">Receive</span><span className="text-[0.875rem] text-muted">Enter a code or scan</span></span>
          </button>
        </div>

        <ul className="mt-9 space-y-4 text-[0.9375rem] leading-snug">
          <li className="flex gap-3"><Smartphone size={20} className="mt-0.5 shrink-0 text-seal" aria-hidden="true" /><span><strong className="font-semibold">Pair</strong> with a one-time code or QR code that expires in 3 minutes.</span></li>
          <li className="flex gap-3"><ShieldCheck size={20} className="mt-0.5 shrink-0 text-seal" aria-hidden="true" /><span><strong className="font-semibold">Check</strong> that both screens show the same number, so no one can get in between.</span></li>
          <li className="flex gap-3"><Lock size={20} className="mt-0.5 shrink-0 text-seal" aria-hidden="true" /><span><strong className="font-semibold">Send</strong> with end-to-end encryption. Each piece is checked on arrival.</span></li>
        </ul>

        <div className="mt-auto pt-10 text-[0.875rem] text-muted">
          {editing ? (
            <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); onRename(draft.trim() || deviceName); setEditing(false); }}>
              <label className="sr-only" htmlFor="device-name">Device name</label>
              <input id="device-name" className="field py-2" value={draft} maxLength={40} autoFocus onChange={(e) => setDraft(e.target.value)} />
              <button className="rounded-xl bg-seal px-4 font-semibold text-seal-ink" type="submit">Save</button>
            </form>
          ) : (
            <button className="inline-flex items-center gap-1.5 rounded-lg py-1 hover:text-ink" onClick={() => { setDraft(deviceName); setEditing(true); }}>
              Other devices see this one as <strong className="font-semibold text-ink">{deviceName}</strong>
              <Pencil size={14} aria-label="Rename" />
            </button>
          )}
        </div>
      </div>
    </Screen>
  );
}

function PickFiles({ picked, setPicked, onBack, onContinue }) {
  const inputRef = useRef(null);
  const [over, setOver] = useState(false);
  const [rejected, setRejected] = useState([]);
  const add = (list) => {
    const ok = [];
    const bad = [];
    for (const f of list) (f.size > MAX_FILE_BYTES ? bad : ok).push(f);
    setRejected(bad.map((f) => f.name));
    setPicked((p) => [...p, ...ok]);
  };
  const total = picked.reduce((n, f) => n + f.size, 0);
  return (
    <Screen title="Send files" onBack={onBack} role="send" step="pick"
      actions={<button className="btn-primary" disabled={!picked.length} onClick={onContinue}>
        {picked.length ? `Continue with ${picked.length} file${picked.length > 1 ? "s" : ""}` : "Continue"}
      </button>}>
      <input ref={inputRef} type="file" multiple className="sr-only" tabIndex={-1}
        onChange={(e) => { add([...e.target.files]); e.target.value = ""; }} />
      <button
        onClick={() => inputRef.current.click()}
        onDragOver={(e) => { e.preventDefault(); setOver(true); }}
        onDragLeave={() => setOver(false)}
        onDrop={(e) => { e.preventDefault(); setOver(false); add([...e.dataTransfer.files]); }}
        className={`flex w-full flex-col items-center gap-2 rounded-3xl border-2 border-dashed px-4 ${picked.length ? "py-6" : "py-12"} text-center transition-colors focus-visible:outline focus-visible:outline-[3px] focus-visible:outline-seal ${over ? "border-seal bg-mint" : "border-line hover:border-seal/60"}`}>
        {picked.length ? <Plus size={26} className="text-seal" aria-hidden="true" /> : <Upload size={30} className="text-seal" aria-hidden="true" />}
        <span className="text-[1.0625rem] font-semibold">{picked.length ? "Add more files" : "Choose files"}</span>
        <span className="text-[0.875rem] text-muted">Up to 250 MB each{picked.length ? "" : ". You can also drop files here."}</span>
      </button>

      {rejected.length > 0 && (
        <div className="mt-4"><Notice>{rejected.join(", ")} {rejected.length > 1 ? "are" : "is"} larger than 250 MB and {rejected.length > 1 ? "were" : "was"} not added.</Notice></div>
      )}

      {picked.length > 0 && (
        <>
          <ul className="mt-5 divide-y divide-line">
            {picked.map((f, i) => (
              <li key={i} className="flex items-center gap-3 py-3">
                <FileText size={22} className="shrink-0 text-muted" aria-hidden="true" />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-[0.9375rem] font-medium">{f.name}</div>
                  <div className="text-[0.8125rem] text-muted">{formatBytes(f.size)}</div>
                </div>
                <button className="icon-btn" aria-label={`Remove ${f.name}`} onClick={() => setPicked((p) => p.filter((_, j) => j !== i))}><X size={18} /></button>
              </li>
            ))}
          </ul>
          <div className="mt-2 text-[0.875rem] text-muted">{formatBytes(total)} in total</div>
        </>
      )}
    </Screen>
  );
}

function Countdown({ until }) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => { const t = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(t); }, []);
  const left = Math.max(0, Math.round((until - now) / 1000));
  return <>{Math.floor(left / 60)}:{String(left % 60).padStart(2, "0")}</>;
}

function Host({ s, onRenew, onClose }) {
  const lanHint = s.joinUrl ? new URL(s.joinUrl).origin : null;
  return (
    <Screen title="Pair a device" onClose={onClose} role="send" step="host">
      <p className="mb-5 text-[1.0625rem] leading-snug">Scan this with the other device's camera, or open SecureLink there and enter the code.</p>

      <div className={`mx-auto w-full max-w-[13rem] rounded-3xl bg-white p-3 sm:max-w-[17rem] ring-1 ring-line ${s.codeExpired ? "opacity-25" : ""}`}>
        {s.qrSrc ? <img src={s.qrSrc} alt="QR code that opens SecureLink on the other device and pairs it" className="aspect-square w-full" /> : <div className="aspect-square" />}
      </div>

      <div className="mt-6 text-center">
        <div className="text-[0.9375rem] text-muted">Pairing code</div>
        <div className={`font-figures text-[3rem] font-bold leading-tight tracking-[0.08em] tabular-nums ${s.codeExpired ? "text-muted line-through decoration-2" : ""}`} aria-label={`Pairing code ${s.code ? s.code.split("").join(" ") : ""}`}>
          {splitCode(s.code) || "--- ---"}
        </div>
        {s.codeExpired ? (
          <div className="mt-3 space-y-3">
            <div className="text-[0.9375rem] text-alert">This code expired.</div>
            <button className="btn-quiet mx-auto max-w-[16rem]" onClick={onRenew}><RefreshCw size={18} aria-hidden="true" /> Get a new code</button>
          </div>
        ) : (
          <div className="text-[0.9375rem] text-muted">Works once. Expires in <span className="tabular-nums"><Countdown until={s.codeExpiresAt} /></span></div>
        )}
      </div>

      <div className="mt-auto space-y-3 pt-8">
        {!s.codeExpired && <div className="flex justify-center"><Spinner label="Waiting for the other device" /></div>}
        {lanHint && (
          <p className="text-center text-[0.8125rem] text-muted">On the other device, open<br /><span className="whitespace-nowrap font-medium text-ink">{lanHint}</span></p>
        )}
      </div>
    </Screen>
  );
}

function Join({ s, onJoin, onBack }) {
  const [code, setCode] = useState("");
  const ready = code.length === 6;
  return (
    <Screen title="Receive files" onBack={onBack} role="receive" step="join"
      actions={<button className="btn-primary" disabled={!ready} form="join-form" type="submit">Connect</button>}>
      <form id="join-form" onSubmit={(e) => { e.preventDefault(); if (ready) onJoin(code); }}>
        <label htmlFor="code" className="mb-4 block text-[1.0625rem] leading-snug">Enter the 6-digit code shown on the sending device.</label>
        <input id="code" className="field text-center font-figures text-[2.25rem] font-bold tracking-[0.3em] tabular-nums"
          inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]*" placeholder="000000" maxLength={6} autoFocus
          value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
          aria-invalid={!!s.joinError} aria-describedby={s.joinError ? "join-error" : undefined} />
        {s.joinError && <p id="join-error" className="mt-3 text-[0.9375rem] text-alert" role="alert">{s.joinError}</p>}
      </form>
      <div className="mt-8 flex gap-3 rounded-2xl bg-mint p-4 text-[0.9375rem] leading-snug">
        <ScanLine size={20} className="mt-0.5 shrink-0 text-seal" aria-hidden="true" />
        <span>Faster: point this device's camera at the QR code on the sender's screen and open the link.</span>
      </div>
    </Screen>
  );
}

function Connecting({ s, onClose }) {
  return (
    <Screen title={s.role === "send" ? "Pair a device" : "Receive files"} onClose={onClose} role={s.role} step="connecting">
      <div className="flex flex-1 flex-col items-center justify-center gap-4 text-center">
        <LoaderCircle size={36} className="animate-spin text-seal" aria-hidden="true" />
        <p className="text-[1.0625rem]" role="status">{s.connectingText}</p>
      </div>
    </Screen>
  );
}

function Verify({ s, onMatch, onMismatch, onClose }) {
  const peer = s.peerName || "the other device";
  return (
    <Screen title="Check the number" onClose={onClose} role={s.role} step="verify"
      actions={s.localConfirmed ? null : (
        <>
          <button className="btn-primary" onClick={onMatch}><Check size={20} aria-hidden="true" /> The numbers match</button>
          <button className="btn-danger" onClick={onMismatch}>They're different</button>
        </>
      )}>
      <p className="text-[1.0625rem] leading-snug">Connected to <strong className="font-semibold">{peer}</strong>. Make sure its screen shows this same number.</p>

      <div className="my-8 rounded-[1.75rem] bg-mint px-4 py-8 text-center ring-2 ring-seal/30">
        <div className="font-figures text-[3.5rem] font-bold leading-none tracking-[0.06em] tabular-nums sm:text-[4rem]" aria-label={`Verification number ${s.sas ? s.sas.split("").join(" ") : ""}`}>
          {splitCode(s.sas)}
        </div>
      </div>

      {s.localConfirmed ? (
        <div className="flex justify-center"><Spinner label={`Waiting for ${peer} to confirm`} /></div>
      ) : (
        <p className="text-[0.9375rem] leading-snug text-muted">
          If the numbers are different, someone on this network may be trying to read your files. Tap "They're different" and nothing will be sent.
        </p>
      )}
    </Screen>
  );
}

const STATUS_TEXT = {
  waiting: () => "Waiting to send",
  confirming: (f, peer) => `Sent. Waiting for ${peer} to confirm`,
};

function FileRow({ f, role, peer }) {
  const pct = f.size ? Math.round((100 * (f.bytes || 0)) / f.size) : f.status === "done" ? 100 : 0;
  let status;
  if (f.status === "active") status = `${role === "send" ? "Sending" : "Receiving"} ${pct}%`;
  else if (f.status === "done") status = role === "send" ? `Delivered, verified by ${peer}` : "Received and verified";
  else if (f.status === "failed") status = f.message;
  else status = STATUS_TEXT[f.status] ? STATUS_TEXT[f.status](f, peer) : "";
  const showBar = f.status === "active" || f.status === "confirming";
  return (
    <li className="py-3.5">
      <div className="flex items-center gap-3">
        <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl ${f.status === "failed" ? "bg-alert-tint text-alert" : f.status === "done" ? "bg-mint text-seal" : "bg-paper text-muted"}`}>
          {f.status === "done" ? <CircleCheck size={20} aria-hidden="true" /> : f.status === "failed" ? <TriangleAlert size={20} aria-hidden="true" /> : <FileText size={20} aria-hidden="true" />}
        </div>
        <div className="min-w-0 flex-1">
          <div className="truncate text-[0.9375rem] font-medium">{f.name}</div>
          <div className={`text-[0.8125rem] leading-snug ${f.status === "failed" ? "text-alert" : "text-muted"}`}>
            {formatBytes(f.size)}{status ? `, ${status.charAt(0).toLowerCase()}${status.slice(1)}` : ""}
          </div>
        </div>
        {role === "receive" && f.status === "done" && f.url && (
          <a href={f.url} download={f.name}
            className="inline-flex h-11 items-center gap-1.5 rounded-xl bg-seal px-4 text-[0.9375rem] font-semibold text-seal-ink focus-visible:outline focus-visible:outline-[3px] focus-visible:outline-offset-2 focus-visible:outline-seal">
            <Download size={17} aria-hidden="true" /> Save
          </a>
        )}
      </div>
      {showBar && (
        <div className="mt-2.5 h-1.5 overflow-hidden rounded-full bg-line" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100} aria-label={`${f.name} progress`}>
          <div className="h-full rounded-full bg-seal transition-[width] duration-200" style={{ width: `${f.status === "confirming" ? 100 : pct}%` }} />
        </div>
      )}
    </li>
  );
}

function Transfer({ s, onMore, onFinish }) {
  const moreRef = useRef(null);
  const peer = s.peerName || "the other device";
  const busy = s.files.some((f) => ["waiting", "active", "confirming"].includes(f.status));
  const isSend = s.role === "send";
  const doneCount = s.files.filter((f) => f.status === "done").length;
  return (
    <Screen title={isSend ? `Sending to ${peer}` : `Receiving from ${peer}`} role={s.role} step="transfer"
      badge={<span className="inline-flex h-11 w-11 items-center justify-center text-seal" title="End-to-end encrypted"><Lock size={20} aria-label="End-to-end encrypted" /></span>}
      actions={
        <>
          {isSend && !s.ended && (
            <>
              <input ref={moreRef} type="file" multiple className="sr-only" tabIndex={-1}
                onChange={(e) => { onMore([...e.target.files]); e.target.value = ""; }} />
              <button className="btn-quiet" disabled={busy} onClick={() => moreRef.current.click()}><Plus size={19} aria-hidden="true" /> Send more files</button>
            </>
          )}
          <button className={isSend || s.ended ? "btn-primary" : "btn-quiet"} onClick={onFinish}>{s.ended ? "Start over" : busy ? "Stop and leave" : "Finish"}</button>
        </>
      }>
      <div className="seal-in flex items-center gap-3 rounded-2xl bg-mint p-4">
        <ShieldCheck size={24} className="shrink-0 text-seal" aria-hidden="true" />
        <div className="text-[0.9375rem] leading-snug">
          <div className="font-semibold">{s.verifyMode === "qr" ? "Verified with the QR code" : "Verified: the numbers matched"}</div>
          <div className="text-muted">Only {peer} can open these files.</div>
        </div>
      </div>

      {s.ended && (
        <div className="mt-4">
          <Notice tone={s.ended.duringTransfer ? "alert" : "caution"}>
            {s.ended.text}{!isSend && doneCount > 0 ? " The files you received can still be saved." : ""}
          </Notice>
        </div>
      )}

      {s.files.length === 0 ? (
        <div className="flex flex-1 flex-col items-center justify-center gap-3 py-10 text-center text-muted">
          <Inbox size={34} aria-hidden="true" />
          <p className="max-w-[16rem] text-[0.9375rem]">{isSend ? "Add files to send them to " + peer + "." : `Ready. Files that ${peer} sends will appear here.`}</p>
        </div>
      ) : (
        <ul className="mt-3 divide-y divide-line" aria-live="polite">
          {s.files.map((f) => <FileRow key={f.id} f={f} role={s.role} peer={peer} />)}
        </ul>
      )}
    </Screen>
  );
}

function ErrorScreen({ s, onRestart }) {
  return (
    <Screen title="" actions={<button className="btn-primary" onClick={onRestart}>Start over</button>}>
      <div className="flex flex-1 flex-col justify-center">
        <div className="mb-5 flex h-14 w-14 items-center justify-center rounded-2xl bg-alert-tint text-alert">
          <ShieldAlert size={28} aria-hidden="true" />
        </div>
        <h2 className="mb-3 text-[1.5rem] font-bold leading-tight">{s.fatal.title}</h2>
        <p className="max-w-[24rem] text-[1.0625rem] leading-relaxed text-muted" role="alert">{s.fatal.body}</p>
      </div>
    </Screen>
  );
}

// ---------- app ----------

function App() {
  const [s, dispatch] = useReducer(reducer, initialState);
  const [deviceName, setDeviceName] = useState(() => store.get("sl-device-name") || guessDeviceName());
  const [picked, setPicked] = useState([]);
  const clientRef = useRef(null);
  const pickedRef = useRef([]);
  const urlsRef = useRef([]);
  const lanOriginRef = useRef(null);
  const stepRef = useRef("home");
  stepRef.current = s.step;
  pickedRef.current = picked;
  const cryptoOk = cryptoAvailable();

  useEffect(() => {
    fetch("/api/info").then((r) => r.json()).then((info) => {
      if (info && Array.isArray(info.lanUrls) && info.lanUrls.length) lanOriginRef.current = info.lanUrls[0];
    }).catch(() => {});
  }, []);

  const shutdown = useCallback(() => {
    if (clientRef.current) { clientRef.current.close(); clientRef.current = null; }
  }, []);

  const restart = useCallback(() => {
    shutdown();
    for (const u of urlsRef.current) URL.revokeObjectURL(u);
    urlsRef.current = [];
    setPicked([]);
    dispatch({ type: "reset" });
  }, [shutdown]);

  const handleEvent = useCallback((client) => async (type, p) => {
    if (clientRef.current !== client) return; // a stale session
    switch (type) {
      case "code": {
        const origin = isLocalHost(location.hostname) && lanOriginRef.current ? lanOriginRef.current : location.origin;
        const joinUrl = buildJoinUrl(origin, p.code, p.secret);
        let qrSrc = null;
        try {
          const svg = await QRCode.toString(joinUrl, { type: "svg", margin: 1, errorCorrectionLevel: "M", color: { dark: "#10231C", light: "#FFFFFF" } });
          qrSrc = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`;
        } catch {}
        dispatch({ type: "code", code: p.code, expiresAt: Date.now() + p.ttl * 1000, qrSrc, joinUrl });
        break;
      }
      case "code-expired": dispatch({ type: "code-expired" }); break;
      case "join-failed": {
        if (p.reason === "locked") {
          dispatch({ type: "join-error", text: `Too many wrong codes from this device. Try again in ${Math.max(1, Math.ceil((p.retryAfter || 60) / 60))} minutes.` });
        } else if (p.attemptsLeft === 0) {
          shutdown();
          dispatch({ type: "fatal", fatal: fatalFor("too-many-codes") });
        } else {
          dispatch({ type: "join-error", text: `That code is wrong or has expired. ${p.attemptsLeft} ${p.attemptsLeft === 1 ? "try" : "tries"} left.` });
        }
        break;
      }
      case "server-error": shutdown(); dispatch({ type: "fatal", fatal: fatalFor(p.reason) }); break;
      case "peer-joined": dispatch({ type: "connecting", text: `Setting up a secure connection with ${p.peerName}`, peerName: p.peerName }); break;
      case "checking-qr": dispatch({ type: "connecting", text: "Checking the QR code" }); break;
      case "sas": dispatch({ type: "sas", sas: p.sas, peerName: p.peerName }); break;
      case "local-confirmed": dispatch({ type: "local-confirmed" }); break;
      case "peer-confirmed": dispatch({ type: "peer-confirmed" }); break;
      case "verified": {
        dispatch({ type: "verified", mode: p.mode, sas: p.sas, peerName: p.peerName });
        if (client.isA && pickedRef.current.length) {
          client.sendFiles(pickedRef.current.map(fromBrowserFile));
          setPicked([]);
        }
        break;
      }
      case "file-queued": dispatch({ type: "file-add", file: { id: p.id, name: p.name, size: p.size, bytes: 0, status: "waiting" } }); break;
      case "file-start":
        dispatch({ type: "file-add", file: { id: p.id, name: p.name, size: p.size, bytes: 0, status: "active" } });
        dispatch({ type: "file-update", id: p.id, patch: { status: "active" } });
        break;
      case "file-progress": dispatch({ type: "file-update", id: p.id, patch: { bytes: p.bytes } }); break;
      case "file-sent": dispatch({ type: "file-update", id: p.id, patch: { status: "confirming" } }); break;
      case "file-delivered": dispatch({ type: "file-update", id: p.id, patch: { status: "done", bytes: p.size } }); break;
      case "file-received": {
        const url = URL.createObjectURL(new Blob(p.parts, { type: p.type }));
        urlsRef.current.push(url);
        dispatch({ type: "file-update", id: p.id, patch: { status: "done", bytes: p.size, url } });
        break;
      }
      case "file-failed":
        dispatch({ type: "file-add", file: { id: p.id, name: p.name || "File", size: 0, bytes: 0, status: "failed" } });
        dispatch({ type: "file-update", id: p.id, patch: { status: "failed", message: p.message } });
        break;
      case "peer-left":
        if (p.wasVerified) {
          dispatch({ type: "ended", ended: { duringTransfer: p.duringTransfer, text: p.duringTransfer ? "The other device disconnected before every file finished." : "The other device ended the session." } });
        } else {
          dispatch({ type: "fatal", fatal: fatalFor("peer-left") });
        }
        break;
      case "closed":
        if (stepRef.current === "transfer") dispatch({ type: "ended", ended: { duringTransfer: true, text: "The connection to SecureLink was lost." } });
        else dispatch({ type: "fatal", fatal: fatalFor("closed") });
        break;
      case "error":
        dispatch({ type: "fatal", fatal: fatalFor(p.code, p.message) });
        break;
      default: break;
    }
  }, [shutdown]);

  const startClient = useCallback(async (role, { qrSecret, code } = {}) => {
    shutdown();
    const url = `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}`;
    let client;
    const onEvent = (...args) => client && handleEvent(client)(...args);
    client = new SecureLinkClient({ url, role, name: deviceName, qrSecret, onEvent });
    clientRef.current = client;
    try {
      await client.connect();
      if (code) client.join(code);
    } catch (err) {
      if (clientRef.current === client) dispatch({ type: "fatal", fatal: fatalFor(err.code || "unreachable") });
    }
    return client;
  }, [deviceName, handleEvent, shutdown]);

  // Opened from a QR code: join straight away, then remove the secret from the address bar.
  // (Also when the link opens in a tab that already shows SecureLink: only the # part changes.)
  const startClientRef = useRef(startClient);
  startClientRef.current = startClient;
  useEffect(() => {
    const fromLink = () => {
      const join = parseJoinFragment(location.hash);
      if (!join) return;
      history.replaceState(null, "", location.pathname);
      if (!cryptoAvailable()) return;
      for (const u of urlsRef.current) URL.revokeObjectURL(u);
      urlsRef.current = [];
      dispatch({ type: "reset" });
      dispatch({ type: "go", step: "connecting", role: "receive" });
      dispatch({ type: "connecting", text: "Connecting to the sender" });
      startClientRef.current("receive", { qrSecret: join.secret, code: join.code });
    };
    fromLink();
    window.addEventListener("hashchange", fromLink);
    return () => window.removeEventListener("hashchange", fromLink);
  }, []);

  useEffect(() => () => shutdown(), [shutdown]);

  const rename = (n) => { setDeviceName(n); store.set("sl-device-name", n); };

  switch (s.step) {
    case "home":
      return <Home deviceName={deviceName} onRename={rename} cryptoOk={cryptoOk}
        onSend={() => dispatch({ type: "go", step: "pick", role: "send" })}
        onReceive={() => { dispatch({ type: "go", step: "join", role: "receive" }); }} />;
    case "pick":
      return <PickFiles picked={picked} setPicked={setPicked} onBack={restart}
        onContinue={() => { dispatch({ type: "connecting", text: "Creating a pairing code" }); startClient("send"); }} />;
    case "host":
      return <Host s={s} onClose={restart} onRenew={() => clientRef.current && clientRef.current.renewCode()} />;
    case "join":
      return <Join s={s} onBack={restart} onJoin={async (code) => {
        dispatch({ type: "connecting", text: "Connecting to the sender" });
        if (clientRef.current && !clientRef.current.dead) clientRef.current.join(code);
        else await startClient("receive", { code });
      }} />;
    case "connecting":
      return <Connecting s={s} onClose={restart} />;
    case "verify":
      return <Verify s={s} onClose={restart}
        onMatch={() => clientRef.current && clientRef.current.confirmSas(true)}
        onMismatch={() => clientRef.current && clientRef.current.confirmSas(false)} />;
    case "transfer":
      return <Transfer s={s} onFinish={restart}
        onMore={(files) => {
          const ok = files.filter((f) => f.size <= MAX_FILE_BYTES);
          if (clientRef.current && ok.length) clientRef.current.sendFiles(ok.map(fromBrowserFile));
          for (const f of files.filter((x) => x.size > MAX_FILE_BYTES)) {
            dispatch({ type: "file-add", file: { id: `big-${f.name}-${Date.now()}`, name: f.name, size: f.size, bytes: 0, status: "failed", message: "Larger than 250 MB, so it was not sent." } });
          }
        }} />;
    case "error":
      return <ErrorScreen s={s} onRestart={restart} />;
    default:
      return null;
  }
}

createRoot(document.getElementById("root")).render(<App />);
