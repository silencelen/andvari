/**
 * andvari biometric quick-unlock CONNECTOR (0.17.0) — spec docs/design/2026-07-18-biometric-quick-unlock.md.
 *
 * The WebAuthn ceremony can't run in the service worker (no navigator.credentials) nor the action popup
 * (the OS prompt closes the popup — spike 2026-07-18: the popup document dies mid-`get()`, the connector
 * WINDOW survived every prompt). So the SW opens THIS page in a dedicated popup window and drives it as an
 * RPC: we ask for the pending op ("ready"), run create()/get() under our OWN Continue button (fresh user
 * activation — the popup→SW→connector hop loses the popup's), and post the PRF secret back ("result").
 *
 * Trust boundary: this page only ever talks to OUR service worker (same extension). The secret is base64
 * on the wire (there is no other IPC channel — chrome.runtime messaging is same-extension only) and the
 * raw PRF bytes are zeroized here the moment they're encoded. Device-binding is the SW-side co-key, not
 * this PRF, so a leaked secret still can't open the vault blob without the non-extractable co-key.
 */

const RP_ID = "andvari.monahanhosting.com"; // fixed RP id, authorized by the manifest host_permissions
const RP_NAME = "andvari";
const CEREMONY_TIMEOUT_MS = 60_000;

type BioReq =
  | { op: "enroll"; prfSalt: string; userHandleB64: string; userName: string; reuse?: { credentialId: string; prfSalt: string } }
  | { op: "eval"; credentialId: string; prfSalt: string };
type BioResult =
  | { ok: true; op: "enroll"; credentialId: string; prfEnabled: boolean; prfSalt: string; secretB64: string }
  | { ok: true; op: "eval"; secretB64: string }
  | { ok: false; error: string };

// ---- base64url (no Buffer in a page context) ----
function bytesToB64url(u: Uint8Array): string {
  let s = "";
  for (const b of u) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlToBytes(s: string): Uint8Array {
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}
const rand = (n: number) => crypto.getRandomValues(new Uint8Array(n)); // infers Uint8Array<ArrayBuffer> (a BufferSource)

// ---- DOM ----
const $ = <T extends HTMLElement = HTMLElement>(id: string): T => document.getElementById(id) as T;
function setMsg(text: string, kind: "" | "err" | "ok" = ""): void {
  const m = $("cx-msg");
  m.textContent = text;
  m.className = kind;
}
function showClose(): void {
  const btn = $("cx-close");
  btn.hidden = false;
  btn.addEventListener("click", () => window.close(), { once: true });
}

// ---- WebAuthn ----
/** The UV (user-verified) flag is bit 0x04 of the authenticatorData flags byte (offset 32). We run no RP
 *  server, so this LOCAL check is the only thing asserting the OS actually did biometric/PIN verification
 *  (not a bare user-presence tap). A missing UV bit ⇒ reject: quick-unlock must mean a verified user. */
function uvVerified(authData: ArrayBuffer): boolean {
  const bytes = new Uint8Array(authData);
  return bytes.length > 32 && (bytes[32] & 0x04) === 0x04;
}

async function ceremonyCreate(userHandle: Uint8Array, userName: string): Promise<{ credentialId: Uint8Array; prfEnabled: boolean }> {
  const cred = (await navigator.credentials.create({
    publicKey: {
      rp: { id: RP_ID, name: RP_NAME },
      user: { id: userHandle as BufferSource, name: userName, displayName: userName },
      challenge: rand(32),
      pubKeyCredParams: [
        { type: "public-key", alg: -7 }, // ES256
        { type: "public-key", alg: -257 }, // RS256
      ],
      authenticatorSelection: { authenticatorAttachment: "platform", residentKey: "required", userVerification: "required" },
      extensions: { prf: {} },
      timeout: CEREMONY_TIMEOUT_MS,
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("no credential created");
  const ext = cred.getClientExtensionResults();
  return { credentialId: new Uint8Array(cred.rawId), prfEnabled: ext.prf?.enabled === true };
}

async function ceremonyEval(credentialId: Uint8Array, prfSalt: Uint8Array): Promise<Uint8Array> {
  const assertion = (await navigator.credentials.get({
    publicKey: {
      rpId: RP_ID,
      challenge: rand(32),
      allowCredentials: [{ type: "public-key", id: credentialId as BufferSource, transports: ["internal"] }],
      userVerification: "required",
      extensions: { prf: { eval: { first: prfSalt as BufferSource } } },
      timeout: CEREMONY_TIMEOUT_MS,
    },
  })) as PublicKeyCredential | null;
  if (!assertion) throw new Error("no assertion");
  const resp = assertion.response as AuthenticatorAssertionResponse;
  if (!uvVerified(resp.authenticatorData)) throw new Error("user verification not performed");
  const first = assertion.getClientExtensionResults().prf?.results?.first;
  if (!first) throw new Error("no PRF result");
  return new Uint8Array(first as ArrayBuffer);
}

// ---- run a pending op → a wire result (secret bytes zeroized after encoding) ----
async function runEnroll(req: Extract<BioReq, { op: "enroll" }>): Promise<BioResult> {
  // Amendment 4: reuse an on-record passkey (a get() only — no fresh TPM/SEP credential) when one exists;
  // if it's been deleted the get() throws and we fall through to a fresh create()+get().
  if (req.reuse) {
    try {
      const secret = await ceremonyEval(b64urlToBytes(req.reuse.credentialId), b64urlToBytes(req.reuse.prfSalt));
      const secretB64 = bytesToB64url(secret);
      secret.fill(0);
      return { ok: true, op: "enroll", credentialId: req.reuse.credentialId, prfEnabled: true, prfSalt: req.reuse.prfSalt, secretB64 };
    } catch {
      /* stored credential gone / failed → mint a fresh one below */
    }
  }
  const { credentialId, prfEnabled } = await ceremonyCreate(b64urlToBytes(req.userHandleB64), req.userName);
  if (!prfEnabled) {
    // Platform without PRF — report it; the engine writes NOTHING (bio_unsupported).
    return { ok: true, op: "enroll", credentialId: bytesToB64url(credentialId), prfEnabled: false, prfSalt: req.prfSalt, secretB64: "" };
  }
  const secret = await ceremonyEval(credentialId, b64urlToBytes(req.prfSalt));
  const secretB64 = bytesToB64url(secret);
  secret.fill(0);
  return { ok: true, op: "enroll", credentialId: bytesToB64url(credentialId), prfEnabled: true, prfSalt: req.prfSalt, secretB64 };
}

async function runEval(req: Extract<BioReq, { op: "eval" }>): Promise<BioResult> {
  const secret = await ceremonyEval(b64urlToBytes(req.credentialId), b64urlToBytes(req.prfSalt));
  const secretB64 = bytesToB64url(secret);
  secret.fill(0);
  return { ok: true, op: "eval", secretB64 };
}

// ---- SW status poll (the connector's completion feedback; passive — no autolock re-arm) ----
type Statusish = { unlocked?: boolean; quickUnlock?: { enrolled?: boolean; kind?: string } };
async function pollUntilDone(op: BioReq["op"]): Promise<boolean> {
  for (let i = 0; i < 24; i++) {
    try {
      const s = (await chrome.runtime.sendMessage({ type: "status" })) as Statusish | undefined;
      if (op === "eval" && s?.unlocked === true) return true;
      if (op === "enroll" && s?.quickUnlock?.enrolled === true && s.quickUnlock.kind === "biometric") return true;
    } catch {
      /* SW momentarily unreachable — keep polling */
    }
    await new Promise((r) => setTimeout(r, 400));
  }
  return false; // no confirmation in ~10 s — let the caller show a neutral finish
}

// Keep the MV3 service worker alive for the whole ceremony (spec §5, the 0.16.3 TOTP-keepalive
// pattern): the OS biometric prompt can outlast the SW's ~30 s idle eviction, and an evicted SW loses
// the in-flight `pendingBio` + redeem stack. A light periodic message resets its idle timer; the
// interval dies with this page when the window closes. Passive (never re-arms the vault autolock).
setInterval(() => void chrome.runtime.sendMessage({ type: "ping" }).catch(() => {}), 20_000);

async function main(): Promise<void> {
  let req: BioReq | null = null;
  try {
    req = (await chrome.runtime.sendMessage({ __bio: "ready" })) as BioReq | null;
  } catch {
    req = null;
  }
  // Shape-check the reply: an unexpected answer (an {error} object, a stale SW's undefined) must land
  // on the friendly no-op screen, never be mis-run as a ceremony with undefined fields.
  if (req && (req.op !== "enroll" && req.op !== "eval")) req = null;
  if (!req) {
    setMsg("Nothing to do here — you can close this window.");
    showClose();
    return;
  }

  const isEnroll = req.op === "enroll";
  $("cx-title").textContent = isEnroll ? "Set up quick unlock" : "Unlock andvari";
  setMsg(isEnroll ? "Set up unlocking with your device’s biometrics or PIN." : "Confirm it’s you to unlock andvari.");
  const cont = $<HTMLButtonElement>("cx-continue");
  cont.textContent = "Continue";
  cont.hidden = false;
  $("cx-hint").hidden = false;

  cont.addEventListener(
    "click",
    async () => {
      cont.disabled = true;
      $("cx-hint").hidden = true;
      setMsg("Follow your device’s prompt…");
      let result: BioResult;
      try {
        result = req!.op === "enroll" ? await runEnroll(req as Extract<BioReq, { op: "enroll" }>) : await runEval(req as Extract<BioReq, { op: "eval" }>);
      } catch (e) {
        result = { ok: false, error: String(e) };
      }
      // Hand the result to the SW regardless of outcome (a failure resolves the broker → bio_cancelled).
      try {
        await chrome.runtime.sendMessage({ __bio: "result", ...result });
      } catch {
        /* the SW got it or died; the poll below reflects reality either way */
      }
      if (!result.ok) {
        setMsg("Cancelled — you can close this window and try again.", "err");
        showClose();
        return;
      }
      if (result.op === "enroll" && !result.prfEnabled) {
        setMsg("This device can’t do biometric quick unlock. Use a PIN instead.", "err");
        showClose();
        return;
      }
      setMsg(isEnroll ? "Finishing setup…" : "Unlocking…");
      const done = await pollUntilDone(req!.op);
      if (done) {
        setMsg(isEnroll ? "Quick unlock is on ✓" : "Unlocked ✓ — reopen andvari.", "ok");
        setTimeout(() => window.close(), 900);
      } else {
        setMsg("Done — you can close this window and reopen andvari.");
        showClose();
      }
    },
    { once: true },
  );
}

void main();
