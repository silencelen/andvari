import { useEffect, useMemo, useRef, useState } from "react";
import { ApiError, type ApiClient } from "../api/client";
import type { UserLookupResponse } from "../api/types";
import { groupedShort } from "../crypto/fingerprint";
import { identityFingerprint } from "../crypto/sharedgrant";
import { fromB64 } from "../crypto/bytes";
import { qrModules } from "../vendor/qrcode-generator";
import { Account } from "../vault/account";
import type { Contact } from "../vault/accountstate";
import { composeIdentityQr, parseIdentityQr, pinFromQr, pinFromTyped } from "../vault/contacts";
import type { VaultStore } from "../vault/store";
import { Busy } from "./Busy";
import { UNREACHABLE } from "./errors";
import { Field } from "./Field";
import { fmtDate } from "./format";
import { Msg } from "./Msg";
import { QrSvg } from "./QrSvg";

/**
 * Household verification and the personal vault (security review 2026-10, root cause A §4, §7.2; branch A5).
 *
 *  - {@link MyIdentityCard}: my 32-hex identity code and my identity QR `andvari-id:1:<userId>:<hex64>`, both
 *    computed from the SEED-DERIVED key this session holds (never a server value).
 *  - {@link VerifyMemberPanel}: "Verify a household member". Pins a contact ONLY from a human verification:
 *    typing their 32 hex as read from THEIR screen (compared with SHA-256 of the key the server serves for
 *    them), or a camera scan of their QR (full-length compare). Their code is never displayed first.
 *  - {@link HouseholdCard}: the pinned contacts (pairwise only, owner decision Q4), removal, anomalies.
 *  - {@link PersonalVaultCard} / {@link PersonalVaultBanner}: the §8.5 "Which vault is your Personal vault?"
 *    question and the Settings re-designation (password reauth, owner decision Q9).
 */

function qrOrNull(text: string): boolean[][] | null {
  try {
    return qrModules(text, "M");
  } catch {
    return null;
  }
}

export function MyIdentityCard({ account, intro }: { account: Account; intro?: string }) {
  const [qr, setQr] = useState<string | null>(null);
  const [fp, setFp] = useState("");
  useEffect(() => {
    let live = true;
    void (async () => {
      const [payload, full] = await Promise.all([composeIdentityQr(account.userId, account.identityPub), identityFingerprint(account.identityPub)]);
      if (live) {
        setQr(payload);
        setFp(full);
      }
    })();
    return () => {
      live = false;
    };
  }, [account]);
  const modules = useMemo(() => (qr ? qrOrNull(qr) : null), [qr]);
  return (
    <div>
      {intro && <p className="muted" style={{ marginTop: 0 }}>{intro}</p>}
      {modules && <QrSvg modules={modules} ariaLabel="My identity QR code" />}
      <div className="mono fingerprint" style={{ whiteSpace: "pre-line", marginTop: 8 }} data-testid="my-identity-code">{fp ? groupedShort(fp) : "…"}</div>
    </div>
  );
}

/** Camera QR scan through the browser's BarcodeDetector, where it exists. Returns the decoded text. */
function QrScanner({ onScan, onCancel }: { onScan: (text: string) => void; onCancel: () => void }) {
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const [err, setErr] = useState("");
  useEffect(() => {
    let stream: MediaStream | null = null;
    let stop = false;
    void (async () => {
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const Detector = (window as any).BarcodeDetector;
        if (!Detector || !navigator.mediaDevices?.getUserMedia) {
          setErr("This browser can't scan QR codes. Type their code instead.");
          return;
        }
        const detector = new Detector({ formats: ["qr_code"] });
        stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
        const v = videoRef.current;
        if (!v) return;
        v.srcObject = stream;
        await v.play();
        while (!stop) {
          const codes = await detector.detect(v).catch(() => []);
          const raw = codes?.[0]?.rawValue;
          if (typeof raw === "string" && raw.length > 0) {
            onScan(raw);
            return;
          }
          await new Promise((r) => setTimeout(r, 250));
        }
      } catch {
        setErr("Couldn't open the camera. Type their code instead.");
      }
    })();
    return () => {
      stop = true;
      stream?.getTracks().forEach((t) => t.stop());
    };
  }, [onScan]);
  return (
    <div>
      {err ? <Msg kind="err">{err}</Msg> : <video ref={videoRef} muted playsInline style={{ width: "100%", maxWidth: 320 }} aria-label="Camera preview for scanning a QR code" />}
      <button type="button" className="link" onClick={onCancel}>Cancel scan</button>
    </div>
  );
}

/**
 * "Verify a household member" (root cause A §7.2). Find them by email, then compare codes face to face (or
 * on a call): they read their 32 characters from THEIR screen and you type them, or you scan their QR.
 * Either way the comparison is against SHA-256 of the key the server serves for them; on a match exactly
 * that key is pinned. Nothing is pinned from the lookup alone.
 */
export function VerifyMemberPanel({ client, account, store, onDone, initialEmail }: { client: ApiClient; account: Account; store: VaultStore; onDone: (c: Contact | null) => void; initialEmail?: string }) {
  const [email, setEmail] = useState(initialEmail ?? "");
  const [served, setServed] = useState<UserLookupResponse | null>(null);
  const [typed, setTyped] = useState("");
  const [scanning, setScanning] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const find = async () => {
    setBusy(true);
    setErr("");
    try {
      const r = await client.lookupUser(email.trim());
      if (r.userId === account.userId) return setErr("That's you. Verify someone else.");
      setServed(r);
    } catch (e) {
      setErr(e instanceof ApiError && e.code === "no_such_user" ? "No active account has that email." : e instanceof ApiError ? "Lookup failed." : UNREACHABLE);
    } finally {
      setBusy(false);
    }
  };

  const pin = async (c: Contact | null, wrong: string) => {
    if (!c) return setErr(wrong);
    setBusy(true);
    try {
      await store.accountState.pin(c);
      onDone(c);
    } catch {
      setErr("Couldn't save the verification. Try again.");
    } finally {
      setBusy(false);
    }
  };

  const checkTyped = async () => {
    if (!served) return;
    setErr("");
    await pin(
      await pinFromTyped(typed, { userId: served.userId, identityPub: served.identityPub }, served.displayName, Date.now()),
      "That code doesn't match the key this server holds for them. If they read it correctly from their own screen, STOP: do not share with this account until your admin checks it.",
    );
  };

  const onScan = async (text: string) => {
    setScanning(false);
    if (!served) return;
    const qr = parseIdentityQr(text);
    if (!qr) return setErr("That isn't an andvari identity code.");
    if (qr.userId !== served.userId) return setErr("That QR belongs to a different account than the one you looked up.");
    await pin(
      await pinFromQr(text, { userId: served.userId, identityPub: served.identityPub }, served.displayName, Date.now()),
      "Their QR doesn't match the key this server holds for them. STOP: do not share with this account until your admin checks it.",
    );
  };

  if (!served) {
    return (
      <div className="check-block">
        {err && <Msg kind="err">{err}</Msg>}
        <Field label="Their email">
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="the household member's address" />
        </Field>
        <button type="button" className="ghost" disabled={busy || !email.trim()} onClick={() => void find()}>{busy ? <Busy>Looking up…</Busy> : "Next"}</button>{" "}
        <button type="button" className="link" onClick={() => onDone(null)}>Cancel</button>
      </div>
    );
  }
  return (
    <div className="check-block">
      {err && <Msg kind="err">{err}</Msg>}
      <p>
        Verifying <strong>{served.displayName}</strong>. Do this together, in person or on a call you trust. Show them your code; they show you theirs.
      </p>
      <MyIdentityCard account={account} intro="Your code (they type this, or scan the QR):" />
      {scanning ? (
        <QrScanner onScan={(t) => void onScan(t)} onCancel={() => setScanning(false)} />
      ) : (
        <>
          <Field label={`Type ${served.displayName}'s code, as they read it from THEIR screen (32 characters)`} prompt>
            <input className="mono" value={typed} onChange={(e) => setTyped(e.target.value)} placeholder="from their screen, not this one" />
          </Field>
          <button type="button" className="primary" disabled={busy || typed.replace(/[^0-9a-fA-F]/g, "").length !== 32} onClick={() => void checkTyped()}>Verify</button>{" "}
          <button type="button" className="ghost" onClick={() => setScanning(true)}>Scan their QR instead</button>{" "}
          <button type="button" className="link" onClick={() => onDone(null)}>Cancel</button>
        </>
      )}
    </div>
  );
}

const METHOD_LABEL: Record<string, string> = { qr: "QR scan", typed: "typed code", enrol: "in-person enrolment" };

/** Settings: the household members this account has verified (pairwise pins, Q4). */
export function HouseholdCard({ client, account, store }: { client: ApiClient; account: Account; store: VaultStore }) {
  const [contacts, setContacts] = useState<Contact[]>(store.accountState.contacts());
  const [verifying, setVerifying] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [anomaly, setAnomaly] = useState(store.accountState.anomaly);
  const [fps, setFps] = useState<Record<string, string>>({});

  const reload = async () => {
    try {
      await store.accountState.refresh();
    } catch {
      /* offline: show the local copy */
    }
    setContacts([...store.accountState.contacts()]);
    setAnomaly(store.accountState.anomaly);
  };
  useEffect(() => {
    void reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  useEffect(() => {
    let live = true;
    void Promise.all(contacts.map(async (c) => [c.userId, await identityFingerprint(fromB64(c.identityPub))] as const)).then((rows) => {
      if (live) setFps(Object.fromEntries(rows));
    });
    return () => {
      live = false;
    };
  }, [contacts]);

  const remove = async (userId: string) => {
    setBusy(true);
    setErr("");
    try {
      await store.accountState.unpin(userId);
      await reload();
    } catch {
      setErr("Couldn't remove it. Try again.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="sheet">
      <h2>Household members you've verified</h2>
      <p className="muted" style={{ marginTop: 0 }}>
        Each person does this once with each other person (not once per vault). andvari never trusts a key just because the server sent it.
      </p>
      {anomaly === "rollback" && <Msg kind="err">The server sent an older copy of your verified-members list. Your newer copy was kept. If this keeps happening, tell your admin.</Msg>}
      {anomaly === "unreadable" && <Msg kind="err">The server sent a verified-members list this account did not write. It was ignored. Tell your admin.</Msg>}
      {err && <Msg kind="err">{err}</Msg>}
      {contacts.length === 0 ? (
        <p className="muted">Nobody yet.</p>
      ) : (
        <ul className="plain-list">
          {contacts.map((c) => (
            <li key={c.userId} style={{ marginBottom: 6 }}>
              <strong>{c.label}</strong> <span className="muted">· {METHOD_LABEL[c.method] ?? c.method} · {fmtDate(c.verifiedAt)}</span>
              <div className="mono muted" style={{ whiteSpace: "pre-line" }}>{fps[c.userId] ? groupedShort(fps[c.userId]!) : "…"}</div>
              <button type="button" className="link" disabled={busy} onClick={() => void remove(c.userId)}>Remove</button>
            </li>
          ))}
        </ul>
      )}
      {verifying ? (
        <VerifyMemberPanel
          client={client}
          account={account}
          store={store}
          onDone={() => {
            setVerifying(false);
            void reload();
          }}
        />
      ) : (
        <button type="button" className="ghost" onClick={() => setVerifying(true)}>Verify a household member</button>
      )}
    </div>
  );
}

/** Settings: which vault is personal, and the Q9 re-designation (fresh password reauth). */
export function PersonalVaultCard({ client, account, store }: { client: ApiClient; account: Account; store: VaultStore }) {
  const [open, setOpen] = useState(false);
  const [choice, setChoice] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ kind: "err" | "info"; text: string } | null>(null);
  const choices = store.redesignationChoices();
  const current = store.vaults().find((v) => v.vaultId === account.personalVaultId);

  const save = async () => {
    setBusy(true);
    setMsg(null);
    try {
      const keys = await client.accountKeys();
      const authKey = await Account.deriveAuthKey(password, keys.kdfSalt, keys.kdfParams);
      await store.designatePersonalVault(choice, authKey);
      setOpen(false);
      setPassword("");
      setMsg({ kind: "info", text: "Saved. New items now go to this vault by default." });
    } catch (e) {
      setMsg({ kind: "err", text: e instanceof ApiError && e.status === 401 ? "Wrong master password." : e instanceof ApiError ? "The server refused the change." : UNREACHABLE });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="sheet">
      <h2>Personal vault</h2>
      <p className="muted" style={{ marginTop: 0 }}>
        {current ? <>Your personal vault is <strong>{current.name}</strong>. New items, imports and usage history go here.</> : "Your personal vault isn't confirmed yet."}
      </p>
      {msg && <Msg kind={msg.kind}>{msg.text}</Msg>}
      {open ? (
        <div className="check-block">
          <Field label="This is my personal vault">
            <select value={choice} onChange={(e) => setChoice(e.target.value)}>
              <option value="">Choose…</option>
              {choices.map((v) => (
                <option key={v.vaultId} value={v.vaultId}>{v.name}</option>
              ))}
            </select>
          </Field>
          <Field label="Master password (required to change this)">
            <input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </Field>
          <button type="button" className="primary" disabled={busy || !choice || !password} onClick={() => void save()}>{busy ? <Busy>Saving…</Busy> : "Save"}</button>{" "}
          <button type="button" className="link" onClick={() => setOpen(false)}>Cancel</button>
        </div>
      ) : (
        <button type="button" className="link" onClick={() => setOpen(true)}>Change which vault is personal…</button>
      )}
    </div>
  );
}

/**
 * Vault banner while the personal vault is not confirmed (§4.3): no default destination, usage paused.
 * When the §8.5 migration needs the human, it asks "Which vault is your Personal vault?", listing only
 * vaults keyed from this account's own wrap that the server labels personal.
 */
export function PersonalVaultBanner({ account, store, onChanged }: { account: Account; store: VaultStore; onChanged: () => void }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  if (account.personalStatus === "confirmed" || account.personalStatus === "migrated-unstored") return null;
  const choices = store.personalVaultChoices ?? [];
  const pick = async (vaultId: string) => {
    setBusy(true);
    setErr("");
    try {
      await store.designatePersonalVault(vaultId);
      onChanged();
    } catch (e) {
      setErr(e instanceof ApiError && e.code === "personal_wrap_exists" ? "Another device already chose. Change it in Settings, with your master password." : "Couldn't save that. Try again.");
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="msg err" style={{ display: "block" }} role="alert">
      <strong>Your personal vault isn't confirmed yet.</strong> Until it is, pick a vault every time you save or import, and usage history is paused.
      {account.personalStatus === "unreadable" && <div>The server sent a personal-vault record this account can't read. Choose your personal vault in Settings (it asks for your master password), and tell your admin.</div>}
      {account.personalStatus === "absent" && choices.length > 0 && (
        <div style={{ marginTop: 6 }}>
          Which vault is your Personal vault?{" "}
          {choices.map((c) => (
            <button key={c.vaultId} type="button" className="ghost" disabled={busy} onClick={() => void pick(c.vaultId)} style={{ marginRight: 6 }}>
              {c.name ?? "(unnamed)"} · {c.itemCount} items
            </button>
          ))}
        </div>
      )}
      {err && <div>{err}</div>}
    </div>
  );
}
