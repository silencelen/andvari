import { useEffect, useMemo, useRef, useState } from "react";
import { ApiClient, ApiError } from "../api/client";
import type { AttachmentRef, ClientPolicy, ItemDoc } from "../api/types";
import { toB64 } from "../crypto/bytes";
import { generatePassword } from "../crypto/generator";
import { hibpCountInRange, hibpPrefix, hibpSha1UpperHex } from "../crypto/hibp";
import { randomBytes } from "../crypto/provider";
import { base32Decode, parseOtpauthUri, totpCode, totpSecondsRemaining } from "../crypto/totp";
import type { Account } from "../vault/account";
import type { PendingUpload, VaultItem, VaultStore } from "../vault/store";
import { Admin } from "./Admin";
import { humanSize } from "./format";
import { Health } from "./Health";
import { Settings } from "./Settings";
import { estimateStrength } from "./strength";

type View = "vault" | "health" | "settings" | "admin";

interface Props {
  account: Account;
  store: VaultStore;
  client: ApiClient;
  policy: ClientPolicy | null;
  isAdmin: boolean;
  mustChangePassword: boolean;
  onLock: () => void;
}

export function Vault({ account, store, client, policy, isAdmin, mustChangePassword, onLock }: Props) {
  const [view, setView] = useState<View>("vault");
  const [items, setItems] = useState<VaultItem[]>(store.list());
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [editing, setEditing] = useState<ItemDoc | null>(null);
  const [mustChange, setMustChange] = useState(mustChangePassword);
  const [online, setOnline] = useState(true);

  const refresh = () => setItems(store.list());

  // WS dirty-bell → pull. The ticket mint adds a round-trip before the socket exists, so
  // sync once on open to catch any rev pushed during that window (the notifier has no replay).
  useEffect(() => {
    const close = client.events(
      async () => {
        await store.sync();
        refresh();
      },
      () => onLock(),
      async () => {
        await store.sync();
        refresh();
      },
    );
    return close;
  }, [client, store, onLock]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return items;
    return items.filter((it) => it.doc.name.toLowerCase().includes(q) || (it.doc.login?.username ?? "").toLowerCase().includes(q) || (it.doc.login?.uris?.[0] ?? "").toLowerCase().includes(q));
  }, [items, query]);

  const startNew = (type: "login" | "note") => {
    setSelected(null);
    setEditing(type === "login" ? { type, name: "", login: { username: "", password: "", uris: [""] } } : { type, name: "", notes: "" });
  };

  const openItem = (it: VaultItem) => {
    setSelected(it.itemId);
    setEditing(null);
  };

  const save = async (doc: ItemDoc, newFiles: PendingUpload[], onProgress?: (done: number, total: number) => void) => {
    await store.save(selected, doc, newFiles, onProgress);
    refresh();
    setEditing(null);
    setSelected(null);
  };

  const remove = async (itemId: string) => {
    await store.remove(itemId);
    refresh();
    setSelected(null);
  };

  const goToItem = (itemId: string) => {
    setView("vault");
    setEditing(null);
    setSelected(itemId);
  };

  const navBtn = (v: View, label: string) => (
    <button className={`navbtn ${view === v ? "active" : ""}`} onClick={() => { setView(v); setEditing(null); setSelected(null); }}>{label}</button>
  );

  const current = selected ? store.get(selected) : null;

  return (
    <div>
      <div className="appbar">
        <div className="row">
          <span className="brand"><span className="a-mark">and</span>vari</span>
          <nav className="nav">
            {navBtn("vault", "Vault")}
            {navBtn("health", "Health")}
            {navBtn("settings", "Settings")}
            {isAdmin && navBtn("admin", "Admin")}
          </nav>
        </div>
        <div className="row">
          <span className="muted"><span className={`dot ${online ? "on" : "off"}`} />{account.userId.slice(0, 8)}</span>
          <button className="ghost" onClick={onLock}>Lock</button>
        </div>
      </div>

      {mustChange && (
        <div className="banner">
          <span>Recovery sign-in — set a new master password now.</span>
          <button className="link" onClick={() => { setView("settings"); setEditing(null); setSelected(null); }}>Go to Settings →</button>
        </div>
      )}

      <div className="wrap">
        {view === "health" ? (
          <Health store={store} client={client} onOpenItem={goToItem} />
        ) : view === "settings" ? (
          <Settings client={client} account={account} policy={policy} onPasswordChanged={() => setMustChange(false)} />
        ) : view === "admin" && isAdmin ? (
          <Admin client={client} />
        ) : editing ? (
          <Editor initial={editing} policy={policy} onSave={save} onCancel={() => setEditing(null)} />
        ) : current ? (
          <Detail
            item={current}
            client={client}
            store={store}
            policy={policy}
            onEdit={() => setEditing(current.doc)}
            onDelete={() => remove(current.itemId)}
            onBack={() => setSelected(null)}
          />
        ) : (
          <>
            <div className="toolbar">
              <input placeholder="Search vault…" value={query} onChange={(e) => setQuery(e.target.value)} autoFocus />
              <button className="ghost" onClick={() => startNew("login")}>+ Login</button>
              <button className="ghost" onClick={() => startNew("note")}>+ Note</button>
            </div>
            {filtered.length === 0 ? (
              <div className="empty">
                <div className="sigil">ᛝ</div>
                <p>{items.length === 0 ? "Your hoard is empty. Add your first secret." : "Nothing matches that search."}</p>
              </div>
            ) : (
              <div className="list">
                {filtered.map((it) => (
                  <button className="item" key={it.itemId} onClick={() => openItem(it)}>
                    <span className="glyph">{(it.doc.name || "?").charAt(0).toUpperCase()}</span>
                    <span className="body">
                      <div className="name">{it.doc.name || "(untitled)"}</div>
                      <div className="sub">{it.doc.type === "login" ? it.doc.login?.username || it.doc.login?.uris?.[0] || "login" : "secure note"}</div>
                    </span>
                    <span className="tag">{it.doc.type}</span>
                  </button>
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

// ---- copy with auto-clear ----
function useCopy(clearSeconds: number) {
  const [flash, setFlash] = useState<string | null>(null);
  const timer = useRef<number | null>(null);
  const copy = async (label: string, value: string) => {
    await navigator.clipboard.writeText(value);
    setFlash(label);
    if (timer.current) window.clearTimeout(timer.current);
    window.setTimeout(() => setFlash((f) => (f === label ? null : f)), 1200);
    // Auto-clear the clipboard after the policy window (best-effort).
    window.setTimeout(() => navigator.clipboard.writeText("").catch(() => {}), Math.max(1, clearSeconds) * 1000);
  };
  return { flash, copy };
}

function Detail({ item, client, store, policy, onEdit, onDelete, onBack }: { item: VaultItem; client: ApiClient; store: VaultStore; policy: ClientPolicy | null; onEdit: () => void; onDelete: () => void; onBack: () => void }) {
  const { flash, copy } = useCopy(policy?.clipboardClearSeconds ?? 30);
  const doc = item.doc;
  return (
    <div className="sheet">
      <button className="link" onClick={onBack}>← back to vault</button>
      <h2 style={{ marginTop: 12 }}>{doc.name}</h2>
      <div className="muted" style={{ marginBottom: 18 }}>{doc.type === "login" ? "Login" : "Secure note"}</div>

      {doc.type === "login" && doc.login && (
        <>
          {doc.login.username && (
            <div className="field">
              <label>Username</label>
              <div className="secret-row">
                <input readOnly value={doc.login.username} className="mono" />
                <button className="ghost" onClick={() => copy("username", doc.login!.username!)}>Copy</button>
              </div>
            </div>
          )}
          {doc.login.password && (
            <div className="field">
              <label>Password {flash === "password" && <span className="copy-flash">copied ✓</span>}</label>
              <div className="secret-row">
                <PasswordField value={doc.login.password} />
                <button className="ghost" onClick={() => copy("password", doc.login!.password!)}>Copy</button>
              </div>
            </div>
          )}
          {doc.login.totp && <TotpView uri={doc.login.totp} onCopy={(code) => copy("code", code)} />}
          {doc.login.uris?.[0] && (
            <div className="field">
              <label>Website</label>
              <input readOnly value={doc.login.uris[0]} />
            </div>
          )}
          {doc.login.password && <HealthLine password={doc.login.password} client={client} />}
        </>
      )}

      {doc.notes && (
        <div className="field">
          <label>Notes</label>
          <textarea readOnly rows={5} value={doc.notes} />
        </div>
      )}

      {(doc.attachments?.length ?? 0) > 0 && <AttachmentList item={item} store={store} />}

      <div className="actions">
        <button className="primary" onClick={onEdit}>Edit</button>
        <div className="spacer" />
        <button className="ghost" onClick={onDelete} style={{ color: "var(--danger)" }}>Delete</button>
      </div>
    </div>
  );
}

/** Detail-view attachments: download → decrypt → hand the browser a one-shot object URL. */
function AttachmentList({ item, store }: { item: VaultItem; store: VaultStore }) {
  const [busyId, setBusyId] = useState<string | null>(null);
  const [err, setErr] = useState("");

  const download = async (ref: AttachmentRef) => {
    setErr("");
    setBusyId(ref.id);
    try {
      const plain = await store.downloadAttachment(item, ref);
      const url = URL.createObjectURL(new Blob([plain as BlobPart], { type: "application/octet-stream" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = ref.name || "attachment";
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch {
      setErr(`Could not download “${ref.name}” — the blob is missing or failed to decrypt.`);
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div className="field">
      <label>Attachments</label>
      {err && <div className="msg err">{err}</div>}
      <div className="attach-list">
        {item.doc.attachments!.map((ref) => (
          <div className="attach-row" key={ref.id}>
            <span className="attach-name">{ref.name}</span>
            <span className="muted">{humanSize(ref.size)}</span>
            <button type="button" className="ghost" disabled={busyId === ref.id} onClick={() => download(ref)}>
              {busyId === ref.id ? "Opening…" : "Download"}
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

function PasswordField({ value }: { value: string }) {
  const [show, setShow] = useState(false);
  return (
    <>
      <input readOnly className="mono" type={show ? "text" : "password"} value={value} />
      <button className="ghost" onClick={() => setShow((s) => !s)}>{show ? "Hide" : "Show"}</button>
    </>
  );
}

function TotpView({ uri, onCopy }: { uri: string; onCopy: (code: string) => void }) {
  const [code, setCode] = useState("······");
  const [remaining, setRemaining] = useState(30);
  const [period, setPeriod] = useState(30);
  useEffect(() => {
    let cfg;
    try {
      cfg = parseOtpauthUri(uri);
    } catch {
      setCode("invalid");
      return;
    }
    setPeriod(cfg.periodSeconds);
    const tick = async () => {
      const now = Math.floor(Date.now() / 1000);
      setCode(await totpCode(cfg!, now));
      setRemaining(totpSecondsRemaining(cfg!, now));
    };
    tick();
    const id = window.setInterval(tick, 1000);
    return () => window.clearInterval(id);
  }, [uri]);
  return (
    <div className="field">
      <label>One-time code</label>
      <div className="totp-wrap">
        <button className="totp link" onClick={() => onCopy(code.replace(/\s/g, ""))} title="copy">{code.replace(/(\d{3})(\d{3})/, "$1 $2")}</button>
        <div className="ring" style={{ ["--p" as string]: String((remaining / period) * 100) }} title={`${remaining}s`} />
      </div>
    </div>
  );
}

function HealthLine({ password, client }: { password: string; client: ApiClient }) {
  const [status, setStatus] = useState<string>("");
  const check = async () => {
    setStatus("checking…");
    try {
      const hash = await hibpSha1UpperHex(password);
      const body = await client.hibpRange(hibpPrefix(hash));
      const count = hibpCountInRange(body, hash);
      setStatus(count > 0 ? `⚠ found in ${count.toLocaleString()} breaches — change it` : "✓ not in any known breach");
    } catch {
      setStatus("breach check unavailable");
    }
  };
  return (
    <div style={{ marginTop: 4 }}>
      <button className="link" onClick={check}>Check breach exposure</button>
      {status && <span className="muted" style={{ marginLeft: 10, color: status.startsWith("⚠") ? "var(--danger)" : "var(--ink-dim)" }}>{status}</span>}
    </div>
  );
}

function Editor({ initial, policy, onSave, onCancel }: { initial: ItemDoc; policy: ClientPolicy | null; onSave: (d: ItemDoc, files: PendingUpload[], onProgress?: (done: number, total: number) => void) => Promise<void>; onCancel: () => void }) {
  const [doc, setDoc] = useState<ItemDoc>(structuredClone(initial));
  const [pending, setPending] = useState<PendingUpload[]>([]);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [fileErr, setFileErr] = useState("");
  const [saveErr, setSaveErr] = useState("");
  const [busy, setBusy] = useState(false);
  const fileInput = useRef<HTMLInputElement | null>(null);
  const isLogin = doc.type === "login";
  const login = doc.login ?? {};

  const setLogin = (patch: Partial<NonNullable<ItemDoc["login"]>>) => setDoc({ ...doc, login: { ...login, ...patch } });

  const gen = () => setLogin({ password: generatePassword() });

  const maxBytes = policy?.attachmentMaxBytes ?? 25 * 1024 * 1024;

  const addFiles = async (files: FileList | null) => {
    if (!files || files.length === 0) return;
    setFileErr("");
    const errors: string[] = [];
    const newRefs: AttachmentRef[] = [];
    const newPending: PendingUpload[] = [];
    for (const file of Array.from(files)) {
      if (file.size === 0) {
        errors.push(`“${file.name}” is empty — empty files can't be attached.`);
        continue;
      }
      if (file.size > maxBytes) {
        errors.push(`“${file.name}” is ${humanSize(file.size)} — over the ${humanSize(maxBytes)} limit.`);
        continue;
      }
      const data = new Uint8Array(await file.arrayBuffer());
      const ref: AttachmentRef = { id: crypto.randomUUID(), name: file.name, size: file.size, fileKey: toB64(randomBytes(32)) };
      newRefs.push(ref);
      newPending.push({ id: ref.id, data });
    }
    if (newRefs.length > 0) {
      setDoc((d) => ({ ...d, attachments: [...(d.attachments ?? []), ...newRefs] }));
      setPending((p) => [...p, ...newPending]);
    }
    if (errors.length > 0) setFileErr(errors.join(" "));
    if (fileInput.current) fileInput.current.value = "";
  };

  const removeAttachment = (id: string) => {
    // Dropping the doc entry is enough — server-side GC reaps the orphaned blob.
    setDoc((d) => ({ ...d, attachments: (d.attachments ?? []).filter((a) => a.id !== id) }));
    setPending((p) => p.filter((f) => f.id !== id));
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setSaveErr("");
    setProgress(null);
    try {
      await onSave(doc, pending, (done, total) => setProgress({ done, total }));
    } catch (err) {
      setSaveErr(err instanceof ApiError && err.status === 413 ? `Save rejected: ${err.message || "attachment quota exceeded"}.` : "Save failed — nothing was changed.");
    } finally {
      setBusy(false);
      setProgress(null);
    }
  };

  const attachments = doc.attachments ?? [];
  const pendingIds = new Set(pending.map((p) => p.id));

  return (
    <form className="sheet" onSubmit={submit}>
      <button type="button" className="link" onClick={onCancel}>← cancel</button>
      <h2 style={{ marginTop: 12 }}>{initial.name ? "Edit" : isLogin ? "New login" : "New note"}</h2>
      <div className="field">
        <label>Name</label>
        <input autoFocus value={doc.name} onChange={(e) => setDoc({ ...doc, name: e.target.value })} />
      </div>
      {isLogin && (
        <>
          <div className="field">
            <label>Username</label>
            <input className="mono" value={login.username ?? ""} onChange={(e) => setLogin({ username: e.target.value })} />
          </div>
          <div className="field">
            <label>Password</label>
            <div className="secret-row">
              <input className="mono" value={login.password ?? ""} onChange={(e) => setLogin({ password: e.target.value })} />
              <button type="button" className="ghost" onClick={gen}>Generate</button>
            </div>
            {login.password && <StrengthBar password={login.password} />}
          </div>
          <div className="field">
            <label>Website</label>
            <input value={login.uris?.[0] ?? ""} onChange={(e) => setLogin({ uris: [e.target.value] })} placeholder="https://" />
          </div>
          <div className="field">
            <label>TOTP secret (otpauth:// URI or base32)</label>
            <input className="mono" value={login.totp ?? ""} onChange={(e) => setLogin({ totp: normalizeTotp(e.target.value) })} placeholder="optional" />
          </div>
        </>
      )}
      <div className="field">
        <label>Notes</label>
        <textarea rows={isLogin ? 3 : 6} value={doc.notes ?? ""} onChange={(e) => setDoc({ ...doc, notes: e.target.value })} />
      </div>

      <div className="field">
        <label>Attachments</label>
        {fileErr && <div className="msg err">{fileErr}</div>}
        {attachments.length > 0 && (
          <div className="attach-list">
            {attachments.map((ref) => (
              <div className="attach-row" key={ref.id}>
                <span className="attach-name">{ref.name}</span>
                <span className="muted">{humanSize(ref.size)}{pendingIds.has(ref.id) ? " · new" : ""}</span>
                <button type="button" className="ghost" onClick={() => removeAttachment(ref.id)} style={{ color: "var(--danger)" }}>Remove</button>
              </div>
            ))}
          </div>
        )}
        <input ref={fileInput} type="file" multiple style={{ display: "none" }} onChange={(e) => addFiles(e.target.files)} />
        <button type="button" className="ghost" onClick={() => fileInput.current?.click()}>+ Attach files</button>
        <span className="muted" style={{ marginLeft: 10 }}>encrypted on this device · up to {humanSize(maxBytes)} each</span>
      </div>

      {saveErr && <div className="msg err">{saveErr}</div>}
      <div className="actions">
        <button className="primary" disabled={busy || !doc.name}>
          {busy ? (progress && progress.total > 0 ? `Sealing… ${Math.min(progress.done + 1, progress.total)}/${progress.total}` : "Sealing…") : "Save"}
        </button>
        <button type="button" className="ghost" onClick={onCancel}>Cancel</button>
      </div>
    </form>
  );
}

function StrengthBar({ password }: { password: string }) {
  const score = estimateStrength(password);
  const colors = ["var(--danger)", "var(--danger)", "var(--gold)", "var(--ok)", "var(--ok)"];
  return (
    <div className="strength">
      <span style={{ width: `${(score + 1) * 20}%`, background: colors[score] }} />
    </div>
  );
}

/** Accept either a full otpauth URI or a bare base32 secret (wrap the latter). */
function normalizeTotp(input: string): string {
  const t = input.trim();
  if (!t) return "";
  if (t.toLowerCase().startsWith("otpauth://")) return t;
  try {
    base32Decode(t);
    return `otpauth://totp/andvari?secret=${t.replace(/\s/g, "")}`;
  } catch {
    return t;
  }
}
