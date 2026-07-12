import { useEffect, useMemo, useState } from "react";
import { ApiClient, ApiError } from "../api/client";
import type {
  AdminDeviceSummary,
  AdminStatus,
  AdminUserSummary,
  AuditEvent,
  ClientPolicy,
  InviteResponse,
} from "../api/types";
import { composeEnrollLink } from "../enroll/enrolllink";
import { Field } from "./Field";
import { fmtDate, humanSize } from "./format";
import { Announcer, Msg } from "./Msg";
import { isPrivateOrigin } from "./origin";
import { QrSvg } from "./QrSvg";
import { ViewHeader } from "./ViewHeader";
import { qrModules } from "../vendor/qrcode-generator";

type Tab = "users" | "audit" | "policy" | "status";

export function Admin({ client }: { client: ApiClient }) {
  const [tab, setTab] = useState<Tab>("users");
  return (
    <div>
      <ViewHeader title="Administration" />
      <div className="tabs">
        {(["users", "audit", "policy", "status"] as Tab[]).map((t) => (
          <button key={t} className={tab === t ? "active" : ""} aria-pressed={tab === t} onClick={() => setTab(t)}>
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>
      {tab === "users" && <UsersTab client={client} />}
      {tab === "audit" && <AuditTab client={client} />}
      {tab === "policy" && <PolicyTab client={client} />}
      {tab === "status" && <StatusTab client={client} />}
    </div>
  );
}

function errText(e: unknown): string {
  if (e instanceof ApiError) {
    switch (e.code) {
      case "admin_only": return "This account is not an administrator.";
      case "last_admin": return "That's the only active administrator — disabling it would lock everyone out of this console. Make another account an admin first.";
      case "no_such_user": return "That account no longer exists — the list has been refreshed.";
    }
    return `${e.code}: ${e.message}`;
  }
  return "Request failed.";
}

function shortId(id: string | null): string {
  return id ? id.slice(0, 8) : "—";
}

// ---- Users ----

function UsersTab({ client }: { client: ApiClient }) {
  const [users, setUsers] = useState<AdminUserSummary[] | null>(null);
  const [devices, setDevices] = useState<Record<string, AdminDeviceSummary[]>>({});
  const [expanded, setExpanded] = useState<string | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const load = () => client.adminUsers().then(setUsers).catch((e) => setErr(errText(e)));
  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [client]);

  const toggleDevices = async (userId: string) => {
    if (expanded === userId) return setExpanded(null);
    setErr("");
    try {
      setDevices((d) => ({ ...d, [userId]: [] }));
      const list = await client.adminDevices(userId);
      setDevices((d) => ({ ...d, [userId]: list }));
      setExpanded(userId);
    } catch (e) {
      setErr(errText(e));
    }
  };

  const disableUser = async (userId: string) => {
    setBusy(true);
    setErr("");
    try {
      await client.adminDisableUser(userId);
      await load();
    } catch (e) {
      setErr(errText(e));
      // A stale/ghost row (no_such_user) can't be acted on — reload so it disappears,
      // making the "the list has been refreshed" copy true.
      if (e instanceof ApiError && e.code === "no_such_user") await load().catch(() => {});
    } finally {
      setBusy(false);
    }
  };

  const revokeDevice = async (userId: string, deviceId: string) => {
    setBusy(true);
    setErr("");
    try {
      await client.adminRevokeDevice(deviceId);
      setDevices((d) => ({ ...d, [userId]: (d[userId] ?? []).map((dev) => (dev.deviceId === deviceId ? { ...dev, revokedAt: Date.now() } : dev)) }));
    } catch (e) {
      setErr(errText(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      {err && <Msg kind="err">{err}</Msg>}
      <InviteForm client={client} onInvited={load} />
      {!users ? (
        <p className="muted">loading…</p>
      ) : (
        <div className="table-scroll">
          <table className="table">
            <thead>
              <tr>
                <th>User</th>
                <th>Status</th>
                <th>Created</th>
                <th>Devices</th>
                <th>Escrow</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <UserRows
                  key={u.userId}
                  user={u}
                  expanded={expanded === u.userId}
                  devices={devices[u.userId] ?? []}
                  busy={busy}
                  onToggleDevices={() => toggleDevices(u.userId)}
                  onDisable={() => disableUser(u.userId)}
                  onRevoke={(deviceId) => revokeDevice(u.userId, deviceId)}
                  onDownloadEscrow={() => client.adminUserEscrow(u.userId)}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function UserRows({ user: u, expanded, devices, busy, onToggleDevices, onDisable, onRevoke, onDownloadEscrow }: {
  user: AdminUserSummary;
  expanded: boolean;
  devices: AdminDeviceSummary[];
  busy: boolean;
  onToggleDevices: () => void;
  onDisable: () => void;
  onRevoke: (deviceId: string) => void;
  onDownloadEscrow: () => Promise<string>;
}) {
  // Disabling is drastic (revokes every session; sign-in then fails like a wrong
  // password) — never fire it off a single click. The server additionally refuses to
  // disable the last active admin (last_admin).
  const [confirming, setConfirming] = useState(false);
  // F59 recovery step 1 — hand the admin the sealed escrow blob as a file to carry to the
  // offline recovery-cli (docs/drills/account-recovery-drill.md). The blob is crypto_box_seal'd
  // to the org recovery PUBLIC key — useless without the printed sheet — so this is safe to
  // download. `no_escrow` (a race: the escrow was removed since the list loaded) surfaces
  // inline; the button itself only shows for users who have an escrow blob on file.
  const [escrowBusy, setEscrowBusy] = useState(false);
  const [escrowMsg, setEscrowMsg] = useState("");
  const downloadEscrow = async () => {
    setEscrowMsg("");
    setEscrowBusy(true);
    try {
      const sealed = await onDownloadEscrow();
      const url = URL.createObjectURL(new Blob([sealed], { type: "text/plain" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = `andvari-escrow-${u.userId}.txt`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e) {
      setEscrowMsg(e instanceof ApiError && e.code === "no_escrow" ? "no escrow on file" : "download failed");
    } finally {
      setEscrowBusy(false);
    }
  };
  return (
    <>
      <tr>
        <td>
          <div>{u.email} {u.isAdmin && <span className="tag">admin</span>}</div>
          <div className="muted">{u.displayName}</div>
        </td>
        <td>{u.status === "active" ? u.status : <span className="tone-bad">{u.status}</span>}</td>
        <td className="muted">{fmtDate(u.createdAt)}</td>
        <td><button type="button" className="link" onClick={onToggleDevices}>{u.deviceCount} device{u.deviceCount === 1 ? "" : "s"} {expanded ? "▴" : "▾"}</button></td>
        <td className="mono muted" title={u.escrowFingerprint ?? undefined}>{u.escrowFingerprint ? u.escrowFingerprint.slice(0, 12) + "…" : "—"}</td>
        <td>
          {u.escrowFingerprint && (
            <div style={{ marginBottom: u.status === "active" ? 6 : 0 }}>
              <button type="button" className="ghost" disabled={escrowBusy} onClick={downloadEscrow}>{escrowBusy ? "Fetching…" : "Download escrow"}</button>
              {escrowMsg && <span className="muted" style={{ marginLeft: 8 }}>{escrowMsg}</span>}
            </div>
          )}
          {u.status === "active" && (confirming ? (
            <span style={{ whiteSpace: "nowrap" }}>
              <span className="muted">Disable {u.email}?&nbsp;</span>
              <button type="button" className="ghost" style={{ color: "var(--danger)" }} disabled={busy} onClick={() => { setConfirming(false); onDisable(); }}>Yes, disable</button>{" "}
              <button type="button" className="ghost" disabled={busy} onClick={() => setConfirming(false)}>Keep</button>
            </span>
          ) : (
            <button type="button" className="ghost" style={{ color: "var(--danger)" }} disabled={busy} onClick={() => setConfirming(true)}>Disable</button>
          ))}
        </td>
      </tr>
      {expanded && (
        <tr className="subrow">
          <td colSpan={6}>
            {devices.length === 0 ? (
              <span className="muted">no devices</span>
            ) : (
              <table className="table inner">
                <thead>
                  <tr><th>Device</th><th>Platform</th><th>Client</th><th>Last seen</th><th></th></tr>
                </thead>
                <tbody>
                  {devices.map((d) => (
                    <tr key={d.deviceId}>
                      <td>{d.name}</td>
                      <td className="muted">{d.platform}</td>
                      <td className="muted">{d.clientVersion ?? "—"}</td>
                      <td className="muted">{fmtDate(d.lastSeenAt)}</td>
                      <td>
                        {d.revokedAt ? (
                          <span className="tone-bad">revoked</span>
                        ) : (
                          <button type="button" className="ghost" style={{ color: "var(--danger)" }} disabled={busy} onClick={() => onRevoke(d.deviceId)}>Revoke</button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </td>
        </tr>
      )}
    </>
  );
}

/** Every invite is a bearer credential; per AdminService.kt the invite TTL is the SOLE containment
 *  for a photographed/leaked QR (the org recovery fingerprint the enrollee types is PUBLIC — it
 *  does NOT bind a token holder). So the admin picks the lifetime, defaulting SHORT; 1 day / 3 days
 *  are conscious hand-delivery opt-ins. Values stay inside the server's [5, 4320]-minute clamp.
 *  Pure + exported so a refactor that adds an out-of-range or wrong default trips a unit test. */
export type InviteTtl = "1h" | "1d" | "3d";
export const INVITE_TTL_DEFAULT: InviteTtl = "1h";
export function inviteTtlMinutes(choice: InviteTtl): number {
  switch (choice) {
    case "1h": return 60;
    case "1d": return 24 * 60;
    case "3d": return 72 * 60;
    // Fail SAFE to the SHORT window: a future <option> added without its own case mints at 60 min,
    // NEVER silently at the server's 72h default (which is what returning `undefined` →
    // adminInvite(undefined) would do). Keeps "secure-by-default-short" robust against a careless edit.
    default: return 60;
  }
}

/** v1 containment (design §Server work 2): the QR path is offered only on a private origin.
 *  The link embeds that origin, and public register is server-refused anyway — a public QR
 *  would sail through the ceremony and die at the last step. Pure, so a refactor that drops
 *  or inverts this gate trips a unit test rather than silently exposing it. */
export function shouldOfferQr(origin: string): boolean {
  return isPrivateOrigin(origin);
}

/** The vendored QR encoder THROWS a bare string on capacity overflow — never let a long
 *  origin+email white-screen Admin; the caller falls back to the copyable link. Pure. */
export function tryQrModules(link: string): boolean[][] | null {
  try {
    return qrModules(link, "M");
  } catch {
    return null;
  }
}

/** The invite result view is a pure function of (can this origin show a QR, did the link encode,
 *  did the QR matrix build). Pinned so a refactor can't resurface a dead/misleading QR affordance
 *  on the public break-glass origin — qrAvailable=false is ALWAYS "token-only" (breaker BLOCKER 2:
 *  gating a QR/compose note on bare !resultLink would paint a false "couldn't encode a QR" on every
 *  public invite, since resultLink is null there too). */
export type InviteResultView = "token-only" | "qr" | "overflow-link" | "compose-note";
export function inviteResultView(qrAvailable: boolean, linkComposed: boolean, modulesOk: boolean): InviteResultView {
  if (!qrAvailable) return "token-only";
  if (!linkComposed) return "compose-note";
  return modulesOk ? "qr" : "overflow-link";
}

function InviteForm({ client, onInvited }: { client: ApiClient; onInvited: () => void }) {
  const [email, setEmail] = useState("");
  const [isAdmin, setIsAdmin] = useState(false);
  const [ttl, setTtl] = useState<InviteTtl>(INVITE_TTL_DEFAULT);
  const [result, setResult] = useState<InviteResponse | null>(null);
  const [resultLink, setResultLink] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [copiedLink, setCopiedLink] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [sendEmail, setSendEmail] = useState(false);
  const [emailAvailable, setEmailAvailable] = useState(false);
  // The enroll link embeds location.origin verbatim. On the public break-glass origin that link
  // would sail through the whole ceremony and then die at register (public-register is
  // server-refused) — so the QR path simply doesn't exist there; the plain token stays, redeemed
  // wherever the member actually enrolls. shouldOfferQr gates every QR-bearing surface below.
  const qrAvailable = shouldOfferQr(window.location.origin);

  // cut 4: the "email this invite" checkbox appears only when the server has email fully configured
  // (SMTP + a valid private base URL) AND we're on a private origin (an emailed public-origin link
  // dies at register). One status fetch drives availability.
  useEffect(() => {
    let live = true;
    if (qrAvailable) client.adminStatus().then((s) => { if (live) setEmailAvailable(s.emailConfigured); }).catch(() => {});
    return () => { live = false; };
  }, [client, qrAvailable]);

  const mint = async () => {
    setBusy(true);
    setErr("");
    setResult(null);
    setResultLink(null);
    try {
      const r = await client.adminInvite(email.trim(), isAdmin, inviteTtlMinutes(ttl), sendEmail && emailAvailable);
      setResult(r);
      if (qrAvailable) {
        // composeEnrollLink refuses ill-formed UTF-16 (null) — a lone surrogate can round-trip
        // JSON as \udXXX, so "the server validated the email" is no guarantee. On null we KEEP the
        // token (the invite WAS minted) and fall to the "compose-note" view — there is no plain
        // Invite button to retry with anymore, so NEVER clear the result.
        setResultLink(composeEnrollLink(window.location.origin, r.inviteToken, r.email));
      }
      setEmail("");
      setIsAdmin(false);
      setSendEmail(false);
      // keep `ttl` — an admin minting several invites is likely using one delivery method
      onInvited();
    } catch (e) {
      setErr(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    await mint();
  };

  const copy = async (value: string, link: boolean) => {
    await navigator.clipboard.writeText(value);
    (link ? setCopiedLink : setCopied)(true);
    window.setTimeout(() => (link ? setCopiedLink : setCopied)(false), 1200);
  };

  // The vendored encoder THROWS (a bare string) on capacity overflow — never let a long
  // origin+email white-screen Admin; fall back to the copyable link.
  const modules = useMemo(() => (resultLink ? tryQrModules(resultLink) : null), [resultLink]);
  const view: InviteResultView | null = result ? inviteResultView(qrAvailable, resultLink !== null, modules !== null) : null;
  const showLink = view === "qr" || view === "overflow-link";

  return (
    <form className="sheet" style={{ marginBottom: 20 }} onSubmit={submit}>
      <h2>Invite a user</h2>
      {err && <Msg kind="err">{err}</Msg>}
      {/* AM-2 / BL-1: "Invite created" is async status → a PERSISTENT (unconditionally mounted)
          visually-hidden region, driven by result?.email so it re-announces on a same-email repeat. */}
      <Announcer text={result ? `Invite created for ${result.email}` : ""} />
      <div className="row" style={{ alignItems: "flex-end" }}>
        <Field label="Email" style={{ flex: 1, marginBottom: 0 }}>
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="new@user" />
        </Field>
        <Field label="Invite expires in" style={{ marginBottom: 0 }}>
          <select value={ttl} disabled={sendEmail} onChange={(e) => setTtl(e.target.value as InviteTtl)}>
            <option value="1h">1 hour</option>
            <option value="1d">1 day</option>
            <option value="3d">3 days</option>
          </select>
        </Field>
        <label className="check" style={{ margin: "0 0 10px" }}>
          <input type="checkbox" checked={isAdmin} onChange={(e) => setIsAdmin(e.target.checked)} />
          <span>admin</span>
        </label>
        {qrAvailable && emailAvailable && (
          <label className="check" style={{ margin: "0 0 10px" }}>
            <input type="checkbox" checked={sendEmail} onChange={(e) => { setSendEmail(e.target.checked); if (e.target.checked) setTtl("1h"); }} />
            <span>email it</span>
          </label>
        )}
        <button className="ghost" disabled={busy || !email.trim()}>{busy ? "Inviting…" : "Invite"}</button>
      </div>
      {qrAvailable && emailAvailable && sendEmail && (
        <div className="muted" style={{ marginTop: 8 }}>
          andvari will also email the enroll link to this address — a one-time key that expires within
          the hour. Still hand over the printed recovery sheet in person.
        </div>
      )}
      {result && (
        <div className="token-box">
          <div className="muted" style={{ marginBottom: 6 }}>
            One-time invite token for <strong>{result.email}</strong> — shown ONCE, expires {fmtDate(result.expiresAt)}. Hand it over securely.
          </div>
          <div className="secret-row">
            <input readOnly className="mono token" value={result.inviteToken} onFocus={(e) => e.target.select()} />
            <button type="button" className="ghost" onClick={() => void copy(result.inviteToken, false)}>{copied ? "Copied ✓" : "Copy"}</button>
          </div>
          {view === "compose-note" && (
            <div className="muted" style={{ marginTop: 8 }}>
              Couldn't encode a QR link for this address — hand over the token above instead.
            </div>
          )}
          {showLink && resultLink && (
            <div style={{ marginTop: 12 }}>
              {view === "qr" && modules ? (
                <QrSvg modules={modules} ariaLabel={`Enrollment QR code for ${result.email}`} />
              ) : (
                <div className="msg info" style={{ display: "block" }}>QR too dense to render — use the link below instead.</div>
              )}
              <div className="secret-row" style={{ marginTop: 8 }}>
                <input readOnly className="mono token" value={resultLink} onFocus={(e) => e.target.select()} />
                <button type="button" className="ghost" onClick={() => void copy(resultLink, true)}>{copiedLink ? "Copied ✓" : "Copy link"}</button>
              </div>
              <div className="muted" style={{ marginTop: 8 }}>
                Expires {fmtDate(result.expiresAt)}. They scan this with their phone camera (or open the link) <strong>while on the same network as this page's address</strong> — for a phone that isn't on the tailnet yet, mint from the LAN address instead. <strong>Anyone who photographs this can use it until it expires — it can't be revoked</strong>, so keep the window short and hand them the <strong>printed recovery sheet in person</strong>.
              </div>
            </div>
          )}
        </div>
      )}
    </form>
  );
}

// ---- Audit ----

const AUDIT_PAGE = 200;

function AuditTab({ client }: { client: ApiClient }) {
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [typeFilter, setTypeFilter] = useState("");
  const [limit, setLimit] = useState(AUDIT_PAGE);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const load = async (type: string, lim: number) => {
    setBusy(true);
    setErr("");
    try {
      setEvents(await client.adminAudit({ type: type.trim() || undefined, limit: lim }));
    } catch (e) {
      setErr(errText(e));
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    load(typeFilter, limit);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [client]);

  const applyFilter = (e: React.FormEvent) => {
    e.preventDefault();
    setLimit(AUDIT_PAGE);
    load(typeFilter, AUDIT_PAGE);
  };

  // NOTE: the server's `since` filters `id > since` (a tail checkpoint, not an
  // "older than" cursor), so paging DOWN is done by refetching with a larger limit.
  const loadMore = () => {
    const next = Math.min(limit + AUDIT_PAGE, 1000);
    setLimit(next);
    load(typeFilter, next);
  };

  const exhausted = events !== null && (events.length < limit || limit >= 1000);

  return (
    <div>
      {err && <Msg kind="err">{err}</Msg>}
      <form className="toolbar" onSubmit={applyFilter}>
        <input aria-label="Filter by event type" placeholder="Filter by event type (exact, e.g. login_fail)…" value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)} />
        <button className="ghost" disabled={busy}>Filter</button>
      </form>
      {!events ? (
        <p className="muted">loading…</p>
      ) : events.length === 0 ? (
        <div className="empty"><p>No audit events{typeFilter ? " of that type" : ""}.</p></div>
      ) : (
        <>
          <div className="table-scroll">
            <table className="table">
              <thead>
                <tr>
                  <th>Id</th>
                  <th>When</th>
                  <th>Type</th>
                  <th>User</th>
                  <th>Device</th>
                  <th>Ip</th>
                  <th>Meta</th>
                </tr>
              </thead>
              <tbody>
                {events.map((ev) => (
                  <tr key={ev.id}>
                    <td className="muted">{ev.id}</td>
                    <td className="muted">{fmtDate(ev.at)}</td>
                    <td>{ev.type.includes("fail") ? <span className="tone-bad">{ev.type}</span> : ev.type}</td>
                    <td className="mono muted" title={ev.userId ?? undefined}>{shortId(ev.userId)}</td>
                    <td className="mono muted" title={ev.deviceId ?? undefined}>{shortId(ev.deviceId)}</td>
                    <td className="mono muted">{ev.ip ?? "—"}</td>
                    <td className="muted">{ev.meta ?? ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {!exhausted && (
            <div style={{ textAlign: "center", margin: "14px 0" }}>
              <button type="button" className="ghost" disabled={busy} onClick={loadMore}>{busy ? "Loading…" : "Load more"}</button>
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ---- Policy ----

const MIB = 1024 * 1024;

function PolicyTab({ client }: { client: ApiClient }) {
  // PUT replaces the FULL policy: keep the GET response whole and patch fields into it.
  const [policy, setPolicy] = useState<ClientPolicy | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [msg, setMsg] = useState("");

  useEffect(() => {
    client.adminPolicy().then(setPolicy).catch((e) => setErr(errText(e)));
  }, [client]);

  if (!policy) return err ? <Msg kind="err">{err}</Msg> : <p className="muted">loading…</p>;

  const patch = (p: Partial<ClientPolicy>) => setPolicy({ ...policy, ...p });
  const patchMin = (platform: string, v: string) => patch({ minVersion: { ...policy.minVersion, [platform]: v } });

  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    setMsg("");
    try {
      setPolicy(await client.adminSetPolicy(policy));
      setMsg("Policy saved — clients pick it up on their next poll.");
    } catch (e) {
      setErr(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const numField = (label: string, value: number, onChange: (n: number) => void, suffix?: string) => (
    <Field label={`${label}${suffix ? ` (${suffix})` : ""}`} style={{ flex: 1 }}>
      <input type="number" min={0} value={value} onChange={(e) => onChange(Number(e.target.value) || 0)} />
    </Field>
  );

  return (
    <form className="sheet" onSubmit={save}>
      <h2>Client policy</h2>
      {err && <Msg kind="err">{err}</Msg>}
      {msg && <Msg kind="info">{msg}</Msg>}
      {/* BL-1: "Policy saved" is async info → persistent region. */}
      <Announcer text={msg} />

      <label style={{ marginBottom: 8 }}>Minimum client versions</label>
      <div className="row">
        {(["android", "windows", "web"] as const).map((p) => (
          <Field label={p} style={{ flex: 1 }} key={p}>
            <input className="mono" value={policy.minVersion[p] ?? ""} onChange={(e) => patchMin(p, e.target.value)} placeholder="0.1.0" />
          </Field>
        ))}
      </div>

      <div className="row">
        {numField("Auto-lock", policy.autoLockSeconds, (n) => patch({ autoLockSeconds: n }), "seconds")}
        {numField("Clipboard clear", policy.clipboardClearSeconds, (n) => patch({ clipboardClearSeconds: n }), "seconds")}
      </div>

      {/* F64: session lifetimes were live policy knobs with no UI. Clamp ≥1 — a 0 TTL would
          mint already-expired tokens and lock everyone out on the next refresh. */}
      <div className="row">
        {numField("Access-token lifetime", policy.sessionAccessTtlSeconds, (n) => patch({ sessionAccessTtlSeconds: Math.max(1, n) }), "seconds")}
        {numField("Refresh-token lifetime", policy.sessionRefreshTtlDays, (n) => patch({ sessionRefreshTtlDays: Math.max(1, n) }), "days")}
      </div>

      <label className="check">
        <input type="checkbox" checked={policy.offlineCacheAllowed} onChange={(e) => patch({ offlineCacheAllowed: e.target.checked })} />
        <span>Allow clients to keep an encrypted offline cache</span>
      </label>

      <label style={{ marginBottom: 8 }}>Attachment quotas</label>
      <div className="row">
        {numField("Per attachment", Math.round(policy.attachmentMaxBytes / MIB), (n) => patch({ attachmentMaxBytes: n * MIB }), "MiB")}
        {numField("Per item", Math.round(policy.itemAttachmentsMaxBytes / MIB), (n) => patch({ itemAttachmentsMaxBytes: n * MIB }), "MiB")}
        {numField("Per user", Math.round(policy.userAttachmentsMaxBytes / MIB), (n) => patch({ userAttachmentsMaxBytes: n * MIB }), "MiB")}
      </div>

      <Field label="KDF (read-only — changing it requires a coordinated re-enrollment)">
        <input readOnly className="mono" value={`${policy.kdfParams.alg} · ops ${policy.kdfParams.ops} · mem ${humanSize(policy.kdfParams.memBytes)}`} />
      </Field>

      <div className="actions">
        <button className="primary" disabled={busy}>{busy ? "Saving…" : "Save policy"}</button>
      </div>
    </form>
  );
}

// ---- Status ----

function StatusTab({ client }: { client: ApiClient }) {
  const [status, setStatus] = useState<AdminStatus | null>(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    client.adminStatus().then(setStatus).catch((e) => setErr(errText(e)));
  }, [client]);

  if (err) return <Msg kind="err">{err}</Msg>;
  if (!status) return <p className="muted">loading…</p>;

  const yes = (b: boolean) => (b ? <span className="tone-good">yes</span> : <span className="tone-bad">no</span>);

  return (
    <div className="sheet">
      <h2>Server status</h2>
      <dl className="kv">
        <dt>Server version</dt><dd className="mono">{status.serverVersion}</dd>
        <dt>Server time</dt><dd>{fmtDate(status.serverTime)}</dd>
        <dt>Escrow configured</dt><dd>{yes(status.escrowConfigured)}</dd>
        <dt>Recovery fingerprint</dt><dd className="mono fingerprint">{status.recoveryFingerprint ? status.recoveryFingerprint.replace(/(.{4})/g, "$1 ").trim() : "—"}</dd>
        <dt>Break-glass configured</dt><dd>{yes(status.breakGlassConfigured)}</dd>
        <dt>Last public request</dt><dd>{status.lastPublicRequestAt ? fmtDate(status.lastPublicRequestAt) : "never"}</dd>
        <dt>Users</dt><dd>{status.userCount} ({status.totpEnrolledCount} with TOTP)</dd>
        <dt>Items</dt><dd>{status.itemCount}</dd>
        <dt>Attachments</dt><dd>{status.attachmentCount} · {humanSize(status.attachmentBytes)}</dd>
        <dt>Database size</dt><dd>{humanSize(status.dbBytes)}</dd>
        <dt>Downloads manifest</dt><dd>{yes(status.downloadsManifest)}</dd>
      </dl>
    </div>
  );
}
