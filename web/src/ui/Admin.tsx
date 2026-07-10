import { useEffect, useState } from "react";
import { ApiClient, ApiError } from "../api/client";
import type {
  AdminDeviceSummary,
  AdminStatus,
  AdminUserSummary,
  AuditEvent,
  ClientPolicy,
  InviteResponse,
} from "../api/types";
import { fmtDate, humanSize } from "./format";
import { ViewHeader } from "./ViewHeader";

type Tab = "users" | "audit" | "policy" | "status";

export function Admin({ client }: { client: ApiClient }) {
  const [tab, setTab] = useState<Tab>("users");
  return (
    <div>
      <ViewHeader title="Administration" />
      <div className="tabs">
        {(["users", "audit", "policy", "status"] as Tab[]).map((t) => (
          <button key={t} className={tab === t ? "active" : ""} onClick={() => setTab(t)}>
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
      {err && <div className="msg err">{err}</div>}
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

function InviteForm({ client, onInvited }: { client: ApiClient; onInvited: () => void }) {
  const [email, setEmail] = useState("");
  const [isAdmin, setIsAdmin] = useState(false);
  const [result, setResult] = useState<InviteResponse | null>(null);
  const [copied, setCopied] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    setResult(null);
    try {
      setResult(await client.adminInvite(email.trim(), isAdmin));
      setEmail("");
      setIsAdmin(false);
      onInvited();
    } catch (e) {
      setErr(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const copy = async (token: string) => {
    await navigator.clipboard.writeText(token);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1200);
  };

  return (
    <form className="sheet" style={{ marginBottom: 20 }} onSubmit={submit}>
      <h2>Invite a user</h2>
      {err && <div className="msg err">{err}</div>}
      <div className="row" style={{ alignItems: "flex-end" }}>
        <div className="field" style={{ flex: 1, marginBottom: 0 }}>
          <label>Email</label>
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="new@user" />
        </div>
        <label className="check" style={{ margin: "0 0 10px" }}>
          <input type="checkbox" checked={isAdmin} onChange={(e) => setIsAdmin(e.target.checked)} />
          <span>admin</span>
        </label>
        <button className="ghost" disabled={busy || !email.trim()}>{busy ? "Inviting…" : "Invite"}</button>
      </div>
      {result && (
        <div className="token-box">
          <div className="muted" style={{ marginBottom: 6 }}>
            One-time invite token for <strong>{result.email}</strong> — shown ONCE, expires {fmtDate(result.expiresAt)}. Hand it over securely.
          </div>
          <div className="secret-row">
            <input readOnly className="mono token" value={result.inviteToken} onFocus={(e) => e.target.select()} />
            <button type="button" className="ghost" onClick={() => copy(result.inviteToken)}>{copied ? "Copied ✓" : "Copy"}</button>
          </div>
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
      {err && <div className="msg err">{err}</div>}
      <form className="toolbar" onSubmit={applyFilter}>
        <input placeholder="Filter by event type (exact, e.g. login_fail)…" value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)} />
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

  if (!policy) return err ? <div className="msg err">{err}</div> : <p className="muted">loading…</p>;

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
    <div className="field" style={{ flex: 1 }}>
      <label>{label}{suffix ? ` (${suffix})` : ""}</label>
      <input type="number" min={0} value={value} onChange={(e) => onChange(Number(e.target.value) || 0)} />
    </div>
  );

  return (
    <form className="sheet" onSubmit={save}>
      <h2>Client policy</h2>
      {err && <div className="msg err">{err}</div>}
      {msg && <div className="msg info">{msg}</div>}

      <label style={{ marginBottom: 8 }}>Minimum client versions</label>
      <div className="row">
        {(["android", "windows", "web"] as const).map((p) => (
          <div className="field" style={{ flex: 1 }} key={p}>
            <label>{p}</label>
            <input className="mono" value={policy.minVersion[p] ?? ""} onChange={(e) => patchMin(p, e.target.value)} placeholder="0.1.0" />
          </div>
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

      <div className="field">
        <label>KDF (read-only — changing it requires a coordinated re-enrollment)</label>
        <input readOnly className="mono" value={`${policy.kdfParams.alg} · ops ${policy.kdfParams.ops} · mem ${humanSize(policy.kdfParams.memBytes)}`} />
      </div>

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

  if (err) return <div className="msg err">{err}</div>;
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
