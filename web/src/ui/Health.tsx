import { useMemo, useState } from "react";
import { ApiClient } from "../api/client";
import { hibpCountInRange, hibpPrefix, hibpSha1UpperHex } from "../crypto/hibp";
import type { VaultStore } from "../vault/store";
import { Msg } from "./Msg";
import { EmptySigil } from "./Sigil";
import { STRENGTH_LABELS, estimateStrength } from "./strength";
import { ViewHeader } from "./ViewHeader";

interface Props {
  store: VaultStore;
  client: ApiClient;
  /** CR-08: keys the in-session breach cache per-account so a shared browser never cross-contaminates. */
  userId: string;
  onOpenItem: (itemId: string) => void;
}

interface Row {
  itemId: string;
  name: string;
  password: string;
  strength: number;
  reused: number; // other items sharing this password
  hasTotp: boolean;
}

/** Vault-wide password health: strength, reuse, and (on demand) HIBP breach exposure. */
export function Health({ store, client, userId, onOpenItem }: Props) {
  const rows = useMemo<Row[]>(() => {
    const logins = store.list().filter((it) => it.doc.type === "login" && it.doc.login?.password);
    const byPassword = new Map<string, number>();
    for (const it of logins) {
      const pw = it.doc.login!.password!;
      byPassword.set(pw, (byPassword.get(pw) ?? 0) + 1);
    }
    return logins.map((it) => {
      const pw = it.doc.login!.password!;
      return {
        itemId: it.itemId,
        name: it.doc.name || "(untitled)",
        password: pw,
        strength: estimateStrength(pw),
        reused: (byPassword.get(pw) ?? 1) - 1,
        hasTotp: !!it.doc.login!.totp,
      };
    });
  }, [store]);

  // itemId → breach count, filled by a scan and cached ON-DEVICE (by itemId — never the plaintext
  // password, which is only the scan's lookup key) so it survives navigating away from Health.
  // Loaded from the cache on mount → the button reads "Rescan" and the column shows last results.
  const [breachByItem, setBreachByItem] = useState<Map<string, number> | null>(() => loadBreachCache(userId));
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState({ done: 0, total: 0 });
  const [scanErr, setScanErr] = useState("");

  const scan = async () => {
    setScanning(true);
    setScanErr("");
    try {
      // k-anonymity (spec 03 §8): hash every UNIQUE password, fetch each 5-hex
      // prefix range once, then map suffix counts back — sequential, gentle on the relay.
      const unique = [...new Set(rows.map((r) => r.password))];
      const hashes = new Map<string, string>(); // password → sha1 upper hex
      for (const pw of unique) hashes.set(pw, await hibpSha1UpperHex(pw));
      const byPrefix = new Map<string, string[]>(); // prefix → passwords
      for (const [pw, hash] of hashes) {
        const p = hibpPrefix(hash);
        byPrefix.set(p, [...(byPrefix.get(p) ?? []), pw]);
      }
      setProgress({ done: 0, total: byPrefix.size });
      const result = new Map<string, number>();
      let done = 0;
      for (const [prefix, passwords] of byPrefix) {
        const body = await client.hibpRange(prefix);
        for (const pw of passwords) result.set(pw, hibpCountInRange(body, hashes.get(pw)!));
        setProgress({ done: ++done, total: byPrefix.size });
      }
      // Persist + display keyed by itemId — never the plaintext password (the scan's lookup key).
      const byItem = new Map(rows.map((r) => [r.itemId, result.get(r.password) ?? 0]));
      setBreachByItem(byItem);
      saveBreachCache(userId, byItem);
    } catch {
      setScanErr("Breach scan failed — the HIBP relay is unavailable. Partial results were discarded.");
    } finally {
      setScanning(false);
    }
  };

  const weak = rows.filter((r) => r.strength <= 1).length;
  const reused = rows.filter((r) => r.reused > 0).length;
  const breached = breachByItem ? rows.filter((r) => (breachByItem.get(r.itemId) ?? 0) > 0).length : null;
  // Highest breach count first (owner ask), then alphabetical; unscanned/no-breach items tie at 0.
  const sorted = useMemo(() => {
    const n = (id: string) => breachByItem?.get(id) ?? 0;
    return [...rows].sort((a, b) => n(b.itemId) - n(a.itemId) || a.name.localeCompare(b.name));
  }, [rows, breachByItem]);

  return (
    <div>
      <ViewHeader
        title="Vault health"
        actions={
          <button className="ghost" onClick={scan} disabled={scanning || rows.length === 0}>
            {scanning ? `Scanning… ${progress.done}/${progress.total}` : breachByItem ? "Rescan for breaches" : "Scan for breaches"}
          </button>
        }
      />
      {scanErr && <Msg kind="err">{scanErr}</Msg>}

      <div className="tiles">
        <Tile label="Logins" value={String(rows.length)} />
        <Tile label="Weak" value={String(weak)} tone={weak > 0 ? "bad" : "good"} />
        <Tile label="Reused" value={String(reused)} tone={reused > 0 ? "bad" : "good"} />
        <Tile label="Breached" value={breached === null ? "—" : String(breached)} tone={breached === null ? undefined : breached > 0 ? "bad" : "good"} hint={breached === null ? "run a scan" : undefined} />
      </div>

      {rows.length === 0 ? (
        <div className="empty">
          <div className="sigil"><EmptySigil /></div>
          <p>No logins with passwords yet — nothing to assess.</p>
        </div>
      ) : (
        <div className="table-scroll">
          <table className="table">
            <thead>
              <tr>
                <th>Item</th>
                <th>Strength</th>
                <th>Reused</th>
                <th>TOTP</th>
                <th>Breaches</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((r) => {
                const count = breachByItem?.get(r.itemId);
                return (
                  <tr
                    key={r.itemId}
                    className="rowlink"
                    // F80: the row is a click target, so the keyboard gets the same
                    // affordance (Space is prevented — it must not page-scroll).
                    // a11yweb-07: role+name so a screen reader announces it as an
                    // openable control, not a bare table row.
                    role="button"
                    aria-label={`Open ${r.name}`}
                    tabIndex={0}
                    onClick={() => onOpenItem(r.itemId)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        onOpenItem(r.itemId);
                      }
                    }}
                  >
                    <td>{r.name}</td>
                    <td><StrengthTag score={r.strength} /></td>
                    <td>{r.reused > 0 ? <span className="tone-bad">{r.reused} other{r.reused > 1 ? "s" : ""}</span> : <span className="muted">no</span>}</td>
                    <td>{r.hasTotp ? "yes" : <span className="muted">no</span>}</td>
                    <td>
                      {breachByItem === null ? (
                        <span className="muted">—</span>
                      ) : count && count > 0 ? (
                        <span className="tone-bad">{count.toLocaleString()}</span>
                      ) : (
                        <span className="tone-good">none</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// In-session breach cache — itemId → count only (no password material). CR-08 (compliance
// 2026-07-15): this used to persist to a GLOBAL localStorage key ("andvari:breach-cache:v1"),
// where a map derived from decrypted passwords (a >10M count fingerprints a top-100 password)
// survived sign-out/revocation, landed on the public break-glass origin, and cross-contaminated
// accounts on a shared browser — a client-at-rest artifact outside the spec 02 §5 table and every
// WC-13 wipe gate. Fix: keep it in MEMORY only, keyed PER-ACCOUNT, matching the wipe table —
// retained across a lock and Health unmount/remount (module scope survives a phase change), GONE
// on sign-out (clearBreachCache, called from App.signOut, the one wipe choke point) and on reload.
// Nothing is written at rest, so there is no residue, no public-origin leak, and no gate to bypass.
const breachCacheByUser = new Map<string, Map<string, number>>();
/** CR-08: the retired global localStorage key. Proactively purged (below) so the pre-fix at-rest
 *  residue — item count + a password-popularity fingerprint on the public break-glass origin — is
 *  removed from devices that ran the old build, not merely left un-updated. */
const LEGACY_BREACH_CACHE_KEY = "andvari:breach-cache:v1";
function purgeLegacyBreachResidue(): void {
  try {
    localStorage.removeItem(LEGACY_BREACH_CACHE_KEY);
  } catch {
    /* storage unreachable (privacy mode / non-window) — nothing to purge */
  }
}
function loadBreachCache(userId: string): Map<string, number> | null {
  purgeLegacyBreachResidue(); // opening Health scrubs any old at-rest map first
  const m = breachCacheByUser.get(userId);
  return m ? new Map(m) : null; // a copy — callers own their snapshot; never share the stored ref
}
function saveBreachCache(userId: string, byItem: Map<string, number>): void {
  breachCacheByUser.set(userId, new Map(byItem));
}
/** CR-08 / WC-13 §E.4: drop every account's in-memory breach map. Called from App.signOut (the
 *  declared wipe choke point) so the map is GONE on sign-out / revocation / definitive-401 — never
 *  outliving the session the way the old localStorage key did. A lock does NOT call this (retained). */
export function clearBreachCache(): void {
  breachCacheByUser.clear();
  purgeLegacyBreachResidue(); // and scrub the legacy at-rest residue at the wipe choke point
}

function Tile({ label, value, tone, hint }: { label: string; value: string; tone?: "good" | "bad"; hint?: string }) {
  return (
    <div className="tile">
      <div className={`tile-value ${tone === "bad" ? "tone-bad" : tone === "good" ? "tone-good" : ""}`}>{value}</div>
      <div className="tile-label">{label}{hint ? <span className="muted"> · {hint}</span> : null}</div>
    </div>
  );
}

function StrengthTag({ score }: { score: number }) {
  const cls = score <= 1 ? "tone-bad" : score === 2 ? "tone-mid" : "tone-good";
  return <span className={cls}>{STRENGTH_LABELS[score] ?? "?"}</span>;
}
