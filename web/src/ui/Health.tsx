import { useMemo, useState } from "react";
import { ApiClient } from "../api/client";
import { hibpCountInRange, hibpPrefix, hibpSha1UpperHex } from "../crypto/hibp";
import type { VaultStore } from "../vault/store";
import { STRENGTH_LABELS, estimateStrength } from "./strength";

interface Props {
  store: VaultStore;
  client: ApiClient;
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
export function Health({ store, client, onOpenItem }: Props) {
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

  // password → breach count, filled by the scan; null until one has run.
  const [breaches, setBreaches] = useState<Map<string, number> | null>(null);
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
      setBreaches(result);
    } catch {
      setScanErr("Breach scan failed — the HIBP relay is unavailable. Partial results were discarded.");
    } finally {
      setScanning(false);
    }
  };

  const weak = rows.filter((r) => r.strength <= 1).length;
  const reused = rows.filter((r) => r.reused > 0).length;
  const breached = breaches ? rows.filter((r) => (breaches.get(r.password) ?? 0) > 0).length : null;

  return (
    <div>
      <div className="toolbar" style={{ alignItems: "center" }}>
        <h2 className="view-title">Vault health</h2>
        <div className="spacer" />
        <button className="ghost" onClick={scan} disabled={scanning || rows.length === 0}>
          {scanning ? `Scanning… ${progress.done}/${progress.total}` : breaches ? "Rescan breaches" : "Scan breaches"}
        </button>
      </div>
      {scanErr && <div className="msg err">{scanErr}</div>}

      <div className="tiles">
        <Tile label="Logins" value={String(rows.length)} />
        <Tile label="Weak" value={String(weak)} tone={weak > 0 ? "bad" : "good"} />
        <Tile label="Reused" value={String(reused)} tone={reused > 0 ? "bad" : "good"} />
        <Tile label="Breached" value={breached === null ? "—" : String(breached)} tone={breached === null ? undefined : breached > 0 ? "bad" : "good"} hint={breached === null ? "run a scan" : undefined} />
      </div>

      {rows.length === 0 ? (
        <div className="empty">
          <div className="sigil">ᛝ</div>
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
              {rows.map((r) => {
                const count = breaches?.get(r.password);
                return (
                  <tr key={r.itemId} className="rowlink" onClick={() => onOpenItem(r.itemId)}>
                    <td>{r.name}</td>
                    <td><StrengthTag score={r.strength} /></td>
                    <td>{r.reused > 0 ? <span className="tone-bad">{r.reused} other{r.reused > 1 ? "s" : ""}</span> : <span className="muted">no</span>}</td>
                    <td>{r.hasTotp ? "yes" : <span className="muted">no</span>}</td>
                    <td>
                      {breaches === null ? (
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
