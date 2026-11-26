import { useState } from "react";
import type { SharedLogSession } from "../vault/sharedlogs";
import { ChangeNotStoredError, LogActionError, type VaultStore } from "../vault/store";
import { LOG_ADD_NONE, LOG_ADD_TITLE, LOG_NOT_COMPARED } from "./copy";
import { Msg } from "./Msg";
import { logActionText } from "./logactiontext";

/**
 * Adding a member to a log-governed shared vault (design §3.7, §6.9): the person picks one of this browser's CURRENT
 * contacts, never an address the server resolves. The signed `add` seals the vault key to that contact's key. A
 * contact whose safety codes were not compared is shown but cannot be picked: the web offers no "share anyway"
 * release (the safer reading where the design names no web wording for it). Members of the verified log are left
 * out. Labels render as plain text only.
 */
/**
 * One addition from the panel: "" when it was made (after [onAdded]), else the line to show. An addition that is HELD
 * (its answer was lost, "cannot tell", or the server asked to slow down) calls [onHeld] at once, so that the member
 * panel draws the waiting line and its Withdraw button now, not at its next redraw.
 */
export async function addFromPanel(
  store: Pick<VaultStore, "addVaultMember">,
  vaultId: string,
  userId: string,
  role: "writer" | "reader",
  onAdded: () => Promise<void>,
  onHeld: () => void,
): Promise<string> {
  try {
    await store.addVaultMember(vaultId, userId, role);
    await onAdded();
    return "";
  } catch (e) {
    if (e instanceof ChangeNotStoredError) onHeld();
    return e instanceof LogActionError || e instanceof ChangeNotStoredError ? logActionText(e) : e instanceof Error ? e.message : String(e);
  }
}

export function LogAddMember({ vaultId, store, shared, onAdded, onHeld }: { vaultId: string; store: VaultStore; shared: SharedLogSession; onAdded: () => Promise<void>; onHeld: () => void }) {
  const [pick, setPick] = useState<string | null>(null);
  const [role, setRole] = useState<"writer" | "reader">("writer");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const members = shared.logs.verifiedState(vaultId)?.members ?? {};
  const candidates = shared.contacts.list().filter((c) => c.current !== null && !(c.record.userId in members));

  const add = async () => {
    if (pick === null) return;
    setBusy(true);
    setErr("");
    try {
      const line = await addFromPanel(store, vaultId, pick, role, onAdded, onHeld);
      if (line === "") setPick(null);
      setErr(line);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={{ marginTop: 18 }}>
      <div className="field-head">{LOG_ADD_TITLE}</div>
      {err && <Msg kind="err">{err}</Msg>}
      {candidates.length === 0 ? (
        <p className="muted">{LOG_ADD_NONE}</p>
      ) : (
        <div className="attach-list" role="radiogroup" aria-label={LOG_ADD_TITLE}>
          {candidates.map((c) => (
            <label className="attach-row" key={c.record.userId}>
              <input
                type="radio"
                name={`log-add-${vaultId}`}
                disabled={busy || !c.record.compared}
                checked={pick === c.record.userId}
                onChange={() => setPick(c.record.userId)}
              />
              <span className="attach-name">{c.labelText}</span>
              {!c.record.compared && <span className="muted">{LOG_NOT_COMPARED}</span>}
            </label>
          ))}
        </div>
      )}
      {candidates.length > 0 && (
        <div className="secret-row" style={{ marginTop: 8 }}>
          <select value={role} aria-label="Role" disabled={busy} onChange={(e) => setRole(e.target.value === "reader" ? "reader" : "writer")} style={{ width: "auto" }}>
            <option value="writer">writer</option>
            <option value="reader">reader</option>
          </select>
          <button type="button" className="primary" disabled={busy || pick === null} onClick={() => void add()}>
            {busy ? "Adding…" : "Add"}
          </button>
        </div>
      )}
    </div>
  );
}
