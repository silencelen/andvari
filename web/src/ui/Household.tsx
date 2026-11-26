import type { Account } from "../vault/account";
import type { VaultStore } from "../vault/store";

/**
 * The personal vault (security review 2026-10, root cause A §4, §7.2; branch A5).
 *
 * {@link PersonalVaultCard}: which vault is personal. Design §5.3: it is the genesis vault, in force only when its served
 * wrap opened at unlock; nothing designates, proposes or re-designates one (§15's web row). The anomaly of having none
 * is shown by `NoPersonalVaultNotice`.
 *
 * The old "Household members you've verified" card is gone (2026-11-16): it listed the old typed, QR and enrolment pins,
 * which design §6.9 deletes (every contact now comes from a link, made on a native device), and the web makes no
 * contact and compares no code (§13). The contacts this browser uses are confirmed through the one-tap list and the
 * per-contact prompt (SharedPrompts).
 */

/** Settings: which vault is personal (design §5.3: the genesis vault, when its wrap opened; nothing to change here). */
export function PersonalVaultCard({ account, store }: { account: Account; store: VaultStore }) {
  const current = account.personalVaultId ? store.vaults().find((v) => v.vaultId === account.personalVaultId) : undefined;
  return (
    <div className="sheet">
      <h2>Personal vault</h2>
      <p className="muted" style={{ marginTop: 0 }}>
        {current ? <>Your personal vault is <strong>{current.name}</strong>. New items, imports and usage history go here.</> : "Your personal vault isn't confirmed yet."}
      </p>
    </div>
  );
}
