import type { Account } from "../vault/account";
import { NO_PERSONAL_VAULT } from "./copy";

/**
 * Design §5.3: a served personal wrap that was withheld or does not open leaves "no personal vault" with the anomaly:
 * no default save destination, and no question. The old designation question ("Which vault is your Personal
 * vault?"), proposals and re-designation are deleted; only the genesis vault can be the personal vault.
 */
export function NoPersonalVaultNotice({ account }: { account: Account }) {
  if (account.personalVaultId) return null;
  return (
    <div className="msg err" style={{ display: "block" }} role="alert">
      {NO_PERSONAL_VAULT}
    </div>
  );
}
