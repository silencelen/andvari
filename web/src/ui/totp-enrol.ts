import type { ApiClient } from "../api/client";
import type { TotpSetupResponse } from "../api/types";
import type { Account } from "../vault/account";

/**
 * Security review 2026-10 (server F4, client half): the server refuses a FIRST TOTP enrollment from
 * a session whose password login is older than its fresh-login window unless the setup carries the
 * password proof — so a stolen session can't enroll a factor the owner doesn't hold and lock them
 * out. Derive the login authKey from the typed master password under the account's OWN stored KDF
 * salt/params (the values prelogin serves, so it verifies against the server's login verifier) and
 * send it with the setup. Security review 2026-10 (A9, M-1): the derivation is `account.reauthAuthKey`,
 * the one fenced in-session derivation (KDF floor/ceiling, and only the salt THIS session unlocked
 * with), so a served salt or weakened params derive nothing.
 */
export async function beginTotpEnrolment(
  client: Pick<ApiClient, "accountKeys" | "totpSetup">,
  password: string,
  account: Pick<Account, "reauthAuthKey">,
): Promise<TotpSetupResponse> {
  const keys = await client.accountKeys();
  const currentAuthKey = await account.reauthAuthKey(password, keys);
  return client.totpSetup(currentAuthKey);
}
