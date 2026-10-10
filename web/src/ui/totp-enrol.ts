import type { ApiClient } from "../api/client";
import type { TotpSetupResponse } from "../api/types";
import { Account } from "../vault/account";

/**
 * Security review 2026-10 (server F4, client half): the server refuses a FIRST TOTP enrollment from
 * a session whose password login is older than its fresh-login window unless the setup carries the
 * password proof — so a stolen session can't enroll a factor the owner doesn't hold and lock them
 * out. Derive the login authKey from the typed master password under the account's OWN stored KDF
 * salt/params (the values prelogin serves, so it verifies against the server's login verifier —
 * the same derivation Settings' PasswordCard uses) and send it with the setup.
 */
export async function beginTotpEnrolment(
  client: Pick<ApiClient, "accountKeys" | "totpSetup">,
  password: string,
): Promise<TotpSetupResponse> {
  const keys = await client.accountKeys();
  const currentAuthKey = await Account.deriveAuthKey(password, keys.kdfSalt, keys.kdfParams);
  return client.totpSetup(currentAuthKey);
}
