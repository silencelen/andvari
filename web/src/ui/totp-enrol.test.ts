import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ApiClient } from "../api/client";
import { Account } from "../vault/account";
import { beginTotpEnrolment } from "./totp-enrol";

/**
 * Security review 2026-10 (server F4, client half): the web enrolls from Settings, usually long
 * after sign-in, where the server now refuses a bare first-enrollment setup. The TOTP card asks for
 * the master password and enrolls through beginTotpEnrolment, which derives the login authKey under
 * the account's OWN stored KDF salt/params (the same derivation the password-change card uses).
 */
describe("beginTotpEnrolment", () => {
  afterEach(() => vi.restoreAllMocks());

  it("derives the authKey from the typed password under the account's KDF params and sends it", async () => {
    const keys = { kdfSalt: "SALT", kdfParams: { memBytes: 67108864, ops: 3, parallelism: 1 } };
    // A9 (M-1): the proof is the account's fenced reauth derivation (KDF fence + the session's salt), never the static.
    const account = { reauthAuthKey: vi.fn(async () => "DERIVED") };
    const client = {
      accountKeys: vi.fn(async () => keys),
      totpSetup: vi.fn(async (k?: string) => ({ secretBase32: "S", otpauthUri: `otpauth://${k}` })),
    };
    const setup = await beginTotpEnrolment(client as unknown as Pick<ApiClient, "accountKeys" | "totpSetup">, "hunter2 hunter2", account as unknown as Account);
    expect(account.reauthAuthKey).toHaveBeenCalledWith("hunter2 hunter2", keys);
    expect(client.totpSetup).toHaveBeenCalledWith("DERIVED");
    expect(setup.otpauthUri).toBe("otpauth://DERIVED");
  });
});

describe("Settings TotpCard — the enable step asks for the master password", () => {
  const src = readFileSync(fileURLToPath(new URL("./Settings.tsx", import.meta.url)), "utf8");
  const card = src.slice(src.indexOf("function TotpCard("), src.indexOf("function PasswordCard("));

  it("enrolls through beginTotpEnrolment with the typed password, never the bare call", () => {
    expect(card).toContain("beginTotpEnrolment(client, password, account)");
    expect(card).not.toContain("client.totpSetup()");
  });

  it("renders a master-password field above the turn-on button", () => {
    expect(card).toContain('aria-label="Master password"');
    expect(card.indexOf('aria-label="Master password"')).toBeLessThan(card.indexOf("Turn on two-factor sign-in"));
  });
});
