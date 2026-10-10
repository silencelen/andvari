import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * Security review 2026-10, root cause C. The master-password breach check hashed the master
 * password with SHA-1 and sent the 20-bit prefix to andvari's own relay, i.e. to the one server
 * that also holds the Argon2id verifier, kdfSalt and wrappedUvk. With the prefix, an offline
 * guesser drops ~2^20 − 1 of every 2^20 candidates at SHA-1 speed before paying for Argon2id.
 * The live hint did it on every 700 ms pause while the password was being TYPED, so partial
 * values leaked too. The zero-knowledge rule is that nothing derived from the master password
 * reaches the server; an advisory warning that blocked nothing does not justify breaking it.
 *
 * The fix drops the check for the two secrets that are (or may equal) the master password:
 * the master password itself and the backup passphrase. Item passwords keep their on-demand
 * check (Vault's "Check breach exposure", the Health scan); those are not the server's KDF secret.
 */
const src = (p: string) => readFileSync(fileURLToPath(new URL(p, import.meta.url)), "utf8");

describe("root cause C — no master-password-derived request can reach the server", () => {
  // Every surface where a master password or backup passphrase is typed or chosen.
  const surfaces = {
    passwordadvice: src("./passwordadvice.tsx"),
    Welcome: src("./Welcome.tsx"),
    Settings: src("./Settings.tsx"),
    Recover: src("./Recover.tsx"),
    ExportPanel: src("./ExportPanel.tsx"),
  } as const;

  it("the shared advice module has no breach seam left to call", async () => {
    const mod: Record<string, unknown> = await import("./passwordadvice");
    for (const name of ["createBreachWatch", "breachWarningFor", "useBreachedPassword", "BREACH_CHECK_DEBOUNCE_MS"]) {
      expect(mod[name], `passwordadvice must not export ${name}`).toBeUndefined();
    }
    // …and the composite that hashed a password AND fetched its range is gone from the crypto
    // module, so no future surface can pick it back up by accident.
    const hibp: Record<string, unknown> = await import("../crypto/hibp");
    expect(hibp.hibpBreachCount).toBeUndefined();
  });

  it("no master-password surface hashes, fetches or forwards a range", () => {
    for (const [name, s] of Object.entries(surfaces)) {
      expect(s, `${name} must not import the HIBP helpers`).not.toContain("crypto/hibp");
      for (const needle of ["hibpRange", "hibpBreachCount", "breachWarningFor", "useBreachedPassword", "BreachRangeSource"]) {
        expect(s, `${name} must not reference ${needle}`).not.toContain(needle);
      }
    }
  });

  it("the master-password hint is no longer handed an API client", () => {
    for (const name of ["Welcome", "Settings", "Recover"] as const) {
      expect(surfaces[name], `${name}'s MasterPasswordHint must not get a client`).not.toMatch(/<MasterPasswordHint[^>]*client=/);
    }
    // The ExportPanel element itself, up to its own "/>", must not be handed the client.
    const vault = src("./Vault.tsx");
    const exportPanel = vault.slice(vault.indexOf("<ExportPanel"), vault.indexOf("/>", vault.indexOf("<ExportPanel")));
    expect(exportPanel).toContain("mode={exportMode}");
    expect(exportPanel).not.toContain("client=");
  });

  it("no copy promises that a master-password check 'sent nothing'", () => {
    // The old sentence said andvari checked "without sending it anywhere" — false: the prefix
    // went to the vault server. With the check gone the sentence has no caller and is removed.
    const strength = src("./strength.ts");
    expect(strength).not.toContain("BREACHED_PASSWORD_WARNING");
    expect(strength).not.toContain("without sending it anywhere");
  });

  it("item passwords keep their on-demand check through the relay", () => {
    // The scope line: only master-password-derived data moved. The Vault editor's check and the
    // Health scan still exist, and still go through the session's relay, never upstream directly.
    const vault = src("./Vault.tsx");
    expect(vault).toContain("await client.hibpRange(hibpPrefix(hash))");
    expect(vault).toContain("Check breach exposure");
    expect(src("./Health.tsx")).toContain("hibpRange(");
  });
});
