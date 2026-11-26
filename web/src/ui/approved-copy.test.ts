import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import * as C from "./copy";
import { fill, LINK_REQUIRED_WEB, LINK_REQUIRED_WEB_TITLE } from "./copy";

/**
 * The wording the owner approved on 2026-11-15 (the copy page's entries), as the web shows it. Each entry the web held
 * as a PLACEHOLDER carries the approved title and body word for word, and no longer carries the mark.
 */

const copyTs = readFileSync(fileURLToPath(new URL("./copy.ts", import.meta.url)), "utf8");
const welcomeTsx = readFileSync(fileURLToPath(new URL("./Welcome.tsx", import.meta.url)), "utf8");

/** The doc comment directly above `export const <name>` (empty when there is none). */
function docAbove(name: string): string {
  const at = copyTs.indexOf(`export const ${name} =`);
  expect(at, name).toBeGreaterThan(-1);
  const before = copyTs.slice(0, at);
  const open = before.lastIndexOf("/**");
  const close = before.lastIndexOf("*/");
  return open > -1 && close > open && before.slice(close + 2).trim() === "" ? before.slice(open, close) : "";
}

describe("approved wording, 2026-11-15", () => {
  it("LINK_REQUIRED_CANNOT_LINK: the web's link_required title and body, filled with the account's email", () => {
    expect(LINK_REQUIRED_WEB_TITLE).toBe("This account only allows linked devices");
    expect(fill(LINK_REQUIRED_WEB, "bea@example.org")).toBe(
      "bea@example.org has “New devices must be linked” turned on, and andvari in a browser can't be linked. Your master password was right. To sign in here, open andvari on one of your devices → Settings → Your devices, and turn that setting off. You can turn it on again once this browser has signed in.",
    );
    expect(docAbove("LINK_REQUIRED_WEB_TITLE")).not.toContain("PLACEHOLDER");
    // The sign-in shows the title above the filled body.
    expect(welcomeTsx).toContain("setErrTitle(LINK_REQUIRED_WEB_TITLE);");
    expect(welcomeTsx).toContain('setErr(fill(LINK_REQUIRED_WEB, email.trim() || "This account"));');
  });

  it("OWNERSHIP_OFFER (entry 26): title, body, button and the open-offer note, filled from real values", () => {
    expect(fill(C.OWNERSHIP_OFFER_TITLE, "Bob", "Family")).toBe("Make Bob the owner of “Family”?");
    expect(C.OWNERSHIP_OFFER_BODY).toBe(
      "Nothing changes until they accept in their app. They have 14 days, and you can cancel until then. Afterwards they manage the vault's members, and only they can rename it, hand it over or delete it. You stay in it as a writer.",
    );
    expect(fill(C.OWNERSHIP_OFFER_ASK, "Bob")).toBe("Ask Bob to take over");
    expect(fill(C.OWNERSHIP_OFFER_OPEN, "Bob", "Family", "Nov 30")).toBe("You asked Bob to take over “Family”. They can accept until Nov 30.");
    const sharing = readFileSync(fileURLToPath(new URL("./Sharing.tsx", import.meta.url)), "utf8");
    expect(sharing).toContain("fill(OWNERSHIP_OFFER_TITLE, targetMember.name, vault.name)");
    expect(sharing).toContain("{OWNERSHIP_OFFER_BODY}");
    expect(sharing).toContain("fill(OWNERSHIP_OFFER_ASK, targetMember.name)");
    expect(sharing).toContain("fill(OWNERSHIP_OFFER_OPEN, ");
    expect(sharing).not.toContain("you can cancel anytime");
    for (const k of ["OWNERSHIP_OFFER_TITLE", "OWNERSHIP_OFFER_BODY", "OWNERSHIP_OFFER_ASK", "OWNERSHIP_OFFER_OPEN"]) expect(docAbove(k)).not.toContain("PLACEHOLDER");
  });
});

/** Where the design gives the exact words (§3.3, §3.6, §8.5), the web shows those words, unmarked. */
describe("the design's own words", () => {
  it("the one-tap list (§8.5), the share prompt and the connect-first line (§3.6), and the clock-ahead refusal (§3.3)", () => {
    expect(C.ONE_TAP_TITLE).toBe("People you've connected with");
    expect(C.ONE_TAP_BODY).toBe(
      "You signed in without linking from another device, so andvari can't yet tell whether this list is current. The server keeps it sealed under your account's key. On its own, the server can hide people or bring back someone you removed, but it can't add anyone. Whoever holds your account's key could: a page from a dishonest server while you used andvari on the web. Untick anyone you don't recognise.",
    );
    expect(C.ONE_TAP_CONFIRM).toBe("Use these on this device");
    expect(C.ONE_TAP_LATER).toBe("Later");
    expect(C.CONTACT_PROMPT_YES).toBe("Use on this device");
    expect(C.SHARE_ASK.replace("{name}", "Alice").replace("{vault}", "Family")).toBe("Alice wants to share “Family” with you.");
    expect(fill(C.SHARE_CONNECT_FIRST, "Alice")).toBe("Alice wants to share a vault with you. Connect with them first.");
    expect(C.LOG_CLOCK_AHEAD).toBe("Your device's clock is ahead. Set the correct time and try again.");
    for (const k of ["ONE_TAP_TITLE", "ONE_TAP_BODY", "SHARE_ASK", "SHARE_CONNECT_FIRST", "LOG_CLOCK_AHEAD", "CONTACT_PROMPT_YES"]) expect(docAbove(k)).not.toContain("PLACEHOLDER");
    // §8.5: the list starts with everyone ticked, and has its Later.
    const prompts = readFileSync(fileURLToPath(new URL("./SharedPrompts.tsx", import.meta.url)), "utf8");
    expect(prompts).toContain("useState<ReadonlySet<string>>(() => new Set(entries.map((e) => e.userId)))");
    expect(prompts).toContain("{ONE_TAP_LATER}");
  });

  it("the sign-up code line is CODE_SENT_DAILY (the existing-account mail goes at most once a day), filled with the address the person typed, and holds one slot", () => {
    // Named by its key, so it holds whatever its words are: the sign-up form shows it with the address in its one slot.
    expect(welcomeTsx).toContain("{fill(CODE_SENT_DAILY, email.trim())}");
    expect(welcomeTsx).not.toContain("{fill(CODE_SENT, ");
    for (const key of ["CODE_SENT", "CODE_SENT_DAILY"] as const) {
      expect(C[key].match(/\{\d+\}/g)).toEqual(["{0}"]);
      expect(fill(C[key], "bea@example.org")).toContain("bea@example.org");
      expect(docAbove(key)).not.toBe("");
    }
  });

  it("OWNER_OUT_OF_SPACE_YOURS / _THEIRS (entries 27, 28): a save refused for the owner's quota says whose space is full", () => {
    expect(C.OWNER_OUT_OF_SPACE_YOURS).toBe("This wasn't saved. You own this vault: remove items or attachments you no longer need, or ask the operator for more space.");
    expect(C.OWNER_OUT_OF_SPACE_THEIRS).toBe("This wasn't saved. Ask the vault's owner to free up space.");
    // Under the existing OWNER_OUT_OF_SPACE, which is core AppCopy's row byte for byte.
    const core = readFileSync(fileURLToPath(new URL("../../../core/src/commonMain/kotlin/io/silencelen/andvari/core/app/AppCopy.kt", import.meta.url)), "utf8");
    expect(core).toContain(`OWNER_OUT_OF_SPACE("${C.OWNER_OUT_OF_SPACE}")`);
    // The 2026-11-16 walk: a full account read only "Save failed — nothing was changed." The editor now picks the entry
    // by who owns the vault the item was saved into.
    // The editor's error line is saveerror.ts's, which Vault.tsx calls with whether this account owns the target vault.
    const vault = readFileSync(fileURLToPath(new URL("./Vault.tsx", import.meta.url)), "utf8");
    expect(vault).toContain("setSaveErr(saveErrorText(err, ownsTarget(vaultId)));");
  });

  it("the save's quota refusal through saveErrorText: whose space is full, ahead of the 413 row", async () => {
    const { saveErrorText } = await import("./saveerror");
    const { ApiError } = await import("../api/client");
    const full = new ApiError(413, "quota_exceeded", "full");
    expect(saveErrorText(full, true)).toBe(`${C.OWNER_OUT_OF_SPACE} ${C.OWNER_OUT_OF_SPACE_YOURS}`);
    expect(saveErrorText(full, false)).toBe(`${C.OWNER_OUT_OF_SPACE} ${C.OWNER_OUT_OF_SPACE_THEIRS}`);
  });
});
