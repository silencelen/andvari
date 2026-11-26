import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { SIGN_IN_KEYS_NOT_THIS_ACCOUNT, UNSENT_SEND_FIRST_SIGN_IN } from "./copy";

/**
 * The screens say the way out (decided on 2026-11-17). Where a sign-in is refused because the server's keys are not this
 * account's as this browser knows them, the line SIGN_IN_KEYS_NOT_THIS_ACCOUNT says what the person can do: nothing
 * changed here; ask whoever runs the server; and, if sure, sign out of this browser's copy, which says first how many
 * changes were not sent, then sign in again. The rule pinned here is that the way out it names is on the same card:
 * every sign-in form that can show the line (one over a copy this browser holds) has the copy's Sign out right under it,
 * and that Sign out counts the unsent changes before it deletes anything. Its words are not pinned.
 */
const src = (f: string) => readFileSync(new URL(f, import.meta.url), "utf8");

describe("the sign-in refused over keys that are not this account's says the way out, and the way out is there", () => {
  const welcome = src("./Welcome.tsx");
  const unlock = welcome.slice(welcome.indexOf("function Unlock("), welcome.indexOf("const submit = async", welcome.indexOf("function Unlock(")));

  it("the refusal shows the line, ends only the sign-in's own session and writes nothing", () => {
    expect(SIGN_IN_KEYS_NOT_THIS_ACCOUNT.length).toBeGreaterThan(0);
    expect(welcome).toMatch(/case "keys_not_this_account":[\s\S]{0,200}void abandonSignIn\(ctx\.client, flow\);\s*setErr\(SIGN_IN_KEYS_NOT_THIS_ACCOUNT\);\s*return;/);
  });

  it("every sign-in form over a copy this browser holds has its Sign out under it, which counts first and offers to send first", () => {
    const forms = unlock.split("<SignIn ").slice(1);
    expect(forms).toHaveLength(2); // the card of a session the server ended, and the sign-in a held session asks for
    for (const after of forms) {
      const next = after.indexOf("<SignOutLink userId={session.userId} onSignOut={() => onForget()} sendFirst={UNSENT_SEND_FIRST_SIGN_IN} />");
      expect(next).toBeGreaterThan(-1);
      expect(next).toBeLessThan(after.indexOf("</>"));
    }
    expect(UNSENT_SEND_FIRST_SIGN_IN.length).toBeGreaterThan(0);
    // SignOutLink arms on its first click with the count (or "cannot tell") and acts only on the second.
    const link = src("./SignOutLink.tsx");
    expect(link).toContain("unsentArmStep");
  });
});
