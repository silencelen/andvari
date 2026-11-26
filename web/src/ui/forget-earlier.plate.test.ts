import { readFileSync } from "node:fs";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { toB64 } from "../crypto/bytes";
import { randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import type { Account } from "../vault/account";
import { IDENTITY_PUB_MISMATCH, SELF_IDENTITY_MISMATCH } from "../vault/accountopen";
import { recordSelfIdentityPub } from "../vault/selfidentity";
import { IDENTITY_FAULT } from "./copy";
import { identityRefusal } from "./ForgetEarlier";
import { browserStorages } from "./forget-earlier.testkit";

/**
 * The plate above the offer: the identity fault's line ("don't enter your password again here; contact the person who runs
 * this server") takes one side of the two possibilities, so where the offer is made the offer's own lines stand alone, at
 * the sign-in, the unlock of a kept session and the kit's check, as at the registration. Where nothing is offered (the
 * same account under another key, any other fault) the plate stays exactly as it was: that is the case it is for.
 */
const EMAIL = "alice@example.com";
const A = "11111111-1111-4111-8111-111111111111";
const B = "22222222-2222-4222-8222-222222222222";
const src = (f: string) => readFileSync(new URL(f, import.meta.url), "utf8");

describe("the identity fault's plate and the offer", () => {
  let st: ReturnType<typeof browserStorages>;
  beforeAll(async () => {
    await initSodium();
  });
  beforeEach(() => {
    st = browserStorages();
    recordSelfIdentityPub(A, { identityPub: randomBytes(32) } as unknown as Account, EMAIL);
  });
  afterEach(() => st.restore());

  it("another account served: the offer alone, no plate above it", () => {
    expect(identityRefusal(EMAIL, SELF_IDENTITY_MISMATCH, B)).toEqual({ err: "", offer: { email: EMAIL, userId: A, sessionKept: false, served: B } });
  });

  it("the same account under another key: the plate exactly as before, and nothing offered", () => {
    expect(identityRefusal(EMAIL, SELF_IDENTITY_MISMATCH, A)).toEqual({ err: IDENTITY_FAULT, offer: null });
  });

  it("any other fault, an unknown account met, or a record that disagrees with itself: the plate, nothing offered", () => {
    expect(identityRefusal(EMAIL, IDENTITY_PUB_MISMATCH, B)).toEqual({ err: IDENTITY_FAULT, offer: null });
    expect(identityRefusal(EMAIL, SELF_IDENTITY_MISMATCH, undefined)).toEqual({ err: IDENTITY_FAULT, offer: null });
    st.local.setItem(`andvari.selfIdentityPub.${A}`, toB64(randomBytes(32)));
    expect(identityRefusal(EMAIL, SELF_IDENTITY_MISMATCH, B)).toEqual({ err: IDENTITY_FAULT, offer: null });
  });

  it("the sign-in, the unlock's lookup and the kit's check set the line and the offer from it, and nowhere stands the plate beside an offer", () => {
    const welcome = src("./Welcome.tsx");
    for (const at of ["identityRefusal(email, r.reason, r.servedUserId)", "identityRefusal(session.email, SELF_IDENTITY_MISMATCH, session.userId)", "identityRefusal(step.email, r.reason, r.servedUserId)"]) {
      expect(welcome).toMatch(new RegExp(`const f = ${at.replace(/[()]/g, "\\$&")};\\s*setErr\\(f\\.err\\);\\s*setEarlier\\(f\\.offer\\);`));
    }
    expect(welcome).not.toMatch(/setErr\(IDENTITY_FAULT\);\s*setEarlier\(/);
    // The registration, as it was: the refusal's line alone where the offer is made.
    expect(welcome).toContain('setErr(o === null ? fill(REMADE_ACCOUNT_REFUSAL, emailNorm(email) ?? email.trim(), shownName(pin)) : "");');
  });
});
