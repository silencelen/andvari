// node --test. The sign-in's back-off has a line of its own (the wording page's FX3): the server answers a sign-in, whose
// caller has proven nothing, with a fixed 60 seconds, so the line says "at least a minute" and never the number. Before,
// a back-off at the password's sign-in folded into "the server had a problem answering", through the real background.ts.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import * as E from "./errors.ts";
import { signedInWorld } from "./testing/bgharness.ts";

test("a sign-in the server holds back reads the sign-in's own wait line, at the password step as at the code's", async () => {
  const { server, acct, w } = await signedInWorld({ signIn: false });
  server.override = (method: string, path: string) =>
    method === "POST" && path === "/api/v1/auth/login" ? new Response(JSON.stringify({ error: "rate_limited", message: "slow down" }), { status: 429, headers: { "content-type": "application/json", "retry-after": "60" } }) : null;
  const r = await w.popup({ type: "unlock", email: acct.email, password: acct.password });
  assert.equal(r.ok, false);
  assert.equal(r.code, "rate_limited", "not the server's fault: its back-off");
  assert.equal(E.unlockErrorCopy(r.code), E.SIGN_IN_TOO_MANY_TRIES);
  assert.equal(E.unlockErrorCopy("totp_rate_limited"), E.SIGN_IN_TOO_MANY_TRIES);
  assert.notEqual(E.unlockErrorCopy(r.code), E.SIGN_IN_SERVER_ERROR);
});

test("the line names no cause: the server answers too many tries from one network address the same way (the wording page's PQ1)", () => {
  assert.equal(E.SIGN_IN_TOO_MANY_TRIES, "Too many tries to sign in. Wait at least a minute, then try again.");
  assert.doesNotMatch(E.SIGN_IN_TOO_MANY_TRIES, /email/i);
});

test("the line names no number of seconds (the server's 60 is the same for everyone)", () => {
  assert.doesNotMatch(E.SIGN_IN_TOO_MANY_TRIES, /\d/);
  assert.doesNotMatch(E.SIGN_IN_TOO_MANY_TRIES, /\{\d+\}/);
});
