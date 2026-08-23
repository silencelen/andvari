import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { MIN_ASKABLE_LENGTH, reuseWarning, shouldAskReuse } from "./reusealert.ts";

/**
 * Signup reuse alert (owner ask 2026-08-22). Every rule here bounds when a typed password
 * crosses to the service worker, so these are egress pins as much as UX pins.
 */

const base = {
  value: "correct horse battery",
  lastAsked: undefined as string | undefined,
  filling: false,
  isSignup: true,
  isNewPasswordField: true,
};

describe("shouldAskReuse", () => {
  it("asks for a settled password typed into a signup form", () => {
    assert.equal(shouldAskReuse(base), true);
  });

  // A sign-in form re-typing its own saved password is not reuse. Warning there would fire on
  // every login the user performs, and would ship the password to the SW every time.
  it("never asks on a sign-in form", () => {
    assert.equal(shouldAskReuse({ ...base, isSignup: false }), false);
  });

  it("never asks about a field that is not a new-password target", () => {
    assert.equal(shouldAskReuse({ ...base, isNewPasswordField: false }), false);
  });

  // Our own generated password is unique by construction — warning about it would be a lie.
  it("never asks while the extension is filling", () => {
    assert.equal(shouldAskReuse({ ...base, filling: true }), false);
  });

  it("never asks twice about the same settled value on the same field", () => {
    assert.equal(shouldAskReuse({ ...base, lastAsked: base.value }), false);
  });

  it("asks again once the value actually changes", () => {
    assert.equal(shouldAskReuse({ ...base, lastAsked: "something else" }), true);
  });

  it("ignores a half-typed value", () => {
    assert.equal(shouldAskReuse({ ...base, value: "a".repeat(MIN_ASKABLE_LENGTH - 1) }), false);
    assert.equal(shouldAskReuse({ ...base, value: "a".repeat(MIN_ASKABLE_LENGTH) }), true);
  });

  it("ignores an empty field", () => {
    assert.equal(shouldAskReuse({ ...base, value: "" }), false);
  });
});

describe("reuseWarning", () => {
  it("says nothing when the password is unique", () => {
    assert.equal(reuseWarning(0), null);
  });

  it("is singular for one other login and plural beyond", () => {
    assert.match(reuseWarning(1)!, /another login/);
    assert.match(reuseWarning(3)!, /3 other logins/);
  });

  // The vault could not be consulted, so silence must not be read as an all-clear.
  it("stays silent when locked, even if a count came back", () => {
    assert.equal(reuseWarning(5, true), null);
  });
});
