// node --test. Pins the capture-time save-vs-update decision (the dup-registration fix, 2026-07-12):
// a password-only re-login must map to the existing item, never a new duplicate. Resolve applies a
// stricter rule of its own (no silent 2b clobber) — that lives in background.ts, tested by shape here.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { resolveSaveAction, saveTargetFor } from "./savetarget.ts";

const item = (itemId: string, username: string, password: string) => ({ itemId, doc: { login: { username, password } } });

test("username present: exact (host∧username) match is the target", () => {
  const alice = item("a", "alice@x.com", "P_A");
  const bob = item("b", "bob@x.com", "P_B");
  assert.equal(saveTargetFor([alice, bob], "bob@x.com", "whatever")?.itemId, "b");
});

test("username present but no match → undefined (a new account → New, recoverable)", () => {
  const alice = item("a", "alice@x.com", "P_A");
  assert.equal(saveTargetFor([alice], "carol@x.com", "P_C"), undefined);
});

test("2a — password-only, password equals an existing item → that item (drives the unchanged-password suppress)", () => {
  const alice = item("a", "alice@x.com", "P_A");
  const bob = item("b", "bob@x.com", "P_B");
  assert.equal(saveTargetFor([alice, bob], "", "P_B")?.itemId, "b");
});

test("2b — password-only, no password match, LONE host login → that login (a password change, user-confirmed)", () => {
  const alice = item("a", "alice@x.com", "P_A");
  assert.equal(saveTargetFor([alice], "", "P_NEW")?.itemId, "a");
});

test("2c — password-only, no password match, MULTIPLE host logins → undefined (New; never overwrite the wrong account)", () => {
  const alice = item("a", "alice@x.com", "P_A");
  const bob = item("b", "bob@x.com", "P_B");
  assert.equal(saveTargetFor([alice, bob], "", "P_NEW"), undefined);
});

test("password-only, no host logins at all → undefined (genuinely first credential → New)", () => {
  assert.equal(saveTargetFor([], "", "P"), undefined);
});

test("2a shared password: picks the first password-equal item (accepted residual — a third same-password account is suppressed)", () => {
  const alice = item("a", "alice@x.com", "SHARED");
  const bob = item("b", "bob@x.com", "SHARED");
  assert.equal(saveTargetFor([alice, bob], "", "SHARED")?.itemId, "a");
});

// resolveSaveAction — the STRICTER post-unlock rule (never a silent clobber, never a silent drop).
test("resolve: a frozen updatesItemId target (the user saw an Update banner) → update it", () => {
  const alice = item("a", "alice@x.com", "P_A");
  assert.deepEqual(resolveSaveAction(alice, [alice], "", "P_A"), { kind: "update", target: alice });
});

test("resolve: username-present exact match → update that account", () => {
  const alice = item("a", "alice@x.com", "P_A");
  assert.deepEqual(resolveSaveAction(undefined, [alice], "alice@x.com", "P_NEW"), { kind: "update", target: alice });
});

test("resolve REGRESSION GUARD: username-present NEW account reusing an existing password → CREATE, never suppress", () => {
  // host has alice@x.com/P; user registers bob@x.com REUSING P. Must create bob, not silently drop him.
  const alice = item("a", "alice@x.com", "P");
  assert.deepEqual(resolveSaveAction(undefined, [alice], "bob@x.com", "P"), { kind: "create" });
});

test("resolve: password-only submit whose password belongs to a host login → suppress (a 2a re-login)", () => {
  const alice = item("a", "alice@x.com", "P_A");
  assert.deepEqual(resolveSaveAction(undefined, [alice], "", "P_A"), { kind: "suppress" });
});

test("resolve BLOCKER-1 GUARD: locked-at-capture password-only for a DIFFERENT account → CREATE, never clobber the lone login", () => {
  // host has ONLY alice/P_A; a password-only bob/P_B submitted while locked recorded as New.
  // resolve must create bob, NOT putExisting(alice, P_B).
  const alice = item("a", "alice@x.com", "P_A");
  assert.deepEqual(resolveSaveAction(undefined, [alice], "", "P_B"), { kind: "create" });
});

test("resolve: password-only, no host logins → create", () => {
  assert.deepEqual(resolveSaveAction(undefined, [], "", "P"), { kind: "create" });
});
