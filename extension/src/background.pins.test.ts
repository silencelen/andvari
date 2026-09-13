// Service-worker WIRING pins (node --test). Source-text assertions, not behaviour tests.
//
// Why a source-text file at all: background.ts is not node-importable (extensionless imports plus
// top-level `chrome` side effects — locksequence.test.ts and serverswitch.test.ts state the
// constraint and test the extracted leaves instead). The leaves are honestly covered, but a leaf
// test passes just as green when the SW stops CALLING the leaf. That gap is what the 2026-09-13
// audit named in H90: the existing G19 pins (web/src/extension-pins.test.ts) pin the storage lines
// and the constants, so deleting `void refreshKnownLogins();` from persistSession, or
// `isKnownLoginWhileLocked(...)` from capturedCredential, stayed green. A pin on a definition is
// not a pin on a call site.
//
// Scope, deliberately narrow: the seams the 2026-09-13 remediation landed in this file (H59 purge,
// H69 TOTP-copy usage, H70 role refresh) plus the H90 call sites and the memory-only residency of
// the TOTP challenge. Editing any pinned line must break THIS file first, on purpose. These pins
// live extension-side (rather than only in web's extension-pins.test.ts) so the extension's own
// gate — `npm test` in extension/, the leg a contributor runs after touching the SW — fails too.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const bg = readFileSync(new URL("./background.ts", import.meta.url), "utf-8");
const popup = readFileSync(new URL("./popup.ts", import.meta.url), "utf-8");

/** The slice of `src` from the first `from` to the next `to` after it. Both ends are asserted
 *  present and in order: a renamed anchor must fail loudly here rather than silently widen or
 *  empty the span (an empty span makes every `contains` assertion below vacuous). */
function spanOf(src: string, from: string, to: string): string {
  const a = src.indexOf(from);
  assert.ok(a > -1, `span start missing: ${from}`);
  const b = src.indexOf(to, a);
  assert.ok(b > a, `span end missing or out of order: ${to}`);
  return src.slice(a, b);
}

// ---- H59: the per-origin purge erases the known-logins digest with everything else ----

test("H59 — purgeOriginNamespace sweeps KLKEY and nulls the cached HMAC key", () => {
  const purge = spanOf(bg, "export async function purgeOriginNamespace(", "// Re-offer a pending save once");
  // The digest record is per-origin namespaced state with a disclosure bound of its own
  // (knownlogins.ts: someone who can read the locked compartment can test GUESSED (site, username)
  // pairs), and this is the one path whose copy promises that origin's cached state is gone.
  assert.match(purge, /const keys = \[QKEY, KLKEY,/, "KLKEY must be on the purge list, beside QKEY");
  // Storage alone is not the wipe: the HMAC key is also cached in SW memory, so a later rebuild
  // for this origin would re-mint the same digests under the same key.
  assert.ok(
    purge.includes("if (originKey === currentOriginKey) knownLoginsKey = null;"),
    "the purge must null the in-memory HMAC key for the current origin",
  );
});

// ---- H69: a copied one-time code counts as a use; the 1 s ticker does not ----

test("H69 — the totp handler records usage ONLY for the copy send", () => {
  const handler = spanOf(bg, 'case "totp": {', 'case "setTotp":');
  assert.ok(handler.includes("if (msg.forCopy === true) recordUsage(msg.itemId);"), "the copy send must record a use");
  // The guard is the whole point. This message is also the popup's per-second display refresh for
  // every visible chip (hence "totp" in PASSIVE_MSGS), so an unconditional recordUsage would stamp
  // lastUsedAt on every TOTP item once a second for as long as the popup is open — that does not
  // fix the staleness signal, it destroys it. A bare `recordUsage(msg.itemId);` fails here.
  assert.equal(
    (handler.match(/recordUsage\(/g) ?? []).length,
    1,
    "exactly one recordUsage in the totp handler, and it must be the guarded one",
  );
  // Ordering: the popup-only sender gate stands ahead of the recording, so a page sender can never
  // reach it (and, being refused before `msg` is read, can never forge the flag either).
  assert.ok(
    handler.indexOf("if (sender.tab !== undefined)") < handler.indexOf("recordUsage("),
    "the popup-only gate must precede the usage record",
  );
});

test("H69 — the popup sends forCopy from the click path and NEVER from the ticker", () => {
  const copy = spanOf(popup, "async function copyTotp(", "function startTotp(");
  assert.ok(copy.includes('ask({ type: "totp", itemId, forCopy: true })'), "the chip click must flag the copy");
  const tick = spanOf(popup, "async function tickTotp(", "/* ---- cards:");
  assert.ok(!tick.includes("forCopy"), "the 1 s display ticker must never flag a use");
  // One flagged send in the whole surface — a second one would be a second, unreviewed use path.
  assert.equal((popup.match(/forCopy: true/g) ?? []).length, 1, "exactly one forCopy call site");
});

// ---- H70: the G21 reader gate's input is refreshed by the periodic pull ----

test("H70 — resync refreshes vaultRoles from the delivered grants", () => {
  const rs = spanOf(bg, "async function resync(): Promise<void> {", "// ---- live change-push");
  assert.ok(
    rs.includes("for (const g of sync.grants) if (session.vaultKeys.has(g.vaultId)) session.vaultRoles.set(g.vaultId, g.role);"),
    "every delivered grant for a vault we hold must refresh its role",
  );
  assert.ok(
    rs.includes("if (!granted.has(vaultId)) session.vaultRoles.delete(vaultId);"),
    "a vanished grant must not leave a stale role behind",
  );
  // The refresh has to be persisted, or a SW eviction restores the pre-demotion snapshot and the
  // gate goes stale again with no further pull to correct it before the next full unlock.
  assert.ok(rs.indexOf("session.vaultRoles.set(") < rs.indexOf("persistSession();"), "the role refresh must be persisted");
});

// ---- H90: the G19 wiring, pinned at the CALL SITE rather than at the definition ----

test("H90 — persistSession is the known-logins rebuild choke point", () => {
  // Every persist of the session is exactly "items changed or were (re)installed". Drop this line
  // and the digest set silently freezes at whatever it held: a login added today is not recognized
  // at the next locked capture, so the pre-digest nag returns — a fail-open no leaf test can see.
  const ps = spanOf(bg, "function persistSession(): Promise<void> {", "let knownLoginsKey");
  assert.ok(ps.includes("void refreshKnownLogins();"), "persistSession must rebuild the known-logins digest");
});

test("H90 — the locked capture path consults the digest before it banners", () => {
  const cc = spanOf(bg, "async function capturedCredential(", "async function resolvePendingSave(");
  assert.ok(
    cc.includes("if (await isKnownLoginWhileLocked(host, username)) {"),
    "the locked capture must consult the digest — without it every re-login nags again",
  );
});

test("H90 — the TOTP challenge stays MEMORY-ONLY: no part of it reaches the session snapshot", () => {
  // pendingTotp holds authKey + wrapKey. Persisting the snapshot puts it in storage.session, the
  // locked compartment — breaker B1 territory, and the exact change ("persist the challenge so a
  // popup reopen survives SW death") that would look harmless in review. The comment at the
  // pendingTotp declaration argues against it; this is the tripwire that argues back in CI.
  const snap = spanOf(bg, "function persistSession(): Promise<void> {", "return chrome.storage.session.set({ [SKEY]: snap });");
  for (const forbidden of ["pendingTotp", "authKey", "wrapKey"]) {
    assert.ok(!snap.includes(forbidden), `the session snapshot must never carry ${forbidden}`);
  }
});
