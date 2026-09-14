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


// ---- H33 / H35 / H05: the usage-ledger seams (the leaf planFlush is behaviour-tested in usage.test.ts;
// these pin that the SW CALLS it and that the teardown flush is awaited before the tokens go) ----

test("H33/R43 — doLock captures the flush, drops the session AT ONCE, and awaits the bound before the tokens go", () => {
  const lock = spanOf(bg, "async function doLock(", "async function doSignOut(");
  const capture = "const teardownFlush = flushUsageForTeardown();";
  const awaited = "await Promise.race([teardownFlush, delay(TEARDOWN_FLUSH_TIMEOUT_MS)]);";
  const drop = "session = null;";
  const forget = "api.setTokens(null, null);";
  for (const anchor of [capture, awaited, drop, forget]) assert.ok(lock.includes(anchor), `doLock anchor missing: ${anchor}`);
  // The old `void flushUsage()` dispatched the GET with a token and issued the PUT after
  // api.setTokens(null, null) had emptied the header — 401, dropped, not re-armed. A bare `void`
  // reintroduces exactly that race.
  assert.ok(!/^\s*void flushUsage\(\);/m.test(lock), "the lock-path flush must not be fire-and-forget");
  assert.ok(!lock.includes("await Promise.race([flushUsage(), delay("), "the lock path must not await the SESSION-reading flush ahead of the drop (R43: that kept reveal/fill serviceable for 2 s)");
  // Natives' lock-path shape (VaultSession.lock): capture the context, drop the session and keys
  // immediately, and only the token pair waits — bounded — for the round that rides on it.
  assert.ok(lock.indexOf(capture) < lock.indexOf(drop), "the round's context is captured BEFORE the session drops");
  assert.ok(lock.indexOf(drop) < lock.indexOf(awaited), "the session drops BEFORE the bounded await — the lock itself is never delayed by the flush");
  assert.ok(lock.indexOf(awaited) < lock.indexOf(forget), "the bounded await lands BEFORE the tokens the PUT rides on are forgotten");
  // And the capture really is synchronous + self-contained: the round takes vk/userId/mine as
  // arguments, never reads `session` after the caller nulls it.
  const td = spanOf(bg, "function flushUsageForTeardown(): Promise<void> {", "async function flushUsageRound(");
  assert.ok(td.includes("const mine = pendingUsage;") && td.includes("pendingUsage = {};"), "the teardown flush takes the buffer synchronously");
  assert.ok(td.includes("return flushUsageRound({ vk, userId: session.userId, mine });"), "the teardown flush hands the round an explicit context");
  const round = spanOf(bg, "async function flushUsageRound(", "function reveal(");
  assert.ok(!round.includes("session.userId") && !round.includes("session.vaultKeys"), "the round must not read the session it may have outlived");
  assert.ok(round.includes("if (session) pendingUsage = mergeUsage(mine, pendingUsage);"), "the re-arm stays session-gated so a late teardown round cannot resurrect records into a locked SW");
});

test("H33 — doSignOut AWAITS the bounded usage flush BEFORE api.logout() revokes the session", () => {
  const so = spanOf(bg, "async function doSignOut(", "/** Re-arm the policy idle lock");
  const flush = "await Promise.race([flushUsage(), delay(TEARDOWN_FLUSH_TIMEOUT_MS)]);";
  assert.ok(so.includes(flush), "sign-out must flush the usage buffer, bounded");
  assert.ok(so.indexOf(flush) < so.indexOf("await Promise.race([api.logout(), delay(5000)]);"), "the flush must land before logout() revokes the tokens it rides on");
});

test("H35 — flushUsage runs the prune round even with an EMPTY buffer when handed a live set", () => {
  const fu = spanOf(bg, "async function flushUsage(", "function flushUsageForTeardown(");
  // The gate must let a live-set call through with nothing buffered; `length === 0) return;` on
  // its own (the pre-fix gate) is exactly the dirty-gate that left the G04 prune inert here.
  assert.ok(fu.includes("if (Object.keys(pendingUsage).length === 0 && !liveItemIds) return;"), "the empty-buffer gate must be conditioned on no live set");
  assert.ok(!fu.includes("Object.keys(pendingUsage).length === 0) return;"), "an unconditional empty-buffer return re-inerts the post-sync prune");
  // resync is still the ONLY caller that passes a set (G04).
  assert.equal([...bg.matchAll(/flushUsage\(new Set\(/g)].length, 1, "exactly one prune caller — resync's post-full-snapshot point");
});

test("H05 — flushUsage decides through planFlush and re-arms (never PUTs) on an unreadable server copy", () => {
  const fu = spanOf(bg, "async function flushUsage(", "function reveal(");
  assert.ok(fu.includes("await flushUsageRound({ vk, userId: session.userId, mine, liveItemIds });"), "the live flush runs the shared round");
  assert.ok(fu.includes("const put = planFlush(server, mine, liveItemIds);"), "the write decision must be the shared pure leaf");
  assert.ok(fu.includes('server = { kind: "unreadable" };'), "a failed GET / unopenable blob must be classified unreadable, not empty");
  assert.ok(fu.includes('if (server.kind === "unreadable" && session) pendingUsage = mergeUsage(mine, pendingUsage);'), "the skipped round must re-arm the buffer (session-gated)");
  // The pre-fix shape: a merge seeded from `mine` that fell through to the PUT on any GET failure.
  assert.ok(!fu.includes("let merged = mine;"), "the 'store ours on a read miss' seed must be gone");
});

// ---- H01 (recheck R02): the reuse ask is page-driveable, so it must never re-arm the autolock ----

test("H01 — passwordReuse is in PASSIVE_MSGS (page-driveable: value-set + trusted blur)", () => {
  // Same extraction as the web [C2] pin so the two gates read the same literal. A page can set
  // `input.value` and drive a TRUSTED focusout on its own signup field at will (F01's
  // driveability test), so the ask stream is page traffic, not user activity; out of this set it
  // would re-arm the idle alarm forever. The typed-gesture gate (H02) bounds the ORACLE, not the
  // arm — both are needed.
  const set = bg.match(/const PASSIVE_MSGS = new Set<Req\["type"\]>\(\[([^\]]*)\]\)/)?.[1] ?? "";
  assert.ok(set.length > 0, "PASSIVE_MSGS literal must exist");
  assert.ok(set.includes('"passwordReuse"'), "passwordReuse must be passive");
});

// ---- H02 (recheck R04): the typed mark is consumed by the ask, so each answer costs a keystroke ----

test("H02 — checkPasswordReuse CONSUMES the typed mark right after it records the ask", () => {
  const content = readFileSync(new URL("./content.ts", import.meta.url), "utf-8");
  const ask = spanOf(content, "async function checkPasswordReuse(", "// ---- capture engine ----");
  const rec = "reuseAsked.set(input, value);";
  const consume = "reuseTyped.delete(input);";
  const send = 'await safeSend({ type: "passwordReuse", password: value });';
  for (const a of [rec, consume, send]) assert.ok(ask.includes(a), `checkPasswordReuse anchor missing: ${a}`);
  // The mark is per-FIELD and a page drives trusted focus/blur at will: without the consume, one
  // real keystroke armed the membership oracle for every later `value = guess; blur()`.
  assert.ok(ask.indexOf(rec) < ask.indexOf(consume) && ask.indexOf(consume) < ask.indexOf(send), "record → consume → send, in that order");
  // The mark is still only ever SET by a trusted keydown (the listener) — never by the ask path.
  assert.ok(!ask.includes("reuseTyped.add("), "the ask path must never mint the mark");
});

// ---- H20 (recheck R01/R03): every put path lands a `conflict` and materializes the displaced version ----

test("H20 — all FOUR put paths treat a landed conflict as ok:true and materialize the displaced version", () => {
  // Spec 03 §5: `conflict` is a write the server APPLIED. The pre-fix `status === "applied"` test
  // reported a landed write as a failure and left the local rev stale; the extension is the one
  // party handed the losing version, so it is the party that must materialize it. The pure leaves
  // (conflictcopy.test.ts) stay green when the SW stops calling them — hence a call-site pin.
  const paths: Array<[string, string, string]> = [
    ["putExisting", "async function putExisting(", "/** `uri` is the stored site uri"],
    ["putNewLogin", "async function putNewLogin(", "/** [X2-A6] NEW card (G2 save-card)"],
    ["putNewCard", "async function putNewCard(", "// ---- TOTP add (design 2026-08-12"],
    ["putCard", "async function putCard(", "/** One-tap URI backfill for legacy items"],
  ];
  for (const [name, from, to] of paths) {
    const span = spanOf(bg, from, to);
    assert.ok(span.includes("if (!putLanded(r)) return saveFailure(r?.status);"), `${name}: the landed test must be putLanded (applied OR conflict)`);
    assert.ok(!span.includes('status !== "applied"'), `${name}: a bare applied-only test reports a landed conflict as a failure`);
    assert.ok(/await materializeConflictCopy\(r, (target\.vaultId|session\.personalVaultId)\);/.test(span), `${name}: must materialize the displaced version after persistSession()`);
    assert.ok(span.indexOf("persistSession();") < span.indexOf("await materializeConflictCopy("), `${name}: the landed write persists BEFORE the best-effort copy`);
  }
  // putLanded keeps both landed statuses; saveFailure keeps conflict's slot in the union (the
  // rung's copy is true only because no put path emits it any more).
  const landed = spanOf(bg, "function putLanded(", "/** H20: the pushing client's duty");
  assert.ok(landed.includes('r?.status === "applied" || r?.status === "conflict"'), "putLanded = applied OR conflict");
  const sf = spanOf(bg, "function saveFailure(", "/** H20 (2026-09-13 audit): did this put LAND?");
  assert.ok(sf.includes('status === "conflict" ? "conflict"'), "saveFailure still maps conflict so the union keeps its slot");
});

// ---- H03 (recheck R37): the extension is a push client — a server `rejected` is permanent ----

test("H03 — saveFailure maps the server's `rejected` verdict to its own rung, never the retryable default", () => {
  const sf = spanOf(bg, "function saveFailure(", "/** H20 (2026-09-13 audit): did this put LAND?");
  assert.ok(sf.includes('status === "rejected" ? "rejected"'), "rejected must not fold into \"failed\" (the same put fails identically forever)");
  const api = readFileSync(new URL("./api.ts", import.meta.url), "utf-8");
  assert.match(api, /status: "applied" \| "conflict" \| "duplicate" \| "denied" \| "rejected";/, "api.ts MutationResult must carry the rejected status the server answers");
  assert.ok(api.includes("reason?: string;"), "and the refusal reason beside it");
});

// ---- H64: the personal vault (and so the usage key) never follows a server label alone ----

test("H64 — both session builds pick the personal vault through pickPersonalVaultId, which skips member grants", () => {
  // Behaviour, not decoration: `Vault.type` is server plaintext bound into no AD (spec 02 §4), so
  // a hostile server can relabel a SHARED vault the user only holds by member grant. The extension
  // keys the usage ledger from VK(personalVault) (crypto.ts usageKey), so adopting a relabelled
  // vault would seal the user's per-item behavioural log under a key every OTHER member of that
  // vault already holds. Core (Account.setPersonalVault) and web (account.ts) refuse the same way;
  // this file is where a revert in the SW would otherwise stay green.
  assert.match(
    bg,
    /function pickPersonalVaultId\([\s\S]*?v\.type === "personal" && vaultKeys\.has\(v\.vaultId\) && !memberGranted\.has\(v\.vaultId\)/,
    "pickPersonalVaultId must exclude member-granted vaults",
  );
  assert.match(bg, /memberGranted\.add\(g\.vaultId\)/, "buildVaultKeys must record sealedVk provenance");
  // Both session builds — the full password unlock and the quick redeem — go through it, and
  // NEITHER re-derives the id inline (an inline `.find(... type === "personal" ...)` is exactly the
  // shape that carried the bug).
  const inline = bg.match(/vaults\.find\(\(v\) => v\.type === "personal"/g) ?? [];
  assert.equal(inline.length, 1, `only pickPersonalVaultId may scan for type="personal" (found ${inline.length})`);
  assert.equal((bg.match(/pickPersonalVaultId\(sync, vaultKeys, memberGranted\)/g) ?? []).length, 2, "hydrateSession and the redeem path must both call it");
});

// ---- H67 / R38 / R39: the damaged-account-keys terminal, wired in the SW ----

// R39: the extension's entire H67 production wiring could be deleted with the whole extension gate
// green — `keys_damaged` appears only in errors.ts (the copy string) and errors.unions.test.ts (a
// length assertion), and neither reads background.ts. Deleting the structure-first gate and the
// mapper row left 399/399 passing and tsc clean, on the one client where the SW is the only place
// the gate can live. Same idiom as the H90 pins above: a leaf test is not a call-site test.
test("H67/R38 — hydrateSession refuses a structurally broken account-key blob BEFORE using the secret", () => {
  const hydrate = spanOf(bg, "async function hydrateSession(", "const sync = await api.sync(0)");
  // wrappedUvk: structure first, secret second.
  assert.ok(hydrate.includes("envelopeStructuralRefusal(wrapped)"), "wrappedUvk must be header-checked");
  assert.ok(hydrate.includes("new VaultKeyDamagedError"), "…and refused with the damaged-keys terminal");
  assert.ok(
    hydrate.indexOf("envelopeStructuralRefusal(wrapped)") < hydrate.indexOf("open(wk, wrapped, adUvk("),
    "the header check must run BEFORE the wrap key is applied — that ordering IS the rule",
  );
  // R38: the sibling account-key blob in the same row gets the same gate, one line later.
  assert.ok(hydrate.includes("envelopeStructuralRefusal(seedEnvelope)"), "encryptedIdentitySeed must be header-checked too");
  assert.ok(
    hydrate.indexOf("envelopeStructuralRefusal(seedEnvelope)") < hydrate.indexOf("boxKeypairFromSeed(open(uvk, seedEnvelope"),
    "…before the UVK is applied to it",
  );
});

test("H67/R39 — the mapper turns that terminal into `keys_damaged`, never a credentials verdict", () => {
  const mapper = spanOf(bg, "function mapUnlockError(", "if (e instanceof ApiError)");
  assert.ok(mapper.includes('VaultKeyDamagedError) return "keys_damaged"'), "the damaged-keys row must precede the ApiError ladder");
  // The whole point of H67: a damaged row must never come back as the wrong-password sentence.
  assert.ok(!mapper.includes("bad_credentials"), "no credentials verdict may be reachable before the damaged-keys row");
});
