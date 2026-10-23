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
  const snap = spanOf(bg, "function persistSession(): Promise<void> {", 'return sessionSeal.set("session", currentOriginKey, snap)');
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

// ---- H02, per value since the 2026-10 security review: only the user-typed VALUE is askable ----

test("H02 — checkPasswordReuse asks only about the value the user's keystrokes produced", () => {
  const content = readFileSync(new URL("./content.ts", import.meta.url), "utf-8");
  const ask = spanOf(content, "async function checkPasswordReuse(", "// ---- capture engine ----");
  const gate = "typedByUser: reuseCustody.askable(input, value),";
  const rec = "reuseAsked.set(input, value);";
  const send = 'await safeSend({ type: "passwordReuse", password: value });';
  for (const a of [gate, rec, send]) assert.ok(ask.includes(a), `checkPasswordReuse anchor missing: ${a}`);
  assert.ok(ask.indexOf(gate) < ask.indexOf(rec) && ask.indexOf(rec) < ask.indexOf(send), "gate → record → send, in that order");
  // The per-FIELD mark it replaces let a page swap a guess in after each real keystroke; custody is
  // only ever fed by the trusted keydown/input listeners — never by the ask path.
  assert.ok(!/reuseCustody\.(keydown|input)\(/.test(ask), "the ask path must never feed custody");
  assert.ok(content.includes("if (reuseTracked(t)) reuseCustody.keydown(t, {"), "the trusted keydown listener arms custody");
  assert.ok(content.includes("reuseCustody.input(t, t.value,"), "the trusted input listener settles it");
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

test("A5 / H-1 — both session builds pick the personal vault from the wrap (or this device's cached wrap), never a label", () => {
  // Security review 2026-10, root cause A §4 and the A5 review's H-1: "personal" is AccountKeys.personalWrap;
  // when the server withholds it, the wrap this device cached stands. The SW never reads the server's label.
  assert.match(bg, /export async function pickPersonalVaultId\([\s\S]*?pickPersonal\(wrap, uvk, userId, vaultKeys, \{ cached \}\)/);
  assert.equal((bg.match(/type === "personal"/g) ?? []).length, 0, "no SW decision reads the server's personal label");
  // A6: the sync's vault rows ride along only so a pending change can NAME both vaults (A5b LOW-3).
  assert.equal((bg.match(/await pickPersonalVaultId\(s\.accountKeys\.personalWrap, uvk, s\.userId, vaultKeys, sync\.vaults\)/g) ?? []).length, 1, "the password unlock picks from the wrap");
  assert.equal((bg.match(/await pickPersonalVaultId\(keys\.personalWrap, begin\.uvk, begin\.userId, vaultKeys, sync\.vaults\)/g) ?? []).length, 1, "the quick redeem picks from the wrap");
  // A6 (Q8): key building moved to the UVK-wraps-only leaf, which still records member-grant provenance (display).
  const leaf = readFileSync(new URL("./grantkeys.ts", import.meta.url), "utf-8");
  assert.match(leaf, /memberGranted\.add\(g\.vaultId\)/, "the key builder still records member-grant provenance (display)");
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

// ---- security review 2026-10, plugin scan F1/F2 (branch A10): wire-boundary ids + strict storage records ----
// The leaves (wireids.ts, trustrecords.ts) are behaviour-tested; these pins hold the CALL SITES, which a leaf test
// cannot see (the H90 gap).

test("A10: the worker's api client reports refused ids, and the api sanitises sync/members/keys/login at the wire", () => {
  const api = readFileSync(new URL("./api.ts", import.meta.url), "utf-8");
  assert.ok(bg.includes("a.onRefusedIds = (endpoint, refused) =>"), "makeApi wires onRefusedIds");
  assert.ok(api.includes('this.reported("sync", sanitizeSync('), "sync() passes the wire-id check");
  assert.ok(api.includes('this.reported("members", sanitizeMembers('), "vaultMembers() passes the wire-id check");
  assert.ok(api.includes('this.reported("accountKeys", sanitizeAccountKeys('), "getAccountKeys() passes the wire-id check");
  assert.ok(api.includes("const r = refusedSession(s);") && api.includes('"bad_wire_id"'), "login() refuses a malformed session id");
});

test("A10: every trust record is read through its strict decoder (since A15 from the trusted store, not storage.local)", () => {
  assert.ok(bg.includes("const d = decodeItemHomes((await trusted.get(k))[k]);"), "loadHomes decodes strictly");
  assert.ok(bg.includes("[homesKey(userId)]: encodeItemHomes(homes)"), "saveHomes writes only well-formed pairs");
  assert.ok(bg.includes("const d = decodePersonalWrap((await trusted.get(key))[key]);"), "the personal-wrap cache decodes strictly");
  assert.ok(bg.includes("const d = decodePersonalChange((await trusted.get(k))[k]);"), "the pending change decodes strictly");
  assert.ok(!/as PersonalWrapWire \| undefined/.test(bg) && !/as Record<string, string> \| undefined/.test(bg), "no raw cast reads a trust record any more");
});

// ---- security review 2026-10, branch A15: trust state out of content-script-reachable storage ----
// The leaves (trustedkv.ts, trustmigrate.ts, updateoffer.ts, storageaccess.ts, serverswitch.purgeOriginRecords) are
// behaviour-tested; these pins hold the worker to them, and storagefence.test.ts holds who touches which storage.

test("A15: worker start awaits the storage access levels, then settles the migration, then loads the server state", () => {
  const ready = spanOf(bg, "const serverReady: Promise<void> = (async () => {", "})();");
  const order = ["await storageAccess;", "await migrateTrustState(legacyLocal, trusted, () =>", "await applyServerState(outcome, true);", "if (trustedStoreOk) await adoptLegacyNamespaceOnce();"];
  let at = -1;
  for (const step of order) {
    const i = ready.indexOf(step);
    assert.ok(i > at, `serverReady must run "${step}" after the step before it`);
    at = i;
  }
  // A16: the verdict is combined with the seal's key in custodyReady (quickUnlockCompartment).
  assert.match(bg, /const storageAccess: Promise<StorageAccessVerdict> = restrictStorageAccess\(chrome\.storage as unknown as StorageAccessAreas\);/);
  assert.match(bg, /const trusted = trustedStore\(\);/);
});

test("A15: doLock samples the compartment verdict only after the access-level calls settled", () => {
  const lock = spanOf(bg, 'async function doLock(reason: "idle" | "manual" | "signout" = "manual"): Promise<void> {', "redeemGen++;");
  assert.ok(lock.indexOf("await storageAccess;") > -1 && lock.indexOf("await storageAccess;") < lock.indexOf("compartmentTrusted: quCompartmentTrusted"));
});

test("A15: the server choice changes only through the setServerUrl message — canonicalized, persisted, then switched", () => {
  assert.ok(!bg.includes("chrome.storage.onChanged"), "the storage.onChanged trigger is gone");
  const handler = spanOf(bg, 'case "setServerUrl":', 'case "forgetLegacyServer":');
  assert.ok(handler.includes("return commitServerUrl(msg.url);"));
  const commit = spanOf(bg, "async function commitServerUrl(", "/** Apply a server change.");
  const steps = ["canonicalizeServerUrl(raw)", "await setServerUrl(canonical, trusted);", "switchChain.then(() => applyServerChange(canonical))"];
  let at = -1;
  for (const step of steps) {
    const i = commit.indexOf(step);
    assert.ok(i > at, `commitServerUrl: "${step}" in order`);
    at = i;
  }
  assert.ok(commit.includes('return { ok: false, code: "invalid" }') && commit.includes('return { ok: false, code: "storage" }'));
});

test("A15: the update offer is re-checked on read, its link built only by the offer leaf, its seq kept in the trusted store", () => {
  const status = spanOf(bg, "async function updateStatus(", "// ---- message dispatch ----");
  assert.ok(status.includes("const offer = readUpdateOffer(await trustedGet(kInfo), current, serverUrl);"), "re-checked on every read");
  assert.ok(!status.includes("isNewerVersion("), "the read goes through the leaf, not a version-only check");
  const check = spanOf(bg, "async function checkForUpdate(", "/** Popup query:");
  assert.ok(check.includes("chromeUrl: offerDownloadUrl(ext.chromeUrl, serverUrl), firefoxUrl: offerDownloadUrl(ext.firefoxUrl, serverUrl)"));
  assert.ok(check.includes("storedSeq = (await trusted.get(kSeq))[kSeq];"), "the anti-rollback seq is read from the trusted store");
  assert.ok(check.includes("await trusted.set({ [kInfo]: info, [kSeq]: decision.seq });"), "…and written there with the offer");
  assert.ok(!bg.includes("function downloadUrl("), "the old absolutizer (any https URL passed) is gone");
  // The throttle and the quiet marker are not trust state: storage.session (re-derived by the forced start check), as
  // two of the plain inventory's three records (A16: sessionseal.ts).
  assert.ok(check.includes("const seen = (await plainSession.get(kLast))[kLast];"));
});

test("A15: the purge clears every record of that origin in the trusted store, storage.local and storage.session", () => {
  const purge = spanOf(bg, "export async function purgeOriginNamespace(", "// Re-offer a pending save once");
  assert.ok(purge.includes("await purgeOriginRecords(originKey, [trusted, legacyLocal, sessionSeal.purgeArea()]);"));
});

test("A15: the remembered email is recorded by the worker, from the popup's own unlock, never by a page", () => {
  const mapper = spanOf(bg, "async function unlockWithMapping(", "function mapUnlockError(");
  assert.ok(mapper.includes('if (r.ok || r.code === "totp_required") await rememberEmail(email);'));
  const status = spanOf(bg, 'case "status": {', 'case "lock": {');
  assert.ok(status.includes("rememberedEmail: session ? null : await readRememberedEmail(),"));
});

// ---- A15 review (2026-10-22): F1 the pending server dials nothing, F2 the attested migration, F3 the seq read, S1 the
// lock path, S3 the popup's no-answer. The leaves (serverstate.ts, trustmigrate.ts, trustedkv.ts) are behaviour-tested;
// these pins hold the worker and the pages to them. ----

test("A15 review F1: every dial is refused right after the sender gate while a server is pending", () => {
  const head = spanOf(bg, "async function dispatch(msg: Req, sender: chrome.runtime.MessageSender): Promise<unknown> {", "switch (msg.type) {");
  const gate = head.indexOf("if (gate.refused) return gate.answer;");
  const held = head.indexOf("const held = dialRefusal(msg.type, dialBlock);");
  assert.ok(gate > -1 && held > gate, "after the A14 sender gate, before any handler");
  assert.ok(head.includes("if (held) return held;"));
  // The handlers the leaf names are the real ones (a renamed case would silently escape the hold).
  for (const t of ["ping", "unlock", "unlockTotp", "unlockWithPin", "unlockWithBio"]) assert.ok(bg.includes(`case "${t}":`), `case "${t}" exists`);
});

test("A15 review F1: no update poll while a server is pending; autofill excludes the pending origin (fail closed)", () => {
  const check = spanOf(bg, "async function checkForUpdate(", "/** Popup query:");
  const ready = check.indexOf("await serverReady;");
  const skip = check.indexOf("if (dialBlock) return;");
  assert.ok(ready > -1 && skip > ready && skip < check.indexOf("fetch("), "checked before any fetch");
  const reg = spanOf(bg, "async function reconcileAutofillScripts(): Promise<void> {", "async function unregisterAutofillScripts(");
  // One reconcile at a time: two overlapping runs (worker start + onInstalled) made the second register throw a
  // duplicate id, and its fail-closed catch unregistered the first (seen live on an update).
  assert.ok(bg.includes("autofillChain = autofillChain.then(reconcileAutofillScripts, reconcileAutofillScripts);"));
  assert.ok(reg.includes("const excludeMatches = autofillExcludeMatches(serverUrl, dialBlock);"));
  assert.ok(/if \(excludeMatches === null\) \{\s*await unregisterAutofillScripts\(\);\s*return;/.test(reg), "null = no autofill at all");
});

test("A15 review F1: only the gate's commit and 'Not mine' lift the block; the pages render from serverInfo's block", () => {
  const commit = spanOf(bg, "async function commitServerUrl(", "/** Apply a server change.");
  assert.ok(commit.indexOf("await setServerUrl(canonical, trusted);") < commit.indexOf("dialBlock = null;"), "lifted only after the choice was kept");
  assert.ok(commit.indexOf("await switchChain;") < commit.indexOf("if (serverUrl === canonical) dialBlock = null;"), "…and only once the switch took effect");
  const forget = spanOf(bg, "async function forgetLegacyServer(", "\n}\n");
  assert.ok(forget.includes("if (!(await forgetPendingServer(dialBlock, trusted, legacyLocal))) return { ok: false };"));
  assert.ok(forget.indexOf("forgetPendingServer(") < forget.indexOf("dialBlock = null;"));
  assert.equal((bg.match(/dialBlock = null;/g) ?? []).length, 2, "nowhere else");
  assert.ok(bg.includes("return { url: serverUrl, trustedStore: trustedStoreOk, block: dialBlock };"));
});

test("A15 review F1: the popup leads with the confirm route; no server page opens and the header names no server meanwhile", () => {
  const refresh = spanOf(popup, "async function refresh(): Promise<void> {", "/** Render the self-update banner");
  const info = refresh.indexOf('const info = await ask({ type: "serverInfo" });');
  const confirm = refresh.indexOf("showConfirmServer(info.block);");
  const status = refresh.indexOf('const s = await ask({ type: "status" });');
  assert.ok(info > -1 && confirm > info && status > confirm, "asked first; the confirm card replaces every sign-in form");
  const show = spanOf(popup, "function showConfirmServer(block: ServerBlockWire): void {", "\n}\n");
  assert.ok(show.includes('el("locked").hidden = true;'), "the sign-in form is hidden");
  assert.ok(show.includes("Not mine — use ${new URL(DEFAULT_SERVER_URL).host} instead"), '"Not mine" names the server it switches to');
  assert.ok(show.includes('open.textContent = block.keepable ? "Confirm in Options" : "Open Options";'));
  assert.ok(popup.includes('const r = await ask({ type: "forgetLegacyServer" });'));
  const html = readFileSync(new URL("../popup.html", import.meta.url), "utf-8");
  assert.ok(html.includes('<section id="confirm-server"') && html.includes('id="confirm-server-not-mine"') && html.includes('id="confirm-server-open"'));
  assert.ok(!html.includes("legacy-server-cta"), "the old strip (beside a live sign-in form) is gone");
  const header = spanOf(popup, "async function renderServerOrigin(): Promise<void> {", "\n}\n");
  assert.ok(header.includes("!info.block ? info.url : null"), "the header shows an origin only when one is in effect");
});

test("A15 review S3: no answer from the worker opens nothing (never a guessed default)", () => {
  const cur = spanOf(popup, "async function currentServer(): Promise<string | null> {", "\n}\n");
  assert.ok(cur.includes("!r.block ? r.url : null"));
  assert.ok(!cur.includes("DEFAULT_SERVER_URL"), "no fallback to the default");
  const open = spanOf(popup, "async function openServerPage(path = \"\"): Promise<void> {", "\n}\n");
  assert.ok(open.indexOf("if (base === null) {") > -1 && open.indexOf("if (base === null) {") < open.indexOf("chrome.tabs.create("));
  const opt = readFileSync(new URL("./options.ts", import.meta.url), "utf-8");
  const info = spanOf(opt, "async function serverInfoNow(): Promise<Res<\"serverInfo\"> | null> {", "\n}\n");
  assert.ok(info.includes("return null;") && !info.includes("DEFAULT_SERVER_URL"), "options: no answer is no server, not the default");
});

test("A15 review F2: worker start waits (bounded) for the browser's install event; a late one still owes the migration", () => {
  const ready = spanOf(bg, "const serverReady: Promise<void> = (async () => {", "})();");
  assert.ok(ready.includes("Promise.race([installSignal, delay(INSTALL_SIGNAL_WAIT_MS).then(() => null)])"));
  const installed = spanOf(bg, "chrome.runtime.onInstalled.addListener((details) => {", "chrome.runtime.onStartup.addListener(");
  assert.ok(installed.includes("installSignalSeen(sig);"));
  assert.ok(installed.includes("const late = serverReady.then(() => lateInstallSignal(sig)).catch(() => {});"));
  assert.ok(installed.includes("void late.then(() => checkForUpdate(true));"), "the forced check runs after a late migration");
  const late = spanOf(bg, "async function lateInstallSignal(", "\n}\n");
  assert.ok(late.includes("if (!installWaitTimedOut || !attestsPreA15Upgrade(d)) return;"));
  assert.ok(late.indexOf("await trusted.set({ [A15_OWED_KEY]: true });") < late.indexOf("migrateTrustState("), "owed is recorded before the run");
});

test("A15 review F3: a failed seq read aborts the update check before anything is fetched", () => {
  const check = spanOf(bg, "async function checkForUpdate(", "/** Popup query:");
  const read = check.indexOf("storedSeq = (await trusted.get(kSeq))[kSeq];");
  assert.ok(read > -1 && read < check.indexOf("fetch("), "read before the fetch");
  assert.ok(/storedSeq = \(await trusted\.get\(kSeq\)\)\[kSeq\];\s*\} catch \{\s*return;\s*\}/.test(check), "a read error returns");
  assert.ok(!check.includes("trustedGet(kSeq)"), "not the fold-to-absent reader");
});

test("A15 review S1: a lock waits for the trusted store only within its bound, and a cold lock erases the snapshot first", () => {
  const lock = spanOf(bg, 'async function doLock(reason: "idle" | "manual" | "signout" = "manual"): Promise<void> {', "redeemGen++;");
  // A16: the bound covers the sealing key as well as the origin (custodyLoaded = serverReady + custodyReady).
  const race = lock.indexOf("const custodyKnown = await Promise.race([custodyLoaded.then(() => true), delay(LOCK_STORE_WAIT_MS).then(() => false)]);");
  assert.ok(race > -1 && race < lock.indexOf("armGate("), "bounded, before the arm gate");
  assert.ok(bg.includes("const custodyLoaded: Promise<unknown> = Promise.all([serverReady, custodyReady]);"));
  const cold = lock.slice(lock.indexOf("if (!custodyKnown) {"));
  const erase = cold.indexOf('const first = sessionSeal.remove("session", currentOriginKey);');
  assert.ok(cold.indexOf("lockedBeforeOrigin = true;") < erase && erase > -1);
  assert.ok(erase < cold.indexOf('await sessionSeal.peek("tabs", currentOriginKey)'), "the snapshot goes before anything else is awaited");
  assert.ok(!cold.slice(0, cold.indexOf("armGate(")).includes("sessionSeal.get("), "the cold path never waits for the sealing key (peek, not get)");
  assert.ok(lock.includes(": { tokens: { access: null, refresh: null }, attempt: false };"), "no arm without the origin");
  assert.ok(bg.includes("if (msg.type !== \"lock\") await ensureLoaded();"), "handle() does not make a lock wait on serverReady");
  const load = spanOf(bg, "function ensureLoaded(): Promise<void> {", "\nfunction ");
  assert.ok(load.includes("if (lockedBeforeOrigin) snap = undefined;"), "a snapshot read before a cold lock's erase never hydrates");
  assert.ok(load.includes("const t = lockedBeforeOrigin ? undefined :"), "nor do the tab records' sensitive half");
  assert.ok(bg.includes("return openBoundedIdb(() => (globalThis as { indexedDB?: IDBFactory }).indexedDB, IDB_NAME, IDB_STORE);"), "the co-key DB opens bounded too");
});

// ---- security review 2026-10, branch A16: secret-bearing storage.session records are sealed ----
// The leaf (sessionseal.ts: the key, the seal, the epoch, the start sweep, the plain area) is behaviour-tested in
// sessionseal.test.ts, and storagefence.test.ts holds every storage.session write to the seal or the plain inventory.
// These pins hold the worker's custody paths and its lock to them.

test("A16: the sealing key lives in its own IndexedDB database, opened bounded, and is set up at worker start", () => {
  assert.ok(bg.includes("const sessionSeal = new SessionSeal({ session: sessionRaw, keys: idbKv(() => (globalThis as { indexedDB?: IDBFactory }).indexedDB, SEAL_DB_NAME) });"));
  const ready = spanOf(bg, "const custodyReady: Promise<void> = Promise.all([storageAccess, sessionSeal.ready]).then(", "});");
  assert.ok(ready.includes("quCompartmentTrusted = quickUnlockCompartment(verdict, sealed);"), "the verdict needs the key; the access level is the belt");
  assert.equal((bg.match(/^\s*quCompartmentTrusted = /gm) ?? []).length, 1, "set in one place only");
});

test("A16: every custody record is read and written through the seal", () => {
  const persist = spanOf(bg, "function persistSession(): Promise<void> {", "let knownLoginsKey");
  assert.ok(persist.includes('return sessionSeal.set("session", currentOriginKey, snap).then(() => {});'));
  assert.ok(bg.includes('void sessionSeal.set("tabs", currentOriginKey, Object.fromEntries([...tabs].map(([id, st]) => [String(id), st]))).catch(() => {});'));
  const load = spanOf(bg, "function ensureLoaded(): Promise<void> {", "\nfunction ");
  assert.ok(load.includes('let snap = (await sessionSeal.get("session", currentOriginKey)) as SessionSnapshot | undefined;'));
  assert.ok(load.includes('(await sessionSeal.get("tabs", currentOriginKey)) as Record<string, TabState> | undefined'));
  const qu = spanOf(bg, "const quStore: QuStore = {", "\n};\n");
  assert.ok(qu.includes('await sessionSeal.get("quickUnlock", currentOriginKey)'));
  assert.ok(qu.includes('if (!(await sessionSeal.set("quickUnlock", currentOriginKey, rec))) throw new Error("the quick-unlock record was not kept");'), "an unkept arm or reserve fails closed");
  assert.ok(qu.includes('remove: () => sessionSeal.remove("quickUnlock", currentOriginKey),'));
  const kl = spanOf(bg, "async function refreshKnownLogins(): Promise<void> {", "/** The locked capture path's membership test.");
  assert.ok(kl.includes('const rec = (await sessionSeal.get("knownLogins", ok)) as KnownLoginsRecord | undefined;'));
  assert.ok(kl.indexOf("if (session !== s) return;") > kl.indexOf('await sessionSeal.get("knownLogins", ok)'), "a lock during the read does not re-mint a wiped digest");
  assert.ok(kl.includes('await sessionSeal.set("knownLogins", ok, { key: toB64(knownLoginsKey), digests } satisfies KnownLoginsRecord);'));
  const known = spanOf(bg, "async function isKnownLoginWhileLocked(", "/** One gate for every locked-state RE-offer surface");
  assert.ok(known.includes('const rec = (await sessionSeal.get("knownLogins", currentOriginKey)) as KnownLoginsRecord | undefined;'));
  // The pre-namespacing bare quick-unlock record is never adopted: the seal's start sweep drops it (plaintext).
  const adopt = spanOf(bg, "async function adoptLegacyNamespaceOnce(): Promise<void> {", "/** One-shot enroll bench");
  assert.ok(!adopt.includes("sessionSeal.") && !adopt.includes("plainSession"), "no storage.session adoption any more");
});

test("A16: the lock erases the session records before anything in it can wait on IndexedDB", () => {
  const lock = spanOf(bg, "async function doLock(", "async function doSignOut(");
  const erase = lock.indexOf("const erased = sessionSeal.lockErase();");
  assert.ok(erase > -1, "the erase");
  const kl = lock.indexOf('if (reason === "signout" || !quCompartmentTrusted) {');
  assert.ok(kl > erase, "the known-logins wipe right after it");
  assert.ok(lock.slice(kl, lock.indexOf("if (attemptArm) {")).includes('await sessionSeal.remove("knownLogins", currentOriginKey);'));
  // Everything that can wait on IndexedDB (the quick-unlock co-key delete inside wipe(), the arm) or on the network
  // (the teardown flush) comes after the erase.
  for (const later of ["quickUnlock.arm(", "await quickUnlock.wipe();", "await Promise.race([teardownFlush, delay(TEARDOWN_FLUSH_TIMEOUT_MS)]);"]) {
    const at = lock.indexOf(later);
    assert.ok(at > kl, `"${later}" comes after the erase`);
  }
  assert.ok(lock.indexOf("session = null;") < erase, "the in-memory session is dropped first");
  assert.ok(lock.indexOf("await erased;") > lock.indexOf("api.setTokens(null, null);"), "awaited only at the end");
  // The allow-listed tab remainder is re-persisted after the erase (under the new epoch).
  assert.ok(lock.indexOf("if (tabs.size > 0) persistTabs();") > erase);
});

test("A16: quick unlock cannot be enrolled where it cannot arm", () => {
  for (const [from, to] of [
    ["async function enrollQuickUnlock(pin: string): Promise<Res<\"enrollQuickUnlock\">> {", "async function enrollQuickUnlockBio("],
    ["async function enrollQuickUnlockBio(): Promise<Res<\"enrollQuickUnlockBio\">> {", "/** Quick-unlock redeem (spec 01 §8.4)."],
  ] as const) {
    const fn = spanOf(bg, from, to);
    const gate = fn.indexOf('if (!quCompartmentTrusted) return { ok: false, code: "unavailable" };');
    assert.ok(gate > fn.indexOf("await custodyReady;") && fn.indexOf("await custodyReady;") > -1, "the verdict is settled first");
    assert.ok(gate > -1 && gate < fn.indexOf("quickUnlock.enroll"), "refused before anything is wiped, prompted or written");
  }
});
