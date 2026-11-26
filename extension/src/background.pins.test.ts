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

test("H33 — sign-out's bounded usage flush lands BEFORE the logout revokes the session (A16 review R4: after the erase)", () => {
  const so = spanOf(bg, "async function doSignOut(", "/** Re-arm the policy idle lock");
  // The flush is doLock's teardown flush (bounded, before the pair is forgotten); the revoke comes after doLock returns.
  const lock = so.indexOf('await doLock("signout", seen, sayLost);');
  const revoke = so.indexOf("await revokePair(origin, pair);");
  assert.ok(lock > -1 && revoke > lock, "the lock (erase + teardown flush) first, the revoke after it");
  assert.ok(spanOf(bg, "async function revokePair(", "\n}\n").includes("await Promise.race([revoker.logout(), delay(5000)]);"), "bounded");
  const dl = spanOf(bg, "async function doLock(", "type TokenPair =");
  assert.ok(dl.indexOf("const teardownFlush = flushUsageForTeardown();") < dl.indexOf("await Promise.race([teardownFlush, delay(TEARDOWN_FLUSH_TIMEOUT_MS)]);"));
  assert.ok(!so.includes("flushUsage()"), "no second, session-reading flush ahead of the erase");
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
    assert.ok(span.includes("if (!putLanded(r)) return saveFailure(r?.status, r?.reason);"), `${name}: the landed test must be putLanded (applied OR conflict)`);
    assert.ok(!span.includes('status !== "applied"'), `${name}: a bare applied-only test reports a landed conflict as a failure`);
    // With the session the write was made under, so a copy never lands in a session that replaced it.
    assert.ok(/await materializeConflictCopy\(r, (target\.vaultId|owner\.personalVaultId), owner\);/.test(span), `${name}: must materialize the displaced version after persistSession()`);
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
  // BZ: the reason is kept up to the sentence, and the Safari app's own refusal is never the server's `rejected`.
  assert.equal((bg.match(/saveFailure\(r\?\.status, r\?\.reason\)/g) ?? []).length, 4, "every put path hands the server's reason on");
  const app = spanOf(bg, "async function saveThroughApp(", "async function resolvePendingSave(");
  assert.ok(app.includes('r === "refused" ? "app_refused"'), "the app's refusal has a code of its own");
  assert.ok(!app.includes('"rejected"'), "never the server's code");
});

// ---- H64: the personal vault (and so the usage key) never follows a server label alone ----

test("§12.2 rules 1–2 — both session builds verify the genesis and take the personal vault from it, never a label", () => {
  // Design 2026-11-15 §5.2, §5.3, §12.2: the genesis is verified at EVERY unlock (full and quick), and the personal
  // vault is its personalVaultId, its key the served wrap that names it (or this device's cached one). No label.
  const build = spanOf(bg, "async function buildUnlockKeys(", "\n}\n");
  assert.ok(build.includes("verifyGenesis(frame, { own: ownKeysFromSeed(seed), sessionUserId: userId, pinnedInstanceId: instanceId"), "the genesis against the seed's own keys and the pin");
  assert.ok(build.indexOf("if (!g.ok) throw new GenesisRefused(g.verdict);") < build.indexOf("personalVaultKey("), "the identity fault comes before any key");
  assert.ok(build.includes("const personalVaultId = g.genesis.personalVaultId;"));
  assert.ok(build.includes("buildVaultKeys(grants, uvk, userId, personalVaultId, records)"), "shared wraps only under the account state's records");
  assert.equal((bg.match(/type === "personal"/g) ?? []).length, 0, "no SW decision reads the server's personal label");
  assert.equal((bg.match(/await buildUnlockKeys\(s\.accountKeys, uvk, seed, s\.userId, sync\.grants\)/g) ?? []).length, 1, "the password unlock");
  assert.equal((bg.match(/await buildUnlockKeys\(keys, begin\.uvk, seed, begin\.userId, sync\.grants\)/g) ?? []).length, 1, "the quick redeem");
});

test("§4.4 — the card chain is checked before anything password-derived leaves, at sign-in and at a quick redeem", () => {
  const unlockFn = spanOf(bg, "async function unlock(email: string, password: string)", "\n}\n");
  assert.ok(unlockFn.indexOf("await ensureCardFresh();") > -1 && unlockFn.indexOf("await ensureCardFresh();") < unlockFn.indexOf("dialer.prelogin(email)"), "the card before prelogin");
  assert.ok(unlockFn.includes("dialer.login(email, toB64(ak), deviceObject(device.rec), undefined, replaces)"), "the device object rides the login, with the session it replaces");
  const redeem = spanOf(bg, "async function finishRedeem(", "\n}\n");
  assert.ok(redeem.indexOf("await ensureCardFresh();") < redeem.indexOf("api.forceRefresh()"), "the card before the refresh token is spent");
  const fresh = spanOf(bg, "async function ensureCardFresh(): Promise<void> {", "\n}\n");
  assert.ok(fresh.includes("await recordFork(origin, stored, r.stored);"), "a fork is stored and blocks, through the one fork routine");
  const fork = spanOf(bg, "async function recordFork(origin: string, judged: StoredPin, forked: StoredPin): Promise<void> {", "\n}\n");
  assert.ok(fork.includes('dialBlock = { kind: "fork", origin };') && fork.includes("await trusted.set({ [pinKeyFor(origin)]: forked });"));
  assert.ok(!fork.includes("doLock("), "a fork stops traffic, not reading (§4.4): it does not lock");
  // No default server anywhere, and the server choice changes only through the pinned paths.
  assert.ok(!bg.includes("DEFAULT_SERVER_URL"));
  assert.ok(bg.includes('case "chooseServer":\n      return chooseServer(msg);') && bg.includes('case "confirmServer":\n      return confirmServer(msg);'));
  assert.equal((bg.match(/await setServerUrl\(/g) ?? []).length, 3, "the Safari app adoption, switchToPinned and a followed move (just before it) are the only writers");
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
    hydrate.indexOf("envelopeStructuralRefusal(seedEnvelope)") < hydrate.indexOf("const seed = open(uvk, seedEnvelope"),
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
  assert.ok(api.includes('this.reported("accountKeys", sanitizeAccountKeys('), "getAccountKeys() passes the wire-id check");
  assert.ok(api.includes("const r = refusedSession(s);") && api.includes('"bad_wire_id"'), "login() refuses a malformed session id");
});

test("A10: every trust record is read through its strict decoder (since A15 from the trusted store, not storage.local)", () => {
  assert.ok(bg.includes("raw = (await trusted.get(k))[k];") && bg.includes("const d = decodeItemHomes(raw);"), "loadHomes decodes strictly");
  assert.ok(bg.includes("[homesKey(userId)]: encodeItemHomes(homes)"), "saveHomes writes only well-formed pairs");
  assert.ok(bg.includes("const cached = decodePersonalWrap((await trusted.get(cacheKey))[cacheKey]).value;"), "the personal-wrap cache decodes strictly");
  assert.ok(bg.includes("decodeStoredPin((await trusted.get(k))[k], origin)"), "the card pin decodes strictly, against its namespace's origin (damaged is never 'no pin')");
  assert.ok(bg.includes("memory = decodeStateMemory(raw);"), "the account-state memory decodes strictly");
  assert.ok(!/as PersonalWrapWire \| undefined/.test(bg) && !/as Record<string, string> \| undefined/.test(bg), "no raw cast reads a trust record any more");
});

// ---- security review 2026-10, branch A15: trust state out of content-script-reachable storage ----
// The leaves (trustedkv.ts, trustmigrate.ts, updateoffer.ts, storageaccess.ts, serverswitch.purgeOriginRecords) are
// behaviour-tested; these pins hold the worker to them, and storagefence.test.ts holds who touches which storage.

test("worker start awaits the storage access levels, then the first-launch wipe (§12.4), then loads the server state", () => {
  const ready = spanOf(bg, "const serverReady: Promise<void> = (async () => {", "})();");
  const order = ["await storageAccess;", "await wipeOldFormatOnce(trusted, [legacyLocal, sessionRaw], [coKeyDb, sealKeyDb]);", "formatWipeSettled();", "await applyServerState(storeOutcome);"];
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
  const lock = spanOf(bg, 'async function doLock(reason: "idle" | "manual" | "signout" = "manual", seen?: { tokens?: TokenPair }, sayLost: boolean = reason === "idle"): Promise<void> {', "if (seen) seen.tokens = toks;");
  assert.ok(lock.indexOf("await storageAccess;") > -1 && lock.indexOf("await storageAccess;") < lock.indexOf("compartmentTrusted: quCompartmentTrusted"));
});

test("Safari's app server commit is canonicalized, persisted, then switched; no storage write is a switch", () => {
  assert.ok(!bg.includes("chrome.storage.onChanged"), "the storage.onChanged trigger is gone");
  const commit = spanOf(bg, "async function commitServerUrl(", "/** No server has been chosen");
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
  assert.ok(purge.includes("await purgeOriginRecords(originKey, [trusted, legacyLocal, sessionSeal.purgeArea()], opts.keepTrust === true ? isTrustRecord : null);"));
  // Only "Remove data for this server" keeps the trust records; forget, a move's old
  // namespace and the Safari retirement remove everything.
  assert.ok(bg.includes("(originKey) => purgeOriginNamespace(originKey, { keepTrust: true }),"));
  assert.equal((bg.match(/keepTrust: true/g) ?? []).length, 1);
});

test("A15: the remembered email is recorded by the worker, from the popup's own unlock, never by a page", () => {
  const mapper = spanOf(bg, "async function unlockWithMapping(", "function mapUnlockError(");
  // And only while the attempt is still current, at the server it started under.
  assert.ok(mapper.includes('if ((r.ok || r.code === "totp_required") && gen === redeemGen && at === api) await rememberEmail(email);'));
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
  assert.ok(reg.includes("const excludeMatches = autofillExcludeMatches(serverUrl, dialBlock, PUBLIC_INSTANCE.origin);"));
  assert.ok(/if \(excludeMatches === null\) \{\s*await unregisterAutofillScripts\(\);\s*return;/.test(reg), "null = no autofill at all");
});

test("only a kept pin (or Safari's app adoption) lifts the block; the pages render from serverInfo's block", () => {
  const commit = spanOf(bg, "async function commitServerUrl(", "/** No server has been chosen");
  assert.ok(commit.indexOf("await setServerUrl(canonical, trusted);") < commit.indexOf("dialBlock = null;"), "lifted only after the choice was kept");
  assert.ok(commit.indexOf("await switchChain;") < commit.indexOf("if (serverUrl === canonical) dialBlock = null;"), "…and only once the switch took effect");
  const pinned = spanOf(bg, "async function switchToPinned(", "\n}\n");
  assert.ok(pinned.indexOf("await setServerUrl(origin, trusted);") < pinned.indexOf('dialBlock = stored.fork ? { kind: "fork", origin } : null;'));
  assert.ok(pinned.indexOf("await switchChain;") < pinned.indexOf("dialBlock = stored.fork"));
  const confirm = spanOf(bg, "async function confirmServer(", "\n}\n");
  assert.ok(confirm.includes("c.record.pin.hash !== msg.hash") && confirm.includes('if (existing.kind !== "none") return { ok: false, code: "stale" };'), "a root never replaces an existing pin");
  const forget = spanOf(bg, "async function forgetServer(", "\n}\n");
  assert.ok(forget.indexOf("await trusted.remove([SERVER_URL_KEY, LAST_EMAIL_KEY]);") > -1 && forget.indexOf("await trusted.remove([SERVER_URL_KEY, LAST_EMAIL_KEY]);") < forget.indexOf("await purgeOriginNamespace(originKey)") && forget.includes('dialBlock = { kind: "no_server" };'));
  // The Safari build's third lift: with no store to keep a choice, the app's own Trust-Gated origin (read through the
  // native handler, which no page can write) is used for one worker life, once the origin-clean switch applied.
  const unkept = spanOf(bg, "async function adoptAppServerUnkept(", "\n}\n");
  assert.ok(unkept.indexOf("await switchChain;") < unkept.indexOf("if (serverUrl !== canonical) return false;"));
  assert.ok(unkept.indexOf("if (serverUrl !== canonical) return false;") < unkept.indexOf("dialBlock = null;"));
  assert.equal((bg.match(/adoptAppServerUnkept\(/g) ?? []).length, 2, "defined once, called once: from the Safari-only ask");
  assert.equal((bg.match(/dialBlock = null;/g) ?? []).length, 2, "nowhere else");
  assert.match(bg, /function noServerChosen\(\): boolean \{\s*return serverUrl === NO_SERVER_ORIGIN;/);
  assert.match(bg, /if \(dialBlock === null && noServerChosen\(\)\) dialBlock = \{ kind: "unsettled" \};/, "no server chosen: nothing dialed, no autofill");
  assert.ok(bg.includes('return { url: noServerChosen() ? "" : serverUrl, trustedStore: trustedStoreOk, block: dialBlock, name: currentPin === null ? null : nameText(currentPin.pin.name) };'));
});

test("§12.2: the popup leads with the server choice or the stop; no server page opens and the header names no server meanwhile", () => {
  const refresh = spanOf(popup, "async function refresh(): Promise<void> {", "/** Render the self-update banner");
  const info = refresh.indexOf('const info = await ask({ type: "serverInfo" });');
  const confirm = refresh.indexOf("showConfirmServer(info.block, info.trustedStore === true);");
  const status = refresh.indexOf('const s = await ask({ type: "status", takeLost: true });');
  assert.ok(info > -1 && confirm > info && status > confirm, "asked first; the confirm card replaces every sign-in form");
  const show = spanOf(popup, "function showConfirmServer(block: ServerBlockWire, storeKept: boolean): void {", "\n}\n");
  assert.ok(show.includes('el("locked").hidden = true;'), "the sign-in form is hidden");
  assert.ok(show.includes("notMine.textContent = T.FORGET_THIS_SERVER;"), "the stop's only way on (§12.3)");
  assert.ok(show.includes("open.textContent = T.YOUR_OWN_SERVER;") && show.includes("pub.textContent = PUBLIC_INSTANCE.name;"), "the first popup's two choices");
  assert.ok(popup.includes('const r = await ask({ type: "forgetServer" });') && popup.includes('await ask({ type: "chooseServer", choice: "public" })'));
  const html = readFileSync(new URL("../popup.html", import.meta.url), "utf-8");
  assert.ok(html.includes('<section id="confirm-server"') && html.includes('id="confirm-server-not-mine"') && html.includes('id="confirm-server-open"') && html.includes('id="confirm-server-public"'));
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

test("the server state worker start applies: the pin with it, and a block closes the socket", () => {
  const apply = spanOf(bg, 'async function applyServerState(storeOutcome: "ok" | "unavailable" | "timedOut"): Promise<void> {', "\n}\n");
  assert.ok(apply.includes('const st = await loadServerState(storeOutcome, trusted, BUILD_TARGET !== "safari");'), "Safari holds no card pin");
  assert.ok(apply.indexOf("currentPin = st.pin;") < apply.indexOf("dialBlock = st.block;"));
  assert.ok(/if \(dialBlock\) \{\s*events\?\.close\(\);\s*events = null;/.test(apply), "a block closes the socket");
  // The install event no longer gates anything: there is no migration (clean break, §12.4).
  assert.ok(!bg.includes("installSignal") && !bg.includes("migrateTrustState") && !bg.includes("adoptLegacyNamespaceOnce"));
});

test("A15 review F3: a failed seq read aborts the update check before anything is fetched", () => {
  const check = spanOf(bg, "async function checkForUpdate(", "/** Popup query:");
  const read = check.indexOf("storedSeq = (await trusted.get(kSeq))[kSeq];");
  assert.ok(read > -1 && read < check.indexOf("fetch("), "read before the fetch");
  assert.ok(/storedSeq = \(await trusted\.get\(kSeq\)\)\[kSeq\];\s*\} catch \{\s*return;\s*\}/.test(check), "a read error returns");
  assert.ok(!check.includes("trustedGet(kSeq)"), "not the fold-to-absent reader");
});

test("A15 review S1: a lock waits for the trusted store only within its bound — after its erase (A16 review R4)", () => {
  const lock = spanOf(bg, 'async function doLock(reason: "idle" | "manual" | "signout" = "manual", seen?: { tokens?: TokenPair }, sayLost: boolean = reason === "idle"): Promise<void> {', "if (seen) seen.tokens = toks;");
  // A16: the bound covers the sealing key as well as the origin (custodyLoaded = serverReady + custodyReady); a sign-out
  // (which never arms) waits longer for its full wipe's namespace and its revoke's pair.
  const race = lock.indexOf(
    'const custodyKnown = await Promise.race([custodyLoaded.then(() => true), delay(reason === "signout" ? SIGNOUT_STORE_WAIT_MS : LOCK_STORE_WAIT_MS).then(() => false)]);',
  );
  assert.ok(race > -1 && race < lock.indexOf("armGate("), "bounded, before the arm gate");
  assert.ok(race > lock.indexOf("const erase = sessionSeal.lockErase();"), "and after the erase");
  assert.ok(bg.includes("const custodyLoaded: Promise<unknown> = Promise.all([serverReady, custodyReady]);"));
  assert.ok(lock.includes(": { tokens: { access: null, refresh: null }, attempt: false };"), "no arm without the origin");
  assert.ok(bg.includes('if (msg.type !== "lock" && msg.type !== "signOut") await ensureLoaded();'), "handle() makes neither a lock nor a sign-out wait on serverReady");
  assert.ok(bg.includes("return openBoundedIdb(() => (globalThis as { indexedDB?: IDBFactory }).indexedDB, IDB_NAME, IDB_STORE);"), "the co-key DB opens bounded too");
});

test("A16 review R4: a load that a lock (or a browser-start report) overtook installs nothing it read", () => {
  const load = spanOf(bg, "function ensureLoaded(): Promise<void> {", "\nfunction ");
  const gen = load.indexOf("const gen = hydrateGen;");
  assert.ok(gen > -1 && gen < load.indexOf("await serverReady;"), "captured before the first await");
  const check = load.indexOf("if (gen !== hydrateGen) return;");
  assert.ok(check > load.indexOf('await sessionSeal.get("tabs", currentOriginKey)'), "after the reads");
  assert.ok(check > load.indexOf("await loadHomes(snap.userId)"), "after the last await");
  assert.ok(check < load.indexOf("api.setTokens(snap.access || null, snap.refresh);") && check < load.indexOf("tabs = new Map("), "before anything is installed");
  assert.ok(!load.slice(check).includes("await "), "nothing is awaited between the check and the install");
  assert.ok(!bg.includes("lockedBeforeOrigin"), "the S1 flag is subsumed");
});

// ---- security review 2026-10, branch A16: secret-bearing storage.session records are sealed ----
// The leaf (sessionseal.ts: the key, the seal, the epoch, the start sweep, the plain area) is behaviour-tested in
// sessionseal.test.ts, and storagefence.test.ts holds every storage.session write to the seal or the plain inventory.
// These pins hold the worker's custody paths and its lock to them.

test("A16: the sealing key lives in its own IndexedDB database, opened bounded, and is set up at worker start", () => {
  assert.ok(bg.includes("const sealKeyDb = idbKv(() => (globalThis as { indexedDB?: IDBFactory }).indexedDB, SEAL_DB_NAME);"));
  // The seal reaches its key database only once the first-launch wipe settled.
  assert.ok(bg.includes("const sessionSeal = new SessionSeal({ session: sessionRaw, keys: afterFormatWipe(sealKeyDb), originKey: () => serverReady.then(() => currentOriginKey) });"));
  const ready = spanOf(bg, "const custodyReady: Promise<void> = Promise.all([storageAccess, sessionSeal.ready]).then(", "});");
  assert.ok(ready.includes("storageVerdict = verdict;") && ready.includes("decideCompartment();"));
  const decide = spanOf(bg, "function decideCompartment(): void {", "\n}\n");
  assert.ok(decide.includes("quCompartmentTrusted = storageVerdict !== null && quickUnlockCompartment(storageVerdict, sessionSeal.available());"), "the verdict needs the key; the access level is the belt");
  assert.equal((bg.match(/^\s*quCompartmentTrusted = /gm) ?? []).length, 1, "set in one place only");
});

test("A16 review R1: a browser-start report (onStartup, onInstalled) replaces the key and drops this worker life's custody, never arming it", () => {
  const installed = spanOf(bg, "chrome.runtime.onInstalled.addListener(() => {", "chrome.runtime.onStartup.addListener(");
  assert.ok(installed.indexOf("browserSessionReported();") > -1 && installed.indexOf("browserSessionReported();") < installed.indexOf("const ready = serverReady"), "first thing");
  const startup = spanOf(bg, "chrome.runtime.onStartup.addListener(() => {", "});");
  assert.ok(startup.trimStart().startsWith("chrome.runtime.onStartup.addListener(() => {\n  browserSessionReported();"), "first thing");
  const fn = spanOf(bg, "function browserSessionReported(): void {", "\n}\n");
  for (const step of ["hydrateGen++;", "redeemGen++;", "session = null;", "api.setTokens(null, null);", "knownLoginsKey = null;", "tabs.clear();", "const rotated = sessionSeal.rotate();", "decideCompartment();", "void rotated.then(decideCompartment);"]) {
    assert.ok(fn.includes(step), `browserSessionReported: ${step}`);
  }
  assert.ok(fn.indexOf("session = null;") < fn.indexOf("const rotated = sessionSeal.rotate();"));
  assert.ok(!/\bawait\b|quickUnlock\.arm|doLock\(|persistSession|persistTabs/.test(fn), "one synchronous step; nothing is armed or written");
  // A quick-unlock record read under the old key is never written back under the new one (an arm, a reserved attempt).
  const qu = spanOf(bg, "function quStoreAt(originKeyOf: () => string): QuStore {", "\n}\n");
  assert.ok(qu.includes("quReadUnder.set(rec, { gen: sessionSeal.generation(), originKey, removals });"));
  assert.ok(qu.indexOf("if (readUnder.gen !== sessionSeal.generation()) throw") < qu.indexOf('await sessionSeal.set("quickUnlock"'));
  // …and a lock that began before a report does not arm with what it saw (its copy is absent; the verdict is false).
  const lock = spanOf(bg, "async function doLock(", "type TokenPair =");
  assert.ok(lock.includes("compartmentTrusted: quCompartmentTrusted && sessionSeal.generation() === sealGen,"));
});

test("A16: every custody record is read and written through the seal", () => {
  const persist = spanOf(bg, "function persistSession(): Promise<void> {", "let knownLoginsKey");
  assert.ok(persist.includes('return sessionSeal.set("session", currentOriginKey, snap).then(() => {});'));
  assert.ok(bg.includes('void sessionSeal.set("tabs", currentOriginKey, Object.fromEntries([...tabs].map(([id, st]) => [String(id), st]))).catch(() => {});'));
  const load = spanOf(bg, "function ensureLoaded(): Promise<void> {", "\nfunction ");
  assert.ok(load.includes('let snap = (await sessionSeal.get("session", currentOriginKey)) as SessionSnapshot | undefined;'));
  assert.ok(load.includes('(await sessionSeal.get("tabs", currentOriginKey)) as Record<string, TabState> | undefined'));
  const qu = spanOf(bg, "function quStoreAt(originKeyOf: () => string): QuStore {", "\n}\n");
  assert.ok(bg.includes("const quStore: QuStore = quStoreAt(() => currentOriginKey);"), "the engine's store is the current server's");
  assert.ok(qu.includes("const originKey = originKeyOf();") && qu.includes('await sessionSeal.get("quickUnlock", originKey)'));
  assert.ok(qu.includes('if (!(await sessionSeal.set("quickUnlock", originKey, rec))) throw new Error("the quick-unlock record was not kept");'), "an unkept arm or reserve fails closed");
  assert.ok(qu.includes('remove: () => sessionSeal.remove("quickUnlock", originKeyOf()),'));
  const kl = spanOf(bg, "async function refreshKnownLogins(): Promise<void> {", "/** The locked capture path's membership test.");
  assert.ok(kl.includes('const rec = (await sessionSeal.get("knownLogins", ok)) as KnownLoginsRecord | undefined;'));
  assert.ok(kl.indexOf("if (session !== s || s.serverEnded) return;") > kl.indexOf('await sessionSeal.get("knownLogins", ok)'), "a lock during the read does not re-mint a wiped digest");
  assert.ok(kl.includes('await sessionSeal.set("knownLogins", ok, { key: toB64(knownLoginsKey), digests } satisfies KnownLoginsRecord);'));
  const known = spanOf(bg, "async function isKnownLoginWhileLocked(", "/** One gate for every locked-state RE-offer surface");
  assert.ok(known.includes('const rec = (await sessionSeal.get("knownLogins", currentOriginKey)) as KnownLoginsRecord | undefined;'));
  // Nothing pre-cut-over is adopted: the first-launch wipe deletes it (§12.4).
  assert.ok(!bg.includes("adoptLegacyNamespaceOnce"), "no adoption of older records");
});

test("A16 (review R4): the lock's erase is its first act — before ANY await — and the arm is decided after it", () => {
  const lock = spanOf(bg, "async function doLock(", "type TokenPair =");
  const body = lock.slice(lock.indexOf("{\n") + 2);
  const erase = body.indexOf("const erase = sessionSeal.lockErase();");
  assert.ok(erase > -1, "the erase");
  assert.ok(!/\bawait\b/.test(body.slice(0, erase).replace(/\/\/.*$/gm, "")), "nothing is awaited before it");
  assert.ok(body.indexOf("hydrateGen++;") < erase, "a load in flight is overtaken first");
  // The whole in-memory teardown is in the same synchronous step: no await before the session and the tab half go.
  const firstAwait = body.search(/^\s*(?:const [^=]+= )?await /m);
  for (const sync of ["session = null;", "redeemGen++;", "events = null;", "const teardownFlush = flushUsageForTeardown();", "clearPendingTotp();", "pendingCardSave.clear();", "reuseNotices.clear();"]) {
    const at = body.indexOf(sync);
    assert.ok(at > -1 && at < firstAwait, `"${sync}" is in the erase's synchronous step`);
  }
  // The arm is decided after: from the live pair, or the lock's own copy (opened, not loaded).
  assert.ok(body.indexOf("if (!api.getTokens().access) copy = await Promise.race([erase.opened(currentOriginKey), delay(LOCK_STORE_WAIT_MS).then(() => ({}))]);") > firstAwait, "bounded");
  assert.ok(body.includes("return live.access ? live : snapshotTokens(copy.session);"));
  assert.ok(!body.includes("hydrate: ensureLoaded"), "no general load inside a lock");
  const kl = body.indexOf('if (reason === "signout" || !quCompartmentTrusted) {');
  assert.ok(body.slice(kl, body.indexOf("if (attemptArm) {")).includes('await sessionSeal.remove("knownLogins", currentOriginKey);'));
  // The arm is told whose session this lock ends, taken before the session is dropped.
  assert.ok(body.indexOf("const userAtLock = session?.userId ?? null;") > -1 && body.indexOf("const userAtLock = session?.userId ?? null;") < body.indexOf("session = null;"));
  assert.ok(body.includes("const armUser = userAtLock ?? snapshotUserId(copy.session);"));
  assert.ok(body.includes("quickUnlock.arm({ access: toks.access!, refresh: toks.refresh }, armUser)"));
  // No account known and no quick unlock under way on this client → declined, decided from
  // the mark taken in the same synchronous step as the session.
  assert.ok(body.includes('armUser === null && !redeemAtLock ? "declined"'));
  const markAt = body.indexOf("const redeemAtLock = redeemClient !== null && redeemClient === api;");
  assert.ok(markAt > -1 && markAt < body.indexOf("session = null;"));
  for (const later of ["quickUnlock.arm(", "await quickUnlock.wipe();", "await Promise.race([teardownFlush, delay(TEARDOWN_FLUSH_TIMEOUT_MS)]);"]) {
    assert.ok(body.indexOf(later) > erase, `"${later}" comes after the erase`);
  }
  assert.ok(body.indexOf("await erase.erased;") > body.indexOf("api.setTokens(null, null);"), "awaited only at the end");
  // A16 review R2: then the epoch, bounded; the allow-listed tab remainder is re-persisted after it.
  const durable = body.indexOf("await sessionSeal.lockDurable(LOCK_EPOCH_WAIT_MS);");
  assert.ok(durable > body.indexOf("await erase.erased;") && durable < body.indexOf("if (tabs.size > 0) persistTabs();"));
  const tokens = spanOf(bg, "function snapshotTokens(raw: unknown): TokenPair {", "\n}\n");
  assert.ok(tokens.includes("s.origin !== serverUrl"), "a copied snapshot's pair counts only for the dialed origin (§4.1 rule 1)");
});

test("A16 review R4: sign-out erases first, then revokes on the pair the lock saw — and not while a server is pending", () => {
  const so = spanOf(bg, "async function doSignOut(", "/** Re-arm the policy idle lock");
  const lock = so.indexOf('await doLock("signout", seen, sayLost);');
  assert.ok(lock > -1);
  assert.ok(!/\bawait\b/.test(so.slice(so.indexOf("{\n"), lock).replace(/\/\/.*$/gm, "")), "the lock is the first thing awaited");
  const origin = so.indexOf("const origin = serverUrl;");
  assert.ok(origin > -1 && origin < lock, "the origin whose pair the lock collects is taken before the lock");
  assert.ok(so.indexOf("await revokePair(origin, pair);") > lock);
  // The revoke goes only to that origin, and only while it is still dialed with its pin in force.
  const rp = spanOf(bg, "async function revokePair(", "\n}\n");
  const gate = rp.indexOf("if (origin !== serverUrl || dialBlock !== null || pair.access === null) return;");
  assert.ok(gate > -1 && gate < rp.indexOf("revoker.logout()"));
  assert.ok(rp.includes("revoker.mayDial = () => origin === serverUrl && dialBlock === null;"));
  assert.ok(rp.includes("revoker.setTokens(pair.access, pair.refresh);") && rp.includes("revoker.setTokens(null, null);"));
  assert.ok(!so.includes("api.logout()") && !rp.includes("api.logout()"), "the worker's api has forgotten the pair by then");
});

test("A16 review R4: nothing dials while a server is pending — the api refuses every request, and resync / the socket do not start", () => {
  const make = spanOf(bg, "function makeApi(url: string): AndvariApi {", "\n}\n");
  assert.ok(make.includes("a.mayDial = () => dialBlock === null && session?.serverEnded !== true;"));
  const rs =spanOf(bg, "async function resync(): Promise<void> {", "\n}\n");
  assert.ok(rs.indexOf("if (dialBlock) return;") > -1 && rs.indexOf("if (dialBlock) return;") < rs.indexOf("api.sync(0)"));
  const sock = spanOf(bg, "async function ensureSocket(reset = false): Promise<void> {", "\n}\n");
  assert.ok(sock.indexOf("if (dialBlock) return;") > -1 && sock.indexOf("if (dialBlock) return;") < sock.indexOf("startEvents("));
  // The only AndvariApi built outside makeApi are the two revokers, each gated by hand: revokePair (sign-out, an
  // operator session, an abandoned sign-in), and the Safari
  // build's retirement of the session an earlier build made.
  assert.equal((bg.match(/new AndvariApi\(/g) ?? []).length, 3);
  const retire = spanOf(bg, "async function retireOwnSession(", "const ownSessionRetired");
  assert.ok(retire.indexOf("if (dialBlock !== null) return;") > -1 && retire.indexOf("if (dialBlock !== null) return;") < retire.indexOf("new AndvariApi("));
});

test("§12.2 rule 4: putItem, the one function that sends an item, refuses any vault but the personal one before it seals", () => {
  const put = spanOf(bg, "async function putItem(", "\n}\n");
  const refuse = put.indexOf('if (!session || session.personalVaultId === "" || vaultId !== session.personalVaultId) return undefined;');
  assert.ok(refuse > -1 && refuse < put.indexOf("seal(vk,") && refuse < put.indexOf("api.push("), "refused before anything is sealed or sent");
  // Every item send goes through putItem: no other push in the worker.
  assert.equal((bg.match(/api\.push\(/g) ?? []).length, 1);
});

test("The locked popup's Forgot link says where recovery happens; it opens no #recover route", () => {
  assert.ok(popup.includes('el("forgot").addEventListener("click", () => showMsg("info", RECOVER_IN_APP));'));
  assert.ok(!popup.includes("#recover"));
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

test("§4.4: a session the server ends — the revoked frame and a refused refresh — ends it without deleting what it holds", () => {
  const sock = spanOf(bg, "async function ensureSocket(reset = false): Promise<void> {", "\n}\n");
  // After the lock's deadline check (a frame is a way into the worker too).
  assert.ok(sock.includes("onRevoked: () => void lockIfDue().then(() => endSessionByServer()),"), "the revoked frame ends the session, it does not sign out");
  assert.ok(!sock.includes("doSignOut"));
  const make = spanOf(bg, "function makeApi(url: string): AndvariApi {", "\n}\n");
  assert.ok(make.includes('if (a === api && session !== null && redeemClient !== a) void endSessionByServer(why === "not_confirmed");'), "a refused refresh of a live session");
  assert.ok(make.includes("a.mayDial = () => dialBlock === null && session?.serverEnded !== true;"), "nothing is sent while it stands");
  const end = spanOf(bg, "async function endSessionByServer(unconfirmed = false): Promise<void> {", "\n}\n");
  for (const gone of ["api.setTokens(null, null);", "await quickUnlock.wipe()", "events?.close();", 'clearAlarm("resync")']) assert.ok(end.includes(gone), gone);
  for (const kept of ["doLock(", "doSignOut(", "purgeOriginNamespace(", "session = null", "trusted.remove"]) assert.ok(!end.includes(kept), `keeps what it holds: no ${kept}`);
  // Only the known-logins digest goes with the quick-unlock material (spec 01 §8.4); the snapshot and the tabs stay.
  assert.deepEqual(end.match(/sessionSeal\.remove\([^)]*\)/g), ['sessionSeal.remove("knownLogins", currentOriginKey)'], "keeps what it holds: the one removal is the digest");
  const put = spanOf(bg, "async function putItem(", "\n}\n");
  assert.ok(put.includes("if (dialBlock !== null || session.serverEnded) return undefined;"), "nothing is written");
});

// ---- The session's list of opened items never holds an item of a vault whose key the session does not hold ----
// The rule is held in one function, itemsUnderHeldKeys. A behaviour test shows one race it closes (readd.harness.test.ts,
// two pulls at once); this pin makes every way background.ts sets a list of opened items go through the function, so a
// new place that sets the list without it fails here.

const HELD = "itemsUnderHeldKeys(";

/** Every place in [source] (background.ts or a variant of it) that sets a list of opened items without
 *  itemsUnderHeldKeys, as "line N: what". Whole-line comments and trailing `// ` comments are blanked first (comments
 *  name these forms freely); line numbers are kept. */
function listSettersWithoutTheRule(source: string): { problems: string[]; assignments: number; literals: number } {
  const code = source
    .split("\n")
    .map((l) => (/^\s*(\/\/|\/\*|\*)/.test(l) ? "" : l.replace(/\s\/\/\s.*$/, "")))
    .join("\n");
  const lineOf = (at: number) => code.slice(0, at).split("\n").length;
  const problems: string[] = [];
  // 1. Every assignment of a list of opened items (`x.items = …`, `??=`, `||=`, `&&=`) is the function's result.
  const assigns = [...code.matchAll(/\.items\s*(?:\?\?|\|\||&&)?=(?![=>])\s*/g)];
  for (const m of assigns) {
    if (!code.startsWith(HELD, m.index! + m[0].length)) problems.push(`line ${lineOf(m.index!)}: a list of opened items set without ${HELD}`);
  }
  // 2. A list is never changed in place: no entry is added, replaced or cut, so no item can arrive that way.
  for (const re of [/\.items\s*\.\s*(?:push|unshift|splice|fill|copyWithin)\s*\(/g, /\.items\s*\[[^\]]*\]\s*=(?!=)/g, /\.items\s*\.\s*length\s*=(?!=)/g]) {
    for (const m of code.matchAll(re)) problems.push(`line ${lineOf(m.index!)}: a list of opened items changed in place (${m[0]})`);
  }
  // 3. A session is made only by an object literal assigned to `session` (or ended with null), and that literal's list
  //    is the function's result.
  let literals = 0;
  for (const m of code.matchAll(/\bsession\s*(?:\?\?|\|\||&&)?=(?![=>])\s*/g)) {
    const at = m.index! + m[0].length;
    if (code.startsWith("null", at)) continue;
    if (code[at] !== "{") {
      problems.push(`line ${lineOf(m.index!)}: a session set from something other than an object literal`);
      continue;
    }
    let depth = 0;
    let end = at;
    for (; end < code.length; end++) {
      if (code[end] === "{") depth++;
      else if (code[end] === "}" && --depth === 0) break;
    }
    literals++;
    const body = code.slice(at, end + 1);
    const items = [...body.matchAll(/(?:^|[\s,{])items\b\s*(:\s*)?/g)];
    const ok = items.length === 1 && items[0]![1] !== undefined && body.startsWith(HELD, items[0]!.index! + items[0]![0].length);
    if (!ok) problems.push(`line ${lineOf(m.index!)}: the session's list is set without ${HELD}`);
  }
  // 4. No other way to make or fill a session: no Object.assign, no spread of a session, no cast to Session.
  for (const re of [/Object\.assign\(/g, /\.\.\.\s*(?:session|owner)\b(?!\s*[.!?])/g, /\b(?:as|satisfies)\s+Session\b/g]) {
    for (const m of code.matchAll(re)) problems.push(`line ${lineOf(m.index!)}: a session made or filled another way (${m[0]})`);
  }
  return { problems, assignments: assigns.length, literals };
}

test("every place that sets the session's list of opened items keeps only items of vaults whose key is held", () => {
  assert.ok(bg.includes("function itemsUnderHeldKeys(items: readonly DecryptedItem[], vaultKeys: ReadonlyMap<string, Uint8Array>): DecryptedItem[] {\n  return items.filter((i) => vaultKeys.has(i.vaultId));\n}"), "the function keeps exactly the items whose vault key is held");
  const found = listSettersWithoutTheRule(bg);
  assert.deepEqual(found.problems, []);
  // Not vacuous: the drop, the install and the three saves that add an item; the unlock, the quick unlock, the restore.
  assert.ok(found.assignments >= 5, `the known assignments are found (${found.assignments})`);
  assert.equal(found.literals, 3, "the session is made at the unlock, the quick unlock and the restore from the snapshot");
});

test("the check above finds a new place that sets the list without the function", () => {
  const install = "session.items = itemsUnderHeldKeys(homed.items, session.vaultKeys);";
  const added = "owner.items = itemsUnderHeldKeys([...owner.items, { itemId, vaultId: owner.personalVaultId, rev, formatVersion: LOGIN_FORMAT_VERSION, doc }], owner.vaultKeys);";
  const unlocked = "items: itemsUnderHeldKeys(homed.items, vaultKeys),";
  for (const anchor of [install, added, unlocked]) assert.ok(bg.includes(anchor), `anchor present: ${anchor}`);
  const variants: [string, string][] = [
    ["the install of a pull, plain", bg.replace(install, "session.items = homed.items;")],
    ["a save that pushes its item", bg.replace(added, "owner.items.push({ itemId, vaultId: owner.personalVaultId, rev, formatVersion: LOGIN_FORMAT_VERSION, doc });")],
    ["an index write", bg.replace(install, "session.items[0] = homed.items[0]!;")],
    ["a session literal with its list plain", bg.replace(unlocked, "items: homed.items,")],
    ["a session literal with the shorthand", bg.replace(unlocked, "items,")],
    ["a session from a variable", bg.replace(install, "session = restored;")],
    ["a session filled by Object.assign", bg.replace(install, "Object.assign(session, { items: homed.items });")],
  ];
  for (const [what, src] of variants) {
    assert.notEqual(src, bg, `${what}: the variant differs`);
    assert.ok(listSettersWithoutTheRule(src).problems.length > 0, `${what}: found`);
  }
});
