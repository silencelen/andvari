// node --test. Security review 2026-10, branch A15: who may touch which storage.
//
// chrome.storage.local is reachable from content scripts (Chrome by default, until Chrome 140's setAccessLevel locks
// it; Firefox always, by design: Mozilla bug 2018494), and so is its onChanged stream. Since A15 the extension keeps
// its trust state in the extension origin's IndexedDB instead (trustedkv.ts), with the service worker as its only
// reader and writer. These source fences hold that layout:
//   1. content-side modules (content.ts and everything it imports) never touch chrome.storage or IndexedDB;
//   2. our pages (popup, options, connector, offscreen, the KDF worker) never touch them either — they ask the worker,
//      so "the worker is the only writer" is true by construction (and a Firefox page shown in a private window,
//      which would get a private IndexedDB of its own, never reads a different store than the worker);
//   3. the worker hands chrome.storage.local to exactly three leaves — the one-time migration (which reads it only when
//      the browser attested the upgrade, A15 review F2), the server state (which reads its `serverUrl` ONLY to block
//      sign-in: with no trusted store, A15 review F1, or after a start that skipped the migration, A16 review R3), and
//      the purge — and otherwise only removes from it; it no longer listens to storage.onChanged at all.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const src = (f: string) => readFileSync(new URL(`./${f}`, import.meta.url), "utf-8");

/** Source with comments removed, so prose that NAMES storage (to state these rules) is not mistaken for a touch. */
function code(text: string): string {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .split("\n")
    .map((l) => l.replace(/(^|[^:"'`\\])\/\/.*$/, "$1"))
    .join("\n");
}

/** Any spelling of a storage touch this extension could plausibly write. */
const STORAGE_TOUCH = /\b(?:chrome|browser)\s*\??\.\s*storage\b|\[\s*["'`]storage["'`]\s*\]|\bstorage\s*\??\.\s*(?:local|session|sync|managed|onChanged)\b|\bindexedDB\b|\bIDBFactory\b/;

function importClosure(entry: string): Set<string> {
  const seen = new Set<string>();
  const queue = [entry];
  while (queue.length > 0) {
    const f = queue.pop()!;
    if (seen.has(f)) continue;
    seen.add(f);
    for (const m of src(f).matchAll(/from\s+"\.\/([^"]+)"/g)) queue.push(m[1]!.endsWith(".ts") ? m[1]! : `${m[1]}.ts`);
  }
  return seen;
}

test("content-side modules never touch chrome.storage or IndexedDB (the content bundle's whole import closure)", () => {
  const closure = importClosure("content.ts");
  for (const must of ["content.ts", "content-ui.ts", "detect.ts", "cardfill.ts", "card.ts", "errors.ts", "messages.ts", "reusealert.ts"]) {
    assert.ok(closure.has(must), `the closure reached ${must}`);
  }
  assert.ok(!closure.has("serverurl.ts") && !closure.has("trustedkv.ts"), "the content bundle does not even import the store");
  for (const f of closure) {
    const hit = code(src(f)).match(STORAGE_TOUCH);
    assert.equal(hit, null, `${f} touches storage: ${hit?.[0]}`);
  }
});

test("our pages never touch chrome.storage or IndexedDB, and never read or write the server choice themselves", () => {
  for (const f of ["popup.ts", "options.ts", "connector.ts", "offscreen.ts", "kdf-worker.ts", "grantflow.ts", "livemsg.ts", "theme.ts", "trustgate.ts"]) {
    const c = code(src(f));
    const hit = c.match(STORAGE_TOUCH);
    assert.equal(hit, null, `${f} touches storage: ${hit?.[0]}`);
    for (const call of ["getServerUrl(", "setServerUrl(", "trustedStore(", "idbKv("]) {
      assert.ok(!c.includes(call), `${f} calls ${call} — pages ask the worker (serverInfo / setServerUrl messages)`);
    }
  }
  // …and they do ask it: the options page commits through the message, the popup reads through it.
  assert.match(src("options.ts"), /send\(\{ type: "setServerUrl", url: canonical \}\)/);
  assert.match(src("options.ts"), /send\(\{ type: "serverInfo" \}\)/);
  assert.match(src("popup.ts"), /ask\(\{ type: "serverInfo" \}\)/);
});

test("the worker reads chrome.storage.local only through the one-time migration, and only removes from it otherwise", () => {
  const bg = code(src("background.ts"));
  assert.ok(!/storage\s*\.\s*onChanged/.test(bg), "no storage.onChanged listener: a write there is not a server switch any more");
  const localLines = bg.split("\n").filter((l) => /storage\s*\.\s*local\b/.test(l));
  for (const l of localLines) {
    const t = l.trim();
    const approved =
      t === "const legacyLocal = chrome.storage.local as unknown as KvArea;" || // the migration's input, by name
      t === "await chrome.storage.local.remove(keys);"; // purgeOriginNamespace's fixed list (pre-A15 leftovers)
    assert.ok(approved, `chrome.storage.local reached code this fence has not approved: ${t}`);
  }
  assert.equal(localLines.length, 2, "exactly the two approved lines");
  const legacyLines = bg.split("\n").filter((l) => l.includes("legacyLocal")).map((l) => l.trim());
  for (const t of legacyLines) {
    const approved =
      t === "const legacyLocal = chrome.storage.local as unknown as KvArea;" ||
      t === "const outcome = await migrateTrustState(legacyLocal, trusted, () =>" || // worker start (F2: attested only)
      t === "const outcome = await migrateTrustState(legacyLocal, trusted, async () => null);" || // a late install event
      t === "const st = await loadServerState(outcome, trusted, legacyLocal);" || // F1: block-only read, no store
      t === "if (!(await forgetPendingServer(dialBlock, trusted, legacyLocal))) return { ok: false };" || // "Not mine"
      t === "await purgeOriginRecords(originKey, [trusted, legacyLocal, sessionSeal.purgeArea()]);";
    assert.ok(approved, `legacyLocal reached code this fence has not approved: ${t}`);
  }
  assert.equal(legacyLines.length, 6);
});

test("the server state reads storage.local only to block — with no trusted store, or (A16 review R3) after a start that skipped the migration — only its serverUrl; it never writes there", () => {
  const ss = code(src("serverstate.ts"));
  const reads = ss.match(/legacy\.get\(/g) ?? [];
  assert.equal(reads.length, 1, "one read");
  const one = ss.slice(ss.indexOf("async function previousServer(legacy: KvArea): Promise<string | null> {"));
  assert.ok(one.startsWith("async function previousServer(") && one.includes("return otherServer((await legacy.get(SERVER_URL_KEY))[SERVER_URL_KEY]);"), "of serverUrl alone, in one helper");
  // Its callers: the no-trusted-store branch and the unattested branch, and each turns the answer into a block that cannot
  // be confirmed (never adopted, never offered for connecting).
  assert.equal((ss.match(/await previousServer\(legacy\)/g) ?? []).length, 2);
  const unavailable = ss.slice(ss.indexOf('if (outcome.kind === "unavailable") {'), ss.indexOf('if (outcome.kind === "failed")'));
  assert.ok(unavailable.includes("await previousServer(legacy)"), "inside the no-trusted-store branch");
  assert.ok(unavailable.includes('{ kind: "confirm", origin: previous, keepable: false }'), "as a block that cannot be confirmed (never adopted)");
  const unattested = ss.slice(ss.indexOf('if (outcome.kind === "skipped" || mark === true) {'));
  assert.ok(unattested.indexOf("await previousServer(legacy)") > -1, "inside the unattested branch");
  assert.ok(unattested.indexOf('block: { kind: "confirm", origin: previous, keepable: false }') > unattested.indexOf("await previousServer(legacy)"), "as the same read-only block");
  assert.ok(!/legacy\.set\(/.test(ss), "never a write");
  assert.equal((ss.match(/legacy\.remove\(/g) ?? []).length, 1, "the one removal: 'Not mine' for a block read from storage.local");
  // The migration leaf: storage.local is read in exactly one place, the owed run.
  const tm = code(src("trustmigrate.ts"));
  assert.equal((tm.match(/legacy\.get\(/g) ?? []).length, 1);
  const owedRun = tm.slice(tm.indexOf("async function runOwedMigration("));
  assert.ok(owedRun.includes("all = await legacy.get(null);"), "inside the owed run only");
});

// ---- A16 (security review 2026-10): storage.session holds only sealed records and the plain inventory ----
// That a content script cannot reach storage.session is not relied on (Chrome enforces it in the browser; Firefox's
// exclusion is not relied on). Every secret-bearing record is sealed under a non-extractable key in the extension
// origin's IndexedDB (sessionseal.ts), and the worker reaches storage.session through exactly two wrappers: the seal,
// and the plain area, which refuses any key outside the plain inventory at run time.

test("A16: every storage.session write in the worker goes through the seal or the plain inventory — no raw touch", () => {
  const bg = code(src("background.ts"));
  const sessionLines = bg.split("\n").filter((l) => /storage\s*\??\.\s*session\b|\[\s*["'`]session["'`]\s*\]/.test(l)).map((l) => l.trim());
  assert.deepEqual(sessionLines, ["const sessionRaw = chrome.storage.session as unknown as KvArea;"], "storage.session is named once, by name");
  const rawLines = bg.split("\n").filter((l) => /\bsessionRaw\b/.test(l)).map((l) => l.trim());
  for (const t of rawLines) {
    const approved =
      t === "const sessionRaw = chrome.storage.session as unknown as KvArea;" ||
      t === "const sessionSeal = new SessionSeal({ session: sessionRaw, keys: idbKv(() => (globalThis as { indexedDB?: IDBFactory }).indexedDB, SEAL_DB_NAME), originKey: () => serverReady.then(() => currentOriginKey) });" ||
      t === "const plainSession = plainSessionArea(sessionRaw);";
    assert.ok(approved, `sessionRaw reached code this fence has not approved: ${t}`);
  }
  assert.equal(rawLines.length, 3, "the declaration and the two wrappers");
  // No other alias of the area: nothing assigns `chrome.storage` (or a property of it) to a name.
  assert.ok(!/=\s*chrome\s*\.\s*storage\s*;/.test(bg), "no alias of chrome.storage itself");

  // Every write through the plain area names only the plain inventory's keys (lockNotice, the update throttle stamp and
  // the quiet marker). The area refuses anything else at run time too (sessionseal.test.ts).
  const plainSets = bg.split("\n").filter((l) => /plainSession\s*\.\s*set\(/.test(l));
  assert.ok(plainSets.length >= 4, "the plain writes exist (lockNotice, quiet, throttle)");
  for (const l of plainSets) {
    const arg = l.slice(l.search(/plainSession\s*\.\s*set\(/));
    assert.match(arg, /^plainSession\s*\.\s*set\(\{ \[/, `a plain write is an object literal with computed keys this fence can read: ${l.trim()}`);
    const keys = [...arg.matchAll(/\[\s*([A-Za-z_]+)\s*\]\s*:/g)].map((k) => k[1]!);
    assert.ok(keys.length > 0, l.trim());
    for (const k of keys) assert.ok(["NKEY", "kQuiet", "kLast"].includes(k), `plainSession.set writes ${k}, which is not in the plain inventory`);
  }
  assert.equal((bg.match(/plainSession\s*\.\s*set\(/g) ?? []).length, plainSets.length, "one plain write per line");
  // Every write through the seal names a sealed kind, as a literal.
  const sealSets = [...bg.matchAll(/sessionSeal\s*\.\s*set\(\s*([^,]+),/g)];
  assert.ok(sealSets.length >= 4, "session, tabs, quickUnlock and knownLogins are written");
  for (const m of sealSets) assert.match(m[1]!.trim(), /^"(session|tabs|quickUnlock|knownLogins)"$/, `sessionSeal.set(${m[1]})`);
  // The secret-bearing records are never written or read beside the plain area, nor by the raw area's name.
  for (const key of ["SKEY", "TKEY", "QKEY", "KLKEY", '"session"', '"tabs"', '"quickUnlock"', '"knownLogins"']) {
    for (const l of bg.split("\n").filter((x) => x.includes(key))) {
      assert.ok(!/plainSession|sessionRaw/.test(l), `${key} beside the plain area: ${l.trim()}`);
    }
  }
});

// A16 review (2026-10-23), fence gap: background hands the WHOLE chrome.storage namespace to storageaccess.ts (to set the
// access levels), so the session fence above did not see what that leaf does with it. It may set access levels and test
// that storage.session exists — nothing else: no read, write, removal or listener on any area.
test("A16 review: the access-level leaf, handed all of chrome.storage, only sets access levels — it reads, writes and removes nothing", () => {
  const bg = code(src("background.ts"));
  const whole = bg
    .split("\n")
    .filter((l) => /\bchrome\s*\.\s*storage\b(?!\s*\.\s*(?:local|session)\b)/.test(l))
    .map((l) => l.trim());
  assert.deepEqual(
    whole,
    ["const storageAccess: Promise<StorageAccessVerdict> = restrictStorageAccess(chrome.storage as unknown as StorageAccessAreas);"],
    "the namespace itself is handed to exactly one leaf, once",
  );
  const sa = code(src("storageaccess.ts"));
  assert.equal(sa.match(/^\s*import\b/m), null, "it imports nothing (no other module gets the namespace through it)");
  assert.equal(sa.match(/\b(?:get|set|remove|clear|getKeys|getBytesInUse)\s*\(/), null, "no storage call");
  assert.ok(!/\bonChanged\b|\bsync\b|\bmanaged\b/.test(sa), "no listener, no other area");
  // Every member it touches on an area: `setAccessLevel` (called, with the one TRUSTED level) and `get` (only tested
  // for existence, the Firefox fallback); the areas themselves are `session` and `local`.
  const members = [...sa.matchAll(/\?\.\s*([A-Za-z_]+)/g)].map((m) => m[1]!);
  for (const m of members) assert.ok(["setAccessLevel", "session", "local", "get"].includes(m), `storageaccess.ts touches .${m}`);
  assert.deepEqual([...sa.matchAll(/\.call\(([^)]*)\)/g)].map((m) => m[1]), ["area, TRUSTED"], "setAccessLevel is called once, with TRUSTED");
  assert.ok(sa.includes('const TRUSTED = { accessLevel: "TRUSTED_CONTEXTS" } as const;'));
  assert.deepEqual([...sa.matchAll(/typeof [^\n]*?\.get\b[^\n]*/g)].map((m) => m[0].trim()), ['typeof storage?.session?.get === "function");'], "`get` is only tested for existence");
  assert.equal((sa.match(/\.get\b/g) ?? []).length, 1, "and named nowhere else");
});

test("A16: the seal is the worker's alone — no content-side module or page names it", () => {
  assert.ok(!importClosure("content.ts").has("sessionseal.ts"), "the content bundle does not import the seal");
  for (const f of ["popup.ts", "options.ts", "connector.ts", "offscreen.ts", "kdf-worker.ts"]) {
    const c = code(src(f));
    for (const call of ["SessionSeal", "plainSessionArea(", "SEAL_DB_NAME"]) assert.ok(!c.includes(call), `${f} names ${call}`);
  }
  // The leaf itself is chrome-free: the areas are injected.
  const leaf = code(src("sessionseal.ts"));
  assert.equal(leaf.match(STORAGE_TOUCH), null, "sessionseal.ts names no storage API");
  assert.ok(!/\bchrome\b/.test(leaf), "sessionseal.ts does not touch chrome");
});

test("no trust record is read from, or written to, a chrome.storage area by name", () => {
  const bg = code(src("background.ts"));
  // Every durable trust record and every convenience the migration moved: their keys never sit beside a
  // chrome.storage call on one line (the store they live in now is `trusted`).
  for (const key of ["SERVER_URL_KEY", "UKEY", "USEQ", "DKEY", "BKEY", "homesKey(", "personalWrap:", "personalChange:", "LAST_EMAIL_KEY", "LEGACY_SERVER_KEY", "NS_ADOPTED_KEY"]) {
    for (const l of bg.split("\n").filter((x) => x.includes(key))) {
      assert.ok(!/chrome\s*\.\s*storage/.test(l), `${key} beside a chrome.storage call: ${l.trim()}`);
    }
  }
});
