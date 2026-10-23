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
//   3. the worker reads chrome.storage.local in exactly one place, the one-time migration, and otherwise only removes
//      from it (the purge); it no longer listens to storage.onChanged at all.
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
      t === "await migrateTrustState(legacyLocal, trusted);" ||
      t === "await purgeOriginRecords(originKey, [trusted, legacyLocal, sessionArea]);";
    assert.ok(approved, `legacyLocal reached code this fence has not approved: ${t}`);
  }
  assert.equal(legacyLines.length, 3);
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
