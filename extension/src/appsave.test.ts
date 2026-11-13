import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import nacl from "tweetnacl";
import { buildQueuedSave, MAX_ENTRY_BYTES, MAX_FIELD_CHARS, MAX_SITE_CHARS, parseSaveKeyReply, queueSaveToApp, SAVE_MAGIC, savesThroughApp, sealTo } from "./appsave.ts";
import { fromB64, sealOpen, toB64 } from "./crypto.ts";

const account = nacl.box.keyPair();
const key = { origin: "https://home.example", userId: "u1", identityPub: account.publicKey };
const keyText = JSON.stringify({ v: 1, origin: key.origin, userId: key.userId, identityPub: toB64(account.publicKey) });

test("a sealed box opens with the account's key and nobody else's", () => {
  const sealed = sealTo(account.publicKey, new TextEncoder().encode("hello"));
  assert.equal(new TextDecoder().decode(sealOpen(account.publicKey, account.secretKey, sealed)), "hello");
  const other = nacl.box.keyPair();
  assert.throws(() => sealOpen(other.publicKey, other.secretKey, sealed));
  sealed[40] ^= 1;
  assert.throws(() => sealOpen(account.publicKey, account.secretKey, sealed), "tampered");
});

test("a queue entry holds no plaintext, names its account outside and inside, and opens to the capture", () => {
  const entry = buildQueuedSave(key, "https://shop.example/login", "me", "s3cret-pw", 1234)!;
  for (const secret of ["s3cret-pw", "shop.example", '"me"']) assert.ok(!entry.includes(secret), secret);
  const outer = JSON.parse(entry) as { v: number; origin: string; userId: string; sealed: string };
  assert.deepEqual({ v: outer.v, origin: outer.origin, userId: outer.userId }, { v: 1, origin: key.origin, userId: "u1" });
  const inside = JSON.parse(new TextDecoder().decode(sealOpen(account.publicKey, account.secretKey, fromB64(outer.sealed))));
  assert.deepEqual(inside, { magic: SAVE_MAGIC, origin: key.origin, userId: "u1", site: "https://shop.example/login", username: "me", password: "s3cret-pw", capturedAtMs: 1234, source: "safari" });
});

test("the bounds are the core's: no password, an over-long field or an over-long site is not queued", () => {
  assert.equal(buildQueuedSave(key, "shop.example", "me", "", 1), null);
  assert.equal(buildQueuedSave(key, "shop.example", "me", "x".repeat(MAX_FIELD_CHARS + 1), 1), null);
  assert.equal(buildQueuedSave(key, "shop.example", "u".repeat(MAX_FIELD_CHARS + 1), "pw", 1), null);
  assert.equal(buildQueuedSave(key, "s".repeat(MAX_SITE_CHARS + 1), "me", "pw", 1), null);
  assert.equal(buildQueuedSave(key, " ", "me", "pw", 1), null);
  const biggest = buildQueuedSave(key, "s".repeat(MAX_SITE_CHARS), "u".repeat(MAX_FIELD_CHARS), "p".repeat(MAX_FIELD_CHARS), 1)!;
  assert.ok(new TextEncoder().encode(biggest).length <= MAX_ENTRY_BYTES, "the largest allowed capture fits an entry");
  // The same numbers as core/app/SaveQueue.kt.
  const core = readFileSync(new URL("../../core/src/commonMain/kotlin/io/silencelen/andvari/core/app/SaveQueue.kt", import.meta.url), "utf8");
  assert.match(core, /const val MAX_ENTRY_BYTES = 8 \* 1024/);
  assert.match(core, new RegExp(`const val MAX_FIELD_CHARS = ${MAX_FIELD_CHARS}\\b`));
  assert.match(core, new RegExp(`const val MAX_SITE_CHARS = ${MAX_SITE_CHARS}\\b`));
  assert.match(core, new RegExp(`const val MAGIC = "${SAVE_MAGIC}"`));
});

test("the app's key reply: a key, none, or nothing usable", () => {
  const got = parseSaveKeyReply({ ok: true, type: "saveKey", key: keyText });
  assert.ok(typeof got === "object" && got.userId === "u1" && got.identityPub.length === 32);
  assert.equal(parseSaveKeyReply({ ok: true, type: "saveKey", key: null }), "none");
  for (const bad of [
    undefined,
    { ok: false, type: "saveKey", key: keyText },
    { ok: true, type: "appServer", key: keyText },
    { ok: true, type: "saveKey" },
    { ok: true, type: "saveKey", key: "not json" },
    { ok: true, type: "saveKey", key: JSON.stringify({ v: 2, origin: key.origin, userId: "u1", identityPub: toB64(account.publicKey) }) },
    { ok: true, type: "saveKey", key: JSON.stringify({ v: 1, origin: "https://home.example/path", userId: "u1", identityPub: toB64(account.publicKey) }) },
    { ok: true, type: "saveKey", key: JSON.stringify({ v: 1, origin: key.origin, userId: "u1", identityPub: toB64(new Uint8Array(31)) }) },
  ]) {
    assert.equal(parseSaveKeyReply(bad), "unavailable", JSON.stringify(bad));
  }
});

test("queuing asks for the key, then hands over only ciphertext", async () => {
  const sent: { type: string; id?: string; entry?: string }[] = [];
  const native = async (m: { type: string; id?: string; entry?: string }) => {
    sent.push(m);
    return m.type === "saveKey" ? { ok: true, type: "saveKey", key: keyText } : { ok: true, type: "queueSave", queued: true };
  };
  const capture = { site: "https://shop.example", username: "me", password: "s3cret-pw" };
  assert.equal(await queueSaveToApp(native, capture, 1), "queued");
  assert.deepEqual(sent.map((m) => m.type), ["saveKey", "queueSave"]);
  assert.match(sent[1]!.id!, /^c-[0-9a-f]{32}$/, "an id minted for the capture");
  assert.ok(!JSON.stringify(sent).includes("s3cret-pw"));

  assert.equal(await queueSaveToApp(async () => ({ ok: true, type: "saveKey", key: null }), capture, 1), "no_account");
  assert.equal(await queueSaveToApp(async () => { throw new Error("no host"); }, capture, 1), "unavailable");
  assert.equal(await queueSaveToApp(() => new Promise(() => {}), capture, 1, 10), "unavailable", "silence");
  assert.equal(await queueSaveToApp(native, capture, 1, 3000, () => "../x"), "refused");
  assert.equal(await queueSaveToApp(native, { ...capture, password: "" }, 1), "refused");
  const full = async (m: { type: string }) => (m.type === "saveKey" ? { ok: true, type: "saveKey", key: keyText } : { ok: true, type: "queueSave", queued: false });
  assert.equal(await queueSaveToApp(full, capture, 1), "refused", "the handler's queue is full");
});

test("every capture is an entry of its own: ids are never reused, and a taken id is tried again under a new one", async () => {
  // The handler never replaces an entry; it answers a taken id with taken: true.
  const entries = new Map<string, string>();
  const native = async (m: { type: string; id?: string; entry?: string }) => {
    if (m.type === "saveKey") return { ok: true, type: "saveKey", key: keyText };
    if (entries.has(m.id!)) return { ok: true, type: "queueSave", queued: false, taken: true };
    entries.set(m.id!, m.entry!);
    return { ok: true, type: "queueSave", queued: true, taken: false };
  };
  for (const password of ["first", "second", "third"]) {
    assert.equal(await queueSaveToApp(native, { site: "https://shop.example", username: "me", password }, 1), "queued");
  }
  assert.equal(entries.size, 3, "three captures, three entries");

  const ids = ["c-taken", "c-taken", "c-fresh"];
  entries.set("c-taken", "someone else's");
  assert.equal(await queueSaveToApp(native, { site: "https://shop.example", username: "me", password: "fourth" }, 1, 3000, () => ids.shift()!), "queued");
  assert.equal(entries.get("c-taken"), "someone else's", "the taken entry is untouched");
  assert.ok(entries.has("c-fresh"));
  assert.equal(await queueSaveToApp(native, { site: "https://shop.example", username: "me", password: "fifth" }, 1, 3000, () => "c-taken"), "refused", "gives up after a few taken ids");
  assert.equal(entries.get("c-taken"), "someone else's");
});

test("only the Safari build saves through the app, and the worker does it before it would need a session", () => {
  assert.equal(savesThroughApp("safari"), true);
  assert.equal(savesThroughApp("chrome"), false);
  assert.equal(savesThroughApp("firefox"), false);
  const bg = readFileSync(new URL("./background.ts", import.meta.url), "utf8");
  const fn = bg.slice(bg.indexOf("async function resolvePendingSave("));
  const viaApp = fn.indexOf("if (savesThroughApp(BUILD_TARGET)) return saveThroughApp(tabId, st, pending);");
  assert.ok(viaApp > 0 && viaApp < fn.indexOf("if (!session) {"), "the Safari branch comes before the session check");
  // Where the system saves passwords itself (iOS 26.2), the worker keeps no capture at all: no prompt can follow.
  const capture = bg.slice(bg.indexOf("async function capturedCredential("), bg.indexOf("async function capturedCredential(") + 2200);
  assert.match(capture, /if \(savesThroughApp\(BUILD_TARGET\)\) \{\s*if \(systemSavesPasswords === null\) await syncAppServer\(\);\s*if \(systemSavesPasswords === true\) return \{ ok: true \};/);
  assert.ok(capture.indexOf("systemSavesPasswords === true") < capture.indexOf("const st = tabs.get(tabId)"), "before any tab state is read or written");
});
