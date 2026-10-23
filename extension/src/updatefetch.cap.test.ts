// Security review 2026-10, A13 review RF6 (LOW, the extension sibling of desktop q19): checkForUpdate read the update
// manifest (`arrayBuffer()`) and its detached signature (`text()`) whole, before anything had verified them, so a
// hostile or broken origin could make the service worker buffer an unbounded body. Both reads are now capped the way
// desktop's are (256 KiB / 1 KiB): a declared Content-Length over the cap is refused before reading, and a body with
// no (or a lying) length is read as a stream that stops at the cap.
//
// Runs under Node's built-in runner (node --test); type-stripped natively. Behaviour tests drive the real reader over
// real `Response` objects; the last test is a source pin, because background.ts touches chrome.* and cannot run here.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { readCappedBody, UPDATE_MANIFEST_MAX_BYTES, UPDATE_SIG_MAX_BYTES } from "./updateverify.ts";

/** A body that hands out [chunks] chunks of [size] bytes on demand, counting pulls and noticing a cancel. */
function countingStream(chunks: number, size: number) {
  const seen = { pulls: 0, cancelled: false };
  const stream = new ReadableStream<Uint8Array>({
    pull(c) {
      if (seen.pulls >= chunks) {
        c.close();
        return;
      }
      seen.pulls++;
      c.enqueue(new Uint8Array(size).fill(0x61));
    },
    cancel() {
      seen.cancelled = true;
    },
  });
  return { stream, seen };
}

test("the caps match desktop's (256 KiB manifest, 1 KiB signature)", () => {
  assert.equal(UPDATE_MANIFEST_MAX_BYTES, 256 * 1024);
  assert.equal(UPDATE_SIG_MAX_BYTES, 1024);
});

test("a body within the cap comes back byte for byte, and one exactly at the cap is accepted", async () => {
  const small = new Uint8Array([1, 2, 3, 250]);
  assert.deepEqual(await readCappedBody(new Response(small), 16), small);
  const exact = new Uint8Array(16).fill(7);
  assert.deepEqual(await readCappedBody(new Response(exact), 16), exact);
  assert.deepEqual(await readCappedBody(new Response(new Uint8Array(0)), 16), new Uint8Array(0));
});

test("a body one byte over the cap is refused", async () => {
  assert.equal(await readCappedBody(new Response(new Uint8Array(17)), 16), null);
});

test("a declared Content-Length over the cap is refused before the body is read", async () => {
  const { stream, seen } = countingStream(4, 8);
  const resp = new Response(stream, { headers: { "content-length": "1000000" } });
  assert.equal(await readCappedBody(resp, 16), null);
  assert.equal(seen.pulls <= 1, true, `read ${seen.pulls} chunks of a body it had already refused`);
});

test("a malformed Content-Length is refused", async () => {
  const resp = new Response(new Uint8Array(4), { headers: { "content-length": "4, 4" } });
  assert.equal(await readCappedBody(resp, 16), null);
});

test("a body with no length stops at the cap and is cancelled, never read to the end", async () => {
  const { stream, seen } = countingStream(10_000, 1024); // ~10 MiB on offer
  assert.equal(await readCappedBody(new Response(stream), 4096), null);
  assert.ok(seen.pulls <= 6, `kept reading past the cap: ${seen.pulls} chunks`);
  assert.equal(seen.cancelled, true, "the oversized stream was not cancelled");
});

test("a Content-Length that lies low does not lift the cap", async () => {
  const { stream, seen } = countingStream(100, 1024);
  const resp = new Response(stream, { headers: { "content-length": "10" } });
  assert.equal(await readCappedBody(resp, 4096), null);
  assert.ok(seen.pulls <= 6, `kept reading past the cap: ${seen.pulls} chunks`);
});

test("checkForUpdate reads the manifest and the signature only through the capped reader", () => {
  const bg = readFileSync(fileURLToPath(new URL("./background.ts", import.meta.url)), "utf-8");
  const i = bg.indexOf("async function checkForUpdate(");
  assert.ok(i > -1, "checkForUpdate moved");
  const fn = bg.slice(i, bg.indexOf("\n}\n", i));
  assert.ok(fn.includes("readCappedBody(mResp, UPDATE_MANIFEST_MAX_BYTES)"), "the manifest is not read through the cap");
  assert.ok(fn.includes("readCappedBody(sResp, UPDATE_SIG_MAX_BYTES)"), "the signature is not read through the cap");
  assert.doesNotMatch(fn, /\b[ms]Resp\.(arrayBuffer|text|json|blob)\(/, "an uncapped whole-body read is back");
});
