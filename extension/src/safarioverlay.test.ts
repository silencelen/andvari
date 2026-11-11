import assert from "node:assert/strict";
import { test } from "node:test";
import * as esbuild from "esbuild";
import { loginFillOverlayAllowed } from "./buildtarget.ts";

/** The content bundle as build.mjs makes it for [target] (release settings), in memory. */
async function contentBundle(target: "chrome" | "firefox" | "safari"): Promise<string> {
  const out = await esbuild.build({
    entryPoints: [new URL("./content.ts", import.meta.url).pathname],
    bundle: true,
    format: target === "safari" ? "iife" : "esm",
    target: "es2022",
    minify: true,
    write: false,
    logLevel: "silent",
    define: { __ANDVARI_TARGET__: JSON.stringify(target) },
  });
  return out.outputFiles[0]!.text;
}

// What only the in-page login menu contains: its rows, and the message that asks the worker for a site's logins.
const MENU_MARKS = ["Search all logins", "Use a strong password", 'type:"matches"'];
// What the save capture needs, on every target.
const CAPTURE_MARKS = ['type:"capturedCredential"', 'type:"pendingSave"'];

test("the rule: only the Safari build has no in-page login menu", () => {
  assert.equal(loginFillOverlayAllowed("safari"), false);
  assert.equal(loginFillOverlayAllowed("chrome"), true);
  assert.equal(loginFillOverlayAllowed("firefox"), true);
});

test("the Safari content bundle has no login fill menu at all, and still captures saves", async () => {
  const safari = await contentBundle("safari");
  for (const mark of MENU_MARKS) assert.ok(!safari.includes(mark), `the Safari bundle still carries the menu: ${mark}`);
  for (const mark of CAPTURE_MARKS) assert.ok(safari.includes(mark), `the Safari bundle lost save capture: ${mark}`);
});

test("the Chrome and Firefox content bundles still have the menu and the capture", async () => {
  for (const target of ["chrome", "firefox"] as const) {
    const bundle = await contentBundle(target);
    for (const mark of [...MENU_MARKS, ...CAPTURE_MARKS]) assert.ok(bundle.includes(mark), `${target}: ${mark}`);
  }
});
