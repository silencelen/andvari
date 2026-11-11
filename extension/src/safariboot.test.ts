import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

const file = (f: string) => readFileSync(new URL(`../${f}`, import.meta.url), "utf8");

/** A background-page global with a storage.local that keeps what it is given, and a real event target. */
function page() {
  const kept: Record<string, unknown> = {};
  const target = new EventTarget();
  const self: Record<string, unknown> = {
    addEventListener: target.addEventListener.bind(target),
    chrome: {
      storage: {
        local: {
          set: (items: Record<string, unknown>) => { Object.assign(kept, JSON.parse(JSON.stringify(items))); return Promise.resolve(); },
          get: (keys: string[], cb: (got: Record<string, unknown>) => void) => cb(Object.fromEntries(keys.map((k) => [k, kept[k]]))),
        },
      },
    },
  };
  self.self = self;
  return { kept, target, self };
}

test("the boot script marks the load, records what the page throws, and marks the end of the load", () => {
  const { kept, target, self } = page();
  vm.runInNewContext(file("safari-boot.js"), self);
  assert.equal(typeof kept["diag.backgroundLoadedAt"], "string");
  assert.equal(kept["diag.backgroundReadyAt"], null);
  assert.deepEqual(kept["diag.backgroundErrors"], []);

  const boom = new Error("chrome.action.setBadgeTextColor is not a function");
  target.dispatchEvent(Object.assign(new Event("error"), { message: boom.message, filename: "background.js", lineno: 7, colno: 3, error: boom }));
  target.dispatchEvent(Object.assign(new Event("unhandledrejection"), { reason: new Error("later") }));
  (self.__andvariBootRecord as (l: string, e: unknown) => void)("alarms.onAlarm", new TypeError("undefined is not an object"));
  const errors = kept["diag.backgroundErrors"] as { kind: string; message: string; where: string | null; stack: string | null }[];
  assert.deepEqual(errors.map((e) => e.kind), ["error", "unhandledrejection", "guarded: alarms.onAlarm"]);
  assert.equal(errors[0]!.message, boom.message);
  assert.equal(errors[0]!.where, "background.js:7:3");
  assert.ok(errors[0]!.stack?.includes("setBadgeTextColor"));

  (self.__andvariBootReady as () => void)();
  assert.equal(typeof kept["diag.backgroundReadyAt"], "string");

  for (let i = 0; i < 10; i++) target.dispatchEvent(Object.assign(new Event("error"), { message: `echo ${i}` }));
  assert.equal((kept["diag.backgroundErrors"] as unknown[]).length, 5, "bounded");
});

test("the boot script survives a page with no storage, and the reader hands back what was recorded", async () => {
  const bare: Record<string, unknown> = { addEventListener: () => {} };
  bare.self = bare;
  vm.runInNewContext(file("safari-boot.js"), bare); // must not throw: it is the first script of the page

  const { self } = page();
  vm.runInNewContext(file("safari-boot.js"), self);
  vm.runInNewContext(file("safari-diag.js"), self);
  const got = await (self.__andvariBackgroundDiag as () => Promise<Record<string, unknown>>)();
  assert.equal(typeof got["diag.backgroundLoadedAt"], "string");
});

test("the Safari background is classic scripts with the boot script first; the other manifests are unchanged", () => {
  const safari = JSON.parse(file("manifest.safari.json")) as { background: Record<string, unknown> };
  assert.deepEqual(safari.background, { scripts: ["safari-boot.js", "background.js"], persistent: false });
  const build = file("build.mjs");
  assert.match(build, /format: target === "safari" \? "iife" : "esm"/);
  assert.match(build, /cpSync\("safari-boot\.js", "dist\/safari-boot\.js"\)/);
  assert.equal((JSON.parse(file("manifest.json")) as { background: unknown }).background && true, true);
  assert.ok(!file("manifest.json").includes("safari-boot.js") && !file("manifest.firefox.json").includes("safari-boot.js"));
});

test("every top-level listener registration in the worker stands alone", () => {
  const bg = readFileSync(new URL("./background.ts", import.meta.url), "utf8");
  const bare = bg.split("\n").filter((l) => /^(void )?chrome\.[A-Za-z.]+\.(addListener|setBadge\w+)\(/.test(l));
  assert.deepEqual(bare, [], "a registration outside atLoad ends the whole page on an engine that lacks the API");
  assert.ok(bg.trimEnd().endsWith("__andvariBootReady?.();"), "the last statement marks the end of the load");
  assert.match(bg, /type: BUILD_TARGET === "safari" \? "classic" : "module"/);
});
