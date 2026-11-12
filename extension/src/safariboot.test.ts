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

// The popup on iPhone sat against the left edge with an empty band on the right: the desktop popup's fixed 360 px
// column inside a sheet as wide as the screen.
test("the Safari popup fills the sheet: no fixed pixel width on its root, centred when the sheet is wider, and only in that build", () => {
  const css = file("popup.safari.css").replace(/\/\*[\s\S]*?\*\//g, "");
  const rule = (selector: string): string => new RegExp(`(?:^|})\\s*${selector}\\s*\\{([^}]*)\\}`).exec(css)?.[1] ?? "";
  for (const selector of ["html", "body"]) {
    const body = rule(selector);
    assert.match(body, /(?:^|;)\s*width:\s*100%/, `${selector} is as wide as the sheet`);
    assert.ok(!/(?:^|;|\s)(?:min-|max-)?width:\s*\d+(?:\.\d+)?px/.test(body), `${selector} has no pixel width`);
    assert.match(body, /overflow-x:\s*hidden/, `${selector} cannot scroll sideways`);
  }
  const body = rule("body");
  assert.match(body, /margin-left:\s*auto/);
  assert.match(body, /margin-right:\s*auto/);
  assert.match(body, /padding-left:\s*env\(safe-area-inset-left/);
  assert.match(body, /padding-right:\s*env\(safe-area-inset-right/);
  // Full height: a flex column as tall as the sheet at every detent, the open view growing and scrolling inside
  // itself (no 400 px cap), and the bottom bar pinned to the bottom.
  const rules = [...css.matchAll(/([^{}]+)\{([^}]*)\}/g)].map((m) => ({ selector: m[1]!.replace(/\s+/g, " ").trim(), body: m[2]! }));
  const all = (selector: string): string => rules.filter((r) => r.selector.split(",").map((x) => x.trim()).includes(selector)).map((r) => r.body).join(";");
  assert.match(all("body"), /display:\s*flex/);
  assert.match(all("body"), /flex-direction:\s*column/);
  assert.match(all("body"), /height:\s*100dvh/);
  assert.match(all("body"), /height:\s*-webkit-fill-available/);
  assert.match(all("body"), /overflow:\s*hidden/, "the page itself does not scroll");
  assert.match(all("body"), /padding-bottom:\s*env\(safe-area-inset-bottom/);
  assert.match(all("body > .unlocked:not([hidden])"), /flex:\s*1 1 auto/);
  assert.match(all("body > .unlocked:not([hidden])"), /max-height:\s*none/, "the desktop popup's 400 px cap is lifted");
  assert.match(all("body > .pop-foot"), /margin-top:\s*auto/);
  // The markup this relies on: the open view, the footer and the header are direct children of body, and the list
  // scrolls inside the open view.
  const html = file("popup.html");
  assert.match(html, /\n    <section id="unlocked" class="unlocked" hidden>/);
  assert.match(html, /\n    <footer class="pop-foot">/);
  assert.match(file("popup.css"), /\.vault-scroll \{ flex: 1 1 auto; overflow-y: auto; min-height: 0; \}/);
  // Linked after popup.css so it wins, with a viewport, and only when the target is Safari.
  const build = file("build.mjs");
  assert.match(build, /if \(target === "safari"\) \{[\s\S]*?width=device-width, initial-scale=1, viewport-fit=cover[\s\S]*?popup\.safari\.css[\s\S]*?\} else \{\s*cpSync\("popup\.html", "dist\/popup\.html"\);/);
  assert.ok(!file("popup.html").includes("popup.safari.css"), "the desktop popup's page is untouched");
  assert.match(file("popup.css"), /html \{ width: 360px; \}/, "the desktop popup keeps its fixed column");
});
