// node --test. The round-7 H1 test pages (extension/test-pages/) each put a payment provider's frame on the page with
// a skimmer's fields hidden by another trick: an invisible overlay, blending, and covers the hit test cannot see. The
// structural defence refuses all three whatever the styling, because each frame's src is a provider's. This pins that
// the pages say what they test, so a device check exercises the right thing.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { paymentProviderHost } from "./paymentproviders.ts";

const page = (name: string): string => readFileSync(new URL(`../test-pages/${name}`, import.meta.url), "utf-8");
const frames = (html: string): string[] => [...html.matchAll(/<iframe[^>]*\ssrc="([^"]+)"/g)].map((m) => m[1]!);

test("each attack page embeds a provider's frame that the structural check recognises", () => {
  for (const [name, host] of [
    ["card-overlay.html", "js.stripe.com"],
    ["card-blend.html", "assets.braintreegateway.com"],
    ["card-shadow-cover.html", "checkoutshopper-live.adyen.com"],
  ] as const) {
    const hosts = frames(page(name)).map(paymentProviderHost);
    assert.ok(hosts.includes(host), `${name}: ${host}`);
  }
});

test("each page carries the trick it is named for", () => {
  const overlay = page("card-overlay.html");
  assert.match(overlay, /color: transparent; caret-color: transparent; border: 0;\s*background: transparent linear-gradient\(transparent, transparent\);/);
  assert.match(page("card-blend.html"), /mix-blend-mode: lighten;/);
  // The first-party variant has no provider frame: its defence is the choice and the fill rules ("blended").
  const firstParty = page("card-blend-first-party.html");
  assert.deepEqual(frames(firstParty), []);
  assert.match(firstParty, /\.blended \{ mix-blend-mode: lighten;/);
  const shadow = page("card-shadow-cover.html");
  assert.match(shadow, /pointer-events: none; box-shadow: 0 0 0 400px #fff;/);
  assert.match(shadow, /\.veil::after \{ content: ""; position: absolute;/);
});
