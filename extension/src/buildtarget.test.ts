import assert from "node:assert/strict";
import { test } from "node:test";
import { BUILD_TARGET, selfUpdateChannelAllowed } from "./buildtarget.ts";

test("unbundled source defaults to the chrome target", () => {
  assert.equal(BUILD_TARGET, "chrome");
});

test("only the App Store-distributed Safari build drops the self-update channel", () => {
  assert.equal(selfUpdateChannelAllowed("chrome"), true);
  assert.equal(selfUpdateChannelAllowed("firefox"), true);
  assert.equal(selfUpdateChannelAllowed("safari"), false);
});
