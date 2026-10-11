// Security review 2026-10, root cause A, branch A6 fix round (A5b review LOW-1 parity, LOW-2): "Use the new
// personal vault" is offered — and accepted by the service worker — only after the co-holders of the NEW vault
// were loaded for that exact vaultId in this session. A failed lookup offers nothing but "keep current", which
// comes FIRST. Co-holders are labelled as reported by the server (they inform, they decide nothing).
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { acceptGate, coHoldersLine, coHoldersOf, personalChangeNotice } from "./grantkeys.ts";

const me = "22222222-2222-4222-8222-222222222222";
const V = "aaaaaaaa-aaaa-4aaa-8aaa-000000000001";
const W = "aaaaaaaa-aaaa-4aaa-8aaa-000000000002";

test("gate: refused until a describe for THAT served vault succeeded", () => {
  assert.equal(acceptGate(null, V, me), "coholders_not_loaded");
  assert.equal(acceptGate({ vaultId: W, userId: me }, V, me), "coholders_not_loaded", "another vault's lookup does not count");
  assert.equal(acceptGate({ vaultId: V, userId: "someone-else" }, V, me), "coholders_not_loaded", "another account's lookup does not count");
  assert.equal(acceptGate({ vaultId: V, userId: me }, V, me), null);
});

test("co-holders exclude this account and are labelled as reported by the server", () => {
  const list = coHoldersOf(
    [
      { userId: me, displayName: "Me", email: "me@x", role: "owner" },
      { userId: "u2", displayName: "Mate", email: "mate@x", role: "writer" },
    ],
    me,
  );
  assert.deepEqual(list, [{ displayName: "Mate", email: "mate@x", role: "writer" }]);
  const line = coHoldersLine(list);
  assert.ok(line.includes("as reported by the server") && line.includes("Mate"), line);
  const none = coHoldersLine([]);
  assert.ok(none.includes("as reported by the server") && /no one else/i.test(none), none);
});

test("the notice puts keeping the current vault FIRST", () => {
  const t = personalChangeNotice("Home", "Family");
  const keep = t.indexOf("To keep “Home”");
  const changed = t.indexOf("“Family”");
  assert.ok(keep > -1 && changed > -1 && keep < changed, t);
});

test("fence: background gates acceptPersonalChange on the describe step and loads members through api.ts", () => {
  const bg = readFileSync(new URL("./background.ts", import.meta.url), "utf-8");
  const a = bg.indexOf("async function acceptPersonalChange(");
  const body = bg.slice(a, bg.indexOf("\n}\n", a));
  const gate = body.indexOf("acceptGate(");
  const reopen = body.indexOf("reopenStagedPersonalWrap(");
  assert.ok(gate > -1 && reopen > gate, "the co-holder gate runs before anything is re-opened or installed");
  const d = bg.indexOf("async function describePersonalChange(");
  assert.ok(d > -1);
  const dbody = bg.slice(d, bg.indexOf("\n}\n", d));
  assert.ok(dbody.includes("api.vaultMembers("), "co-holders come from GET /vaults/{id}/members");
  const api = readFileSync(new URL("./api.ts", import.meta.url), "utf-8");
  assert.ok(api.includes("/api/v1/vaults/${encodeURIComponent(vaultId)}/members"));
});

test("popup: keep-current guidance precedes Use new; Use new is hidden unless the describe succeeded", () => {
  const html = readFileSync(new URL("../popup.html", import.meta.url), "utf-8");
  const keep = html.indexOf('id="personal-change-text"');
  const use = html.indexOf('id="personal-change-accept"');
  assert.ok(keep > -1 && use > keep);
  assert.match(html, /id="personal-change-accept"[^>]*hidden/, "Use new starts hidden");
  const popup = readFileSync(new URL("./popup.ts", import.meta.url), "utf-8");
  assert.ok(popup.includes('type: "personalDescribeChange"'));
  assert.match(popup, /el\("personal-change-accept"\)\.hidden = !\(?d\?\.ok/);
});
