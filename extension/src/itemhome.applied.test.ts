// Security review 2026-10, branch A9 (L-1): the extension records an item's home ONLY from an envelope it actually
// APPLIED (design §5.1) — never from a blob-less tombstone or a row under a vault it holds no key for, which a server
// could serve first to home the item away from its genuine row and quarantine that row on this browser for good.
// Plus (the ensureLoaded comment): a session snapshot without `homes` reloads them from storage.local, so a durable
// record is never replaced by server-ordered homes.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { admitRow, admitRows } from "./itemhome.ts";

type Row = { itemId: string; vaultId: string; deleted?: boolean; blob?: string | null };

test("an unhomed row that cannot be applied is skipped: no home, no anomaly, and the genuine row then takes the home", () => {
  assert.equal(admitRow(null, "S", false), "skip");
  assert.equal(admitRow(null, "S", true), "new_home");
  assert.equal(admitRow(null, "S"), "new_home", "applies defaults to true (the shared vector rows)");
  assert.equal(admitRow("P", "P", false), "home", "a tombstone under the home still applies");
  assert.equal(admitRow("P", "S", false), "quarantine", "another vault is quarantined whether or not it could be applied");

  const keys = new Set(["P"]);
  const applies = (r: Row) => !r.deleted && !!r.blob && keys.has(r.vaultId);
  for (const first of [
    { itemId: "X", vaultId: "S", deleted: true, blob: null },
    { itemId: "X", vaultId: "S", blob: "unopenable-here" },
  ]) {
    const homes = new Map<string, string>();
    const rows: Row[] = [first, { itemId: "X", vaultId: "P", blob: "genuine" }];
    const { admitted, tally, changed } = admitRows(rows, homes, applies);
    assert.deepEqual(admitted.map((r) => r.vaultId), ["P"], `${first.deleted ? "tombstone" : "unheld row"} first: only the genuine row applies`);
    assert.equal(homes.get("X"), "P", "the home is the vault of the row this browser applied");
    assert.equal(tally.refused, 0, "nothing was quarantined");
    assert.equal(changed, true);
  }
});

test("a later unheld or tombstone row for a homed item is still quarantined (it names another vault)", () => {
  const homes = new Map([["X", "P"]]);
  const rows: Row[] = [
    { itemId: "X", vaultId: "S", blob: "unopenable-here" },
    { itemId: "X", vaultId: "S", deleted: true, blob: null },
    { itemId: "X", vaultId: "P", deleted: true, blob: null },
  ];
  const { admitted, tally } = admitRows(rows, homes, (r) => !r.deleted && !!r.blob && r.vaultId === "P");
  assert.deepEqual(admitted, [rows[2]], "only the tombstone under the home applies");
  assert.equal(tally.refused, 2);
  assert.equal(tally.anomalies(), 1);
  assert.equal(homes.get("X"), "P");
});

test("the service worker homes only rows it applied, and reloads homes from storage.local when a snapshot lacks them", () => {
  const bg = readFileSync(fileURLToPath(new URL("./background.ts", import.meta.url)), "utf8");
  const decrypt = bg.slice(bg.indexOf("async function homeAndDecrypt("), bg.indexOf("function decryptItems("));
  assert.match(decrypt, /admitRows\(/, "rows are admitted against the homes");
  assert.match(decrypt, /vaultKeys\.(has|get)\(/, "a row under a vault this session holds no key for never homes the item");
  assert.match(decrypt, /\.deleted/, "a tombstone never homes the item");
  assert.match(decrypt, /\bopen\(/, "the envelope must OPEN before its vault becomes the home (design §5.1: the first envelope APPLIED)");
  const loaded = bg.slice(bg.indexOf("loadPromise ??="), bg.indexOf("function persistSession("));
  assert.doesNotMatch(loaded, /snap\.homes \?\? \{\}/, "a snapshot without homes is not an empty (authoritative) map");
  assert.match(loaded, /await loadHomes\(snap\.userId\)/, "it reloads the durable record from storage.local instead");
});
