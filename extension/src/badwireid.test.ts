// Security review 2026-10, branch A11 (c18, LOW): a login answer whose session ids fail the A10 grammar is refused as
// `bad_wire_id`. The extension used to fold it into "server_error" ("The server had a problem answering ... Try again in a
// moment."), softening a tampering-class refusal into a transient one, against the house rule (identity_mismatch,
// kdf_policy, keys_damaged are never "try again"). It now has its own code and terminal, admin-facing copy.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { unlockErrorCopy } from "./errors.ts";

const bg = readFileSync(fileURLToPath(new URL("./background.ts", import.meta.url)), "utf-8");

test("bad_wire_id has tampering-class copy, never 'try again'", () => {
  const t = unlockErrorCopy("bad_wire_id" as Parameters<typeof unlockErrorCopy>[0]);
  assert.equal(t, "The server sent a malformed account record, so sign-in was stopped. Tell your admin — the server may be misbehaving.");
  assert.doesNotMatch(t, /try again/i);
});

test("mapUnlockError maps the ApiError code before the server_error fold", () => {
  const a = bg.indexOf("function mapUnlockError(");
  const body = bg.slice(a, bg.indexOf("\n}\n", a));
  const at = body.indexOf('if (e.code === "bad_wire_id") return "bad_wire_id";');
  assert.ok(at > 0, "the code is mapped");
  assert.ok(at < body.indexOf('return "server_error"'), "before the generic fold");
});
