// Security review 2026-10, branch A9 review round (MEDIUM-1): a served personal wrap on a browser with NO cached wrap
// (a fresh profile, cleared storage) is a PROPOSAL, never a default. The server keeps every wrap the account ever minted
// and chooses which to serve, so a superseded wrap for a co-held vault would otherwise become the capture destination
// silently. Until the human confirms it once (the describe/accept flow, which re-opens the wrap under the UVK) there is
// no capture destination: saves and TOTP adds answer `no_personal_vault` with "Open andvari to confirm your personal
// vault." The cached-wrap path is unchanged (personalpick.test.ts).
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { adVkPersonal, fromB64, seal, toB64 } from "./crypto.ts";
import { NO_PERSONAL_VAULT_CONFIRM, saveErrorCopy, totpAddErrorCopy } from "./errors.ts";
import { personalProposalNotice } from "./grantkeys.ts";
import { pickPersonal } from "./personalpick.ts";

const vectorsDir = fileURLToPath(new URL("../../spec/test-vectors/", import.meta.url));
const v = JSON.parse(readFileSync(vectorsDir + "personalwrap.json", "utf-8"));
const w = v.wrap;
const uvk = fromB64(w.uvkB64);
const bg = readFileSync(fileURLToPath(new URL("./background.ts", import.meta.url)), "utf-8");

test("fresh profile: a served wrap that opens is a proposal (no vault id), its key installed for reading", () => {
  const keys = new Map<string, Uint8Array>();
  const p = pickPersonal({ vaultId: w.vaultId, wrappedVk: w.personalWrapB64 }, uvk, w.userId, keys);
  assert.deepEqual(p, { vaultId: "", source: "proposed", served: { vaultId: w.vaultId, wrappedVk: w.personalWrapB64 } });
  assert.equal(toB64(keys.get(w.vaultId)!), w.vkB64, "items in that vault still decrypt; nothing seals under it by default");
  // The cached path is unchanged: the same wrap, cached here before, is simply the personal wrap.
  assert.deepEqual(pickPersonal({ vaultId: w.vaultId, wrappedVk: w.personalWrapB64 }, uvk, w.userId, new Map(), { cached: { vaultId: w.vaultId, wrappedVk: w.personalWrapB64 } }), { vaultId: w.vaultId, source: "wrap" });
  // A superseded wrap for another vault, replayed to a fresh profile: a proposal too, never adopted.
  const other = "00000000-0000-4000-8000-0000000000b5";
  const otherWrap = toB64(seal(uvk, new Uint8Array(32).fill(7), adVkPersonal(other, w.userId)));
  assert.equal(pickPersonal({ vaultId: other, wrappedVk: otherWrap }, uvk, w.userId, new Map()).source, "proposed");
});

test("the worker stages a proposal as the pending change (no current vault) and caches nothing until accepted", () => {
  const pick = bg.slice(bg.indexOf("export async function pickPersonalVaultId("), bg.indexOf("interface PersonalChangeRecord"));
  assert.match(pick, /pick\.source === "changed" \|\| pick\.source === "proposed"/, "a proposal is staged like a change");
  assert.doesNotMatch(pick, /pick\.source === "wrap" \|\| pick\.source === "proposed"/, "a proposal never writes the wrap cache");
  const accept = bg.slice(bg.indexOf("async function acceptPersonalChange("), bg.indexOf("\n}\n", bg.indexOf("async function acceptPersonalChange(")));
  assert.match(accept, /reopenStagedPersonalWrap\(/, "accepting re-opens the wrap under the UVK");
  assert.match(accept, /session\.personalVaultId = served\.vaultId/, "and only then is there a capture destination");
});

test("captures and TOTP adds without a personal vault answer no_personal_vault, never seal under a guessed vault", () => {
  for (const fn of ["async function putNewLogin(", "async function putNewCard(", "async function setTotp(", "async function resolvePendingSaveInner(", "async function resolveCardSave("]) {
    const a = bg.indexOf(fn);
    if (a < 0) continue; // a name that moved is caught by the count below
    const body = bg.slice(a, bg.indexOf("\n}\n", a));
    assert.match(body, /code: "no_personal_vault"/, `${fn} refuses with the dedicated code`);
    assert.doesNotMatch(body, /!session \|\| !session\.personalVaultId\) return \{ ok: false, code: "locked"/, `${fn} no longer calls a missing personal vault "locked"`);
  }
  assert.ok((bg.match(/code: "no_personal_vault"/g) ?? []).length >= 5, "every capture/TOTP gate carries the code");
  assert.equal(saveErrorCopy("no_personal_vault"), NO_PERSONAL_VAULT_CONFIRM);
  assert.equal(totpAddErrorCopy("no_personal_vault"), NO_PERSONAL_VAULT_CONFIRM);
  assert.equal(NO_PERSONAL_VAULT_CONFIRM, "Open andvari to confirm your personal vault.");
});

test("the popup names the proposal and points at confirming it", () => {
  const t = personalProposalNotice("Home");
  assert.ok(t.includes("“Home”") && t.includes("Open andvari to confirm your personal vault"), t);
  const none = personalProposalNotice(null);
  assert.ok(none.includes("Open andvari to confirm your personal vault"), none);
  const text = bg.slice(bg.indexOf("async function personalChangeText("), bg.indexOf("\n}\n", bg.indexOf("async function personalChangeText(")));
  assert.match(text, /personalProposalNotice\(/, "a staged change with no current vault renders as the proposal");
});
