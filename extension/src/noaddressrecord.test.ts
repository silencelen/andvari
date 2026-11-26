// "Forget the earlier account on this device" (decided on 2026-11-17) belongs where a client refuses because an address is
// known on it under another account or key. Until 19 November the extension kept no record of either, and this file
// pinned that absence. It now keeps both (accountmemory.ts, the web app's two records ported: no build path from
// extension/ to web/src exists), and this file pins where they are read and written, and what the other record kept under
// an address still is: the device's own (its secret and the server's row id; no account id, no key).
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { decodeDeviceRecord, deviceKey, LAST_EMAIL_KEY, newDeviceRecord } from "./device.ts";

const here = (f: string) => fileURLToPath(new URL(f, import.meta.url));
const bg = readFileSync(here("./background.ts"), "utf-8");

test("the two records are read before anything of a password sign-in is synced, and written once it is taken", () => {
  const hydrate = bg.slice(bg.indexOf("async function hydrateSession("), bg.indexOf("/** Where a password sign-in started"));
  const verify = hydrate.indexOf("verifyServerIdentity(identity.publicKey, s.accountKeys.identityPub);");
  const check = hydrate.indexOf("await checkKnownAccount(email, s.userId, identity.publicKey);");
  const sync = hydrate.indexOf("const sync = await api.sync(0);");
  const write = hydrate.indexOf("const records = recordsFor(email, s.userId, toB64(identity.publicKey));");
  const device = hydrate.indexOf("if (device.current()) await rememberDevice(device.dev, s.deviceId);");
  assert.ok(device > check && sync > device, "the device's record: after both checks on the device, before the first request");
  assert.ok(verify > -1 && check > verify && sync > check, "checked after the seed's own key, before the sync");
  assert.ok(write > hydrate.indexOf("const installed = session;"), "written only once the session is installed");
  assert.match(hydrate, /await trusted\.setWhereAbsent\(/, "and only where none is kept");
  // Read in one function, by the current server's namespace: the password sign-in and the quick unlock call it.
  assert.equal(bg.match(/checkKnownAccount\(/g)?.length, 3);
  assert.match(bg, /const names = \[nsk\(keyRecordName\(userId\)\), \.\.\.\(email === null \? \[\] : \[nsk\(addressRecordName\(email\)\)\]\)\];/);
  const redeem = bg.slice(bg.indexOf("async function finishRedeem("), bg.indexOf("async function disableQuickUnlock("));
  const seedCheck = redeem.indexOf("verifyServerIdentity(identity.publicKey, keys.identityPub);");
  const keyCheck = redeem.indexOf("await checkKnownAccount(null, begin.userId, identity.publicKey);");
  assert.ok(seedCheck > -1 && keyCheck > seedCheck && redeem.indexOf("const sync = await api.sync(0);") > keyCheck, "the quick unlock: after the seed's check, before the sync");
});

test("the record kept under an address by the device is still the device's own: a secret and a row id, no account id and no key", () => {
  assert.equal(deviceKey("alice@example.com"), "device:alice@example.com");
  const rec = newDeviceRecord();
  assert.deepEqual(Object.keys(rec).sort(), ["deviceId", "deviceSecret"]);
  const read = decodeDeviceRecord({ ...rec, userId: "11111111-1111-4111-8111-111111111111", identityPub: "x" });
  assert.deepEqual(read, { deviceSecret: rec.deviceSecret, deviceId: null });
  assert.equal(LAST_EMAIL_KEY, "lastEmail");
});

test("the identity fault: the served key against the seed's, the genesis against the session, and the served account's key record", () => {
  assert.equal(bg.match(/throw new IdentityMismatchError\(\)/g)?.length, 1);
  const verify = bg.slice(bg.indexOf("function verifyServerIdentity("), bg.indexOf("async function checkKnownAccount("));
  assert.match(verify, /throw new IdentityMismatchError\(\)/);
  assert.doesNotMatch(verify.slice(0, verify.lastIndexOf("/**")), /trusted|storage|nsk\(/); // compares two values it was handed, reads nothing kept
  assert.match(bg, /throw verdict\.code === "identity_mismatch" \? new IdentityMismatchError\(\) : new RemadeAccountError\(bound \?\? ""\);/);
  assert.match(bg, /verifyGenesis\(frame, \{ own: ownKeysFromSeed\(seed\), sessionUserId: userId, pinnedInstanceId: instanceId, servedPersonalVaultId: served\?\.vaultId \?\? null \}\)/);
  assert.match(bg, /if \(e instanceof RemadeAccountError\) return "remade_account";/);
});
