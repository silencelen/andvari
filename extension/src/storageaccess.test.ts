// node --test. Security review 2026-10, branch A15 (step 1): restrict the storage areas at worker start.
//
// Chrome 140+ lets an extension restrict storage.local to its own pages and worker
// (`setAccessLevel({accessLevel:"TRUSTED_CONTEXTS"})`, enforced in the browser process, onChanged included); Chrome
// 127–139 accept it only for storage.session; Firefox has no setAccessLevel at all. The quick-unlock compartment's
// "trusted" verdict used to be set before the session call even settled (`void …; trusted = true`). Both calls are
// now awaited, and the verdict says only what the code actually saw.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { restrictStorageAccess } from "./storageaccess.ts";

type Call = { area: string; arg: unknown };
function areaWith(name: string, calls: Call[], behaviour: "resolve" | "reject" | "throw" | "absent" | "slow", slow?: { release?: () => void }) {
  const a: Record<string, unknown> = { get: async () => ({}) };
  if (behaviour === "absent") return a;
  a.setAccessLevel = (arg: unknown) => {
    calls.push({ area: name, arg });
    if (behaviour === "throw") throw new TypeError("not supported");
    if (behaviour === "reject") return Promise.reject(new Error("This StorageArea is not available for setting access level"));
    if (behaviour === "slow") return new Promise<void>((res) => (slow!.release = res));
    return Promise.resolve();
  };
  return a;
}

test("Chrome 140+: both areas restricted to TRUSTED_CONTEXTS, and the verdict waits for both calls", async () => {
  const calls: Call[] = [];
  const s = {} as { release?: () => void };
  const l = {} as { release?: () => void };
  let settled = false;
  const p = restrictStorageAccess({ session: areaWith("session", calls, "slow", s), local: areaWith("local", calls, "slow", l) }).then((r) => {
    settled = true;
    return r;
  });
  await new Promise((r) => setTimeout(r, 5));
  assert.equal(settled, false, "nothing is decided before the session call resolves");
  s.release!();
  await new Promise((r) => setTimeout(r, 5));
  assert.equal(settled, false, "…nor before the local call resolves");
  l.release!();
  assert.deepEqual(await p, { sessionTrusted: true, localRestricted: true });
  assert.deepEqual(calls, [
    { area: "session", arg: { accessLevel: "TRUSTED_CONTEXTS" } },
    { area: "local", arg: { accessLevel: "TRUSTED_CONTEXTS" } },
  ]);
});

test("Chrome 127–139: local refuses (or lacks) setAccessLevel — no throw, local reported open, session still trusted", async () => {
  for (const local of ["reject", "throw", "absent"] as const) {
    const r = await restrictStorageAccess({ session: areaWith("session", [], "resolve"), local: areaWith("local", [], local) });
    assert.deepEqual(r, { sessionTrusted: true, localRestricted: false }, local);
  }
});

test("Firefox: no setAccessLevel anywhere — session is trusted only because it exists (Firefox keeps it from content)", async () => {
  assert.deepEqual(await restrictStorageAccess({ session: areaWith("session", [], "absent"), local: areaWith("local", [], "absent") }), {
    sessionTrusted: true,
    localRestricted: false,
  });
  // No storage.session at all: nothing to trust — quick unlock never arms.
  assert.deepEqual(await restrictStorageAccess({ local: areaWith("local", [], "absent") }), { sessionTrusted: false, localRestricted: false });
  assert.deepEqual(await restrictStorageAccess(undefined), { sessionTrusted: false, localRestricted: false });
});

test("a session setAccessLevel that exists but fails leaves the compartment UNTRUSTED (fail closed)", async () => {
  for (const b of ["reject", "throw"] as const) {
    const r = await restrictStorageAccess({ session: areaWith("session", [], b), local: areaWith("local", [], "resolve") });
    assert.deepEqual(r, { sessionTrusted: false, localRestricted: true }, b);
  }
});
