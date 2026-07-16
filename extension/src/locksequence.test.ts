// Quick-unlock SW control-flow seam tests (node --test). These drive the REAL leaf functions
// background.ts delegates to — not hand-rolled mirrors:
//   - shouldAttemptArm / armGate: the cold-SW arm gate (fix D3) — hydrate BEFORE reading tokens, or a
//     cold idle-autolock wipes the enrolled quick-unlock. background.doLock's SOLE arm gate is armGate,
//     so reverting its hydrate to a non-hydrating load (the pre-fix `await serverReady`) fails the
//     regression pin below.
//   - withRedeemInFlight: the redeem in-flight flag lifecycle — background.doUnlockWithPin runs its
//     server dance inside it, so a mid-redeem abort (redeemGen bump / switch) can never STRAND the flag.
// Seam approach (not a full background.test.ts harness) because background.ts is not node-importable —
// extensionless imports + top-level chrome side effects; see serverswitch.test.ts header for the detail.
// Residual for armGate: that background.doLock passes hydrate=ensureLoaded (the token-hydrating load) and
// not the pre-fix non-hydrating serverReady is a one-line wiring choice not itself node-driven — but the
// "non-hydrating load → wipe" regression pin below reproduces exactly that revert's failure mode.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { armGate, shouldAttemptArm, withRedeemInFlight } from "./locksequence.ts";

test("shouldAttemptArm — the exact gate armGate/doLock applies", () => {
  assert.equal(shouldAttemptArm(false, true, true), true); //   idle/manual + live token + trusted → arm
  assert.equal(shouldAttemptArm(true, true, true), false); //   signout is wipe-class in every path
  assert.equal(shouldAttemptArm(false, false, true), false); // no live token (locked / cold, unhydrated)
  assert.equal(shouldAttemptArm(false, true, false), false); // untrusted storage.session compartment
});

// A COLD service worker: `api` holds no tokens until `hydrate` (ensureLoaded) restores the persisted
// pair. This is doLock's reality when an idle-autolock alarm wakes a dead worker — armGate is what
// background.doLock calls with hydrate=ensureLoaded, readTokens=() => api.getTokens().
function coldSw(): { readTokens: () => { access: string | null; refresh: string | null }; hydrate: () => Promise<void>; noHydrate: () => Promise<void> } {
  const snapshot = { access: "at-real", refresh: "rt-real" };
  let apiTokens: { access: string | null; refresh: string | null } = { access: null, refresh: null };
  return {
    readTokens: () => apiTokens,
    hydrate: async () => {
      apiTokens = { ...snapshot };
    },
    noHydrate: async () => {}, // the pre-fix `await serverReady`: loads the ORIGIN, not the tokens
  };
}

test("D3 — armGate AWAITS hydrate before sampling tokens → a cold-SW idle lock ARMS (not wipes)", async () => {
  const sw = coldSw();
  const g = await armGate({ hydrate: sw.hydrate, readTokens: sw.readTokens, isSignout: false, compartmentTrusted: true });
  assert.equal(g.attempt, true, "tokens hydrated before the gate read them → arm");
  assert.deepEqual(g.tokens, { access: "at-real", refresh: "rt-real" }, "returns the hydrated pair for the arm stash");
});

test("D3 — regression pin: a NON-hydrating load (reverting ensureLoaded → serverReady) makes armGate WIPE", async () => {
  const sw = coldSw();
  // If doLock handed armGate a load that does NOT restore the token pair, the gate samples api's still
  // -null tokens and takes the wipe branch — the exact cold-SW quick-unlock wipe fix D3 prevents.
  const g = await armGate({ hydrate: sw.noHydrate, readTokens: sw.readTokens, isSignout: false, compartmentTrusted: true });
  assert.equal(g.attempt, false, "reading null tokens (hydrate didn't restore them) → wipe branch");
});

test("armGate — the ordering is real: readTokens is sampled strictly AFTER hydrate resolves", async () => {
  const order: string[] = [];
  let hydrated = false;
  await armGate({
    hydrate: async () => {
      await Promise.resolve(); // a real hydrate has at least one await (storage.session read)
      hydrated = true;
      order.push("hydrate");
    },
    readTokens: () => {
      order.push("read");
      assert.ok(hydrated, "readTokens must not run before hydrate resolved");
      return { access: "x", refresh: null };
    },
    isSignout: false,
    compartmentTrusted: true,
  });
  assert.deepEqual(order, ["hydrate", "read"]);
});

test("armGate — signout still never arms even with a live hydrated token (wipe-class)", async () => {
  const sw = coldSw();
  const g = await armGate({ hydrate: sw.hydrate, readTokens: sw.readTokens, isSignout: true, compartmentTrusted: true });
  assert.equal(g.attempt, false, "signout is wipe-class in every path");
});

// ---- withRedeemInFlight (FIX 2): the redeem in-flight flag ALWAYS clears on exit ----

test("withRedeemInFlight — sets true for the body's duration, clears false on a NORMAL return", async () => {
  let flag = false;
  const seen: boolean[] = [];
  let insideFlag: boolean | null = null;
  const r = await withRedeemInFlight(
    (v) => {
      flag = v;
      seen.push(v);
    },
    async () => {
      insideFlag = flag;
      return "ok";
    },
  );
  assert.equal(r, "ok");
  assert.equal(insideFlag, true, "the body runs with the flag set (token mutations route to the stash)");
  assert.equal(flag, false, "cleared after the body resolved");
  assert.deepEqual(seen, [true, false], "true on entry, false in the finally");
});

test("withRedeemInFlight — clears the flag on an ABORT return (the redeemGen-bump / switch path)", async () => {
  let flag = false;
  // Models doUnlockWithPin's owns() abort: a mid-redeem switch/lock bumped redeemGen, so the body returns
  // { aborted } early. The flag MUST clear, or a later full unlock's initial setTokens would misroute into
  // the QKEY locked-token stash (the exact FIX 2 stranding).
  const r = await withRedeemInFlight((v) => (flag = v), async () => ({ ok: false, code: "aborted" as const }));
  assert.deepEqual(r, { ok: false, code: "aborted" });
  assert.equal(flag, false, "an aborted redeem never strands the in-flight flag true");
});

test("withRedeemInFlight — clears the flag even when the body THROWS", async () => {
  let flag = false;
  await assert.rejects(
    withRedeemInFlight(
      (v) => (flag = v),
      async () => {
        throw new Error("boom");
      },
    ),
    /boom/,
  );
  assert.equal(flag, false, "the finally clears the flag on the throw path too");
});
