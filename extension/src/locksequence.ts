/**
 * Chrome-free quick-unlock SW control-flow seams for background.ts, extracted so `node --test` drives
 * the REAL logic (the repo's leaf-module discipline). Two order-sensitive invariants live here:
 *   - the cold-SW arm gate (design fix D3): hydrate the token pair BEFORE the arm decision reads it;
 *   - the redeem in-flight guard: the "redeem in progress" flag must clear on EVERY redeem exit.
 *
 * D3 (pre-existing cold-SW quick-unlock wipe): an idle-autolock alarm can fire into a COLD service
 * worker — one whose in-memory `session`/`api` tokens have NOT been hydrated from storage.session
 * yet. If doLock reads `api.getTokens()` for the arm decision before `ensureLoaded()` restores that
 * pair, it sees {access:null} and takes the WIPE branch — erasing the user's enrolled quick-unlock
 * instead of arming it. The fix is `await ensureLoaded()` BEFORE this gate reads the tokens; `armGate`
 * below bakes that ordering into the leaf, so a regression that samples before hydration (or hands in
 * a non-hydrating load) is caught by locksequence.test.ts, not shipped silently.
 */

/**
 * Should doLock ATTEMPT to arm quick-unlock (stash the live token pair + keep the slim blob record),
 * versus fall through to a full wipe? Mirrors doLock's inline gate exactly:
 *   - `signout` (explicit sign-out / revocation) NEVER arms — it is wipe-class in every path.
 *   - no live access token (locked already, OR a cold SW that hasn't hydrated) NEVER arms.
 *   - an untrusted storage.session compartment NEVER arms (the armed record is a crackable UVK blob +
 *     a live refresh token; content scripts must not be able to read it — breaker A9⊕B5).
 * A `true` result only means "attempt": QuickUnlock.arm() still fails closed to "declined" (→ wipe)
 * on a stale/exhausted/blob-less record.
 */
export function shouldAttemptArm(isSignout: boolean, hasAccessToken: boolean, compartmentTrusted: boolean): boolean {
  return !isSignout && hasAccessToken && compartmentTrusted;
}

/** Injected dependencies of the cold-SW arm gate — background wires ensureLoaded + api.getTokens(). */
export interface ArmGateDeps {
  /** Restore the persisted session/token pair (background: ensureLoaded). MUST complete before the
   *  arm decision samples tokens, or a cold SW reads null and WIPES the enrolled quick-unlock. */
  hydrate(): Promise<void>;
  /** Sample the api's live token pair — evaluated AFTER hydrate (background: () => api.getTokens()). */
  readTokens(): { access: string | null; refresh: string | null };
  isSignout: boolean;
  compartmentTrusted: boolean;
}

/**
 * doLock's cold-SW-safe arm gate (fix D3), as a leaf background.doLock delegates to. AWAITS `hydrate`
 * (ensureLoaded — restores the persisted token pair) BEFORE sampling `readTokens`, then decides via
 * shouldAttemptArm. Returns the sampled tokens (the arm stash needs them) + whether to attempt arming.
 * Because the hydrate-before-read ORDER lives here, reverting doLock's hydrate to a non-hydrating load
 * (e.g. `serverReady`, which loads the origin but not the tokens) reproduces the D3 wipe — and the
 * regression test in locksequence.test.ts fails.
 */
export async function armGate(deps: ArmGateDeps): Promise<{ tokens: { access: string | null; refresh: string | null }; attempt: boolean }> {
  await deps.hydrate();
  const tokens = deps.readTokens();
  return { tokens, attempt: shouldAttemptArm(deps.isSignout, !!tokens.access, deps.compartmentTrusted) };
}

/**
 * Run [body] with the quick-unlock "redeem in-flight" flag set, GUARANTEEING it clears on EVERY exit —
 * a normal return, an owns()/redeemGen abort return, or a throw. background.doUnlockWithPin runs its
 * forced-refresh → sync → rebuild server dance inside this: while the flag is set, api token mutations
 * route to the QKEY locked-token stash (persistTokens); a mid-redeem switch/lock that bumps redeemGen
 * and aborts the dance can therefore never STRAND the flag true — which would later misroute a full
 * unlock's initial setTokens into that stash. `setFlag` receives true on entry, false in the finally.
 * `return await body()` (not `return body()`) so the finally runs only after the body settles.
 */
export async function withRedeemInFlight<T>(setFlag: (v: boolean) => void, body: () => Promise<T>): Promise<T> {
  setFlag(true);
  try {
    return await body();
  } finally {
    setFlag(false);
  }
}
