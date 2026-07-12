/** Save-vs-update target selection for a captured credential — the CAPTURE-time decision, kept as a
 *  pure, dependency-free function so it is node-testable (background.ts is chrome-bound). The resolve
 *  path (resolvePendingSave) applies a STRICTER rule and deliberately does NOT reuse the 2b fallback
 *  (a locked-at-capture password-only submit must never silently update a lone host login → clobber).
 *
 *  `matches` is the already-host-filtered login set (matchesFor). With a username, an exact
 *  (host ∧ username) match is the target. A password-only submit (username === "") has no username
 *  to key on, so:
 *   - 2a: a host login whose password EQUALS the submitted one is the SAME login being re-entered —
 *         its unchanged-password path suppresses the banner (never a duplicate);
 *   - 2b: else a LONE host login is the update target (a password change, shown for user consent);
 *   - 2c: an ambiguous multi-login host with no password match stays a NEW item — never silently
 *         overwrite the wrong account (a duplicate is recoverable; a clobbered password is not).
 *  Fixes the dup-registration bug: a password-only re-login no longer mints a password-only twin. */
export interface LoginLike {
  doc: { login?: { username?: string | null; password?: string | null } | null };
}

export function saveTargetFor<T extends LoginLike>(matches: readonly T[], username: string, password: string): T | undefined {
  if (username !== "") return matches.find((i) => (i.doc.login?.username ?? "") === username);
  const byPassword = matches.find((i) => (i.doc.login?.password ?? "") === password);
  if (byPassword) return byPassword;
  return matches.length === 1 ? matches[0] : undefined;
}

export type ResolveAction<T> =
  | { kind: "update"; target: T }
  | { kind: "suppress" }
  | { kind: "create" };

/** The RESOLVE-time (post-unlock) save decision — STRICTER than saveTargetFor: it only auto-updates
 *  on UNAMBIGUOUS same-account signals, never the ambiguous "lone host login" (2b) fallback (a
 *  locked-at-capture password-only submit for a DIFFERENT account only ever showed a "Save new"
 *  banner, so silently updating the host's single login would clobber the wrong account). Rules,
 *  in order:
 *   1. `frozen` (the pending.updatesItemId item the user saw an Update banner for; undefined if it
 *      vanished or was never set) → update it;
 *   2. a NON-empty username with an exact (host∧username) match → update that account; a non-empty
 *      username with NO match → CREATE a new account — even if its password is reused from another
 *      host login (never suppress-on-shared-password: that would silently drop a real new account);
 *   3. a password-only submit whose password already belongs to a host login → a 2a re-login →
 *      SUPPRESS (nothing to save);
 *   4. otherwise → CREATE (a recoverable new item). Pure over the passed items → unit-pinned. */
export function resolveSaveAction<T extends LoginLike>(
  frozen: T | undefined,
  hostMatches: readonly T[],
  username: string,
  password: string,
): ResolveAction<T> {
  if (frozen) return { kind: "update", target: frozen };
  if (username !== "") {
    const byUser = hostMatches.find((i) => (i.doc.login?.username ?? "") === username);
    return byUser ? { kind: "update", target: byUser } : { kind: "create" };
  }
  if (hostMatches.some((i) => (i.doc.login?.password ?? "") === password)) return { kind: "suppress" };
  return { kind: "create" };
}
