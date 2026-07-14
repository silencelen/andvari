import type { ReactNode } from "react";

/**
 * UI-audit #24 (docs/design/2026-07-12-frontend-ui-audit.md): multi-second work — the
 * Argon2id unlock/password change, syncs, downloads — showed literally nothing moving,
 * indistinguishable from a hang. This is the one shared busy affordance: a small turning
 * dial beside the caller's existing busy label, styled by `.busy` in styles.css.
 *
 * The dial is decorative (aria-hidden): the LABEL carries the meaning — callers already
 * swap in busy text ("Unsealing…", "Working…"), and async announcements stay on the
 * persistent Announcer idiom (BL-1), never on this conditionally-mounted node. Under
 * `prefers-reduced-motion: reduce` the dial freezes into a static ring (styles.css), so
 * the busy state stays visible without motion.
 *
 * Usage: `{busy ? <Busy>Re-forging…</Busy> : "Change password"}`.
 */
export function Busy({ children }: { children?: ReactNode }) {
  return (
    <span className="busy">
      <span className="dial" aria-hidden="true" />
      {children}
    </span>
  );
}
