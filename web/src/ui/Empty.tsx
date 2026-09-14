import type { ReactNode } from "react";
import { EmptySigil } from "./Sigil";

/**
 * H132: the ONE empty-state affordance, the sibling of {@link Busy} for the other half of the
 * same problem — a view with nothing in it yet.
 *
 * Before this, three views hand-rolled `<div className="empty"><div className="sigil">…` and
 * three others (Trash, version history, the audit log) shipped a bare `.muted` line instead, so
 * the same "there is nothing here" read as a considered state on one screen and as a rendering
 * accident on the next. The markup is unchanged from the vault list's version — the sigil, then
 * the caller's sentence — so every `.empty` rule in styles.css and every existing HTML pin still
 * matches; what changes is that there is now exactly one place that decides what an empty state
 * looks like.
 *
 * House rules the callers must keep, because the component cannot enforce them:
 *  - ONE sentence, sentence case, with terminal punctuation — an empty state is prose, not a label;
 *  - it says what the user would see here AND (where there is one) the next move, the way
 *    "Your hoard is empty. Add your first secret." does;
 *  - controls that must survive the empty state (Staleness's "Show snoozed") are children too —
 *    unmounting them left snoozed logins unreachable for 30 days once already.
 */
export function Empty({ children }: { children?: ReactNode }) {
  return (
    <div className="empty">
      <div className="sigil"><EmptySigil /></div>
      {children}
    </div>
  );
}
