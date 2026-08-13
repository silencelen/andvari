import type { ReactNode } from "react";

/** F80: the one top-of-view header shape — serif title, optional right-aligned
 *  actions — so views stop hand-rolling their own margins around .view-title.
 *
 *  Audit F11: the title is the view's `<h1>`, not an `<h2>`. Vault's switch mounts exactly one
 *  view, so exactly one of these is on screen at a time, and heading navigation now starts at
 *  level 1 with the name of the place instead of at level 2 with nothing above it. Purely a tag
 *  change — .view-title owns the font/size/margin, so nothing moves. In-view section titles stay
 *  at `<h2>`. (The two branches with no ViewHeader — the vault list and Trash — carry a
 *  visually-hidden `<h1>` in Vault's <main>.) */
export function ViewHeader({ title, actions }: { title: string; actions?: ReactNode }) {
  return (
    <div className="view-head">
      <h1 className="view-title">{title}</h1>
      {actions && (
        <>
          <div className="spacer" />
          {actions}
        </>
      )}
    </div>
  );
}
