import type { ReactNode } from "react";

/** F80: the one top-of-view header shape — serif title, optional right-aligned
 *  actions — so views stop hand-rolling their own margins around .view-title. */
export function ViewHeader({ title, actions }: { title: string; actions?: ReactNode }) {
  return (
    <div className="view-head">
      <h2 className="view-title">{title}</h2>
      {actions && (
        <>
          <div className="spacer" />
          {actions}
        </>
      )}
    </div>
  );
}
