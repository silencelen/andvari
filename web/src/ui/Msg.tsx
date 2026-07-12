import type { ReactNode } from "react";

/**
 * P2 status/error strip (a11yweb-02), the sighted-user box.
 *
 * BL-1: errors get `role="alert"` — an ASSERTIVE region announces on INSERTION, so a
 * conditionally-mounted error strip is still spoken. Info gets NO live role: a POLITE
 * (`role="status"`) region that mounts already-populated is not reliably announced
 * (NVDA especially), so wrapping conditional `.msg info` in `role="status"` would be a
 * silent false-green. Async info surfaces (copy flash, the 426 banner, lock / enrolled
 * notices) drive a persistent <Announcer> instead — see below.
 */
export function Msg({ kind, children }: { kind: "err" | "info"; children: ReactNode }) {
  return (
    <div className={`msg ${kind}`} role={kind === "err" ? "alert" : undefined}>
      {children}
    </div>
  );
}

/**
 * BL-1 / AM-2: a PERSISTENT visually-hidden polite live region. It MUST be rendered
 * unconditionally so it is present (empty) in the accessibility tree at first paint;
 * feed it text and the mutation of the already-mounted node's text is what actually
 * fires the polite announcement. Never gate it behind `{cond && <Announcer/>}` — that
 * recreates the populated-on-mount silence the visible `.msg info` box already suffers.
 */
export function Announcer({ text }: { text: string }) {
  return (
    <div className="visually-hidden" role="status" aria-live="polite">
      {text}
    </div>
  );
}
