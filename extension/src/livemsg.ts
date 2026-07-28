/**
 * The ONE live-region write (a11y 2a), shared by the popup and the options page.
 *
 * ORDER MATTERS, and it is the whole reason this is a module: the region must be in the a11y tree
 * (unhidden) with its live role set BEFORE its text mutates, or the first message is dropped — an
 * already-populated region is a static read, not a live announcement. Three hand-rolled copies of
 * the idiom existed and two had the order inverted, so the FIRST outcome a screen-reader user got
 * on those surfaces — "Connected to …", the declined-grant explanation, the update-channel note —
 * was never announced at all. The rule now lives in one place, with its rationale attached.
 *
 * Deliberately STRUCTURAL, not DOM-typed: the contract is three writes in a fixed order, so it is
 * assertable without a browser (livemsg.test.ts records the write order against a plain object).
 */

/** The slice of an element this module touches. */
export interface LiveRegion {
  hidden: boolean;
  textContent: string | null;
  className: string;
  setAttribute(name: string, value: string): void;
}

/** `role`: "alert" (assertive — a failure the user must not miss) or "status" (polite).
 *  `className` goes first: it carries no a11y semantics, and setting it before the unhide keeps
 *  the region from painting one frame in the previous message's colour. */
export function setLiveMsg(node: LiveRegion, className: string, role: "alert" | "status", text: string): void {
  node.className = className;
  node.hidden = false;
  node.setAttribute("role", role);
  node.textContent = text;
}

/** The hide direction has the opposite order for the same reason: empty the region while it is
 *  still live (so nothing is left for a later static read), then take it out of the tree. */
export function clearLiveMsg(node: LiveRegion): void {
  node.textContent = "";
  node.hidden = true;
}
