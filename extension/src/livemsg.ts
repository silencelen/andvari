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

/** One block of a message with parts: its tag, class and text. Text only: a block is never markup. */
export interface TextBlock {
  tag: "strong" | "p";
  className: string;
  text: string;
}

/** A message with a title and a body (the owner's approved words come as both): the title, then one paragraph per
 *  line of the body, so a paragraph break in the words stays a paragraph break on the screen. Empty lines make no
 *  paragraph. */
export function messageBlocks(title: string | null, body: string): TextBlock[] {
  const out: TextBlock[] = [];
  if (title !== null && title !== "") out.push({ tag: "strong", className: "msg-title", text: title });
  for (const para of body.split("\n")) if (para.trim() !== "") out.push({ tag: "p", className: "msg-para", text: para });
  return out;
}

/** The slice of an element [renderBlocks] touches: it makes child elements and sets their text, nothing else. */
export interface BlockHost {
  ownerDocument: { createElement(tag: "strong" | "p"): { className: string; textContent: string | null } };
  replaceChildren(...nodes: unknown[]): void;
}

/** Replace [host]'s children with [blocks], each element's text set through `textContent` (never as markup). The
 *  elements are built detached and put in with one call, so a live region mutates once. */
export function renderBlocks(host: BlockHost, blocks: readonly TextBlock[]): void {
  const made = blocks.map((b) => {
    const e = host.ownerDocument.createElement(b.tag);
    e.className = b.className;
    e.textContent = b.text;
    return e;
  });
  host.replaceChildren(...made);
}

/** [setLiveMsg] for a message with a title and paragraphs, in the same order: class, unhide, role, then the content. */
export function setLiveMsgBlocks(node: LiveRegion & BlockHost, className: string, role: "alert" | "status", title: string | null, body: string): void {
  node.className = className;
  node.hidden = false;
  node.setAttribute("role", role);
  renderBlocks(node, messageBlocks(title, body));
}

/** The hide direction has the opposite order for the same reason: empty the region while it is
 *  still live (so nothing is left for a later static read), then take it out of the tree. */
export function clearLiveMsg(node: LiveRegion): void {
  node.textContent = "";
  node.hidden = true;
}
