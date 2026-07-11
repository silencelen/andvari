// Offscreen document for the Chrome clipboard-clear backstop (E1-4 / B1). The MV3 service worker
// has no document and Chrome's async Clipboard API refuses UNFOCUSED documents (an offscreen doc is
// never focused), so the SW close-then-recreates THIS document on every "clipboardclear" alarm and
// we clear synchronously here via a textarea + execCommand("copy").
//
// B1: the write is a SINGLE SPACE, never the empty string — select() on an EMPTY textarea yields an
// empty selection and execCommand("copy") is refused (a silent no-op that would clear nothing). The
// smoke asserts "the clipboard no longer holds the secret" (a lone space is a pass), never "empty".
// Running at top level means this executes on EVERY load, so the SW's close-then-recreate cycle
// guarantees a clear on every alarm fire (no clear-on-load-behind-a-create-if-absent-guard trap).
export {}; // force module scope (no imports/exports otherwise → tsc would treat this as a global script)

const ta = document.createElement("textarea");
ta.value = " ";
document.body.appendChild(ta);
ta.select();
try {
  document.execCommand("copy");
} catch {
  /* execCommand unavailable here — nothing more this document can do; best-effort by design */
}
ta.remove();
