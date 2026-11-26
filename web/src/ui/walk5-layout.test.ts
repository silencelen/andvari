import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * Found in the browser walk of 2026-11-16 (part five), at a phone's width: the recovery choice's option names squeezed into
 * a narrow column beside their detail, the "Keep that?" prompt running edge to edge with "Not now" wrapped onto two lines,
 * and the account deletion's two buttons wrapped onto three lines each. Pinned on the markup and the style sheet.
 */
const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const read = (p: string) => readFileSync(here(p), "utf8");

describe("the walk's phone layout fixes", () => {
  it("each recovery option's name and detail are one text box beside its radio", () => {
    const src = read("./RecoveryChoice.tsx");
    expect(src).toContain("<span>\n          <strong>{RECOVERY_ONLY_ME}</strong> — {RECOVERY_ONLY_ME_DETAIL}\n        </span>");
    expect(src).toContain("<span>\n          <strong>{fill(RECOVERY_FAMILY_OPTION)}</strong> — {RECOVERY_FAMILY_OPTION_DETAIL}\n        </span>");
  });

  it("the escrow prompt sits in the list's column and its buttons wrap whole; the unsigned change reads as a warning", () => {
    expect(read("./EscrowPrompt.tsx")).toContain('className={`msg ${unsigned ? "err" : "info"} top-prompt`}');
    const css = read("./styles.css");
    expect(css).toContain(".top-prompt { width: calc(100% - 40px); max-width: 720px;");
    expect(css).toContain(".top-prompt .actions button { white-space: nowrap; }");
  });

  it("the deletion's buttons wrap as whole buttons", () => {
    expect(read("./DeleteAccount.tsx")).toContain('<div className="actions wrap">');
    // A basis of 14em: two buttons share a desktop row; on a phone each takes a row of its own at full width (a nowrap
    // button wider than a phone's column overflowed it in the walk's part six).
    expect(read("./styles.css")).toContain(".actions.wrap button { flex: 1 1 14em; }");
  });
});
