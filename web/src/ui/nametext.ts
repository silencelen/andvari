import { firstRefusedCharacter, type RefusedCharacterKind, textRefusal } from "../crypto/trust/grammar";
import { fill, NAME_BAD_BROKEN, NAME_BAD_CONTROL, NAME_BAD_DIRECTION, NAME_BAD_INVISIBLE, NAME_BAD_LINE_BREAK, NAME_TOO_LONG } from "./copy";

const BY_KIND: Record<RefusedCharacterKind, string> = {
  control: NAME_BAD_CONTROL,
  line_break: NAME_BAD_LINE_BREAK,
  direction: NAME_BAD_DIRECTION,
  invisible: NAME_BAD_INVISIBLE,
  broken: NAME_BAD_BROKEN,
};

/** "U+202E": a code point as a person can look it up. */
const codePoint = (cp: number): string => `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`;

/**
 * A display name or device name a person typed, checked before it is sent (spec 03 §0.1 `text`, the server's list since
 * 2026-11-16, which is the shared code's list of what a name may not hold), so the person reads which kind of character
 * is refused and never a refusal code (`bad_display_name`, `bad_device`). Null when it may be sent. An empty name is the
 * caller's to fill (sign-up uses the address).
 */
export function nameText(name: string): string | null {
  switch (textRefusal(name)) {
    case "character": {
      const c = firstRefusedCharacter(name)!;
      return fill(BY_KIND[c.kind], codePoint(c.cp));
    }
    case "too_long":
      return NAME_TOO_LONG;
    default:
      return null;
  }
}
