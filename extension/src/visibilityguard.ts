/**
 * Anti-clickjacking guard for the in-page surfaces (dropdown, banners, card chip) — security review
 * 2026-10, root cause B. Chrome-free so `node --test` can drive it with a fake observer
 * (visibilityguard.test.ts); content-ui.ts supplies the real IntersectionObserver and the computed
 * style of our host element.
 *
 * Why `isTrusted` is not enough: it proves a human produced the event, not that the human could
 * SEE what they activated. Our UI lives in a closed shadow root, but the host element is page DOM:
 * the page can set it to `opacity:0`, transform it elsewhere, or append a `pointer-events:none`
 * decoy at the same maximum z-index that paints over our rows while clicks fall through to them.
 *
 * Two independent checks, both required:
 *  1. IntersectionObserver v2 (`trackVisibility`): the browser itself reports whether the surface
 *     is unoccluded and free of opacity/transform/filter effects, through every ancestor including
 *     embedding frames. The surface must have been reported visible CONTINUOUSLY for
 *     ACTIVATION_ARM_MS — a flash of visibility, or a click in the first instants after the surface
 *     appeared, proves nothing (the same arm-delay idea browser permission prompts use).
 *  2. A synchronous computed-style read of our shadow host at activation time. IOv2
 *     notifications are delayed by at least 100 ms, so a page could flip `opacity:0` just before
 *     the click; the style read closes that window for effects on our own host. (A late decoy
 *     overlay inside that same window is the residual the arm delay narrows but cannot close:
 *     hit-testing skips `pointer-events:none` elements, so nothing synchronous can see one.)
 *
 * Fail closed: an engine without IOv2 cannot tell us the surface is visible, so EVERY activation is
 * refused there — no weaker heuristic stands in for it. The caller tells the user to use the
 * toolbar popup instead.
 */

/** How long a surface must have been continuously reported visible before it may be activated. */
export const ACTIVATION_ARM_MS = 500;

/** IOv2's minimum notification delay when trackVisibility is set. */
const IO_DELAY_MS = 100;

export interface IoEntryLike {
  target: unknown;
  /** IOv2 only. Absent on engines without trackVisibility support. */
  isVisible?: boolean;
}

export type IoCtorLike = new (
  callback: (entries: IoEntryLike[]) => void,
  options?: { trackVisibility?: boolean; delay?: number; threshold?: number | number[] },
) => { observe(target: never): void; unobserve(target: never): void; trackVisibility?: boolean };

/** The computed-style fields that can hide or relocate our surface without removing it. */
export interface StyleLike {
  opacity: string;
  visibility: string;
  filter: string;
  transform: string;
  clipPath: string;
  mixBlendMode: string;
}

/** "ok" = activate; "hidden" = covered or visually altered; "arming" = not yet proven visible for
 *  long enough; "unsupported" = this engine cannot prove visibility at all. */
export type ActivationVerdict = "ok" | "hidden" | "arming" | "unsupported";

export interface VisibilityGuard {
  readonly supported: boolean;
  watch(el: object): void;
  forget(el: object): void;
  /** `style` is our shadow host's computed style at the moment of the gesture. */
  check(el: object, style: StyleLike): ActivationVerdict;
}

/** True when any visual effect is applied. Our host is `all: initial`, so every field below has a
 *  known untouched value; anything else came from the page. An unreadable value fails too. */
export function styleIsTampered(s: StyleLike): boolean {
  return (
    s.opacity !== "1" ||
    s.visibility !== "visible" ||
    s.filter !== "none" ||
    s.transform !== "none" ||
    s.clipPath !== "none" ||
    s.mixBlendMode !== "normal"
  );
}

export function createVisibilityGuard(Io: IoCtorLike | undefined, now: () => number, armMs = ACTIVATION_ARM_MS): VisibilityGuard {
  /** Per surface: is it visible per the last IOv2 report, and since when. No entry = never reported. */
  const seen = new WeakMap<object, { visible: boolean; since: number }>();
  let io: InstanceType<IoCtorLike> | null = null;
  if (Io) {
    try {
      io = new Io(
        (entries) => {
          for (const e of entries) {
            if (typeof e.target !== "object" || e.target === null) continue;
            const prev = seen.get(e.target);
            const visible = e.isVisible === true;
            // Keep the original `since` across repeated "visible" reports: only a transition from
            // not-visible starts the arm clock.
            if (visible && prev?.visible) continue;
            seen.set(e.target, { visible, since: now() });
          }
        },
        { trackVisibility: true, delay: IO_DELAY_MS, threshold: [0, 1] },
      );
    } catch {
      io = null; // an engine that rejects the v2 options outright is an engine without v2
    }
  }
  // Chromium reflects the option back as an attribute; engines without IOv2 silently drop it.
  const supported = io !== null && io.trackVisibility === true;

  return {
    supported,
    watch(el) {
      seen.delete(el);
      if (supported) io!.observe(el as never);
    },
    forget(el) {
      seen.delete(el);
      if (io) io.unobserve(el as never);
    },
    check(el, style) {
      if (!supported) return "unsupported";
      if (styleIsTampered(style)) return "hidden";
      const s = seen.get(el);
      if (!s) return "arming";
      if (!s.visible) return "hidden";
      return now() - s.since >= armMs ? "ok" : "arming";
    },
  };
}
