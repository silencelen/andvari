// In-page activation guard (security review 2026-10, root cause B). The dropdown, banners and card
// chip live in a closed shadow root, but their HOST element is ordinary page DOM: a hostile page can
// make it transparent, or paint a `pointer-events:none` decoy over it, and steer genuine trusted
// clicks onto rows the user cannot see. `isTrusted` proves a human clicked — not that the human saw
// what they clicked. These tests pin the guard every activation path now consults.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { ACTIVATION_ARM_MS, createVisibilityGuard, styleIsTampered, type IoCtorLike, type IoEntryLike } from "./visibilityguard.ts";

/** A stand-in for IntersectionObserver. `v2` decides whether the engine honours trackVisibility
 *  (Chromium reflects the option back as an attribute; engines without IOv2 drop it silently). */
function fakeIo(v2: boolean): { Ctor: IoCtorLike; emit(entries: IoEntryLike[]): void; observed: Set<unknown> } {
  let cb: ((entries: IoEntryLike[]) => void) | null = null;
  const observed = new Set<unknown>();
  class FakeIo {
    trackVisibility?: boolean;
    constructor(callback: (entries: IoEntryLike[]) => void, opts?: { trackVisibility?: boolean }) {
      cb = callback;
      if (v2) this.trackVisibility = opts?.trackVisibility === true;
    }
    observe(t: unknown): void {
      observed.add(t);
    }
    unobserve(t: unknown): void {
      observed.delete(t);
    }
  }
  return { Ctor: FakeIo, emit: (e) => cb?.(e), observed };
}

const UNTOUCHED = { opacity: "1", visibility: "visible", filter: "none", transform: "none", clipPath: "none", mixBlendMode: "normal" };

test("an occluded surface refuses the activation (IOv2 reports isVisible:false)", () => {
  let t = 1_000;
  const io = fakeIo(true);
  const g = createVisibilityGuard(io.Ctor, () => t);
  const box = {};
  g.watch(box);
  // The page appended a pointer-events:none decoy over the dropdown: the browser computes the
  // target as occluded, however long it has been on screen.
  io.emit([{ target: box, isVisible: false }]);
  t += 10_000;
  assert.equal(g.check(box, UNTOUCHED), "hidden");
});

test("a transparent host refuses the activation even before the observer has caught up", () => {
  let t = 1_000;
  const io = fakeIo(true);
  const g = createVisibilityGuard(io.Ctor, () => t);
  const box = {};
  g.watch(box);
  io.emit([{ target: box, isVisible: true }]);
  t += 10_000;
  // The observer's last word was "visible", but the page has since set opacity:0 on our host — the
  // synchronous computed-style read at activation time closes the IOv2 notification delay.
  assert.equal(g.check(box, { ...UNTOUCHED, opacity: "0" }), "hidden");
  assert.equal(g.check(box, { ...UNTOUCHED, opacity: "0.99" }), "hidden");
  assert.equal(g.check(box, { ...UNTOUCHED, visibility: "hidden" }), "hidden");
  assert.equal(g.check(box, { ...UNTOUCHED, transform: "matrix(1, 0, 0, 1, 400, 0)" }), "hidden");
  assert.equal(g.check(box, { ...UNTOUCHED, filter: "opacity(0)" }), "hidden");
  assert.equal(g.check(box, { ...UNTOUCHED, clipPath: "inset(50%)" }), "hidden");
  assert.equal(g.check(box, { ...UNTOUCHED, mixBlendMode: "multiply" }), "hidden");
  assert.equal(g.check(box, UNTOUCHED), "ok");
});

test("no IOv2 support → every activation is refused (fail closed, never a weaker fallback)", () => {
  let t = 1_000;
  const io = fakeIo(false);
  const g = createVisibilityGuard(io.Ctor, () => t);
  const box = {};
  g.watch(box);
  io.emit([{ target: box, isVisible: true }]); // an engine without v2 never sets this; prove it is ignored anyway
  t += 10_000;
  assert.equal(g.supported, false);
  assert.equal(g.check(box, UNTOUCHED), "unsupported");
  // …and with no IntersectionObserver at all.
  const none = createVisibilityGuard(undefined, () => t);
  none.watch(box);
  assert.equal(none.check(box, UNTOUCHED), "unsupported");
});

test("a freshly shown surface is not activatable until it has been visible for the arm window", () => {
  let t = 1_000;
  const io = fakeIo(true);
  const g = createVisibilityGuard(io.Ctor, () => t);
  const box = {};
  g.watch(box);
  assert.equal(g.check(box, UNTOUCHED), "arming", "no observation yet = not proven visible");
  io.emit([{ target: box, isVisible: true }]);
  t += ACTIVATION_ARM_MS - 1;
  assert.equal(g.check(box, UNTOUCHED), "arming");
  t += 1;
  assert.equal(g.check(box, UNTOUCHED), "ok");
});

test("visible → covered → visible restarts the arm window (a flash of visibility proves nothing)", () => {
  let t = 1_000;
  const io = fakeIo(true);
  const g = createVisibilityGuard(io.Ctor, () => t);
  const box = {};
  g.watch(box);
  io.emit([{ target: box, isVisible: true }]);
  t += ACTIVATION_ARM_MS * 4;
  assert.equal(g.check(box, UNTOUCHED), "ok");
  io.emit([{ target: box, isVisible: false }]);
  assert.equal(g.check(box, UNTOUCHED), "hidden");
  io.emit([{ target: box, isVisible: true }]);
  t += 50;
  assert.equal(g.check(box, UNTOUCHED), "arming");
  // A repeated "visible" notification must not reset the clock of an already-visible surface.
  t += ACTIVATION_ARM_MS;
  io.emit([{ target: box, isVisible: true }]);
  assert.equal(g.check(box, UNTOUCHED), "ok");
});

test("an unwatched surface is refused, and forget() drops both the record and the observation", () => {
  const t = 1_000;
  const io = fakeIo(true);
  const g = createVisibilityGuard(io.Ctor, () => t);
  const box = {};
  assert.equal(g.check(box, UNTOUCHED), "arming");
  g.watch(box);
  assert.ok(io.observed.has(box));
  g.forget(box);
  assert.ok(!io.observed.has(box));
});

test("styleIsTampered: the untouched defaults pass, any visual effect fails", () => {
  assert.equal(styleIsTampered(UNTOUCHED), false);
  assert.equal(styleIsTampered({ ...UNTOUCHED, opacity: "" }), true, "an unreadable value is not proof of visibility");
  assert.equal(styleIsTampered({ ...UNTOUCHED, visibility: "collapse" }), true);
});
