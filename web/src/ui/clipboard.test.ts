import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { resetClipboardClearForTest, scheduleClipboardClear, writeClipboard, type ClipboardClearOutcome } from "./clipboard";
import { CLIPBOARD_FAILED, CLIPBOARD_NOT_CLEARED, CLIPBOARD_NOT_CLEARED_SHORT } from "./errors";

/**
 * ux-error--2 (polish audit 2026-07-27): navigator.clipboard.writeText REJECTS in real conditions
 * ("Document is not focused", permissions-policy) and every web copy button used to fire it
 * unawaited — the failure vanished as an unhandled rejection while the user believed the value
 * was on the clipboard. writeClipboard is the one guarded write behind Vault's useCopy and
 * Settings' CopyButton: it must never reject, and its false arm renders CLIPBOARD_FAILED — the
 * canon sentence the extension popup already shows for the same operation, pinned byte-equal
 * here across all three clients (the token-lockstep cross-source idiom).
 */

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));

describe("CLIPBOARD_FAILED — cross-client twin", () => {
  it("is byte-equal to extension/src/errors.ts CLIPBOARD_FAILED", () => {
    const src = readFileSync(here("../../../extension/src/errors.ts"), "utf8");
    const m = src.match(/export const CLIPBOARD_FAILED = "([^"]+)";/);
    expect(m, "extension CLIPBOARD_FAILED declaration moved — update the pin").not.toBeNull();
    expect(CLIPBOARD_FAILED).toBe(m![1]);
  });

  it("is byte-equal to desktop Ui.kt CLIPBOARD_COPY_FAILED (ux-error--3's failure line)", () => {
    const src = readFileSync(here("../../../app-desktop/src/main/kotlin/io/silencelen/andvari/desktop/Ui.kt"), "utf8");
    const m = src.match(/internal const val CLIPBOARD_COPY_FAILED = "([^"]+)"/);
    expect(m, "desktop CLIPBOARD_COPY_FAILED declaration moved — update the pin").not.toBeNull();
    expect(CLIPBOARD_FAILED).toBe(m![1]);
  });
});

describe("writeClipboard — guarded write", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("true when the platform accepts the write", async () => {
    const writeText = vi.fn(async () => {});
    vi.stubGlobal("navigator", { clipboard: { writeText } });
    await expect(writeClipboard("hunter2")).resolves.toBe(true);
    expect(writeText).toHaveBeenCalledWith("hunter2");
  });

  it("false — never a rejection — when writeText rejects (document not focused)", async () => {
    vi.stubGlobal("navigator", {
      clipboard: { writeText: vi.fn(async () => Promise.reject(new DOMException("Document is not focused."))) },
    });
    await expect(writeClipboard("hunter2")).resolves.toBe(false);
  });

  it("false when the clipboard API is missing entirely (permissions-policy stripped it)", async () => {
    vi.stubGlobal("navigator", {});
    await expect(writeClipboard("hunter2")).resolves.toBe(false);
  });
});

/**
 * Audit F05 — the auto-clear half. Three defects lived on one mechanism: the wipe timer sat in a
 * PER-COMPONENT ref (Detail unmounts on every back-to-list, so the id was dropped while the timer
 * ran on and blanked the NEXT copy early); the wipe itself was a bare `writeText("")` whose
 * rejection was thrown away — and it rejects in exactly the dominant flow, copy → alt-tab → paste,
 * because the document isn't focused; and the UI asserted "clears in 30s" regardless. So: one
 * module-scope slot owned by the newest copy, a focus-driven retry, and an outcome the caller
 * must be able to act on. Driven here against stubbed timers/listeners (node env, no DOM).
 */
describe("scheduleClipboardClear — one slot, honest outcome", () => {
  interface FakeTimer { id: number; fn: () => void }
  let timers: FakeTimer[] = [];
  let cleared: number[] = [];
  let listeners: { target: "document" | "window"; type: string; fn: () => void }[] = [];
  let writes: string[] = [];
  let visibility = "visible";

  const install = (writeText: (v: string) => Promise<void>) => {
    let next = 1;
    timers = [];
    cleared = [];
    listeners = [];
    writes = [];
    vi.stubGlobal("window", {
      setTimeout: (fn: () => void) => {
        const id = next++;
        timers.push({ id, fn });
        return id;
      },
      clearTimeout: (id: number) => cleared.push(id),
      addEventListener: (type: string, fn: () => void) => listeners.push({ target: "window", type, fn }),
      removeEventListener: (type: string, fn: () => void) => {
        listeners = listeners.filter((l) => !(l.target === "window" && l.type === type && l.fn === fn));
      },
    });
    vi.stubGlobal("document", {
      get visibilityState() {
        return visibility;
      },
      addEventListener: (type: string, fn: () => void) => listeners.push({ target: "document", type, fn }),
      removeEventListener: (type: string, fn: () => void) => {
        listeners = listeners.filter((l) => !(l.target === "document" && l.type === type && l.fn === fn));
      },
    });
    vi.stubGlobal("navigator", { clipboard: { writeText: (v: string) => { writes.push(v); return writeText(v); } } });
  };

  /** Let every queued microtask (the guarded write, its catch, the owner callback) settle. */
  const flush = () => new Promise((res) => setImmediate(res));
  const fireLast = async () => {
    timers[timers.length - 1]!.fn();
    await flush();
  };

  afterEach(() => {
    resetClipboardClearForTest();
    visibility = "visible";
    vi.unstubAllGlobals();
  });

  it("a second copy takes over the slot: the first timer is cancelled and its owner never hears back", async () => {
    install(async () => {});
    const outcomes: string[] = [];
    scheduleClipboardClear(30, (o) => outcomes.push(`A:${o}`));
    scheduleClipboardClear(30, (o) => outcomes.push(`B:${o}`));
    expect(cleared).toEqual([1]); // copy A's pending wipe is gone — it can no longer blank B's value
    await fireLast();
    expect(writes).toEqual([""]); // exactly ONE wipe ran, not two
    expect(outcomes).toEqual(["B:cleared"]); // and only the newest copy's owner is told
  });

  it("a wipe the platform accepts reports 'cleared' and arms no retry", async () => {
    install(async () => {});
    const outcomes: ClipboardClearOutcome[] = [];
    scheduleClipboardClear(1, (o) => outcomes.push(o));
    await fireLast();
    expect(outcomes).toEqual(["cleared"]);
    expect(listeners).toEqual([]);
  });

  it("a REFUSED wipe reports 'stuck' — the secret is still on the clipboard and the caller must say so", async () => {
    install(async () => Promise.reject(new DOMException("Document is not focused.")));
    const outcomes: ClipboardClearOutcome[] = [];
    scheduleClipboardClear(1, (o) => outcomes.push(o));
    await fireLast();
    expect(outcomes).toEqual(["stuck"]);
    // …and a one-shot retry is armed on BOTH signals that this tab came back.
    expect(listeners.map((l) => `${l.target}:${l.type}`).sort()).toEqual(["document:visibilitychange", "window:focus"]);
  });

  it("the retry fires when the tab is looked at again, lands the wipe, and unregisters itself", async () => {
    let refuse = true;
    install(async () => {
      if (refuse) return Promise.reject(new DOMException("Document is not focused."));
    });
    const outcomes: ClipboardClearOutcome[] = [];
    scheduleClipboardClear(1, (o) => outcomes.push(o));
    await fireLast();
    expect(outcomes).toEqual(["stuck"]);

    // Still in the background: the listener stays armed and nothing is retried.
    visibility = "hidden";
    listeners.find((l) => l.type === "visibilitychange")!.fn();
    await flush();
    expect(writes).toEqual([""]); // only the first, failed attempt

    refuse = false;
    visibility = "visible";
    listeners.find((l) => l.type === "visibilitychange")!.fn();
    await flush();
    expect(writes).toEqual(["", ""]); // the retry ran
    expect(outcomes).toEqual(["stuck", "cleared"]); // …so the surface can retract its warning
    expect(listeners).toEqual([]); // one-shot
  });
});

/**
 * The rest of F05 is wiring inside 2000-line view files with no seam to render here, so it is
 * pinned on the source (the trash-purge/token-lockstep idiom): the wipe must go through the
 * shared slot (never a per-component ref), and no surface may keep asserting a clear it did not
 * get. Admin's invite copy — the one write that bypassed the guard entirely — is pinned too.
 */
describe("F05 — every copy surface routes through the shared slot and tells the truth", () => {
  const src = (p: string) => readFileSync(here(p), "utf8");
  const vaultTsx = src("./Vault.tsx");
  const welcomeTsx = src("./Welcome.tsx");
  const adminTsx = src("./Admin.tsx");

  it("no view file schedules a raw clipboard wipe of its own any more", () => {
    for (const [name, s] of [["Vault.tsx", vaultTsx], ["Welcome.tsx", welcomeTsx], ["Admin.tsx", adminTsx]] as const) {
      expect(s, `${name} must not fire its own writeText("") timer`).not.toContain('clipboard.writeText("")');
      expect(s, `${name} must not write the clipboard unguarded`).not.toContain("navigator.clipboard.writeText");
    }
  });

  it("Vault's useCopy and Welcome's recovery-phrase copy both arm the shared slot", () => {
    expect(vaultTsx).toContain("scheduleClipboardClear(clampClipboardClearSeconds(clearSeconds)");
    expect(welcomeTsx).toContain("scheduleClipboardClear(clampClipboardClearSeconds(clipboardClearSeconds)");
    // The wipe timer must NOT be a per-instance ref again — that aliasing is the bug.
    expect(vaultTsx).not.toContain("wipeTimer");
  });

  it("the copy pill retracts its promise instead of asserting a clear that did not happen", () => {
    expect(vaultTsx).toContain("wipeStuck ? CLIPBOARD_NOT_CLEARED_SHORT : `copied ✓ · clears in ${clearSecs}s`");
    // One pill for all four secret rows (password / card number / security code / one-time code).
    expect(vaultTsx.match(/copyPill\("/g) ?? []).toHaveLength(4);
    expect(CLIPBOARD_NOT_CLEARED_SHORT).not.toContain("clears in");
    expect(CLIPBOARD_NOT_CLEARED).toContain("Still on your clipboard");
  });

  it("Admin's invite/link copy is guarded and shows the canon failure sentence", () => {
    expect(adminTsx).toContain("const ok = await writeClipboard(value);");
    expect(adminTsx).toContain("{copyFailed && <Msg kind=\"err\">{CLIPBOARD_FAILED}</Msg>}");
  });
});

/**
 * Audit F25, web half — the TOTP enrollment rows copy as VAULT SECRETS.
 *
 * Settings' CopyButton had no auto-clear at all, under a KDoc asserting that was deliberate
 * because everything it copies is "setup material, not a vault secret". Two of its three callers
 * were the account's `otpauth://` URI and its base32 seed, which are the account's second factor —
 * anyone holding either mints valid codes forever, and they sat on the system clipboard
 * indefinitely while every item password was scrubbed on the policy window. android and desktop
 * reclassified their twins in the same audit; this is the third client. The identity code is the
 * one caller that really is non-secret (it is read out loud to verify a share) and keeps the
 * plain path — a pin, not an omission, so a later "parity" sweep doesn't wire it up too.
 */
describe("F25 — the second-factor rows auto-clear, the identity code deliberately does not", () => {
  const settingsTsx = readFileSync(here("./Settings.tsx"), "utf8");

  it("both TOTP rows pass the clamped policy window to the copy button", () => {
    expect(settingsTsx).toContain("<CopyButton value={setup.otpauthUri} clearSeconds={clipClear} />");
    expect(settingsTsx).toContain("<CopyButton value={setup.secretBase32} clearSeconds={clipClear} />");
    expect(settingsTsx).toContain("const clipClear = clampClipboardClearSeconds(policy?.clipboardClearSeconds ?? 30);");
  });

  it("the button arms the SHARED slot (never a timer of its own) and retracts a refused wipe", () => {
    expect(settingsTsx).toContain("scheduleClipboardClear(clampClipboardClearSeconds(clearSeconds), (outcome) => setWipeStuck(outcome === \"stuck\"));");
    expect(settingsTsx).toContain("{wipeStuck && <Msg kind=\"err\">{CLIPBOARD_NOT_CLEARED}</Msg>}");
    // Same rule as the view files above: no surface fires its own raw wipe.
    expect(settingsTsx).not.toContain('clipboard.writeText("")');
    expect(settingsTsx).not.toContain("navigator.clipboard.writeText");
  });

  it("a caller that passes no window still gets a plain copy — the identity code's path", () => {
    expect(settingsTsx).toContain("<CopyButton value={code} />");
    expect(settingsTsx).toContain("if (clearSeconds > 0) {");
  });

  it("the KDoc no longer claims the second factor is mere setup material", () => {
    expect(settingsTsx).not.toContain("the TOTP setup link/code, the identity code) is SETUP MATERIAL");
    expect(settingsTsx).toContain("Setup material and second-factor seeds are not the same class");
  });
});
