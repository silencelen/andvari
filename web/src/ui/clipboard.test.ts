import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { writeClipboard } from "./clipboard";
import { CLIPBOARD_FAILED } from "./errors";

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
