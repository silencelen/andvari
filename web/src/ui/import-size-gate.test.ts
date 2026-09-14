import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ImportError, MAX_BYTES, parseCsvImport } from "../import/csv";

/**
 * H77 (audit 2026-09-13): the web importer read the ENTIRE picked file with `file.arrayBuffer()`
 * and only then compared its length to MAX_BYTES, so a mis-picked multi-GB file (a disk image, a
 * video, a database dump) froze or crashed the tab — a tab holding an unlocked vault — instead of
 * producing the "larger than 10 MiB" refusal that already existed for it. Both natives had been
 * bounded from the start: MainActivity's "CSV import: OpenDocument → BOUNDED read (never buffer a
 * multi-GB file)" and DesktopState's "a mislabeled multi-GB pick is rejected without being
 * buffered". Web is the reference client and was the one lagging its own ports.
 *
 * `onFile` is a closure inside ImportPanel and this suite has no DOM/effects harness (the house
 * pattern is renderToStaticMarkup, which runs no effects), so what is pinned here is the ORDER —
 * the size refusal must sit above the read, textually, in the same try that renders the friendly
 * copy — together with the invariant that makes the early refusal safe: the shared MAX_BYTES and
 * the same ImportError code the post-read gate throws, so both paths land on ONE sentence.
 */

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const vaultTsx = readFileSync(here("./Vault.tsx"), "utf8");
/** The body of ImportPanel's file handler, from its declaration to the catch that renders copy. */
const onFile = vaultTsx.slice(vaultTsx.indexOf("const onFile = async (files: FileList | null)"), vaultTsx.indexOf("setParseErr(friendlyParseError(e));"));

describe("H77 — the import size refusal happens BEFORE the file is read", () => {
  it("the gate is present and reads File.size, which costs nothing", () => {
    expect(onFile).toContain("if (file.size > MAX_BYTES) throw new ImportError(\"too_large\");");
  });

  it("it sits above the arrayBuffer() read — the whole point of the row", () => {
    const gate = onFile.indexOf("file.size > MAX_BYTES");
    const read = onFile.indexOf("await file.arrayBuffer()");
    expect(gate, "the size gate must exist").toBeGreaterThan(-1);
    expect(read, "the read must exist").toBeGreaterThan(-1);
    expect(gate).toBeLessThan(read);
  });

  it("it throws the SAME code the post-read gate throws, so one condition has one sentence", () => {
    // csv.ts's own gate stays: a File-less caller (drag-and-drop of a Blob, a future paste path)
    // must still be refused, and it is the module's own invariant.
    expect(() => parseCsvImport(new Uint8Array(MAX_BYTES + 1))).toThrow(ImportError);
    try {
      parseCsvImport(new Uint8Array(MAX_BYTES + 1));
      expect.unreachable("oversized buffer must be refused");
    } catch (e) {
      expect((e as ImportError).code).toBe("too_large");
    }
    // …and the panel's copy is keyed on that code, not on a second hand-written sentence.
    expect(vaultTsx).toContain('case "too_large":');
    expect(vaultTsx).toContain("That file is larger than 10 MiB");
  });

  it("MAX_BYTES is the shared constant, never a re-typed literal in the panel", () => {
    expect(vaultTsx).toContain("MAX_BYTES");
    expect(onFile).not.toMatch(/file\.size > \d/);
    expect(MAX_BYTES).toBe(10 * 1024 * 1024);
  });
});

/**
 * H64 / R47 — the import destination is resolved by IDENTITY, on every client.
 *
 * H64 made `Account.setPersonalVault` refuse a vault whose VK arrived by member grant, because
 * `type === "personal"` is a server plaintext column bound into no AD (spec 02 §4): a hostile
 * server can withhold the real personal row and relabel a SHARED vault. The refusal was described
 * as a choke point "so any future call site inherits it" — but web's CSV import never went through
 * Account at all. It picked its destination with `vaultChoices.find(v => v.type === "personal")`,
 * so the relabel H64 closes for the usage key still redirected an entire imported CSV — every
 * password in the file — into the housemates' vault, and the preview called it the personal one.
 * Both natives already read `acct.personalVaultId`; web was the outlier.
 *
 * Pinned on the source for the same reason the block above is: `onFile` is a closure with no seam.
 */
describe("H64/R47 — the import's default destination is the account's own personal vault", () => {
  it("resolves by vaultId, never by the server's `type` label", () => {
    expect(onFile).toContain("vaultChoices.find((v) => v.vaultId === personalVaultId)");
    expect(onFile, "the server-labelled lookup is the defect — it must not come back").not.toContain(
      'find((v) => v.type === "personal")',
    );
  });

  it("the id comes from Account, threaded in as a prop — not re-derived inside the panel", () => {
    expect(vaultTsx).toContain("personalVaultId: string;");
    expect(vaultTsx).toContain("personalVaultId={account.personalVaultId}");
  });

  it("fails CLOSED: no match ⇒ the honest refusal, never a fallback vault", () => {
    // H64's own fail-closed state is an EMPTY personalVaultId (every held candidate was
    // member-granted). No choice can match "", so this lands on the refusal below rather than
    // silently filing the whole file into someone else's vault.
    const guard = onFile.slice(onFile.indexOf("const personal ="), onFile.indexOf("if (file.size"));
    expect(guard).toContain("if (store.lastSyncAt === null || !personal)");
    expect(guard).toContain("hasn't finished its first sync");
    expect(guard, "no `?? something` fallback may soften the refusal").not.toMatch(/personal\s*(\?\?|\|\|)/);
  });

  it("the natives resolve the same way — this is a three-client rule, not a web preference", () => {
    const android = readFileSync(here("../../../app-android/src/main/kotlin/io/silencelen/andvari/app/AndvariViewModel.kt"), "utf8");
    const desktop = readFileSync(here("../../../app-desktop/src/main/kotlin/io/silencelen/andvari/desktop/DesktopState.kt"), "utf8");
    for (const [name, src] of [["android", android], ["desktop", desktop]] as const) {
      expect(src, `${name} must take the import destination from the account`).toContain("val dest = acct.personalVaultId");
    }
  });
});
