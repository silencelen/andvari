import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * quality-perf--0 (polish audit 2026-07-27): TrashView's per-tombstone naming is an N+1
 * (store.deletedItems() fetches itemVersions per row), and the purge handler used to re-run the
 * FULL load() in its finally — so every "Delete forever" re-spun one request per remaining
 * tombstone (~10×40 sequential fetches for a 10-item cleanup of a 40-item trash). The success
 * arm now drops the row from local state (nothing else changed server-side); the full re-list
 * survives only on the FAILURE arm, where it reconciles a lost-response success. Pinned on the
 * source (the token-lockstep idiom) — the handler is a component closure with no seam to call.
 */

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const vaultTsx = readFileSync(here("./Vault.tsx"), "utf8");

/** Source between two TrashView markers — the handlers are component closures, not seams. */
function slice(from: string, to: string): string {
  const start = vaultTsx.indexOf(from);
  const end = vaultTsx.indexOf(to, start);
  expect(start, `TrashView's \`${from}\` moved — update the pin`).toBeGreaterThan(-1);
  expect(end, `TrashView's \`${to}\` moved — update the pin`).toBeGreaterThan(start);
  return vaultTsx.slice(start, end);
}

/** The purge handler's source, sliced from `const purge` to the restore handler that follows it. */
const purgeSource = () => slice("const purge = async", "const restore = async");
/** The restore handler's source, sliced to the JSX that follows it. */
const restoreSource = () => slice("const restore = async", "return (");
/** TrashView's list loader, sliced to the effect that first fires it. */
const loadSource = () => slice("const load = useCallback", "useEffect(");

describe("TrashView purge — no full re-list on success", () => {
  it("the success arm drops the purged row locally instead of reloading", () => {
    expect(purgeSource()).toContain("prev.filter((d) => d.itemId !== itemId)");
  });

  it("load() survives only on the failure arm (lost-response reconcile), never in finally", () => {
    const src = purgeSource();
    const finallyBlock = src.slice(src.indexOf("} finally {"));
    expect(src.slice(src.indexOf("} catch {"), src.indexOf("} finally {"))).toContain("load(");
    expect(finallyBlock).not.toContain("load(");
  });
});

/**
 * parity--4 (polish audit 2026-07-27): both TrashView handlers set an error and then re-list to
 * reconcile a possible lost-response success — and load() opened with an unconditional
 * setErr(""), so it ERASED the message it was racing. A failed "Delete forever" rendered as an
 * unchanged list with no error bar: identical to a success, on the one destructive action in the
 * view. load now takes `keepErr` and both reconcile calls pass it.
 */
describe("TrashView — a failed purge/restore keeps saying so after the reconcile re-list", () => {
  it("load clears the error bar only when the caller has not just set one", () => {
    expect(loadSource()).toContain('if (!keepErr) setErr("")');
  });

  it("the purge failure arm reconciles WITHOUT wiping \"Couldn't delete it permanently\"", () => {
    const src = purgeSource();
    expect(src.slice(src.indexOf("} catch {"), src.indexOf("} finally {"))).toContain("load(true)");
  });

  it("the restore re-list preserves \"Restore failed\" the same way", () => {
    expect(restoreSource().slice(restoreSource().indexOf("} finally {"))).toContain("load(true)");
  });
});

/**
 * bug-web--6 / ux-parity--6 (polish audit 2026-07-27): Trash and Version history were the only
 * two surfaces in the app rendering `new Date(x).toISOString().slice(0, 10)` — a UTC substring,
 * so an item deleted at 11 PM local showed tomorrow's date, in an ISO dialect nothing else here
 * speaks (Sharing's own recently-deleted list already said "deleted July 14"). Both now go
 * through ui/format's fmtDay, in the reader's timezone.
 *
 * bug-web--3: TrashView's doc comment claimed "retention is unbounded today (F49)" while the
 * copy three lines below promised a 30-day purge. The REFUTER settled it in the copy's favour —
 * the server Janitor's rule (c) hard-deletes item tombstones past ITEM_TOMBSTONE_RETENTION_MS —
 * so the comment was simply stale, and it was talking maintainers out of a bound that ships.
 */
describe("Trash / history dates are local and in the house dialect", () => {
  it("neither surface renders a raw UTC ISO substring any more", () => {
    expect(vaultTsx).not.toContain("toISOString().slice(0, 10)");
  });

  it("the Trash row and the history row both call fmtDay", () => {
    expect(vaultTsx).toContain("deleted {fmtDay(d.deletedAt)}");
    expect(vaultTsx).toContain("{fmtDay(v.archivedAt)}");
    expect(vaultTsx).toContain('import { fmtDay, humanSize } from "./format"');
  });

  it("TrashView's doc comment no longer contradicts its own copy about retention", () => {
    const doc = vaultTsx.slice(vaultTsx.indexOf("Item undelete (feature)"), vaultTsx.indexOf("function TrashView("));
    expect(doc).not.toContain("retention is unbounded");
    expect(doc).toContain("ITEM_TOMBSTONE_RETENTION_MS");
    // …and the rendered promise it now agrees with.
    expect(vaultTsx).toContain("kept for 30 days, then removed automatically");
  });
});

/**
 * Audit F04 — the 30-day restore promise covered the item's FIELDS only. A restore MUST drop the
 * attachment refs (store.ts's own invariant; the blobs are unlinked server-side at delete, and
 * SyncEngine.kt does the same), so a restored item comes back without its files, permanently. No
 * client said so at delete time, at restore time, or after — the disclosure existed once, in
 * docs/user-test-guide-0.6.0.md, and was dropped. Two web surfaces carry it now, and the sentence
 * is the one the Android/desktop Trash headers use verbatim, so all three clients agree.
 */
describe("F04 — deleting an item with attachments says the files are not coming back", () => {
  const ATTACHMENTS_NOT_RESTORED =
    "Restoring brings the item back, but not its attachments — those were permanently removed when the item was deleted.";

  it("the Trash header states it, in the cross-client wording", () => {
    expect(vaultTsx).toContain(ATTACHMENTS_NOT_RESTORED);
  });

  it("it replaced the sentence that framed a restore as complete", () => {
    expect(vaultTsx).not.toContain("Restoring brings an item back to its vault on every device");
  });

  it("the delete confirm warns BEFORE the delete, and only when the item actually has files", () => {
    const confirm = vaultTsx.slice(
      vaultTsx.indexOf("Delete “{doc.name}” from every device?"),
      vaultTsx.indexOf("Confirm delete"),
    );
    expect(confirm).toContain("(doc.attachments?.length ?? 0) > 0");
    expect(confirm).toContain("cannot be restored, even from Deleted items.");
    // Singular/plural, because "Its 1 attached files" is how copy stops being believed.
    expect(confirm).toContain('doc.attachments!.length === 1 ? "attached file"');
  });
});
