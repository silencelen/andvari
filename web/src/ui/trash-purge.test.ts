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
