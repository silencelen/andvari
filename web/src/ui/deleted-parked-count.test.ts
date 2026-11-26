import { describe, expect, it } from "vitest";
import type { LifecycleNotice } from "../vault/store";
import { DELETED_PARKED_ONE } from "./copy";
import { noticeBody } from "./Vault";

/**
 * The notice that a shared vault was deleted by its owner names the edits made on this device that had not synced: one
 * edit has a line of its own, and only two or more are counted.
 */
const notice = (parkedCount?: number): LifecycleNotice =>
  ({ id: "n", vaultId: "v", vaultName: "Family", kind: "deleted", ...(parkedCount !== undefined ? { parkedCount } : {}) }) as LifecycleNotice;

describe("the notice of a vault deleted by its owner, with edits that had not synced", () => {
  it("one edit has its own line, never '1 of your edits'", () => {
    // On the code before: "… 1 of your edits hadn’t synced — they’ll be recovered …".
    const { body } = noticeBody(notice(1));
    expect(body.endsWith(` ${DELETED_PARKED_ONE}`)).toBe(true);
    expect(body).not.toMatch(/\b1 of your edits\b/);
  });

  it("two or more are counted, and none adds nothing", () => {
    expect(noticeBody(notice(2)).body).toMatch(/\b2 of your edits\b/);
    expect(noticeBody(notice(2)).body).not.toContain(DELETED_PARKED_ONE);
    expect(noticeBody(notice()).body).not.toContain(DELETED_PARKED_ONE);
    expect(noticeBody(notice()).body).not.toMatch(/of your edits/);
  });
});
