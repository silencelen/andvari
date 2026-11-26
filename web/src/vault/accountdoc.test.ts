import { describe, expect, it } from "vitest";
import { type AccountDocument, type ContactRecord, EMPTY_DOCUMENT, mergeDocuments, removeContact, supersedingStamp, withRecovery } from "./accountdoc";

/**
 * The writer rules of the account-state document that the vectors do not grade (design §5.4): a record that
 * supersedes another is stamped later than it, so it wins the merge on every device whatever this one's clock says.
 */
const U = "0b8f6b0e-5a4c-4d5e-9f1a-2b3c4d5e6f70";
const contact = (verifiedAt: number): ContactRecord => ({
  userId: U,
  identityPub: "dmn5TI1-jtERdRVMZoWG5QFr3LXPGreVJcHDayMnGio",
  label: "QWxpY2U",
  method: "link",
  verifiedAt,
  compared: true,
  madeOn: "d0000000-0000-4000-8000-000000000001",
  extra: new Map(),
});
const withContact = (c: ContactRecord): AccountDocument => ({ ...EMPTY_DOCUMENT, contacts: new Map([[c.userId, c]]) });

describe("account document writer rules", () => {
  it("the superseding stamp is the clock, or one past the held record when the clock is behind", () => {
    expect(supersedingStamp(500, null)).toBe(500);
    expect(supersedingStamp(500, 100)).toBe(500);
    expect(supersedingStamp(500, 500)).toBe(501);
    expect(supersedingStamp(500, 9000)).toBe(9001);
  });

  it("a tombstone written by a device whose clock is behind still removes the pin on every device", () => {
    const pinned = withContact(contact(9000));
    const removed = removeContact(pinned, U, 500);
    expect(removed.contactTombstones.get(U)).toBe(9001);
    expect(removed.contacts.has(U)).toBe(false);
    // Merged against a copy that still holds the pin, in either order, the pin stays removed.
    expect(mergeDocuments(removed, pinned).document.contacts.has(U)).toBe(false);
    expect(mergeDocuments(pinned, removed).document.contacts.has(U)).toBe(false);
  });

  it("a second removal is stamped past the tombstone already held", () => {
    const once = removeContact(withContact(contact(100)), U, 200);
    expect(once.contactTombstones.get(U)).toBe(200);
    expect(removeContact(once, U, 150).contactTombstones.get(U)).toBe(201);
  });

  it("a recovery choice made with a slow clock wins against the record it replaces", () => {
    const held = withRecovery(EMPTY_DOCUMENT, { posture: "operator", fp: "a".repeat(64), at: 9000 });
    const off = withRecovery(held, { posture: "private", fp: "none", at: 500 });
    expect(off.recovery).toMatchObject({ posture: "private", at: 9001 });
    expect(mergeDocuments(held, off).document.recovery?.posture).toBe("private");
  });
});
