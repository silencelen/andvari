import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * H06 (audit 2026-09-13): the web Sharing screen is the ONLY production caller of member removal
 * on any client (Android/desktop have no member management), and it called the route with no
 * body — so the spec 03 §11 removal proof, whose minting helper existed and was vector-pinned,
 * was wired to nothing, and every legitimate removal reached the removed member as the
 * "server may be misbehaving" anomaly. The mint itself is tested against the real crypto in
 * store.lifecycle.test.ts; what has to hold HERE is the call site: the screen's remove closure
 * goes through store.removeVaultMember (which mints) and never through the bodyless client
 * method. Pinned on the source (the signout-revoke idiom) — MemberPanel is a closure inside a
 * ~1000-line view with no seam to render in this node env.
 */
const src = readFileSync(fileURLToPath(new URL("./Sharing.tsx", import.meta.url)), "utf8");

describe("Sharing.tsx member removal carries the spec 03 §11 removal proof", () => {
  it("removes through store.removeVaultMember (mints nonce + proof), never the bodyless client call", () => {
    const start = src.indexOf("const remove = (userId: string) =>");
    expect(start, "MemberPanel.remove moved — update the pin").toBeGreaterThan(-1);
    const end = src.indexOf("const pending = ", start);
    const closure = src.slice(start, end);
    expect(closure).toContain("store.removeVaultMember(vault.vaultId, userId)");
    expect(src, "a bodyless client call from the UI re-opens H06").not.toContain("client.deleteVaultMember(");
  });
});

describe("three small sharing points", () => {
  it("a role changes only after a confirming step: the drop-down stages it, the confirm button signs it", () => {
    const sel = src.slice(src.indexOf("aria-label={`Role for ${memberName(r, serverNames)}`}"), src.indexOf("</select>", src.indexOf("aria-label={`Role for")));
    expect(sel).toContain("setRoleDraft({ userId: r.userId, role })");
    expect(sel).not.toContain("changeRole(");
    expect(sel).not.toContain("setMemberRole(");
    const confirm = src.slice(src.indexOf("fill(ROLE_CHANGE_ASK"), src.indexOf("ROLE_CHANGE_CONFIRM}"));
    expect(confirm).toContain("onClick={() => changeRole(r.userId, roleDraft.role)}");
  });

  it("an ownership offer the other person refused is said to the owner who made it", () => {
    expect(src).toContain("shared?.logs.refusedOffer(vault.vaultId)");
    expect(src).toContain("fill(OFFER_REFUSED,");
  });

  it("the note after deleting a vault with no other members does not say that members lost access", async () => {
    const { deletedNoteText } = await import("./Sharing");
    const day = Date.UTC(2026, 10, 23, 12);
    expect(deletedNoteText({ name: "Mine", purgeAt: day, alone: true })).not.toContain("Members");
    expect(deletedNoteText({ name: "Mine", purgeAt: day, alone: true })).toMatch(/^“Mine” is deleted\. You can restore it until /);
    expect(deletedNoteText({ name: "Ours", purgeAt: day, alone: false })).toMatch(/^“Ours” is deleted\. Members lost access immediately\. You can restore it until /);
    expect(src).toContain("const alone = (store.memberRoster(vault.vaultId)?.rows ?? []).every((r) => r.self);");
  });
});

describe("the holding area offers the copy-out the design promises (§3.8, §3.12)", () => {
  it("each held vault with items offers the copy into the personal vault, or says why it can't", () => {
    const held = src.slice(src.indexOf("function RecentlyRemoved("), src.indexOf("function RecentlyDeleted("));
    expect(held).toContain("<HeldCopyOut held={h} store={store} />");
    expect(held).toContain("store.copyHeldToPersonal(held.vaultId,");
    expect(held).toContain("if (!held.canCopyOut) return <div className=\"muted\">{HELD_NO_KEY}</div>;");
    expect(held).toContain("{CHECK_WHAT_YOU_COPY} {HELD_COPY_ATTACHMENTS}");
  });
});

describe("the remove dialog offers Move everything to a new vault right there (design §3.13)", () => {
  it("the confirm row carries the action, opened for the member being removed, and the panel runs the store's move", () => {
    const confirm = src.slice(src.indexOf("{REMOVE_MEMBER_DOES_NOT}"), src.indexOf("Remove\n", src.indexOf("{REMOVE_MEMBER_DOES_NOT}")));
    expect(confirm).toContain("setMoving({ removing: r.userId })");
    expect(confirm).toContain("{MOVE_EVERYTHING}");
    expect(src).toContain("store.moveEverything(vault.vaultId, { name, add: adding.map((m) => m.userId), removing }");
  });

  it("the panel says what does not move before the person starts: the trash and earlier versions stay with the old vault", async () => {
    const copy = await import("./copy");
    // Named by their keys, so this holds whatever their words are: each names the old vault ({0}).
    expect(copy.MOVE_NOT_MOVED).toContain("{0}");
    expect(copy.MOVE_NOT_MOVED_STAYS).toContain("{0}");
    const panel = src.slice(src.indexOf("<label>{MOVE_EVERYTHING}</label>"), src.indexOf("onClick={go}>{deleteWaiting ? MOVE_FINISH : MOVE_EVERYTHING}</button>"));
    const line = panel.indexOf("fill(plan.sourceStays ? MOVE_NOT_MOVED_STAYS : MOVE_NOT_MOVED, vault.name)");
    expect(line).toBeGreaterThan(panel.indexOf("MOVE_INTRO_STAYS : MOVE_INTRO"));
    expect(line).toBeLessThan(panel.indexOf("{MOVE_NAME}</label>"));
  });

  it("\"is removed first\" only on a vault in good standing, where the remove is signed", () => {
    const panel = src.slice(src.indexOf("<label>{MOVE_EVERYTHING}</label>"), src.indexOf("onClick={go}>{deleteWaiting ? MOVE_FINISH : MOVE_EVERYTHING}</button>"));
    expect(panel).toContain("{removing !== null && !plan.sourceStays && <p className=\"muted\">{fill(MOVE_REMOVING, vault.name, removingName)}</p>}");
    expect(panel.match(/MOVE_REMOVING/g)).toHaveLength(1);
  });

  it("the move's member rows are plain lines, not field boxes; a deleted vault's dates wrap instead of being cut short", () => {
    const css = readFileSync(fileURLToPath(new URL("./styles.css", import.meta.url)), "utf8");
    const panel = src.slice(src.indexOf("<label>{MOVE_EVERYTHING}</label>"), src.indexOf("onClick={go}>{deleteWaiting ? MOVE_FINISH : MOVE_EVERYTHING}</button>"));
    expect(panel).not.toContain("attach-row");
    expect(panel).toContain('<div className="member-line" key={m.userId}>');
    expect(panel).toContain('<label className="member-line" key={m.userId}>');
    const line = css.slice(css.indexOf(".member-line {"), css.indexOf("}", css.indexOf(".member-line {")));
    expect(line).not.toMatch(/background|border-radius|border-left/);
    const deleted = src.slice(src.indexOf("function RecentlyDeleted("));
    expect(deleted).toContain('<span className="muted attach-sub">deleted {fmtDay(d.deletedAt)} · erased for good {fmtDay(d.purgeAt)}</span>');
    const sub = css.slice(css.indexOf(".attach-name.two-line .attach-sub {"), css.indexOf("}", css.indexOf(".attach-name.two-line .attach-sub {")));
    expect(sub).toContain("display: block");
    expect(sub).not.toContain("ellipsis");
    expect(css).toContain(".attach-name.two-line { white-space: normal; }");
  });

  it("a stopped move says where it stopped and that the old vault is unchanged, then why", async () => {
    const { moveStoppedText } = await import("./Sharing");
    const { MoveStoppedError } = await import("../vault/store");
    const { ApiError } = await import("../api/client");
    const copy = await import("./copy");
    // Each stage names its own line by its key, filled with the counts and both names, so this holds whatever the words are.
    expect(moveStoppedText(new MoveStoppedError("copy", 3, 7, "Family 2", "v2", new ApiError(413, "quota_exceeded", "full")), "Family")).toBe(
      `${copy.fill(copy.MOVE_STOPPED_COPY, "3", "7 items", "Family 2", "Family")} ${copy.OWNER_OUT_OF_SPACE} ${copy.MOVE_NEEDS_SPACE}`,
    );
    expect(moveStoppedText(new MoveStoppedError("create", 0, 0, "Family 2", null, new TypeError("fetch failed")), "Family").startsWith(`${copy.fill(copy.MOVE_STOPPED_START, "Family")} `)).toBe(true);
    expect(moveStoppedText(new MoveStoppedError("delete", 7, 7, "Family 2", "v2", new TypeError("x")), "Family").startsWith(`${copy.fill(copy.MOVE_STOPPED_DELETE, "7", "7 items", "Family 2", "Family")} `)).toBe(true);
  });
});
