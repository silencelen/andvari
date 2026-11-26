import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { ApiError } from "../api/client";
import { initSodium } from "../crypto/sodium";
import { accountId, wipeOpened } from "../vault/accountopen";
import { Browser } from "./browser";
import { journeysUnavailable, TestInstance } from "./harness";
import { HOOK } from "./wait";

/**
 * Journey 1: a person signs up on a public instance from the web (the emailed code, the proof of work, register,
 * the kit shown and confirmed), signs out, and signs in again on the same browser (a known device) and on a fresh
 * one (a new device). The operator account is refused on the web.
 *
 * Every step runs the web client's flow modules over real HTTP against the real server in its test mode.
 */
const skip = journeysUnavailable();
if (skip) console.warn(skip);

const EMAIL = "carol@example.org";
const PASSWORD = "correct horse Battery 9 staple";

describe.skipIf(skip !== null)("journey 1: sign-up and sign-in on a public instance", () => {
  let inst: TestInstance;

  beforeAll(async () => {
    await initSodium();
    inst = await TestInstance.start({ kind: "public", mode: "open", env: { ANDVARI_SIGNUP_POW_BITS: "10" } });
  }, HOOK.start);

  afterAll(async () => {
    await inst?.stop();
  }, HOOK.stop);

  // Time passes between a person's actions: the server's rate buckets are fixed windows on its (test) clock.
  beforeEach(() => inst.advance(61_000));

  it("signs up with the emailed code and the proof of work, confirms the kit, and signs in again", async () => {
    const browser = new Browser(inst);
    const pin = await browser.settle();
    expect(pin.root).toBe("trust_gate");
    expect(pin.kind).toBe("public");
    expect(pin.origin).toBe(inst.origin);
    // The card names the operator the bootstrap enrolled.
    expect(pin.operator).toBe(inst.operator!.userId);

    const policy = await browser.wire.clientPolicy();
    expect(policy.signup).toMatchObject({ mode: "open", full: false, ageConfirmRequired: true, powBits: 10 });

    // A wrong code is the uniform refusal, and it does not spend the right one.
    const pre = new Browser(inst);
    await pre.settle();
    await expect(pre.wire.signupVerify(EMAIL, "000000")).rejects.toMatchObject({ code: "bad_code" });

    const signed = await browser.signUp(EMAIL, PASSWORD, "Carol");
    expect(signed.session.role).toBe("member");
    expect(signed.session.recoveryPieceId).toBeTruthy();
    expect(signed.opened.personalVaultId).not.toBeNull();
    expect(signed.opened.genesis.fields.instanceId).toBe(pin.instanceId);
    const id = accountId(signed.opened.identity.publicKey);
    // The server recorded the confirmation of the kit this browser showed.
    expect((await browser.wire.accountKeys()).recoveryConfirmed).toBe(true);
    const first = await browser.wire.devices();
    expect(first).toHaveLength(1);
    expect(first[0]).toMatchObject({ platform: "web", how: "registered", current: true, live: true });

    // The vault opens on the personal vault the genesis names; an item is saved, pushed and read back.
    const personal = signed.opened.personalVaultId!;
    const v1 = await browser.openVault(signed.opened, signed.wrap);
    expect(v1.store.vaults().map((v) => [v.vaultId, v.type, v.role])).toEqual([[personal, "personal", "owner"]]);
    await v1.store.save(null, { type: "login", name: "Example", login: { username: "carol", password: "hunter2" } });
    await v1.store.save(null, { type: "note", name: "A note", notes: "kept" });
    const login = v1.store.list().find((i) => i.doc.name === "Example")!;
    expect(login).toMatchObject({ vaultId: personal, doc: { login: { username: "carol", password: "hunter2" } } });
    expect(login.rev).toBeGreaterThan(0);
    // An edit lands over the stored row, and the store's pull sees its own write.
    await v1.store.save(login.itemId, { ...login.doc, login: { username: "carol", password: "hunter3" } }, [], undefined, personal);
    expect(v1.store.get(login.itemId)!.doc.login!.password).toBe("hunter3");
    expect(v1.store.notices()).toEqual([]);
    // The vault's own syncs left the account state as sign-up wrote it: this account's v2 document, with the
    // recovery record. (The store still carries the old account-state reader; it must never overwrite this.)
    const kept = await browser.accountState(signed.opened).read();
    expect(kept.kind).toBe("ok");
    expect(kept.document.recovery).toMatchObject({ posture: "private", fp: "none" });

    // Sign out, then in again on the same browser: the device is known, so no new device row and no mail.
    await browser.signOut();
    await expect(browser.wire.accountKeys()).rejects.toBeInstanceOf(ApiError);
    const wrong = await browser.signIn(EMAIL, PASSWORD + "x");
    expect(wrong.kind).toBe("invalid_credentials");
    const again = await browser.signIn(EMAIL, PASSWORD);
    expect(again.kind).toBe("opened");
    if (again.kind !== "opened") return;
    expect(again.session.userId).toBe(signed.session.userId);
    expect(again.session.deviceId).toBe(signed.session.deviceId);
    expect(accountId(again.opened.identity.publicKey)).toBe(id);
    expect(again.opened.personalVaultId).toBe(signed.opened.personalVaultId);
    expect(await browser.wire.devices()).toHaveLength(1);
    // (No new_device mail for this sign-in: checked below, once a later one has arrived, since the sender sends in order.)
    // The items come back from the server and open under the personal vault's key.
    const v2 = await browser.openVault(again.opened, again.wrap);
    expect(v2.store.list().map((i) => i.doc.name).sort()).toEqual(["A note", "Example"]);
    expect(v2.store.get(login.itemId)!.doc.login).toEqual({ username: "carol", password: "hunter3" });
    // History holds the version the edit displaced; a delete goes to the trash and comes back.
    const versions = await v2.store.itemVersions(login.itemId, personal);
    expect(versions.map((v) => v.doc.login?.password)).toContain("hunter2");
    await v2.store.remove(login.itemId);
    expect(v2.store.get(login.itemId)).toBeUndefined();
    const trash = await v2.store.deletedItems();
    expect(trash.map((t) => t.itemId)).toEqual([login.itemId]);
    await v2.store.restoreDeleted(login.itemId, personal, trash[0]!.doc!);
    expect(v2.store.get(login.itemId)!.doc.login!.password).toBe("hunter3");

    // A fresh browser passes the Trust Gate and signs in with the password: a new device, and the mail says so.
    const other = new Browser(inst, "Safari on a Mac");
    const fresh = await other.signIn(EMAIL, PASSWORD);
    expect(fresh.kind).toBe("opened");
    if (fresh.kind !== "opened") return;
    expect(fresh.session.deviceId).not.toBe(signed.session.deviceId);
    expect(accountId(fresh.opened.identity.publicKey)).toBe(id);
    const devices = await other.wire.devices();
    expect(devices.map((d) => d.how).sort()).toEqual(["password", "registered"]);
    expect(devices.find((d) => d.current)?.deviceId).toBe(fresh.session.deviceId);
    // The mail names the kind of app in the server's own words and, after them, the name the browser gave itself, in
    // quotation marks and marked as the device's own words (decided on 22 November 2026).
    const row = 'Device: Web browser (as the device reported it), "Safari on a Mac" (as the device named itself)';
    await inst.awaitMail(EMAIL, "new_device", 0, { containing: row });
    // The sender worker sends the outbox in the order it was queued, so a mail for the known device's sign-in, queued
    // earlier, would be in the sink by now: the only new_device mail is the new browser's.
    expect(inst.mail().filter((m) => m.to === EMAIL && m.template === "new_device").map((m) => m.text.includes(row))).toEqual([true]);
    // The browser's name stands in that row and in no other line of any mail.
    expect(inst.mail().filter((m) => m.to === EMAIL).flatMap((m) => m.text.split("\n")).filter((l) => l.includes("Safari on a Mac"))).toEqual([row]);
    const v3 = await other.openVault(fresh.opened, fresh.wrap);
    expect(v3.store.list().map((i) => i.doc.name).sort()).toEqual(["A note", "Example"]);
    expect(v3.store.vaults().map((v) => v.vaultId)).toEqual([personal]);
    // A browser that holds no copy of the account state reads the same document after its vault synced.
    const there = await other.accountState(fresh.opened).read();
    expect(there.kind).toBe("ok");
    expect(there.document.recovery).toMatchObject({ posture: "private", fp: "none" });

    // The same address again is the uniform answer, and the mail says an account exists.
    const third = new Browser(inst);
    await third.settle();
    await third.wire.signupStart({ email: EMAIL, ageConfirmed: true, pow: await (await import("../vault/pow")).runPow(EMAIL, 10, inst.now()) });
    await inst.awaitMail(EMAIL, "signup_existing");
    // No mail carries a secret.
    expect(inst.mail().every((m) => !m.text.includes(PASSWORD))).toBe(true);
  }, 600_000);

  it("the operator account is refused on the web, and its session is ended", async () => {
    const browser = new Browser(inst);
    const r = await browser.signIn(inst.operator!.email, inst.operator!.password);
    expect(r.kind).toBe("operator");
    // The flow leaves the tokens for the caller to revoke at once; nothing of the operator's is opened.
    await browser.signOut();
    await expect(browser.wire.accountKeys()).rejects.toBeInstanceOf(ApiError);
  }, 120_000);
});
