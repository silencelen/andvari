import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { ApiError } from "../api/client";
import { toB64, toHexLower } from "../crypto/bytes";
import { boxKeypairFromSeed, randomBytes, sha256Sync } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { NONE } from "../crypto/trust/grammar";
import { kitDisplayForm } from "../crypto/trust/recoverykit";
import type { OpenedAccount } from "../vault/accountopen";
import { commitKitRecovery, parseKitInput, verifyKit } from "../vault/kitflow";
import { completeSignup } from "../vault/onboardflow";
import { readMirror } from "../vault/recoverymirror";
import { SessionWrap } from "../vault/sessionwrap";
import {
  changePassword,
  deleteAccount,
  listRecoveryRequests,
  operatorOffer,
  revokeDevice,
  rotateKitFor,
  setRecoveryPosture,
  setRequireLink,
  vetoRecoveryRequest,
} from "../vault/settingsflow";
import { SIGNIN_BACKOFF } from "../ui/copy";
import { kitRotateText } from "../ui/reauthtext";
import { Browser } from "./browser";
import { journeysUnavailable, TestInstance } from "./harness";
import { HOOK } from "./wait";

/**
 * Journey 2: Settings on a private instance whose card names a recovery key. One person changes the master
 * password, rotates the kit, recovers with the typed kit on a fresh browser (and gets a new kit), lists and
 * revokes devices, turns operator recovery on (first consent) and off, cancels a recovery request someone opened
 * in their name, and deletes the account.
 *
 * Every step runs the web client's flow modules over real HTTP against the real server in its test mode.
 */
const skip = journeysUnavailable();
if (skip) console.warn(skip);

const EMAIL = "dave@example.org";
const P1 = "correct horse Battery 9 staple";
const P2 = "a second Horse battery 12 staple";
const P3 = "the third horse Battery 33 staple";

describe.skipIf(skip !== null)("journey 2: settings, recovery and deletion on a private instance", () => {
  let inst: TestInstance;
  let recoveryFp: string;
  let home: Browser;
  let opened: OpenedAccount;
  /** The wrap the signed-in session keeps (spec 01 §7): one per session, as the app keeps it beside the session's keys. */
  let wrap: SessionWrap;
  let userId: string;
  let firstKit: Uint8Array;
  let rotatedKit: Uint8Array;
  let recoveredKit: Uint8Array;

  beforeAll(async () => {
    await initSodium();
    // The instance recovery key pair, as `recovery-cli keygen` makes it offline; only the public half goes to setup.
    const recovery = boxKeypairFromSeed(randomBytes(32));
    recoveryFp = toHexLower(sha256Sync(recovery.publicKey));
    inst = await TestInstance.start({ kind: "private", mode: "open", setupArgs: ["--recovery-pubkey", toB64(recovery.publicKey)] });
    home = new Browser(inst, "Firefox at home");
    const signed = await home.signUp(EMAIL, P1, "Dave");
    opened = signed.opened;
    wrap = new SessionWrap(signed.wrap);
    userId = signed.session.userId;
    firstKit = signed.kit.slice();
    expect(signed.pin.kind).toBe("private");
    expect(signed.pin.recoveryFp).toBe(recoveryFp);
  }, HOOK.startThenSignUp);

  afterAll(async () => {
    await inst?.stop();
  }, HOOK.stop);

  // Time passes between a person's actions. The server's per-address rate buckets are fixed windows on its (test)
  // clock, which stands still unless the journey moves it: without this the whole journey would share one minute.
  beforeEach(() => inst.advance(61_000));

  it("server 2026-11-16: five wrong proofs, then the right one is refused with the wait, while a sign-in is still served; nothing is retried", async () => {
    const EMAIL_F = "fay@example.org";
    const PF = "fay's correct Horse 7 battery";
    const fay = new Browser(inst, "Chrome at the library");
    const signed = await fay.signUp(EMAIL_F, PF, "Fay");
    const s = fay.settings(signed.opened, EMAIL_F, new SessionWrap(signed.wrap));
    // Five wrong proofs reach the server the way another client could send them (the web itself sends none: it proves
    // the password here first). Each is a wrong password, counted on the account's own back-off for proofs.
    for (let i = 0; i < 5; i++) {
      const e = await fay.wire.setRequireLink(true, toB64(randomBytes(32))).catch((x: unknown) => x);
      expect([(e as ApiError).status, (e as ApiError).code], `wrong proof ${i + 1}`).toEqual([403, "reauth_failed"]);
    }
    // The right password, proven here, is sent once and refused for the wait: the screen says "too many tries", not
    // "wrong password", and nothing is sent again by itself.
    let sent = 0;
    const counting = { ...s, wire: new Proxy(s.wire, { get: (t, n) => { const f = (t as unknown as Record<string | symbol, unknown>)[n]; if (n === "recoverySelfSetup") sent++; return typeof f === "function" ? f.bind(t) : f; } }) };
    const r = await rotateKitFor(counting, PF);
    expect(r).toEqual({ kind: "rate_limited" });
    expect(sent).toBe(1);
    expect(kitRotateText(r as Exclude<typeof r, { kind: "done" }>)).toBe(SIGNIN_BACKOFF);
    // A sign-in is still served: wrong proofs count on the account's own back-off for proofs and never arm the
    // sign-in's, so nobody can keep a person from signing in by sending wrong proofs on a session. The sign-in does
    // not lift the proofs' wait either.
    const signin = await new Browser(inst, "Firefox at home").signIn(EMAIL_F, PF);
    expect(signin.kind).toBe("opened");
    // Once the wait is over, the same action goes through.
    await inst.advance(901_000);
    expect((await rotateKitFor(s, PF)).kind).toBe("done");
  }, 300_000);

  it("changes the master password: the old one is refused locally, the other session ends, the new one signs in", async () => {
    const other = new Browser(inst, "Safari at work");
    const there = await other.signIn(EMAIL, P1);
    expect(there.kind).toBe("opened");
    const s = home.settings(opened, EMAIL, wrap);
    const before = inst.mailCount(EMAIL, "password_changed");
    // A wrong current password never reaches the password route.
    expect((await changePassword(s, "not the password", P2, (await home.wire.clientPolicy()).kdfParams)).kind).toBe("wrong_password");
    const changed = await changePassword(s, P1, P2, (await home.wire.clientPolicy()).kdfParams);
    expect(changed.kind).toBe("done");
    await inst.awaitMail(EMAIL, "password_changed", before);
    // This session continues, under keys that carry the new salt; every other session was revoked.
    const keys = await home.wire.accountKeys();
    if (changed.kind === "done") expect(keys.kdfSalt).toBe(changed.value.keys.kdfSalt);
    await expect(other.wire.accountKeys()).rejects.toBeInstanceOf(ApiError);
    const fresh = new Browser(inst);
    expect((await fresh.signIn(EMAIL, P1)).kind).toBe("invalid_credentials");
    const again = await fresh.signIn(EMAIL, P2);
    expect(again.kind).toBe("opened");
    // The kit survives a password change: the UVK did not change.
    expect((await home.wire.accountKeys()).recoveryConfirmed).toBe(true);
  }, 240_000);

  it("rotates the kit: the new one is shown and confirmed, and the old one opens nothing", async () => {
    const s = home.settings(opened, EMAIL, wrap);
    expect((await rotateKitFor(s, P1)).kind).toBe("wrong_password");
    const r = await rotateKitFor(s, P2);
    expect(r.kind).toBe("done");
    if (r.kind !== "done") return;
    expect((await home.wire.accountKeys()).recoveryConfirmed).toBe(false);
    await home.confirmKit(r.value.secret, r.value.pieceId);
    expect((await home.wire.accountKeys()).recoveryConfirmed).toBe(true);
    rotatedKit = r.value.secret.slice();
    // The kit made at sign-up no longer answers.
    const probe = new Browser(inst);
    await probe.settle();
    const old = parseKitInput(kitDisplayForm(firstKit), EMAIL);
    if (old.kind !== "typed") throw new Error(old.kind);
    expect((await verifyKit({ wire: probe.wire, pins: probe.pins, origin: probe.origin, input: old, knownIdentityPub: () => null })).kind).toBe("invalid_credentials");
  }, 240_000);

  it("recovers with the typed kit on a fresh browser, sets a new password, and gets a new kit that replaces it", async () => {
    const fresh = new Browser(inst, "A borrowed laptop");
    await fresh.settle();
    const input = parseKitInput(kitDisplayForm(rotatedKit), ` ${EMAIL.toUpperCase()} `);
    if (input.kind !== "typed") throw new Error(input.kind);
    const before = inst.mailCount(EMAIL, "recovery_applied");
    const v = await verifyKit({ wire: fresh.wire, pins: fresh.pins, origin: fresh.origin, input, knownIdentityPub: () => null });
    expect(v.kind).toBe("verified");
    if (v.kind !== "verified") return;
    expect(v.verified.userId).toBe(userId);
    const c = await commitKitRecovery({ wire: fresh.wire, pins: fresh.pins, origin: fresh.origin, verified: v.verified, newPassword: P3, kdfParams: (await fresh.wire.clientPolicy()).kdfParams, deviceName: fresh.deviceName });
    expect(c.kind).toBe("recovered");
    if (c.kind !== "recovered") return;
    expect(c.session.userId).toBe(userId);
    expect(c.kit.pieceId).toBeTruthy();
    await inst.awaitMail(EMAIL, "recovery_applied", before);
    // The commit replaced the kit: unconfirmed until the new one is typed back; the scanned one is dead at once.
    expect(c.session.accountKeys.recoveryConfirmed).toBe(false);
    await fresh.confirmKit(c.kit.secret, c.kit.pieceId);
    recoveredKit = c.kit.secret.slice();
    const probe = new Browser(inst);
    await probe.settle();
    const used = parseKitInput(kitDisplayForm(rotatedKit), EMAIL);
    if (used.kind !== "typed") throw new Error(used.kind);
    expect((await verifyKit({ wire: probe.wire, pins: probe.pins, origin: probe.origin, input: used, knownIdentityPub: () => null })).kind).toBe("invalid_credentials");
    // Every earlier session ended with the recovery; the new password signs in, the old ones do not.
    await expect(home.wire.accountKeys()).rejects.toBeInstanceOf(ApiError);
    expect((await probe.signIn(EMAIL, P2)).kind).toBe("invalid_credentials");
    const back = await home.signIn(EMAIL, P3);
    expect(back.kind).toBe("opened");
    if (back.kind !== "opened") return;
    opened = back.opened;
    wrap = new SessionWrap(back.wrap);
    // The recovered session's own devices: this browser's row was made by the recovery.
    const rows = await fresh.wire.devices();
    expect(rows.find((d) => d.current)?.how).toBe("recovered");
  }, 300_000);

  it("lists the account's devices and revokes another one; this device cannot target itself", async () => {
    const s = home.settings(opened, EMAIL, wrap);
    const rows = await home.wire.devices();
    const mine = rows.find((d) => d.current)!;
    const others = rows.filter((d) => !d.current && d.live);
    expect(others.length).toBeGreaterThan(0);
    expect((await revokeDevice(s, others[0]!.deviceId, "wrong password")).kind).toBe("wrong_password");
    expect(await revokeDevice(s, mine.deviceId, P3)).toEqual({ kind: "refused", code: "cannot_target_self" });
    const before = inst.mailCount(EMAIL, "device_removed");
    expect((await revokeDevice(s, others[0]!.deviceId, P3)).kind).toBe("done");
    await inst.awaitMail(EMAIL, "device_removed", before);
    const after = await home.wire.devices();
    expect(after.find((d) => d.deviceId === others[0]!.deviceId)?.live ?? false).toBe(false);
    // "New devices must be linked" is set and cleared with the password.
    expect(await setRequireLink(s, true, P3)).toEqual({ kind: "done", value: true });
    const stranger = new Browser(inst, "A new browser");
    expect(await stranger.signInKind(EMAIL, P3)).toBe("link_required");
    expect(await setRequireLink(s, false, P3)).toEqual({ kind: "done", value: false });
  }, 240_000);

  it("turns operator recovery on with its first consent, and off again; the record and this browser's mirror follow", async () => {
    const s = home.settings(opened, EMAIL, wrap);
    const state = home.accountState(opened);
    const offer = await operatorOffer(s);
    expect(offer.kind).toBe("offer");
    if (offer.kind !== "offer") return;
    expect(offer.offer.fp).toBe(recoveryFp);
    expect(offer.offer.origin).toBe(inst.origin);
    // Card 0 named this key from the start: no unsigned change on the walk.
    expect(offer.offer.unsignedChanges).toEqual([]);
    // Without the box nothing is sent.
    expect(await setRecoveryPosture(s, state, home.storage, { posture: "operator", offer: offer.offer, understood: false, keepDespiteUnsignedChange: false }, P3, inst.now())).toEqual({ kind: "refused", code: "consent_required" });
    const before = inst.mailCount(EMAIL, "recovery_changed");
    const on = await setRecoveryPosture(s, state, home.storage, { posture: "operator", offer: offer.offer, understood: true, keepDespiteUnsignedChange: false }, P3, inst.now());
    expect(on).toMatchObject({ kind: "done", value: { posture: "operator", fp: recoveryFp } });
    await inst.awaitMail(EMAIL, "recovery_changed", before);
    expect((await state.read()).document.recovery).toMatchObject({ posture: "operator", fp: recoveryFp });
    expect(readMirror(home.storage, userId)).toMatchObject({ posture: "operator", fp: recoveryFp });

    // Someone who can read the mailbox asks the operator for a reset (a native app's request, sent here as plain HTTP).
    const r = boxKeypairFromSeed(randomBytes(32));
    const pollSecret = toB64(randomBytes(32));
    const headers = { "Content-Type": "application/json", "X-Andvari-Client": "cli/0.29.1" };
    const seen = inst.mailCount(EMAIL, "recovery_request_code");
    const made = await fetch(`${inst.origin}/api/v1/recovery/requests`, {
      method: "POST", headers,
      body: JSON.stringify({ email: EMAIL, rPub: toB64(r.publicKey), pollHash: toHexLower(sha256Sync(new TextEncoder().encode(pollSecret))), platform: "cli" }),
    });
    expect(made.status).toBe(202);
    const requestId = ((await made.json()) as { requestId: string }).requestId;
    const code = await inst.awaitCode(EMAIL, "recovery_request_code", seen);
    const verified = await fetch(`${inst.origin}/api/v1/recovery/requests/${requestId}/verify`, { method: "POST", headers, body: JSON.stringify({ code }) });
    expect(verified.status).toBe(200);
    // The signed-in browser finds the request and cancels it with a statement signed by the account's key.
    const live = await listRecoveryRequests(s);
    expect(live?.map((q) => q.requestId)).toEqual([requestId]);
    expect((await home.wire.sync(0)).recoveryRequests).toBe(1);
    expect(await vetoRecoveryRequest(s, requestId, inst.now())).toEqual({ kind: "vetoed" });
    expect(await listRecoveryRequests(s)).toEqual([]);

    const off = await setRecoveryPosture(s, state, home.storage, { posture: "private" }, P3, inst.now());
    expect(off).toMatchObject({ kind: "done", value: { posture: "private", fp: NONE } });
    const rec = (await state.read()).document.recovery!;
    expect(rec.posture).toBe("private");
    // The choice that supersedes is stamped later than the one it replaced.
    if (on.kind === "done") expect(rec.at).toBeGreaterThan(on.value.at);
    expect(readMirror(home.storage, userId)).toMatchObject({ posture: "private", at: rec.at });
  }, 300_000);

  it("signs up choosing operator recovery (design §7.7): the escrow is sealed at registration and the record says so", async () => {
    const fresh = new Browser(inst, "Edge on Windows");
    await fresh.settle();
    const offer = await operatorOffer({ wire: fresh.wire, pins: fresh.pins, origin: fresh.origin });
    expect(offer.kind).toBe("offer");
    if (offer.kind !== "offer") return;
    // Without the box nothing is derived or sent.
    const refused = await completeSignup({
      wire: fresh.wire, pins: fresh.pins, origin: fresh.origin, pin: fresh.pins.pinFor(fresh.origin)!, policy: await fresh.wire.clientPolicy(),
      email: "dana@example.org", displayName: "Dana", password: P1, signupTicket: "not-sent", ageConfirmed: true, deviceName: "x", nowMs: inst.now(),
      operator: { offer: offer.offer, understood: false, keepDespiteUnsignedChange: false },
    });
    expect(refused).toEqual({ kind: "recovery_choice", code: "consent_required" });
    const before = inst.mailCount("dana@example.org", "signup_code");
    const signed = await fresh.signUp("dana@example.org", P1, "Dana", { offer: offer.offer, understood: true, keepDespiteUnsignedChange: false });
    expect(inst.mailCount("dana@example.org", "signup_code")).toBeGreaterThan(before);
    const id = signed.opened.userId;
    expect((await fresh.accountState(signed.opened).read()).document.recovery).toMatchObject({ posture: "operator", fp: recoveryFp });
    expect(readMirror(fresh.storage, id)).toMatchObject({ posture: "operator", fp: recoveryFp });
  }, 240_000);

  it("deletes the account: the typed address and the password, no leaves owed; the address can no longer sign in", async () => {
    const s = home.settings(opened, EMAIL, wrap);
    const preview = await home.wire.deletePreview();
    expect(preview).toMatchObject({ blockers: [], leftVaults: [], memberships: [], totpRequired: false });
    expect(preview.deletedVaults).toEqual([opened.personalVaultId]);
    const none = () => null;
    expect((await deleteAccount(s, { typedEmail: "someone@else.example", password: P3, verifiedState: none, nowMs: inst.now() })).kind).toBe("email_mismatch");
    expect((await deleteAccount(s, { typedEmail: EMAIL, password: "wrong", verifiedState: none, nowMs: inst.now() })).kind).toBe("wrong_password");
    const before = inst.mailCount(EMAIL, "account_deleted");
    const done = await deleteAccount(s, { typedEmail: ` ${EMAIL} `, password: P3, verifiedState: none, nowMs: inst.now() });
    expect(done.kind).toBe("deleted");
    await inst.awaitMail(EMAIL, "account_deleted", before);
    await expect(home.wire.accountKeys()).rejects.toBeInstanceOf(ApiError);
    const after = new Browser(inst);
    expect(await after.signInKind(EMAIL, P3)).toBe("invalid_credentials");
    // Neither recovery path survives a deletion.
    const kit = parseKitInput(kitDisplayForm(recoveredKit), EMAIL);
    if (kit.kind !== "typed") throw new Error(kit.kind);
    expect((await verifyKit({ wire: after.wire, pins: after.pins, origin: after.origin, input: kit, knownIdentityPub: () => null })).kind).toBe("invalid_credentials");
  }, 240_000);
});
