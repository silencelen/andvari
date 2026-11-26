import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { fromB64, toB64, toHexLower } from "../crypto/bytes";
import { copyOf } from "../crypto/escrow-v3.testkit";
import { boxKeypairFromSeed, randomBytes, sha256Sync } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { operatorOffer, setRecoveryPosture } from "../vault/settingsflow";
import { SessionWrap } from "../vault/sessionwrap";
import { Browser } from "./browser";
import { journeysUnavailable, recoveryCliUnavailable, type SharePeerProcess, TestInstance } from "./harness";
import { HOOK } from "./wait";

/**
 * Journey 7: an account made in the BROWSER, with operator recovery turned on there, is helped end to end (spec 04 §3
 * and §7). The browser seals the version-3 recovery copy; the server stores it; the operator (the
 * engine's own code, AssistPeer.java) downloads it after the hold; the real offline tool `recovery-cli assist` refuses
 * it when the operator types another address and accepts it for the account's own; the operator uploads the answer
 * token; the person's new native device opens the answer, checks the account and commits a new password; and the
 * browser then signs in with that password.
 */
const skip = journeysUnavailable() ?? recoveryCliUnavailable();
if (skip) console.warn(skip);

const EMAIL = "erin@example.org";
const P1 = "erin's correct Horse 4 battery";
const P2 = "erin recovered by the Operator 77";
const OPERATOR_PASSWORD = "operator horse Battery 9 staple";

describe.skipIf(skip !== null)("journey 7: a browser-made account is helped by the operator and the offline tool", () => {
  let inst: TestInstance;
  let peer: SharePeerProcess;
  let work: string;
  let seed: Uint8Array;

  beforeAll(async () => {
    await initSodium();
    seed = randomBytes(32);
    const recovery = boxKeypairFromSeed(seed);
    inst = await TestInstance.start({ kind: "private", mode: "open", enrolOperator: false, setupArgs: ["--recovery-pubkey", toB64(recovery.publicKey)] });
    peer = await inst.assistPeer("operator@example.org", OPERATOR_PASSWORD);
    work = mkdtempSync(join(tmpdir(), "andvari-web-assist-"));
  }, HOOK.startWithPeer);

  afterAll(async () => {
    await peer?.stop();
    await inst?.stop();
    if (work) rmSync(work, { recursive: true, force: true });
  }, HOOK.stop);

  it("signs up in the browser, turns operator recovery on there, and is helped: the tool takes its copy only for its own address", async () => {
    const recovery = boxKeypairFromSeed(seed);
    const home = new Browser(inst, "Firefox at home");
    const signed = await home.signUp(EMAIL, P1, "Erin");
    const s = home.settings(signed.opened, EMAIL, new SessionWrap(signed.wrap));
    const offer = await operatorOffer(s);
    if (offer.kind !== "offer") throw new Error(offer.kind);
    const on = await setRecoveryPosture(s, home.accountState(signed.opened), home.storage, { posture: "operator", offer: offer.offer, understood: true, keepDespiteUnsignedChange: false }, P1, inst.now());
    expect(on).toMatchObject({ kind: "done", value: { posture: "operator" } });
    const userId = signed.session.userId;
    const accountId = toHexLower(sha256Sync(signed.opened.identity.publicKey));

    // The person, on a new native device, asks for help and proves the address; the hold passes.
    const seenCode = inst.mailCount(EMAIL, "recovery_request_code");
    const asked = await peer.cmd<{ requestCode: string; error?: string }>(`ask ${EMAIL}`);
    expect(asked.error).toBeUndefined();
    const code = await inst.awaitCode(EMAIL, "recovery_request_code", seenCode);
    expect(await peer.cmd(`code ${code}`)).toMatchObject({ step: "Waiting", state: "holding" });
    await inst.advance(7 * 86_400_000 + 60_000);

    // The operator lists the request and downloads the copy the BROWSER sealed: version 3, naming the account's address.
    const listed = await peer.cmd<{ requests: { requestId: string; userId: string; email: string; rPub: string }[] }>("requests");
    const req = listed.requests.find((r) => r.userId === userId)!;
    expect(req.email).toBe(EMAIL);
    const idFile = join(work, "escrow.json");
    const dl = await peer.cmd<{ sealedB64: string }>(`escrow ${userId} ${idFile}`);
    expect(copyOf(dl.sealedB64, recovery)).toEqual({ v: 3, email: EMAIL });
    expect(fromB64(dl.sealedB64).length).toBe(455 + toB64(new TextEncoder().encode(EMAIL)).length);

    const instanceId = signed.pin.instanceId;
    const assist = (typed: string) =>
      inst.recoveryCli(
        ["assist", "--instance", instanceId, "--request", req.requestId, "--request-key", req.rPub, "--request-code", asked.requestCode.replace(/[^0-9a-f]/g, ""),
          "--email", typed, "--user", userId, "--identity-fp", accountId, "--identity-file", idFile],
        `${toB64(seed)}\nRECOVER ${userId.slice(0, 8)}\n`,
      );
    // The operator types another address: the tool refuses the copy and says whose it is.
    const wrong = assist("someone@example.org");
    expect(wrong.status, wrong.stdout + wrong.stderr).not.toBe(0);
    expect(wrong.stderr).toMatch(/another account's/);
    expect(wrong.stderr).toContain(EMAIL);
    expect(wrong.stdout).not.toMatch(/andvari-answer:/);
    // The account's own address: the answer token is the last line.
    const right = assist(EMAIL);
    expect(right.status, right.stderr).toBe(0);
    const lastLine = right.stdout.trim().split("\n").pop()!;
    expect(lastLine.startsWith(`andvari-answer:3:${req.requestId}:${req.rPub}:`)).toBe(true);

    // The operator uploads it; the person's device opens it, checks the account and sets a new password.
    const tokenFile = join(work, "answer.txt");
    writeFileSync(tokenFile, right.stdout);
    expect(await peer.cmd(`fulfil ${req.requestId} ${tokenFile}`)).toEqual({ fulfil: "done" });
    const polled = await peer.cmd<{ step: string; accountId?: string }>("poll");
    expect(polled.step).toBe("CheckAccount");
    expect(accountId.startsWith((polled.accountId ?? "").replace(/[^0-9a-f]/g, "").slice(0, 32))).toBe(true);
    expect(await peer.cmd(`commit ${P2}`)).toEqual({ step: "Recovered" });

    // The browser: the old password no longer signs in, the new one does, to the same account.
    const later = new Browser(inst, "Firefox at home, later");
    expect(await later.signInKind(EMAIL, P1)).toBe("invalid_credentials");
    const back = await later.signIn(EMAIL, P2);
    expect(back.kind).toBe("opened");
    if (back.kind === "opened") expect(back.opened.userId).toBe(userId);
  }, 600_000);
});
