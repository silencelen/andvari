import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { ApiClient } from "../api/client";
import { fromB64 } from "../crypto/bytes";
import { initSodium } from "../crypto/sodium";
import { Account } from "../vault/account";
import { VaultStore } from "../vault/store";

/**
 * Account-recovery DRILL (docs/drills/account-recovery-drill.md), automated against a live
 * scratch server whose recovery keypair is generated for this run — the SEED stands in for the
 * printed sheet (we can't drive the LIVE org key without the owner's physical sheet, by design).
 * Drives the FULL spec 04 §4 forgot-master-password path end to end, including the REAL
 * recovery-cli jar (recover) and the PRC-1 "bundle accepted as-is" check. Orchestrated by
 * scripts/recovery-drill.sh; skipped unless ANDVARI_DRILL (base URL) is set.
 */
const BASE = process.env.ANDVARI_DRILL;
const BOOTSTRAP = process.env.ANDVARI_DRILL_BOOTSTRAP ?? "";
const SEED = process.env.ANDVARI_DRILL_SEED ?? "";
const RECOVERY_JAR = process.env.ANDVARI_DRILL_RECOVERY_JAR ?? "";
const WORK = process.env.ANDVARI_DRILL_WORK ?? "/tmp";

describe.skipIf(!BASE)("account recovery drill", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("escrow → recover → apply → temp login → forced change → data intact", async () => {
    const policy = await (await fetch(`${BASE}/api/v1/client-policy`)).json();
    const recoveryPub = fromB64((await (await fetch(`${BASE}/api/v1/recovery-pubkey`)).text()).trim());

    // --- Admin (bootstrap invite makes the first registrant an admin) ---
    const admin = new ApiClient(BASE!);
    const adminEnroll = await Account.enroll({
      inviteToken: BOOTSTRAP,
      email: "drill-admin@monahanhosting.com",
      displayName: "Drill Admin",
      password: "drill admin master password",
      kdfParams: policy.kdfParams,
      recoveryPublicKey: recoveryPub,
      recoveryFingerprint: policy.recoveryFingerprint,
    });
    const adminSession = await admin.register(adminEnroll.request);
    admin.setTokens({ accessToken: adminSession.accessToken, refreshToken: adminSession.refreshToken });
    expect(adminSession.isAdmin, "bootstrap account is admin").toBe(true);

    // --- Step 1: a throwaway drill account (admin-invited) with ONE known item ---
    const drillEmail = "recovery-drill@monahanhosting.com";
    const invite = await admin.adminInvite(drillEmail, false);
    const OLD_PW = "drill user OLD master password";
    const drill = new ApiClient(BASE!);
    const drillEnroll = await Account.enroll({
      inviteToken: invite.inviteToken,
      email: drillEmail,
      displayName: "Recovery Drill",
      password: OLD_PW,
      kdfParams: policy.kdfParams,
      recoveryPublicKey: recoveryPub,
      recoveryFingerprint: policy.recoveryFingerprint,
    });
    const drillSession = await drill.register(drillEnroll.request);
    drill.setTokens({ accessToken: drillSession.accessToken, refreshToken: drillSession.refreshToken });
    const drillUserId = drillSession.userId;
    const CANARY_PW = "drill-canary-secret-42";
    const store0 = new VaultStore(drill, drillEnroll.account);
    await store0.sync();
    await store0.save(null, { type: "login", name: "drill-canary", login: { username: "canary", password: CANARY_PW } });
    await store0.sync();

    // --- Step 2: admin downloads the sealed escrow blob (F59 route) ---
    const sealed = (await admin.adminUserEscrow(drillUserId)).trim();
    expect(sealed.length, "escrow blob downloaded").toBeGreaterThan(40);

    // --- Step 3: offline recover with the printed-sheet SEED — the ACTUAL recovery-cli jar ---
    const out = execFileSync("java", ["-jar", RECOVERY_JAR, "recover", sealed], {
      input: SEED + "\n",
      cwd: WORK,
      encoding: "utf-8",
    });
    const lines = out.split("\n");
    const tpIdx = lines.findIndex((l) => l.includes("ONE-TIME temporary password"));
    const tempPassword = (lines[tpIdx + 1] ?? "").trim();
    expect(tempPassword.length, "recovery-cli minted a temp password").toBeGreaterThan(0);
    // The bundle recovery-cli wrote must POST AS-IS — tempKdfParams a JSON OBJECT (PRC-1 fix).
    const bundleText = readFileSync(join(WORK, `andvari-recovery-${drillUserId}.json`), "utf-8");
    const bundle = JSON.parse(bundleText);
    expect(typeof bundle.tempKdfParams, "tempKdfParams is a JSON object, not a string (PRC-1)").toBe("object");
    expect(bundle.tempKdfParams, "tempKdfParams is non-null").not.toBeNull();
    expect(bundle.userId).toBe(drillUserId);

    // --- Step 4: admin applies the bundle AS-IS (no hand-editing) ---
    const applyResp = await fetch(`${BASE}/api/v1/admin/recovery`, {
      method: "POST",
      headers: { Authorization: `Bearer ${adminSession.accessToken}`, "Content-Type": "application/json" },
      body: bundleText,
    });
    expect(applyResp.status, `admin/recovery accepted the bundle as-is: ${await applyResp.clone().text()}`).toBe(200);

    // --- Step 5: drill user logs in with the TEMP password → forced change ---
    const c2 = new ApiClient(BASE!);
    const pre = await c2.prelogin(drillEmail);
    const tempAuthKey = await Account.deriveAuthKey(tempPassword, pre.kdfSalt, pre.kdfParams);
    const tempSession = await c2.login(drillEmail, tempAuthKey, "drill-recovered-device");
    expect(tempSession.mustChangePassword, "recovery forces a password change").toBe(true);
    const recovered = await Account.unlock(tempSession.userId, tempPassword, tempSession.accountKeys);
    const NEW_PW = "drill user NEW master password";
    const currentAuthKey = await Account.deriveAuthKey(tempPassword, tempSession.accountKeys.kdfSalt, tempSession.accountKeys.kdfParams);
    const change = await recovered.buildPasswordChange(NEW_PW, policy.kdfParams);
    await c2.changePassword({ currentAuthKey, ...change });

    // --- Step 6: re-login with the NEW password → the vault decrypts under the UNCHANGED UVK ---
    const c3 = new ApiClient(BASE!);
    const pre3 = await c3.prelogin(drillEmail);
    const newAuthKey = await Account.deriveAuthKey(NEW_PW, pre3.kdfSalt, pre3.kdfParams);
    const finalSession = await c3.login(drillEmail, newAuthKey, "drill-final-device");
    expect(finalSession.mustChangePassword, "the change cleared the forced-change flag").toBe(false);
    const finalAccount = await Account.unlock(finalSession.userId, NEW_PW, finalSession.accountKeys);
    const finalStore = new VaultStore(c3, finalAccount);
    await finalStore.sync();
    const canary = finalStore.list().find((i) => i.doc.name === "drill-canary");
    expect(canary, "the known item survived recovery (UVK unchanged)").toBeDefined();
    expect(canary!.doc.login?.password, "its secret decrypts to the SAME value").toBe(CANARY_PW);

    // The OLD password must no longer work (recovery rewrote the verifier).
    const cOld = new ApiClient(BASE!);
    const preOld = await cOld.prelogin(drillEmail);
    const oldAuthKey = await Account.deriveAuthKey(OLD_PW, preOld.kdfSalt, preOld.kdfParams);
    let oldRejected = false;
    try {
      await cOld.login(drillEmail, oldAuthKey, "drill-old-device");
    } catch {
      oldRejected = true;
    }
    expect(oldRejected, "the forgotten OLD password no longer authenticates").toBe(true);
  }, 60_000); // multiple real argon2id (64 MiB) derivations + a JVM recover subprocess
});
