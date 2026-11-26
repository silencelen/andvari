import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeAll, describe, expect, it } from "vitest";
import { initSodium } from "../crypto/sodium";
import type { OperatorOffer } from "../vault/settingsflow";
import { ONLY_ME, RecoveryChoice, recoveryChoiceReady } from "./RecoveryChoice";

/** The recovery choice at sign-up on a private instance: design §7.7's family copy, pinned word for word. */

const offer = (unsigned = false): OperatorOffer => ({
  // "The Smiths" as the card's base64url `name`.
  name: "VGhlIFNtaXRocw",
  origin: "https://vault.smith.example",
  unsignedChanges: unsigned ? [{ fromFp: "a".repeat(64), toFp: "b".repeat(64) } as never] : [],
  pinHash: "c".repeat(64),
  fp: "d".repeat(64),
  recoveryPub: new Uint8Array(32),
});

const text = (html: string) => html.replace(/<[^>]+>/g, "").replace(/&#x27;/g, "'").replace(/&quot;/g, '"').replace(/&amp;/g, "&");

describe("RecoveryChoice", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("asks the §7.7 question with Only me selected and the family option named by the pinned card", () => {
    const t = text(renderToStaticMarkup(createElement(RecoveryChoice, { offer: offer(), value: ONLY_ME, onChange: () => {} })));
    expect(t).toContain("How should this account be recovered if you forget your master password?");
    expect(t).toContain(
      "Only me — You'll save a recovery kit now. If you lose both your master password and your recovery kit, nobody can get your vault back, not even the people who run this server.",
    );
    expect(t).toContain("Me, or the person who runs The Smiths — They can restore your account if you forget your master password.");
    expect(t).not.toContain("Let the person who runs");
  });

  it("the operator option shows the family warning and its box, and an unsigned change its own warning", () => {
    const t = text(renderToStaticMarkup(createElement(RecoveryChoice, { offer: offer(true), value: { ...ONLY_ME, posture: "operator" }, onChange: () => {} })));
    expect(t).toContain("Let the person who runs The Smiths (https://vault.smith.example) restore your account?");
    expect(t).toContain(
      "With this on, they keep a key that can restore your account. Restoring it means they could open your vault, every password, note and card in it, and act as you. Anyone who gets into your email can ask them to reset your account; a request waits 7 days, and your signed-in devices can cancel it. Choose this only if you trust the person who runs this server with your passwords. You will still get your own recovery kit.",
    );
    expect(t).toContain("I understand that the person who runs this server could open my vault and act as me.");
    expect(t).toContain("The recovery key for The Smiths (https://vault.smith.example) changed without the old key's signature.");
    expect(t).toContain("Keep it with the new key");
  });

  it("is ready for Only me, and for the operator only with the box ticked and an unsigned change kept", () => {
    expect(recoveryChoiceReady(ONLY_ME, null)).toBe(true);
    expect(recoveryChoiceReady({ ...ONLY_ME, posture: "operator" }, null)).toBe(false);
    expect(recoveryChoiceReady({ posture: "operator", understood: false, keepNewKey: false }, offer())).toBe(false);
    expect(recoveryChoiceReady({ posture: "operator", understood: true, keepNewKey: false }, offer())).toBe(true);
    expect(recoveryChoiceReady({ posture: "operator", understood: true, keepNewKey: false }, offer(true))).toBe(false);
    expect(recoveryChoiceReady({ posture: "operator", understood: true, keepNewKey: true }, offer(true))).toBe(true);
  });
});
