import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { memoryStorage } from "../api/devicesecret";
import type { SettingsSession } from "../vault/settingsflow";
import type { SharedLogSession } from "../vault/sharedlogs";
import { POSTURE_TITLE } from "./copy";
import { RecoveryPostureCard } from "./RecoveryPostureCard";

/** Settings' recovery choice (design §7.7): the offer is made fresh when the card opens, so it first shows a check. */
describe("RecoveryPostureCard", () => {
  it("opens on a check of the offer and shows no choice before it", () => {
    const settings = { opened: { userId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" } } as unknown as SettingsSession;
    const html = renderToStaticMarkup(createElement(RecoveryPostureCard, { settings, shared: {} as SharedLogSession, storage: memoryStorage() }));
    expect(html).toContain(POSTURE_TITLE);
    expect(html).toContain("Checking");
    expect(html).not.toContain('type="radio"');
  });
});
