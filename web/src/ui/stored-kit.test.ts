import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createElement, type ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeAll, describe, expect, it } from "vitest";
import { initSodium } from "../crypto/sodium";
import { kitGroups } from "../crypto/trust/recoverykit";
import type { WebPin } from "../vault/pinstore";
import {
  IDENTITY_FAULT,
  KIT_IDLE_WARNING,
  KIT_RECOVERY_STORED_KIT_GONE,
  KIT_RECOVERY_STORED_UNCHECKED,
  KIT_RECOVERY_UNKNOWN,
  KIT_RECOVERY_UNKNOWN_KIT_GONE,
  KIT_RECOVERY_UNKNOWN_SERVER_ERROR,
  KIT_RECOVERY_UNKNOWN_UNREADABLE,
  SIGNUP_STORED_KIT_GONE,
  SIGNUP_STORED_UNCHECKED,
  SIGNUP_UNKNOWN,
  SIGNUP_UNKNOWN_KIT_GONE,
  SIGNUP_UNKNOWN_SERVER_ERROR,
  SIGNUP_UNKNOWN_UNREADABLE,
} from "./copy";
import { KIT_IDLE_SECONDS, KitCard, KitIdleWarning, StoredKitCard } from "./KitCard";

/**
 * A registration or a kit recovery the server stored, whose answer this browser then refused: the kit the server holds is
 * shown with its own line before anything is wiped, never the identity fault's line.
 */
const unescape = (s: string) => s.replace(/&#x27;/g, "'").replace(/&quot;/g, '"').replace(/&amp;/g, "&");
const pin = { origin: "https://vault.example.org", card0Hash: "a".repeat(64), name: "RmFtaWx5", kind: "private" } as unknown as WebPin;

describe("the kit of a stored write this browser refused", () => {
  beforeAll(async () => {
    await initSodium();
  });

  const card = (secret: Uint8Array, line: string, gone: string, seen: string[]) => {
    const c = StoredKitCard({ line, gone, kit: { secret, pieceId: null }, email: "gil@example.org", pin, accountId: "abcd-efgh", onSeen: (stays) => void seen.push(stays) }) as ReactElement<{ children: ReactElement[] }>;
    return c.props.children.find((x) => x.type === KitCard) as ReactElement<{ secret: Uint8Array; onConfirmed: () => void; onTimeout: () => void }>;
  };

  it("is wiped only on its way out: typed back, and then its line is said alone", () => {
    const secret = new Uint8Array(32).map((_, i) => i + 1);
    const seen: string[] = [];
    const kitCard = card(secret, KIT_RECOVERY_UNKNOWN, KIT_RECOVERY_UNKNOWN_KIT_GONE, seen);
    expect(kitCard.props.secret).toBe(secret);
    expect(secret.every((x) => x !== 0)).toBe(true);
    expect(seen).toEqual([]);
    kitCard.props.onConfirmed(); // the groups typed back matched (KitCard's confirmMatches)
    expect(secret.every((x) => x === 0)).toBe(true);
    expect(seen).toEqual([KIT_RECOVERY_UNKNOWN]);
  });

  it("taken off the screen by the idle limit, it is wiped and the line that stays says so, never to keep a kit no longer shown", () => {
    const secret = new Uint8Array(32).map((_, i) => i + 1);
    const seen: string[] = [];
    card(secret, KIT_RECOVERY_STORED_UNCHECKED, KIT_RECOVERY_STORED_KIT_GONE, seen).props.onTimeout();
    expect(secret.every((x) => x === 0)).toBe(true);
    expect(seen).toEqual([KIT_RECOVERY_STORED_KIT_GONE]);
    // Each flow and outcome has a line of its own for it.
    const gone = [KIT_RECOVERY_STORED_KIT_GONE, KIT_RECOVERY_UNKNOWN_KIT_GONE, SIGNUP_STORED_KIT_GONE, SIGNUP_UNKNOWN_KIT_GONE];
    expect(new Set(gone).size).toBe(4);
    for (const g of gone) expect([KIT_RECOVERY_STORED_UNCHECKED, KIT_RECOVERY_UNKNOWN, SIGNUP_STORED_UNCHECKED, SIGNUP_UNKNOWN]).not.toContain(g);
  });

  it("the warning names only what resets the limit: the limit counts a click, a tap or a key, never the pointer's movement", () => {
    const src = readFileSync(fileURLToPath(new URL("./useAutoLock.ts", import.meta.url)), "utf8");
    const events = [...src.matchAll(/window\.addEventListener\("([a-z]+)"/g)].map((m) => m[1]);
    expect(new Set(events)).toEqual(new Set(["pointerdown", "keydown", "touchstart"]));
    // Moving the pointer resets nothing, so the warning never tells the person to.
    expect(KIT_IDLE_WARNING).not.toMatch(/\bmov(e|es|ing)\b/i);
  });

  it("the idle limit warns before it acts, on every kit screen", () => {
    expect(unescape(renderToStaticMarkup(createElement(KitIdleWarning, { active: true })))).toContain(KIT_IDLE_WARNING);
    expect(unescape(renderToStaticMarkup(createElement(KitIdleWarning, { active: false })))).not.toContain(KIT_IDLE_WARNING);
    // KitCard keeps useAutoLock's warning and shows it on both of its steps (the kit shown, and the groups typed back).
    const src = readFileSync(fileURLToPath(new URL("./KitCard.tsx", import.meta.url)), "utf8");
    const body = src.slice(src.indexOf("export function KitCard("), src.indexOf("export function KitIdleWarning("));
    expect(body).toContain("const idleWarning = useAutoLock(KIT_IDLE_SECONDS, onTimeout);");
    expect(body.split("{warning}").length - 1).toBe(2);
    // The limit is long enough for the timer to warn ahead of it (a window of a minute or less gets no warning).
    expect(KIT_IDLE_SECONDS).toBeGreaterThan(60);
  });

  for (const line of [KIT_RECOVERY_STORED_UNCHECKED, SIGNUP_STORED_UNCHECKED, KIT_RECOVERY_UNKNOWN, KIT_RECOVERY_UNKNOWN_SERVER_ERROR, KIT_RECOVERY_UNKNOWN_UNREADABLE, SIGNUP_UNKNOWN, SIGNUP_UNKNOWN_SERVER_ERROR, SIGNUP_UNKNOWN_UNREADABLE]) {
    it(`is shown whole, under its own line (${line.slice(0, 40)}…)`, () => {
      const secret = new Uint8Array(32).map((_, i) => i + 1);
      const html = unescape(renderToStaticMarkup(createElement(StoredKitCard, { line, gone: KIT_RECOVERY_UNKNOWN_KIT_GONE, kit: { secret, pieceId: null }, email: "gil@example.org", pin, accountId: "abcd-efgh", onSeen: () => {} })));
      expect(html).toContain(line);
      expect(html).not.toContain(IDENTITY_FAULT);
      for (const g of kitGroups(secret)) expect(html).toContain(g);
      expect(html).toContain("gil@example.org");
      // Showing it wipes nothing: the secret goes only on the way out (typed back, or the idle cap).
      expect(secret.every((x) => x !== 0)).toBe(true);
      expect(html.indexOf(line)).toBeLessThan(html.indexOf(kitGroups(secret)[0]!));
    });
  }
});
