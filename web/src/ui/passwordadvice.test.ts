import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { hibpPrefix, hibpSha1UpperHex, hibpSuffix } from "../crypto/hibp";
import { BREACH_CHECK_DEBOUNCE_MS, breachWarningFor, createBreachWatch, passwordAdvice } from "./passwordadvice";
import { BREACHED_PASSWORD_WARNING, PATTERN_WARNING } from "./strength";

/**
 * Audit F31, the WIRING half.
 *
 * The estimator, the pattern collapse and `hibpBreachCount` all shipped with tests and none of
 * it reached a user: the breach seam had zero production callers, and the gate and the label
 * became different functions without anyone reconciling what the hint SAYS. These pin the two
 * things a user can actually observe — what the hint decides, and what leaves the device — plus
 * the four call sites, because "the module is correct" was already true when it did nothing.
 */

describe("passwordAdvice — the gate and the label can no longer contradict each other", () => {
  it("a pattern-weak password that CLEARS the floor is never affirmed", () => {
    // The F31 exemplar: raw proxy 4 (so the master-password gate passes, by design — a stricter
    // estimate must never lock someone out of changing their password), pattern-aware 2.
    const a = passwordAdvice("Password1!Password1!", false);
    expect(a.meetsFloor).toBe(true); // still submittable — this warns, it does not block
    expect(a.label).toBe("fair"); // the honest label, not the proxy's "strong"
    expect(a.pattern).toBe(PATTERN_WARNING);
    expect(a.affirmed).toBe(false); // ← the defect: it used to render "strength: fair ✓"
  });

  it("a breached password is not affirmed either, and carries the sentence verbatim", () => {
    const a = passwordAdvice("correct-horse-battery-staple", true);
    expect(a.meetsFloor).toBe(true);
    expect(a.breach).toBe(BREACHED_PASSWORD_WARNING);
    expect(a.affirmed).toBe(false);
  });

  it("a clean, strong password still gets the affirmative treatment", () => {
    const a = passwordAdvice("correct-horse-battery-staple", false);
    expect(a).toMatchObject({ meetsFloor: true, affirmed: true, pattern: null, breach: null, nonAscii: false });
  });

  it("below the floor is a refusal, not a caution — the affirmation is off for a different reason", () => {
    const a = passwordAdvice("hunter2", false);
    expect(a.meetsFloor).toBe(false);
    expect(a.affirmed).toBe(false);
  });

  it("the two roles keep their different floors (strength.ts module doc)", () => {
    // A pattern-weak passphrase clears the MASTER floor (pre-pattern proxy) and misses the
    // BACKUP one (pattern-aware estimate) — deliberately opposite directions.
    expect(passwordAdvice("Password1!Password1!", false, "master").meetsFloor).toBe(true);
    expect(passwordAdvice("Password1!Password1!", false, "backup").meetsFloor).toBe(false);
  });

  it("non-ASCII is reported but never withholds the affirmation (spec 01 §1 SHOULD-warn)", () => {
    const a = passwordAdvice("café-très-long-passphrase-2024", false);
    expect(a.nonAscii).toBe(true);
    expect(a.affirmed).toBe(true);
  });
});

/**
 * The k-anonymity contract, at the seam the UI actually uses. hibp-breach.test.ts pins
 * hibpBreachCount itself; these pin the watcher that decides WHEN it runs and WHOSE answer is
 * allowed to reach the screen — the two places a debounced check goes wrong.
 */
describe("createBreachWatch — one lookup per settled value, prefix only, fail-open", () => {
  const password = "correct horse battery staple";
  // Real timers with an injected 1 ms debounce, not fake ones: hibpBreachCount awaits
  // `crypto.subtle.digest`, which resolves off the libuv threadpool — a fake clock advances the
  // debounce but never the SHA-1, so the lookup would appear never to happen.
  const TEST_DEBOUNCE_MS = 1;
  const settle = () => new Promise((r) => setTimeout(r, 30));

  it("the shipped debounce is a real one — this suite's 1 ms is a test seam, not the default", () => {
    expect(BREACH_CHECK_DEBOUNCE_MS).toBeGreaterThan(100);
  });

  it("sends ONLY the 5-character prefix, once, after the field settles", async () => {
    const hash = await hibpSha1UpperHex(password);
    const seen: string[] = [];
    const results: boolean[] = [];
    const watch = createBreachWatch(
      {
        hibpRange: async (prefix) => {
          seen.push(prefix);
          return `${hibpSuffix(hash)}:42\r\n`;
        },
      },
      (b) => results.push(b),
      TEST_DEBOUNCE_MS,
    );
    // Typing: every keystroke re-arms, so the intermediate values are never looked up.
    for (const n of [4, 10, 20, password.length]) watch.check(password.slice(0, n));
    await settle();

    expect(seen).toEqual([hibpPrefix(hash)]);
    expect(seen[0]).toHaveLength(5);
    expect(seen[0]).not.toBe(hash);
    expect(seen[0]).not.toContain(password.slice(0, 5));
    expect(results.at(-1)).toBe(true);
    watch.stop();
  });

  it("retracts the verdict the moment the password changes, and drops the stale answer", async () => {
    let release: ((body: string) => void) | null = null;
    const results: boolean[] = [];
    const watch = createBreachWatch(
      { hibpRange: () => new Promise<string>((resolve) => { release = resolve; }) },
      (b) => results.push(b),
      TEST_DEBOUNCE_MS,
    );
    watch.check("breached-one");
    await settle();
    // The user keeps typing while that lookup is still in flight.
    watch.check("breached-one-plus");
    expect(results.at(-1)).toBe(false); // the previous password's verdict is withdrawn at once
    // The first lookup now answers "breached" — for a password that is no longer in the field.
    const hash = await hibpSha1UpperHex("breached-one");
    release!(`${hibpSuffix(hash)}:9\r\n`);
    await settle();
    expect(results.at(-1)).toBe(false); // never attributed to the new value
    watch.stop();
  });

  it("an unreachable relay is silent — never a warning, never a throw", async () => {
    const results: boolean[] = [];
    const watch = createBreachWatch(
      { hibpRange: () => Promise.reject(new Error("Failed to fetch")) },
      (b) => results.push(b),
      TEST_DEBOUNCE_MS,
    );
    watch.check(password);
    await settle();
    expect(results.length).toBeGreaterThan(0); // it did run — and said nothing
    expect(results.every((r) => r === false)).toBe(true);
    watch.stop();
  });

  it("an empty field is never looked up, and stop() cancels a pending one", async () => {
    let calls = 0;
    const watch = createBreachWatch(
      { hibpRange: async () => { calls++; return ""; } },
      () => {},
      TEST_DEBOUNCE_MS,
    );
    watch.check("");
    await settle();
    expect(calls).toBe(0);
    watch.check(password);
    watch.stop(); // the field unmounted before the debounce elapsed
    await settle();
    expect(calls).toBe(0);
  });
});

/**
 * The one-shot seam the enrollment re-check uses. Same k-anonymity and fail-open contract as the
 * watch above, minus the debounce — the password it is asked about is already committed, so there
 * is nothing to wait for and no stale answer to guard against.
 */
describe("breachWarningFor — the already-chosen password, prefix only, fail-open", () => {
  const password = "correct horse battery staple";

  it("sends ONLY the 5-character prefix and returns the warning verbatim", async () => {
    const hash = await hibpSha1UpperHex(password);
    const seen: string[] = [];
    const warning = await breachWarningFor(
      {
        hibpRange: async (prefix) => {
          seen.push(prefix);
          return `${hibpSuffix(hash)}:1337\r\n`;
        },
      },
      password,
    );
    expect(seen).toEqual([hibpPrefix(hash)]);
    expect(seen[0]).toHaveLength(5);
    expect(seen[0]).not.toBe(hash);
    expect(seen[0]).not.toContain(password.slice(0, 5));
    expect(warning).toBe(BREACHED_PASSWORD_WARNING);
  });

  it("is silent for a clean password", async () => {
    // A range body that answers, and does not contain this password's suffix.
    expect(await breachWarningFor({ hibpRange: async () => "0000000000000000000000000000000000000:9\r\n" }, password)).toBeNull();
  });

  it("FAILS OPEN: a 401 from the session-gated relay is null, not a rejection", async () => {
    // The exact shape of the gap this closed — a client with no session gets 401 from
    // `GET /api/v1/hibp/range/{prefix}` (App.kt requirePrincipal). Silent, and NOT a rejection:
    // the enroll call site fires this detached, where a rejection would be unhandled.
    await expect(breachWarningFor({ hibpRange: () => Promise.reject(new Error("401")) }, password)).resolves.toBeNull();
    await expect(breachWarningFor({ hibpRange: () => Promise.reject(new Error("Failed to fetch")) }, password)).resolves.toBeNull();
  });

  it("never looks up an empty password", async () => {
    let calls = 0;
    expect(await breachWarningFor({ hibpRange: async () => { calls++; return ""; } }, "")).toBeNull();
    expect(calls).toBe(0);
  });
});

/**
 * The call sites. The whole finding was that `hibpBreachCount` had none, so a module test can
 * never be the proof — pin the four surfaces on their source (the trash-purge/health-rows idiom;
 * these cards read window/module singletons and cannot render in the node env).
 */
describe("F31 — every surface where a master password or backup passphrase is CHOSEN", () => {
  const src = (p: string) => readFileSync(fileURLToPath(new URL(p, import.meta.url)), "utf8");
  const welcome = src("./Welcome.tsx");
  const settings = src("./Settings.tsx");
  const recover = src("./Recover.tsx");
  const exportPanel = src("./ExportPanel.tsx");
  const vault = src("./Vault.tsx");

  it("enrollment, change-password and the recovery reset all pass the relay to the shared hint", () => {
    expect(welcome).toContain("<MasterPasswordHint password={password} client={client} />");
    expect(settings).toContain("<MasterPasswordHint password={next} client={client} />");
    expect(recover).toContain("<MasterPasswordHint password={password} client={client} />");
    // …and all three take it from the one component, so a fix lands on all three at once.
    for (const [name, s] of [["Welcome", welcome], ["Settings", settings], ["Recover", recover]] as const) {
      expect(s, `${name} must import the shared hint`).toContain('from "./passwordadvice"');
    }
  });

  it("web enrollment re-checks the master password once register has handed it a session", () => {
    // The gap this closes: the enroll FORM's live hint talks to a session-gated relay (App.kt
    // requirePrincipal), so it 401s and fails open — a web enrollee choosing a breached master
    // password was the one person these four surfaces never warned, while BOTH natives did
    // (checkEnrolledPasswordForBreach). The re-check must therefore run AFTER the tokens land,
    // or it 401s exactly like the form's did.
    const tokensAt = welcome.indexOf("client.setTokens({ accessToken: s.accessToken");
    const checkAt = welcome.indexOf("void breachWarningFor(client, password)");
    expect(tokensAt).toBeGreaterThan(-1);
    expect(checkAt).toBeGreaterThan(tokensAt);
    // DETACHED — enrollment may never wait on the lookup.
    expect(welcome).not.toContain("await breachWarningFor");
    // …and the verdict is a dismissible advisory on the post-enroll surface, never a gate: it is
    // rendered by the wrapper EVERY branch of the card returns through, so no branch can be held
    // shut by it. (`disabled={…breach…}` is refused for Welcome by the shared pin below.)
    expect(welcome).toMatch(/return withBreachAdvisory\(\s*<RecoveryReveal/);
    expect(welcome).toContain("<BreachAdvisory advisory={breachAdvisory} onDismiss={() => setBreachAdvisory(null)} />");
    // BL-1: the verdict arrives asynchronously, so the visible box needs its polite twin.
    expect(welcome).toContain('<Announcer text={breachAdvisory ?? ""} />');
  });

  it("the backup passphrase is checked too, and Vault hands the panel the client to check with", () => {
    expect(exportPanel).toContain("const breached = useBreachedPassword(pw, client ?? null);");
    expect(exportPanel).toContain('const advice = passwordAdvice(pw, breached, "backup");');
    expect(exportPanel).toContain("<PasswordCautions advice={advice} />");
    expect(vault).toMatch(/<ExportPanel[\s\S]*?client=\{client\}[\s\S]*?\/>/);
  });

  it("the backup bar withholds green for a caution, but never promotes a below-floor passphrase", () => {
    // `!advice.affirmed` alone would paint a score-0 passphrase gold — softer than the red it
    // already earned. The caution is a DEMOTION from the affirmative, so it is gated on the floor.
    expect(exportPanel).toContain("<StrengthBar password={pw} caution={advice.meetsFloor && !advice.affirmed} />");
  });

  it("the item-password bar's divergence from its declared twin is a decision, not drift", () => {
    // Vault's editor bar is the original the export panel copied, and it takes NO `caution`. It
    // renders no caution SENTENCE either — an item password's breach exposure is on demand
    // (HealthLine / the Health panel), not bound to the field — so holding the bar out of green
    // would be a signal with nothing beside it to explain itself. Pinned with the reasoning it
    // carries, because the next reader's instinct will be to "fix" the drift.
    expect(vault).toContain("function StrengthBar({ password }: { password: string }) {");
    expect(vault).toContain("<StrengthBar password={login.password} />");
    expect(vault).toContain("deliberately does NOT take");
  });

  it("nothing on these surfaces blocks on the check — the floors are unchanged", () => {
    // The gates stay exactly what they were; F31 may only add sentences.
    expect(welcome).toContain("const pwStrongEnough = meetsMasterPasswordFloor(password);");
    expect(settings).toContain("const canSubmit = current && meetsMasterPasswordFloor(next) && next === confirm;");
    expect(recover).toContain("const pwStrongEnough = meetsMasterPasswordFloor(password);");
    expect(exportPanel).toContain("const passOk = pw.length > 0 && strength >= BACKUP_FLOOR && pw === confirm;");
    for (const [name, s] of [["Welcome", welcome], ["Settings", settings], ["Recover", recover], ["ExportPanel", exportPanel]] as const) {
      expect(s, `${name} must not gate anything on the breach result`).not.toMatch(/disabled=\{[^}]*breach/i);
    }
  });

  it("the raw password never leaves a surface — only the seam ever sees it", () => {
    // Nothing here may call the relay itself; hibpBreachCount is the only thing that composes a
    // prefix, and it is reached exclusively through the watcher.
    for (const [name, s] of [["Welcome", welcome], ["Settings", settings], ["Recover", recover], ["ExportPanel", exportPanel]] as const) {
      expect(s, `${name} must not hand-roll a range call`).not.toContain("hibpRange(");
    }
  });
});
