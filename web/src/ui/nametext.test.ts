import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { memoryStorage } from "../api/devicesecret";
import { fromB64Canonical, firstRefusedCharacter, plainTextOf, refusedKindOf, textRefusal } from "../crypto/trust/grammar";
import { initSodium } from "../crypto/sodium";
import { verifyCardChain } from "../crypto/trust/instancecard";
import { vector } from "../crypto/trust/vectors";
import { deviceName } from "../vault/account";
import { completeSignup } from "../vault/onboardflow";
import { PinStore } from "../vault/pinstore";
import { fill, NAME_BAD_BROKEN, NAME_BAD_CONTROL, NAME_BAD_DIRECTION, NAME_BAD_INVISIBLE, NAME_BAD_LINE_BREAK, NAME_TOO_LONG } from "./copy";
import { nameText } from "./nametext";

/**
 * Spec 03 §0.1 `text` (server 2026-11-16): display names and device names are refused by the server when they carry a
 * character the shared code refuses in a server's name (core `TrustGrammar.isRefusedNameCodePoint`, one list for every
 * client and the server). This is the web's twin of the shared code's own test (core NameCharactersTest): the same list,
 * compared over every code point with the shared code's source and the server's, and graded against the vector file's
 * name rows. The web checks a typed name before it is sent, says which kind of character it found, and a name it makes
 * up itself drops such characters.
 */
const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));

/** A Kotlin predicate of the form `cp <= 0x1F || cp in 0x7F..0x9F || cp == 0xAD || …`, read from [file] after [head]. */
function kotlinList(file: string, head: string, end: string): (cp: number) => boolean {
  expect(existsSync(file), file).toBe(true);
  const kt = readFileSync(file, "utf8");
  const at = kt.indexOf(head);
  expect(at, `${head} moved: update this reader`).toBeGreaterThanOrEqual(0);
  const body = kt.slice(at, kt.indexOf(end, at));
  const singles = [...body.matchAll(/cp == 0x([0-9A-Fa-f]+)/g)].map((m) => parseInt(m[1]!, 16));
  const ranges = [...body.matchAll(/cp in 0x([0-9A-Fa-f]+)\.\.0x([0-9A-Fa-f]+)/g)].map((m) => [parseInt(m[1]!, 16), parseInt(m[2]!, 16)] as const);
  const le = /cp <= 0x([0-9A-Fa-f]+)/.exec(body);
  expect(le, `${head}: the list's form changed: update this reader`).not.toBeNull();
  expect(singles.length + ranges.length).toBe(10);
  const top = parseInt(le![1]!, 16);
  return (cp) => cp <= top || singles.includes(cp) || ranges.some(([lo, hi]) => cp >= lo && cp <= hi);
}

/** The shared code's list, the one every client and the server keep. */
const shared = () =>
  kotlinList(here("../../../core/src/commonMain/kotlin/io/silencelen/andvari/core/trust/TrustGrammar.kt"), "fun isRefusedNameCodePoint(cp: Int): Boolean =", "/** The longest `text`");
/** The server's own copy, which its parity test checks against the shared one. */
const server = () => kotlinList(here("../../../server/src/main/kotlin/io/silencelen/andvari/server/Grammar.kt"), "fun isRefusedInText(cp: Int): Boolean =", "/** Unpadded canonical base64url");

const ours = (cp: number): boolean => textRefusal(`a${String.fromCodePoint(cp)}b`) === "character";

beforeAll(async () => {
  await initSodium();
});

describe("spec 03 §0.1 text: the web's list is the shared code's, over every code point", () => {
  it("equals core TrustGrammar.isRefusedNameCodePoint and the server's copy at every code point outside the surrogates (99 refused)", () => {
    const core = shared();
    const srv = server();
    const differ: string[] = [];
    let refused = 0;
    for (let cp = 0; cp <= 0x10ffff; cp++) {
      if (cp >= 0xd800 && cp <= 0xdfff) continue; // lone surrogates: below
      const o = ours(cp);
      if (o) refused++;
      if (o !== core(cp) || o !== srv(cp) || (refusedKindOf(cp) !== null) !== o) differ.push(cp.toString(16));
    }
    expect(differ).toEqual([]);
    expect(refused).toBe(99);
  });

  it("is graded against the vector file's name rows: every valid name is text, and a name refused for a character is refused in text for the same one", () => {
    const rows = (vector("encodings.json") as unknown as { name: { why: string; name: string; textHex?: string; valid: boolean }[] }).name;
    const core = shared();
    let graded = 0;
    for (const row of rows) {
      if (row.textHex === undefined) continue;
      const bytes = Uint8Array.from(row.textHex.match(/../g) ?? [], (h) => parseInt(h, 16));
      let text: string;
      try {
        text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
      } catch {
        continue; // a row about the UTF-8 encoding, not about characters
      }
      if (fromB64Canonical(row.name) === null && row.name !== "") continue; // a row about the base64url form
      graded++;
      const listed = [...text].some((ch) => core(ch.codePointAt(0)!));
      if (row.valid) expect(textRefusal(text), row.why).toBeNull();
      else if (listed) {
        expect(textRefusal(text), row.why).toBe("character");
        expect(nameText(text), row.why).not.toBeNull();
      } else if (text.length === 0) expect(textRefusal(text), row.why).toBe("empty");
      // Otherwise the row is refused as a name only for what text allows: spaces at either end, more than 64 bytes.
      else {
        expect(row.why, row.why).toMatch(/U\+0020|65 bytes/);
        expect(textRefusal(text), row.why).toBeNull();
      }
    }
    expect(graded).toBeGreaterThanOrEqual(60);
  });

  it("lone surrogates, the length bound, spaces, other scripts and emoji", () => {
    expect(textRefusal("a\ud800b")).toBe("character");
    expect(textRefusal("a\udc00")).toBe("character");
    expect(textRefusal("😀 face")).toBeNull();
    expect(textRefusal("👨\u200D👩\u200D👧")).toBe("character"); // U+200D is on the list
    expect(textRefusal(" Ana María ")).toBeNull(); // spaces anywhere
    expect(textRefusal("Θεόδωρος 山田 Иван عمر")).toBeNull();
    expect(textRefusal("x".repeat(256))).toBeNull();
    expect(textRefusal("x".repeat(257))).toBe("too_long");
    expect(textRefusal("😀".repeat(128))).toBeNull(); // 256 UTF-16 characters
    expect(textRefusal("😀".repeat(128) + "x")).toBe("too_long");
    expect(textRefusal("")).toBe("empty");
  });
});

describe("spec 03 §0.1 text: the person is told which kind of character, before anything is sent", () => {
  it("each kind has its own sentence, naming the code point", () => {
    expect(nameText("Dana\tWork")).toBe(fill(NAME_BAD_CONTROL, "U+0009"));
    expect(nameText("Dana\u0085")).toBe(fill(NAME_BAD_CONTROL, "U+0085"));
    expect(nameText("Dana\u2028Work")).toBe(fill(NAME_BAD_LINE_BREAK, "U+2028"));
    expect(nameText("Dana\u202Eevil")).toBe(fill(NAME_BAD_DIRECTION, "U+202E"));
    expect(nameText("Dana\u2067x")).toBe(fill(NAME_BAD_DIRECTION, "U+2067"));
    expect(nameText("\u061CDana")).toBe(fill(NAME_BAD_DIRECTION, "U+061C"));
    expect(nameText("Dana\u200B")).toBe(fill(NAME_BAD_INVISIBLE, "U+200B"));
    expect(nameText("Da\u00ADna")).toBe(fill(NAME_BAD_INVISIBLE, "U+00AD"));
    expect(nameText("\uFEFFDana")).toBe(fill(NAME_BAD_INVISIBLE, "U+FEFF"));
    expect(nameText("Dana\ud83d")).toBe(NAME_BAD_BROKEN);
    expect(nameText("x".repeat(300))).toBe(NAME_TOO_LONG);
    expect(nameText("Dana")).toBeNull();
    // The first refused character decides, whatever follows.
    expect(firstRefusedCharacter("a\u200Bb\u202E")).toEqual({ kind: "invisible", cp: 0x200b });
    // No sentence carries a refusal code.
    for (const s of [NAME_BAD_CONTROL, NAME_BAD_LINE_BREAK, NAME_BAD_DIRECTION, NAME_BAD_INVISIBLE, NAME_BAD_BROKEN]) expect(s).not.toMatch(/bad_|_name|_device/);
  });

  it("sign-up refuses such a name itself and sends nothing, the display name and the device name alike", async () => {
    const rec = vector("recovery.json");
    const frames = rec.cardChains["rotated-once"].frames as string[];
    const origin = verifyCardChain(frames.map((f) => fromB64Canonical(f)!)).cards[0]!.fields.origin;
    const pins = new PinStore(memoryStorage(), async () => ({ cards: frames, rotations: [rec.rotationFrames["A-to-B"]] }), null);
    const g = await pins.begin(origin);
    if (g.kind !== "needs_trust_gate") throw new Error(g.kind);
    pins.confirmTrustGate(g.ticket);
    const calls: string[] = [];
    const wire = new Proxy({}, { get: (_t, name) => (typeof name === "string" && name !== "then" ? async () => { calls.push(name); throw new Error(`sent: ${name}`); } : undefined) });
    const base = { wire: wire as never, pins, origin, pin: pins.pinFor(origin)!, policy: {} as never, email: "dana@example.org", password: "correct horse Battery 9 staple", signupTicket: "t", ageConfirmed: true, nowMs: 1 };
    expect(await completeSignup({ ...base, displayName: "Dana\u202E", deviceName: "Firefox on Linux" })).toEqual({ kind: "name", field: "displayName", refusal: "character" });
    expect(await completeSignup({ ...base, displayName: "Dana", deviceName: "Firefox\u0007" })).toEqual({ kind: "name", field: "deviceName", refusal: "character" });
    expect(await completeSignup({ ...base, displayName: "x".repeat(257), deviceName: "Firefox" })).toEqual({ kind: "name", field: "displayName", refusal: "too_long" });
    expect(calls).toEqual([]);
    // The screen checks first and shows the sentence; a result of kind "name" shows it too, never the server's code.
    const welcome = readFileSync(here("./Welcome.tsx"), "utf8");
    const register = welcome.slice(welcome.indexOf("const register = async"), welcome.indexOf("if (step.kind === \"record\")", welcome.indexOf("const register = async")));
    expect(register).toContain("const nameRefused = nameText(displayName.trim() || email.trim());");
    expect(register.indexOf("if (nameRefused !== null) return setErr(nameRefused);")).toBeLessThan(register.indexOf("setBusy(true)"));
    expect(register).toContain('case "name":');
  });

  it("a name the browser makes up drops such characters", () => {
    expect(plainTextOf("Chrome\u200B on\u202E Linux\u0007")).toBe("Chrome on Linux");
    expect(plainTextOf("a\ud800b😀")).toBe("ab😀");
    for (const ua of [
      "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
      "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/120.0 Mobile/15E148 Safari/604.1",
      "",
    ]) {
      expect(textRefusal(deviceName(ua || null)), ua).toBeNull();
    }
    const account = readFileSync(here("../vault/account.ts"), "utf8");
    expect(account).toContain('return plainTextOf(os ? `${browser} on ${os}` : browser).slice(0, 256) || "Web browser";');
  });
});
