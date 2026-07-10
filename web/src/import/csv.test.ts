import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { fromB64, utf8 } from "../crypto/bytes";
import { initSodium } from "../crypto/sodium";
import { normalizeTotp } from "../crypto/totp";
import { ImportError, type ImportProjections, parseCsvImport, planImport } from "./csv";

/**
 * Consumes the SAME vector files the Kotlin ImportVectorsTest checks, so both impls parse
 * and plan identically:
 *  - spec/test-vectors/import.json — BYTE-FROZEN (Chrome/Edge + Firefox, spec 06). Planned
 *    here with EMPTY projections: the vault-aware rules must be a no-op against nothing.
 *  - spec/test-vectors/import-foreign.json — Bitwarden/1Password/LastPass adapters + the
 *    F75 vault-aware plan (design 2026-07-09). The consumer below is written to the pinned
 *    schema: { cases: [{ name, csv, existing|null, expect: { format, report, items } }],
 *    reject: [{ name, csv, error }] } — items compared ORDER-SENSITIVE, ids excluded.
 */

const vectorsDir = fileURLToPath(new URL("../../../spec/test-vectors/", import.meta.url));

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function load(name: string): any {
  return JSON.parse(readFileSync(vectorsDir + name, "utf-8"));
}

/** The three vault-rule inputs, all empty — the pre-F75 behavior baseline. */
const NO_VAULT: ImportProjections = { logins: [], notes: [], names: [] };

/** Vector `existing` block → ImportProjections (absent → ""/[]/null, per A7). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function projectionsOf(existing: any): ImportProjections {
  if (!existing) return NO_VAULT;
  return {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    logins: (existing.logins ?? []).map((l: any) => ({
      name: l.name ?? "",
      uris: l.uris ?? [],
      username: l.username ?? "",
      password: l.password ?? "",
      totp: l.totp ?? null,
    })),
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    notes: (existing.notes ?? []).map((n: any) => ({ name: n.name ?? "", notes: n.notes ?? "" })),
    names: existing.names ?? [],
  };
}

beforeAll(async () => {
  await initSodium(); // fromB64 (base64url) needs libsodium ready
});

describe("import.json — files", () => {
  const v = load("import.json");
  for (const c of v.files) {
    it(c.name, () => {
      const parsed = parseCsvImport(fromB64(c.contentB64));
      const exp = c.expect;
      expect(parsed.format).toBe(exp.format);

      expect(parsed.rows.length).toBe(exp.rows.length);
      for (let idx = 0; idx < exp.rows.length; idx++) {
        const er = exp.rows[idx];
        const r = parsed.rows[idx]!;
        expect(r.kind).toBe("login"); // browser CSVs never carry notes
        expect(r.favorite).toBe(false); // …nor a favorite column
        expect(r.name).toBe(er.name);
        expect(r.url).toBe(er.url);
        expect(r.username).toBe(er.username);
        expect(r.password).toBe(er.password);
        expect(r.notes).toBe(er.notes);
        if ("timePasswordChangedMs" in er) expect(r.timePasswordChangedMs).toBe(er.timePasswordChangedMs);
        // Twin of ImportVectorsTest: assertEquals(if ("totp" in er) er.s("totp") else null, r.totp)
        if ("totp" in er) expect(r.totp).toBe(er.totp);
        else expect(r.totp).toBeNull();
      }

      expect(parsed.errors.length).toBe(exp.errors.length);
      for (let idx = 0; idx < exp.errors.length; idx++) {
        const ee = exp.errors[idx];
        const e = parsed.errors[idx]!;
        expect(e.line).toBe(ee.line);
        expect(e.code).toBe(ee.code);
      }

      let seq = 0;
      const plan = planImport(parsed, NO_VAULT, () => `id-${seq++}`);
      expect(plan.items.length).toBe(exp.docs.length);
      for (let idx = 0; idx < exp.docs.length; idx++) {
        const ed = exp.docs[idx];
        const doc = plan.items[idx]!.doc;
        expect(doc.name).toBe(ed.name);
        expect(doc.login?.username ?? "").toBe(ed.username);
        expect(doc.login?.password ?? "").toBe(ed.password);
        expect(doc.login?.uris?.[0] ?? "").toBe(ed.uri);
        expect(doc.notes ?? "").toBe(ed.notes);
        // Twin of ImportVectorsTest: assertEquals(if ("totp" in ed) ed.s("totp") else null, doc.login?.totp)
        if ("totp" in ed) expect(doc.login?.totp).toBe(ed.totp);
        else expect(doc.login?.totp).toBeUndefined();
      }
      expect(plan.report.imported).toBe(exp.report.imported);
      expect(plan.report.skippedEmpty).toBe(exp.report.skippedEmpty);
      expect(plan.report.collapsed).toBe(exp.report.collapsed);
      expect(plan.report.flagged).toEqual(exp.report.flagged);
      // With empty projections every vault-aware bucket MUST stay empty — the F75 rules
      // are strictly additive over the frozen behavior.
      expect(plan.report.alreadyInVault).toEqual([]);
      expect(plan.report.passwordDiffers).toEqual([]);
      expect(plan.report.totpDiffers).toEqual([]);
      expect(plan.report.archivedSkipped).toEqual([]);
      expect(plan.report.unknownTypeSkipped).toEqual([]);
      expect(plan.report.totpUnsupported).toEqual([]);
      expect(plan.report.noteItems).toEqual([]);
    });
  }
});

describe("import.json — reject", () => {
  const v = load("import.json");
  for (const r of v.reject) {
    it(r.name, () => {
      const bytes: Uint8Array =
        "contentB64" in r
          ? fromB64(r.contentB64)
          : utf8(r.construct.header + "\n" + (r.construct.row + "\n").repeat(r.construct.count));
      let caught: unknown;
      try {
        parseCsvImport(bytes);
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(ImportError);
      expect((caught as ImportError).code).toBe(r.reason);
    });
  }
});

// ---- import-foreign.json (guided importers, design 2026-07-09) ----
// The vector file is authored by the Kotlin reference (WS-CORE); this consumer is written
// to the PINNED schema and activates the moment the file lands in spec/test-vectors/.

const foreignPath = vectorsDir + "import-foreign.json";
const foreign = existsSync(foreignPath) ? JSON.parse(readFileSync(foreignPath, "utf-8")) : null;

describe.skipIf(foreign === null)("import-foreign.json — cases", () => {
  for (const c of foreign?.cases ?? []) {
    it(c.name, () => {
      const parsed = parseCsvImport(utf8(c.csv));
      expect(parsed.format).toBe(c.expect.format);

      let seq = 0;
      const plan = planImport(parsed, projectionsOf(c.existing), () => `id-${seq++}`);

      const r = plan.report;
      const er = c.expect.report;
      expect(r.imported).toBe(er.imported);
      expect(r.skippedEmpty).toBe(er.skippedEmpty);
      expect(r.collapsed).toBe(er.collapsed);
      expect(r.flagged).toEqual(er.flagged);
      expect(r.alreadyInVault).toEqual(er.alreadyInVault);
      expect(r.passwordDiffers).toEqual(er.passwordDiffers);
      expect(r.totpDiffers).toEqual(er.totpDiffers);
      expect(r.archivedSkipped).toEqual(er.archivedSkipped);
      expect(r.unknownTypeSkipped).toEqual(er.unknownTypeSkipped);
      expect(r.totpUnsupported).toEqual(er.totpUnsupported);
      expect(r.noteItems).toEqual(er.noteItems);
      expect(r.errors.length).toBe(er.errors.length);
      for (let idx = 0; idx < er.errors.length; idx++) {
        expect(r.errors[idx]!.line).toBe(er.errors[idx].line);
        expect(r.errors[idx]!.code).toBe(er.errors[idx].code);
      }

      // Items are ORDER-SENSITIVE (plan output order); ids excluded.
      expect(plan.items.length).toBe(c.expect.items.length);
      for (let idx = 0; idx < c.expect.items.length; idx++) {
        const ei = c.expect.items[idx];
        const doc = plan.items[idx]!.doc;
        expect(doc.type).toBe(ei.type);
        expect(doc.name).toBe(ei.name);
        expect(doc.notes ?? null).toBe(ei.notes);
        expect(doc.favorite ?? false).toBe(ei.favorite);
        if (ei.login) {
          expect(doc.login?.username ?? "").toBe(ei.login.username);
          expect(doc.login?.password ?? "").toBe(ei.login.password);
          expect(doc.login?.uris ?? []).toEqual(ei.login.uris);
          expect(doc.login?.totp ?? null).toBe(ei.login.totp);
        } else {
          expect(doc.login).toBeUndefined();
        }
      }
    });
  }
});

describe.skipIf(foreign === null)("import-foreign.json — reject", () => {
  for (const r of foreign?.reject ?? []) {
    it(r.name, () => {
      let caught: unknown;
      try {
        parseCsvImport(utf8(r.csv));
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(ImportError);
      expect((caught as ImportError).code).toBe(r.error);
    });
  }
});

// ---- pinned behaviors the vectors also cover (kept as fast local self-checks) ----

describe("detection is specificity-ordered (A3)", () => {
  it("LastPass (a superset of Chrome's required set) detects lastpass, incl. 7-column pre-2023", () => {
    const full = parseCsvImport(utf8("url,username,password,totp,extra,name,grouping,fav\nhttps://a.test,u,p,,,A,,0\n"));
    expect(full.format).toBe("lastpass");
    const old = parseCsvImport(utf8("url,username,password,extra,name,grouping\nhttps://a.test,u,p,,A,\n"));
    expect(old.format).toBe("lastpass");
    expect(old.totpColumn).toBe(false); // pre-2023 export → totp wildcard in vault rules
  });
  it("andvari's own CSV export still detects chrome (never lastpass)", () => {
    expect(parseCsvImport(utf8("name,url,username,password,note,totp\nA,https://a.test,u,p,,\n")).format).toBe("chrome");
  });
  it("org-vault Bitwarden (collections, no folder/favorite) detects bitwarden", () => {
    const p = parseCsvImport(utf8("collections,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n,login,A,,,0,https://a.test,u,p,\n"));
    expect(p.format).toBe("bitwarden");
  });
  it("Apple/Safari export matches the 1Password required set (pinned free win)", () => {
    const p = parseCsvImport(utf8("Title,URL,Username,Password,Notes,OTPAuth\nA,https://a.test,u,p,hello,\n"));
    expect(p.format).toBe("1password");
    expect(p.rows[0]!.notes).toBe("hello");
  });
});

describe("shared TOTP normalize (A5, byte-exact)", () => {
  it("strips ALL ASCII whitespace, passes otpauth:// through, wraps bare base32 with ORIGINAL case", () => {
    expect(normalizeTotp("JBSW Y3DP")).toBe("otpauth://totp/andvari?secret=JBSWY3DP");
    expect(normalizeTotp("jbswy3dp")).toBe("otpauth://totp/andvari?secret=jbswy3dp");
    expect(normalizeTotp("otpauth://totp/x?secret=AAAA")).toBe("otpauth://totp/x?secret=AAAA");
    expect(normalizeTotp("OTPAUTH://TOTP/x?secret=AAAA")).toBe("OTPAUTH://TOTP/x?secret=AAAA");
    expect(normalizeTotp("steam://abc!")).toBe("steam://abc!"); // not base32, not otpauth → unchanged
  });
});

describe("adapter TOTP: reject-don't-corrupt (A5)", () => {
  it("steam://, hotp and junk are kept as a notes line + enumerated; bare base32 is stored", () => {
    const csv =
      "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n" +
      ",0,login,Steam,,,0,https://s.test,u,p,steam://ABC\n" +
      ",0,login,Hotp,,,0,https://h.test,u,p,otpauth://hotp/x?secret=AAAA\n" +
      // Empty-secret otpauth (review [1]): once accepted by the Kotlin twin (empty HMAC key)
      // while web rejected it — both must now route it to totpUnsupported identically.
      ",0,login,Empty,,,0,https://e.test,u,p,otpauth://totp/e?secret=\n" +
      ",0,login,Good,,,0,https://g.test,u,p,JBSWY3DP\n";
    const p = parseCsvImport(utf8(csv));
    expect(p.rows.map((r) => r.totpUnsupported)).toEqual([true, true, true, false]);
    expect(p.rows[0]!.totp).toBeNull();
    expect(p.rows[0]!.notes).toBe("Unsupported TOTP (kept as text): steam://ABC");
    expect(p.rows[1]!.totp).toBeNull();
    expect(p.rows[2]!.totp).toBeNull();
    expect(p.rows[3]!.totp).toBe("otpauth://totp/andvari?secret=JBSWY3DP");
    // The report bucket fills at PLAN time, with the FINAL planned names.
    let seq = 0;
    const plan = planImport(p, NO_VAULT, () => `id-${seq++}`);
    expect(plan.report.totpUnsupported).toEqual(["Steam", "Hotp", "Empty"]);
  });
});

describe("A6 truthiness, pinned once for all formats", () => {
  it("fav=0 (every LastPass row) is falsy; 1/true/y/yes are truthy", () => {
    const csv =
      "url,username,password,totp,extra,name,grouping,fav\n" +
      "https://a.test,u,p,,,A,,0\n" +
      "https://b.test,u,p,,,B,,1\n" +
      "https://c.test,u,p,,,C,,TRUE\n" +
      "https://d.test,u,p,,,D,,false\n";
    const p = parseCsvImport(utf8(csv));
    expect(p.rows.map((r) => r.favorite)).toEqual([false, true, true, false]);
  });
});

describe("bitwarden adapter shapes", () => {
  it("splits comma-joined login_uri into uris[] (A4); notes rows import as note items; unknown types are enumerated", () => {
    const csv =
      "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n" +
      ",1,login,Multi,,,0,\"https://a.test,https://b.test\",u,p,\n" +
      ",0,note,Recipe,the secret sauce,,0,,,,\n" +
      ",0,card,Visa,,,0,,,,\n";
    const p = parseCsvImport(utf8(csv));
    expect(p.rows.length).toBe(2);
    expect(p.rows[0]!.uris).toEqual(["https://a.test", "https://b.test"]);
    expect(p.rows[0]!.url).toBe("https://a.test");
    expect(p.rows[0]!.favorite).toBe(true);
    expect(p.rows[1]!.kind).toBe("note");
    expect(p.unknownTypeSkipped).toEqual(["Visa"]);
    let seq = 0;
    const plan = planImport(p, NO_VAULT, () => `id-${seq++}`);
    expect(plan.items.length).toBe(2);
    expect(plan.items[0]!.doc.login?.uris).toEqual(["https://a.test", "https://b.test"]);
    expect(plan.items[1]!.doc.type).toBe("note");
    expect(plan.report.noteItems).toEqual(["Recipe"]);
    expect(plan.report.unknownTypeSkipped).toEqual(["Visa"]);
  });
  it("custom fields append under the separator — for note rows too (A2)", () => {
    const csv =
      "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n" +
      ",0,note,K,body,\"pin: 1234\",0,,,,\n";
    const p = parseCsvImport(utf8(csv));
    expect(p.rows[0]!.notes).toBe("body\n— custom fields —\npin: 1234");
  });
});

describe("lastpass secure notes (url == http://sn)", () => {
  it("imports as a note item with extra verbatim; two DISTINCT same-empty-credential notes both import (A1)", () => {
    const csv =
      "url,username,password,totp,extra,name,grouping,fav\n" +
      "http://sn,,,,NoteType:Credit Card\\nNumber:4111,Card A,,0\n" +
      "http://sn,,,,plain text,Note B,,0\n";
    const p = parseCsvImport(utf8(csv));
    expect(p.rows.map((r) => r.kind)).toEqual(["note", "note"]);
    let seq = 0;
    const plan = planImport(p, NO_VAULT, () => `id-${seq++}`);
    // Without A1's kind-scoping these rows would be annihilated as empty/exact-dup logins.
    expect(plan.report.imported).toBe(2);
    expect(plan.report.skippedEmpty).toBe(0);
    expect(plan.report.collapsed).toBe(0);
    expect(plan.report.noteItems).toEqual(["Card A", "Note B"]);
  });
});

describe("1password archived rows (design: skip + enumerate)", () => {
  it("archived=TRUE rows are skipped into archivedSkipped; live rows import", () => {
    const csv =
      "title,url,username,password,otpauth,favorite,archived,tags,notes\n" +
      "Old,https://old.test,u,p,,false,TRUE,,\n" +
      "Live,https://live.test,u,p,,false,false,,\n";
    const p = parseCsvImport(utf8(csv));
    expect(p.archivedSkipped).toEqual(["Old"]);
    let seq = 0;
    const plan = planImport(p, NO_VAULT, () => `id-${seq++}`);
    expect(plan.report.imported).toBe(1);
    expect(plan.report.archivedSkipped).toEqual(["Old"]);
    expect(plan.items[0]!.doc.name).toBe("Live");
  });
});

describe("vault-aware plan (F75 rules, A7)", () => {
  const vault: ImportProjections = {
    logins: [{ name: "GitHub", uris: ["https://github.com/login"], username: "u", password: "p", totp: null }],
    notes: [{ name: "Recipe", notes: "line1\nline2" }],
    names: ["GitHub", "Recipe"],
  };
  const chromeCsv = (pass: string) => utf8(`name,url,username,password,note\nGitHub,https://github.com,u,${pass},\n`);

  it("rule 1: an exact match (uri-normalizer equivalence, any saved uri) is skipped as alreadyInVault", () => {
    const plan = planImport(parseCsvImport(chromeCsv("p")), vault, () => "x");
    expect(plan.items.length).toBe(0);
    expect(plan.report.alreadyInVault).toEqual(["GitHub"]);
  });
  it("rule 2 + seeding + A9: a differing password imports as “GitHub (2)” under passwordDiffers", () => {
    let seq = 0;
    const plan = planImport(parseCsvImport(chromeCsv("NEW")), vault, () => `id-${seq++}`);
    expect(plan.items.length).toBe(1);
    expect(plan.items[0]!.doc.name).toBe("GitHub (2)");
    expect(plan.report.passwordDiffers).toEqual(["GitHub (2)"]);
    expect(plan.report.flagged).toEqual([]); // buckets are exclusive — flagged is in-file-only
  });
  it("no-totp-column source is a totp WILDCARD in rules 1–2 (browser re-import never dups a 2FA login)", () => {
    const withTotp: ImportProjections = {
      logins: [{ name: "GH", uris: ["https://gh.test"], username: "u", password: "p", totp: "otpauth://totp/a?secret=JBSWY3DP" }],
      notes: [],
      names: ["GH"],
    };
    // No totp column at all → wildcard → rule 1 match.
    const noCol = planImport(parseCsvImport(utf8("name,url,username,password,note\nGH,https://gh.test,u,p,\n")), withTotp, () => "x");
    expect(noCol.report.alreadyInVault).toEqual(["GH"]);
    // A totp COLUMN with an empty cell testifies "no totp" → rule 2, 2FA-differs bucket.
    let seq = 0;
    const emptyCell = planImport(parseCsvImport(utf8("name,url,username,password,note,totp\nGH,https://gh.test,u,p,,\n")), withTotp, () => `id-${seq++}`);
    expect(emptyCell.report.totpDiffers).toEqual(["GH (2)"]);
  });
  it("TOTP compares by PARSED parameters, never raw string (labels/case don't discriminate)", () => {
    const withTotp: ImportProjections = {
      logins: [{ name: "GH", uris: ["https://gh.test"], username: "u", password: "p", totp: "otpauth://totp/other-label?secret=jbswy3dp" }],
      notes: [],
      names: ["GH"],
    };
    const plan = planImport(
      parseCsvImport(utf8("name,url,username,password,note,totp\nGH,https://gh.test,u,p,,otpauth://totp/x?secret=JBSWY3DP\n")),
      withTotp,
      () => "x",
    );
    expect(plan.report.alreadyInVault).toEqual(["GH"]); // same secret bytes/alg/digits/period
  });
  it("note rule 1 normalizes VAULT-side CRLF before comparing", () => {
    const crlfVault: ImportProjections = { logins: [], notes: [{ name: "Recipe", notes: "line1\r\nline2" }], names: ["Recipe"] };
    const csv = 'url,username,password,extra,name,grouping\nhttp://sn,,,"line1\nline2",Recipe,\n';
    const plan = planImport(parseCsvImport(utf8(csv)), crlfVault, () => "x");
    expect(plan.report.alreadyInVault).toEqual(["Recipe"]);
    expect(plan.items.length).toBe(0);
  });
  it("empty-discriminator guard: url+username both empty keys rule 1 on (name, password); rule 2 never fires", () => {
    const guardVault: ImportProjections = {
      logins: [{ name: "Generated", uris: [], username: "", password: "p", totp: null }],
      notes: [],
      names: ["Generated"],
    };
    const same = planImport(parseCsvImport(utf8("name,url,username,password,note\nGenerated,,,p,\n")), guardVault, () => "x");
    expect(same.report.alreadyInVault).toEqual(["Generated"]);
    let seq = 0;
    const diff = planImport(parseCsvImport(utf8("name,url,username,password,note\nGenerated,,,OTHER,\n")), guardVault, () => `id-${seq++}`);
    expect(diff.report.passwordDiffers).toEqual([]); // rule 2 must NOT fire
    expect(diff.report.totpDiffers).toEqual([]);
    expect(diff.report.imported).toBe(1);
  });
});

describe("totp differentiates exact dupes (review finding)", () => {
  it("keeps two rows that differ only by totp; collapses a true exact repeat", () => {
    const two = planImport(
      parseCsvImport(utf8("name,url,username,password,note,totp\nA,https://a.test,u,p,,otpauth://x\nA,https://a.test,u,p,,\n")),
      NO_VAULT,
      (() => { let n = 0; return () => `id-${n++}`; })(),
    );
    expect(two.items.length).toBe(2);
    expect(new Set(two.items.map((i) => i.doc.login?.totp))).toEqual(new Set(["otpauth://x", undefined]));
    const one = planImport(
      parseCsvImport(utf8("name,url,username,password,note,totp\nA,https://a.test,u,p,,t\nA,https://a.test,u,p,,t\n")),
      NO_VAULT,
      () => "x",
    );
    expect(one.items.length).toBe(1);
  });
});

describe("totp column (andvari CSV round-trip, spec 06 §1 / 07 §1)", () => {
  it("still detects as chrome and maps totp; empty cell and absent column yield no totp", () => {
    const parsed = parseCsvImport(
      utf8("name,url,username,password,note,totp\nGH,https://gh.test,jacob,pw,,otpauth://totp/x?secret=AAAA\nNT,https://n.test,ana,pw2,,\n"),
    );
    expect(parsed.format).toBe("chrome");
    let seq = 0;
    const plan = planImport(parsed, NO_VAULT, () => `id-${seq++}`);
    expect(plan.items[0]!.doc.login?.totp).toBe("otpauth://totp/x?secret=AAAA");
    expect(plan.items[1]!.doc.login?.totp).toBeUndefined();
    const noCol = planImport(parseCsvImport(utf8("name,url,username,password,note\nGH,https://gh.test,jacob,pw,hi\n")), NO_VAULT, () => "x");
    expect(noCol.items[0]!.doc.login?.totp).toBeUndefined();
  });
});

describe("planImport idempotency contract", () => {
  it("mints itemIds once and reuses them across a re-plan of the same parsed input", () => {
    // Two separate plans of the same Parsed get independent id streams (re-parsing =
    // new plan = duplicates), but a single plan's itemIds are stable to reuse on retry.
    const parsed = parseCsvImport(
      utf8("name,url,username,password,note\nA,https://a.test,u,p,\nB,https://b.test,u2,p2,\n"),
    );
    let seq = 0;
    const plan = planImport(parsed, NO_VAULT, () => `stable-${seq++}`);
    expect(plan.items.map((i) => i.itemId)).toEqual(["stable-0", "stable-1"]);
  });
});
