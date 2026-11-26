// Every place in the web app where a request that changes a vault can start, and every place where a request of any
// other kind can start, held to one closed list. The functions that change a vault are those the tables of sends.ts
// mark so; their names are unique in the web app's modules, so every place naming one is found by its name.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import { API_CLIENT_ROWS, namesThatChangeAVault, type SendRow, WIRE_API_ROWS } from "./sends";

/** Every other way a request can start: the browser's own request primitives, and the api client's request functions. */
const REQUEST_STARTS = ["fetch", "XMLHttpRequest", "sendBeacon", "WebSocket", "EventSource", "sendRequest", "requestBytes", "fetchStatic"] as const;

const web = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const src = join(web, "src");

/**
 * The modules: every file under web/src with a TypeScript or JavaScript extension, read from the disk (a new module is
 * found without being named anywhere), except tests (`*.test.ts`, `*.test.tsx`), test kits (`*.testkit.ts`,
 * `*.testkit.tsx`) and the journeys (`journeys/`, which drive the app from outside).
 */
function modules(): string[] {
  const out: string[] = [];
  const walk = (dir: string): void => {
    for (const e of readdirSync(dir)) {
      const p = join(dir, e);
      if (statSync(p).isDirectory()) walk(p);
      else out.push(relative(src, p).split("\\").join("/"));
    }
  };
  walk(src);
  return out.filter((r) => /\.(ts|tsx|js|mjs|cjs)$/.test(r) && !/\.test\.tsx?$|\.testkit\.tsx?$/.test(r) && !r.startsWith("journeys/")).sort();
}

const kindOf = (rel: string): ts.ScriptKind => (rel.endsWith(".tsx") ? ts.ScriptKind.TSX : rel.endsWith(".ts") ? ts.ScriptKind.TS : ts.ScriptKind.JS);

/**
 * Every occurrence of each of [names] in a module's code, by TypeScript's own syntax tree: an identifier, a private
 * identifier, or a string or template literal whose whole text is the name (so `x.name(`, `x.name` handed on, `name:`
 * in an object, `{ name }`, `x["name"]` and a declaration all count). Comments are not code and do not count.
 */
function occurrences(names: ReadonlySet<string>): Record<string, Record<string, number>> {
  const found: Record<string, Record<string, number>> = {};
  for (const rel of modules()) {
    const sf = ts.createSourceFile(rel, readFileSync(join(src, rel), "utf8"), ts.ScriptTarget.Latest, true, kindOf(rel));
    const visit = (n: ts.Node): void => {
      let text: string | null = null;
      if (ts.isIdentifier(n) || ts.isPrivateIdentifier(n)) text = n.text.replace(/^#/, "");
      else if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) text = n.text;
      if (text !== null && names.has(text)) {
        const f = (found[rel] ??= {});
        f[text] = (f[text] ?? 0) + 1;
      }
      ts.forEachChild(n, visit);
    };
    visit(sf);
  }
  return found;
}

type Place = readonly [count: number, how: "asks" | "exempt", why: string];
const ROUTE = "the route itself: its declaration in the client, where no request starts but through a caller listed here";
const TABLE = "the table of sends.ts names it; nothing is sent from there";

/**
 * The closed list: per module, per name, how many times the name stands there, whether the place asks `mayWrite` for the
 * vault it changes or is exempt, and why. A new occurrence anywhere (a new call, an alias, a field that holds a function,
 * a reference handed on, a new module) fails the test until it has its entry here.
 */
const PLACES: Record<string, Record<string, Place>> = {
  "api/sends.ts": {
    appendLog: [2, "exempt", TABLE],
    createVault: [1, "exempt", TABLE],
    deleteAccountWithLeaves: [1, "exempt", TABLE],
    deleteTransferOffer: [1, "exempt", TABLE],
    deleteVault: [1, "exempt", TABLE],
    deleteVaultMember: [1, "exempt", TABLE],
    fetchStatic: [1, "exempt", TABLE],
    leaveVault: [1, "exempt", TABLE],
    postTransferAccept: [1, "exempt", TABLE],
    postTransferOffer: [1, "exempt", TABLE],
    postVaultMember: [1, "exempt", TABLE],
    purgeItem: [2, "exempt", TABLE],
    pushMutations: [2, "exempt", TABLE],
    putSelfWrap: [2, "exempt", TABLE],
    putVaultMeta: [1, "exempt", TABLE],
    requestBytes: [1, "exempt", TABLE],
    restoreItem: [2, "exempt", TABLE],
    restoreVault: [1, "exempt", TABLE],
    sendRequest: [1, "exempt", TABLE],
    setVaultMemberRole: [1, "exempt", TABLE],
    updateVaultMeta: [1, "exempt", TABLE],
    uploadAttachment: [2, "exempt", TABLE],
  },
  "api/client.ts": {
    fetch: [1, "exempt", "the one fetch of the web client (`send`): every request of the app starts here, from one of the places listed"],
    WebSocket: [2, "exempt", "the change bell (`events`): a read, which sends only its ticket"],
    sendRequest: [1, "exempt", "the request function's declaration"],
    requestBytes: [1, "exempt", "the byte request function's declaration"],
    fetchStatic: [1, "exempt", "the declaration of the request of a public file (no credential, no vault)"],
    createVault: [1, "exempt", `${ROUTE}; it has no caller`],
    postVaultMember: [1, "exempt", `${ROUTE}; it has no caller`],
    setVaultMemberRole: [1, "exempt", `${ROUTE}; it has no caller`],
    deleteVaultMember: [1, "exempt", `${ROUTE}; it has no caller`],
    deleteVault: [1, "exempt", `${ROUTE}; it has no caller`],
    restoreVault: [1, "exempt", `${ROUTE}; it has no caller`],
    leaveVault: [1, "exempt", `${ROUTE}; it has no caller`],
    postTransferOffer: [1, "exempt", `${ROUTE}; it has no caller`],
    deleteTransferOffer: [1, "exempt", `${ROUTE}; it has no caller`],
    postTransferAccept: [1, "exempt", `${ROUTE}; it has no caller`],
    updateVaultMeta: [1, "exempt", `${ROUTE}; its one caller is the store's renameVault`],
  },
  "api/wireclient.ts": {
    pushMutations: [1, "exempt", ROUTE],
    restoreItem: [1, "exempt", ROUTE],
    purgeItem: [1, "exempt", ROUTE],
    uploadAttachment: [1, "exempt", ROUTE],
    appendLog: [1, "exempt", ROUTE],
    putVaultMeta: [1, "exempt", `${ROUTE}; it has no caller`],
    putSelfWrap: [1, "exempt", ROUTE],
    deleteAccountWithLeaves: [1, "exempt", ROUTE],
    sendRequest: [3, "exempt", "the wire client's own calls of its transport (`callKeeping`, `ok`, `recoveryPubkey`): every route above goes through them"],
    requestBytes: [2, "exempt", "the wire client's two attachment routes (an upload, asked through the store's uploadInto; a download, a read)"],
  },
  "vault/store.ts": {
    pushMutations: [3, "asks", "ItemWire's declaration, the refusing wire of a store opened without one, and the one call in sendItemChanges, after refuseUnlessMayWrite for every change"],
    restoreItem: [3, "asks", "the declaration, the refusing wire, and the call in restoreDeleted, after refuseUnlessMayWrite"],
    purgeItem: [3, "asks", "the declaration, the refusing wire, and the call in purgeDeleted, after refuseUnlessMayWrite for the vault and the Trash's vault"],
    uploadAttachment: [3, "asks", "the declaration, the refusing wire, and the call in uploadInto, after refuseUnlessMayWrite"],
    updateVaultMeta: [1, "asks", "the call in renameVault, after refuseUnlessMayWrite"],
  },
  "vault/logstore.ts": {
    appendLog: [2, "asks", "LogWire's declaration, and the one call in postOnce, which asks the gate the store attaches, except for a leave, a new log's first entry and the owner's restore of its own deleted vault"],
    putSelfWrap: [2, "exempt", "LogWire's declaration, and postSelfWrap: the wrap of a key for this account only, adopted through a grant under the add the verified log names now (after a yes)"],
  },
  "vault/settingsflow.ts": {
    deleteAccountWithLeaves: [2, "exempt", "SettingsWire's declaration, and the one call in the account's deletion: a leave (each entry it carries is this account's signed leave of a shared vault's log, which a removal never refuses)"],
  },
  "vault/policywipe.ts": {
    pushMutations: [2, "asks", "senderForCopy's wire and its one call, inside the sender: of each batch it is handed, by any caller, only the changes the MayWrite it was made with allows in the same step"],
  },
  "vault/pinstore.ts": {
    fetch: [4, "exempt", "the pin store's own private method of that name, which reads GET /instance through the wire client (ui/opensession.ts)"],
  },
  "ui/Devices.tsx": {
    fetchStatic: [2, "exempt", "the downloads manifest: a read of a public file, with no credential and no vault"],
  },
};

describe("every place where a request can start in the web app is on one closed list", () => {
  it("the modules read are the web app's own, and no test, test kit or journey", () => {
    const m = modules();
    expect(m).toEqual(expect.arrayContaining(["api/client.ts", "api/wireclient.ts", "vault/store.ts", "vault/logstore.ts", "vault/policywipe.ts", "ui/App.tsx", "ui/Vault.tsx", "main.tsx"]));
    expect(m.filter((r) => /\.test\.|\.testkit\.|^journeys\//.test(r))).toEqual([]);
  });

  it("every name that changes a vault, and every request start, stands exactly where the list says, and nowhere else", () => {
    const changing = namesThatChangeAVault();
    expect(changing).toEqual([
      "appendLog",
      "createVault",
      "deleteAccountWithLeaves",
      "deleteTransferOffer",
      "deleteVault",
      "deleteVaultMember",
      "leaveVault",
      "postTransferAccept",
      "postTransferOffer",
      "postVaultMember",
      "purgeItem",
      "pushMutations",
      "putSelfWrap",
      "putVaultMeta",
      "restoreItem",
      "restoreVault",
      "setVaultMemberRole",
      "updateVaultMeta",
      "uploadAttachment",
    ]);
    const found = occurrences(new Set([...changing, ...REQUEST_STARTS]));
    const listed = Object.fromEntries(Object.entries(PLACES).map(([f, names]) => [f, Object.fromEntries(Object.entries(names).map(([n, [count]]) => [n, count]))]));
    expect(found).toEqual(listed);
    for (const names of Object.values(PLACES)) for (const [, how, why] of Object.values(names)) expect(why.length > 0 && (how === "asks" || how === "exempt")).toBe(true);
  });

  it("each name that changes a vault is unique to its function: no other declaration in the web app's modules carries it", () => {
    const changing = new Set(namesThatChangeAVault());
    const declaredBy: Record<string, string[]> = {};
    for (const rel of modules()) {
      const sf = ts.createSourceFile(rel, readFileSync(join(src, rel), "utf8"), ts.ScriptTarget.Latest, true, kindOf(rel));
      const visit = (n: ts.Node): void => {
        const name = (ts.isMethodDeclaration(n) || ts.isMethodSignature(n) || ts.isPropertyDeclaration(n) || ts.isPropertySignature(n) || ts.isFunctionDeclaration(n) || ts.isVariableDeclaration(n)) && n.name && ts.isIdentifier(n.name) ? n.name.text : null;
        if (name !== null && changing.has(name)) (declaredBy[name] ??= []).push(rel);
        ts.forEachChild(n, visit);
      };
      visit(sf);
    }
    for (const list of Object.values(declaredBy)) list.sort();
    expect(declaredBy).toEqual({
      appendLog: ["api/wireclient.ts", "vault/logstore.ts"],
      createVault: ["api/client.ts"],
      deleteAccountWithLeaves: ["api/wireclient.ts", "vault/settingsflow.ts"],
      deleteTransferOffer: ["api/client.ts"],
      deleteVault: ["api/client.ts"],
      deleteVaultMember: ["api/client.ts"],
      leaveVault: ["api/client.ts"],
      postTransferAccept: ["api/client.ts"],
      postTransferOffer: ["api/client.ts"],
      postVaultMember: ["api/client.ts"],
      purgeItem: ["api/wireclient.ts", "vault/store.ts"],
      pushMutations: ["api/wireclient.ts", "vault/policywipe.ts", "vault/store.ts"],
      putSelfWrap: ["api/wireclient.ts", "vault/logstore.ts"],
      putVaultMeta: ["api/wireclient.ts"],
      restoreItem: ["api/wireclient.ts", "vault/store.ts"],
      restoreVault: ["api/client.ts"],
      setVaultMemberRole: ["api/client.ts"],
      updateVaultMeta: ["api/client.ts"],
      uploadAttachment: ["api/wireclient.ts", "vault/store.ts"],
    });
  });

  it("a function whose request carries signed log entries is classed as changing a vault", () => {
    // The type checker over the web app's own configuration: every method of the wire client and of the api client with
    // a parameter whose type has a field that holds entries of a vault's log (`entry`, the frame of an append; `leaves`,
    // the leave frames an account's deletion carries). Each such function changes a vault's log, whatever else it does.
    const cfg = ts.parseJsonConfigFileContent(ts.readConfigFile(join(web, "tsconfig.json"), ts.sys.readFile).config, ts.sys, web);
    const program = ts.createProgram(cfg.fileNames, cfg.options);
    const checker = program.getTypeChecker();
    const LOG_FIELDS = ["entry", "leaves"];
    const carriers = (file: string, cls: string): string[] => {
      const sf = program.getSourceFile(join(src, file))!;
      const out: string[] = [];
      const visit = (n: ts.Node): void => {
        if (ts.isClassDeclaration(n) && n.name?.text === cls) {
          for (const m of n.members) {
            if (!ts.isMethodDeclaration(m) || !m.name || !ts.isIdentifier(m.name)) continue;
            const carries = m.parameters.some((p) => {
              const t = checker.getApparentType(checker.getTypeAtLocation(p));
              return LOG_FIELDS.some((f) => checker.getPropertyOfType(t, f) !== undefined);
            });
            if (carries) out.push(m.name.text);
          }
        }
        ts.forEachChild(n, visit);
      };
      visit(sf);
      return out.sort();
    };
    const wire = carriers("api/wireclient.ts", "WireApi");
    const client = carriers("api/client.ts", "ApiClient");
    expect(wire).toContain("appendLog");
    const classedAsNone = [
      ...wire.filter((n) => !(WIRE_API_ROWS as Record<string, SendRow>)[n]?.changesAVault).map((n) => `wireclient ${n}`),
      ...client.filter((n) => !(API_CLIENT_ROWS as Record<string, SendRow>)[n]?.changesAVault).map((n) => `client ${n}`),
    ];
    expect(classedAsNone).toEqual([]);
  }, 120_000);

  it("no module reaches a wire or the api client through a name built at run time", () => {
    // The type checker over the web app's own configuration: every `x[k]` whose key is not a literal, where `x` is of a
    // type that has a function that changes a vault or starts a request, or is of type any.
    const cfg = ts.parseJsonConfigFileContent(ts.readConfigFile(join(web, "tsconfig.json"), ts.sys.readFile).config, ts.sys, web);
    const program = ts.createProgram(cfg.fileNames, cfg.options);
    const checker = program.getTypeChecker();
    const watched = [...namesThatChangeAVault(), ...REQUEST_STARTS];
    const own = new Set(modules());
    const hits: string[] = [];
    for (const sf of program.getSourceFiles()) {
      const rel = relative(src, sf.fileName).split("\\").join("/");
      if (!own.has(rel)) continue;
      const visit = (n: ts.Node): void => {
        if (ts.isElementAccessExpression(n) && !ts.isStringLiteralLike(n.argumentExpression) && !ts.isNumericLiteral(n.argumentExpression)) {
          const t = checker.getTypeAtLocation(n.expression);
          const reaches = (t.flags & ts.TypeFlags.Any) !== 0 || watched.some((name) => checker.getPropertyOfType(checker.getApparentType(t), name) !== undefined);
          if (reaches) hits.push(`${rel}:${sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1}: ${n.getText(sf).slice(0, 80)}`);
        }
        ts.forEachChild(n, visit);
      };
      visit(sf);
    }
    expect(hits).toEqual([]);
  }, 120_000);
});
