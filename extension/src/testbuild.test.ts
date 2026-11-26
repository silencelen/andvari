// node --test. A person's test build ("andvari dev", build.mjs TESTBUILD=1) of code that is not released never talks to
// the live server by itself: it starts at the test server, names no update address, and the build fails if the live
// server's address is anywhere in its files; every other build fails if the test server's address is anywhere in it.
// Each build here runs build.mjs itself, in a copy of the extension in a temporary directory (the copy's own dist/).
import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { appendFileSync, cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import * as live from "./publicinstance.ts";
import * as testServer from "./publicinstance.testserver.ts";

const EXT = new URL("..", import.meta.url).pathname;
const LIVE_ORIGIN = JSON.parse(readFileSync(new URL("../../spec/public-instance.json", import.meta.url), "utf8")).PUBLIC_INSTANCE.origin as string;
const LIVE_HOST = new URL(LIVE_ORIGIN).host;
const TEST_ORIGIN = "https://staging.andvaripass.com";
const TEST_HOST = new URL(TEST_ORIGIN).host;
const SKIP = new Set(["node_modules", "dist", "artifacts", "store-assets"]);

const roots: string[] = [];
after(() => {
  for (const r of roots) rmSync(r, { recursive: true, force: true });
});

/** A copy of the extension (and the spec file its build reads) under a new temporary root; with [git], the root is a
 *  repository with one commit, as the build of a test build reads the commit. Returns the copy's extension directory. */
function copyOfExtension(git: boolean): { dir: string; commit: string | null } {
  const root = mkdtempSync(join(tmpdir(), "andvari-testbuild-"));
  roots.push(root);
  const dir = join(root, "extension");
  cpSync(EXT, dir, { recursive: true, filter: (src) => !SKIP.has(src.slice(EXT.length).split("/")[0] ?? "") });
  symlinkSync(join(EXT, "node_modules"), join(dir, "node_modules"));
  mkdirSync(join(root, "spec"));
  cpSync(new URL("../../spec/public-instance.json", import.meta.url).pathname, join(root, "spec", "public-instance.json"));
  if (!git) return { dir, commit: null };
  const run = (...args: string[]) => {
    const r = spawnSync("git", ["-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "-c", "user.name=test", "-c", "user.email=test@example.invalid", ...args], { cwd: root, encoding: "utf8" });
    assert.equal(r.status, 0, `git ${args.join(" ")}: ${r.stderr}`);
    return r.stdout.trim();
  };
  run("init", "-q");
  writeIgnore(root);
  run("add", "-A");
  run("commit", "-q", "-m", "copy");
  return { dir, commit: run("rev-parse", "--short=12", "HEAD") };
}

function writeIgnore(root: string): void {
  cpSync(new URL("../../.gitignore", import.meta.url).pathname, join(root, ".gitignore"));
}

/** Runs build.mjs in [dir] with only the given build settings. */
function build(dir: string, settings: Record<string, string>) {
  const env = { ...process.env };
  for (const k of ["TESTBUILD", "TARGET", "DEBUG", "UITEST", "CARDFILL", "RELEASE"]) delete env[k];
  return spawnSync(process.execPath, ["build.mjs"], { cwd: dir, env: { ...env, ...settings }, encoding: "utf8" });
}

function filesOf(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => (statSync(join(dir, n)).isDirectory() ? filesOf(join(dir, n)) : [join(dir, n)]));
}

const plainManifest = (file: string) => JSON.parse(readFileSync(join(EXT, file), "utf8")) as Record<string, unknown>;

test("TESTBUILD=1 for Chrome and Edge: the manifest read back names andvari dev, the commit and the test server only", () => {
  const { dir, commit } = copyOfExtension(true);
  const r = build(dir, { TESTBUILD: "1" });
  assert.equal(r.status, 0, r.stderr);
  const m = JSON.parse(readFileSync(join(dir, "dist", "manifest.json"), "utf8")) as Record<string, any>;
  const plain = plainManifest("manifest.json") as Record<string, any>;
  assert.equal(m.name, "andvari dev");
  assert.equal(m.version, plain.version, "the version Chrome compares stays the release's numbers");
  assert.equal(m.version_name, `${plain.version} dev ${commit}`, "chrome://extensions and edge://extensions show the commit");
  assert.ok(String(m.description).includes(commit!));
  assert.deepEqual(m.host_permissions, [`${TEST_ORIGIN}/*`], "the only host granted without asking is the test server");
  assert.equal(m.action.default_title, "andvari dev");
  // Everything else is the release manifest's.
  for (const k of ["name", "description", "host_permissions", "action", "version_name"]) {
    delete m[k];
    delete plain[k];
  }
  assert.deepEqual(m, plain);
  const files = filesOf(join(dir, "dist"));
  assert.ok(!files.some((f) => f.endsWith(".map")), "no source map");
  assert.ok(!existsSync(join(dir, "dist", "INSTALL.txt")), "no install notes for the released extension");
  for (const f of files.filter((f) => !f.endsWith(".png"))) assert.ok(!readFileSync(f, "utf8").includes(LIVE_HOST), `${f} names the live server`);
  assert.ok(readFileSync(join(dir, "dist", "background.js"), "utf8").includes(TEST_ORIGIN), "the worker starts at the test server");
  assert.ok(readFileSync(join(dir, "dist", "popup.js"), "utf8").includes(TEST_ORIGIN), "the first popup names the test server");
  const popup = readFileSync(join(dir, "dist", "popup.html"), "utf8");
  // The name is a drawing (brand.ts) named "andvari" for a screen reader; " dev" is text right after it, inside the brand.
  const DEV_BRAND = '<svg class="wordmark" role="img" aria-label="andvari" viewBox="0 -740 3017 980"><path data-wordmark="" fill="currentColor"/></svg> dev</span';
  assert.equal(popup.split(DEV_BRAND).length - 1, 2, "both brands in the popup say andvari dev");
  assert.match(popup, /<title>andvari dev<\/title>/);
  const options = readFileSync(join(dir, "dist", "options.html"), "utf8");
  assert.equal(options.split(DEV_BRAND).length - 1, 1, "the options page says andvari dev");
  assert.match(options, /<title>Options · andvari dev<\/title>/);
  assert.match(r.stdout, new RegExp(`test build "andvari dev" of ${commit}, test server ${TEST_ORIGIN.replaceAll(".", "\\.")}`));
});

test("TESTBUILD=1 for Firefox: its own add-on id, no update address, the test server in place of the live one", () => {
  const { dir, commit } = copyOfExtension(true);
  const r = build(dir, { TESTBUILD: "1", TARGET: "firefox" });
  assert.equal(r.status, 0, r.stderr);
  const m = JSON.parse(readFileSync(join(dir, "dist", "manifest.json"), "utf8")) as Record<string, any>;
  const plain = plainManifest("manifest.firefox.json") as Record<string, any>;
  assert.equal(m.name, "andvari dev");
  assert.equal(m.version, plain.version);
  assert.equal(m.version_name, undefined, "Firefox knows no version_name: the description says the commit");
  assert.ok(String(m.description).includes(commit!));
  assert.deepEqual(m.browser_specific_settings, { gecko: { id: "andvari-dev@andvaripass.com", strict_min_version: plain.browser_specific_settings.gecko.strict_min_version } });
  assert.notEqual(m.browser_specific_settings.gecko.id, plain.browser_specific_settings.gecko.id, "never stands in for the released add-on");
  assert.deepEqual(m.host_permissions, (plain.host_permissions as string[]).map((h) => (h === `${LIVE_ORIGIN}/*` ? `${TEST_ORIGIN}/*` : h)));
  assert.ok(!JSON.stringify(m).includes(LIVE_HOST));
  for (const k of ["name", "description", "host_permissions", "action", "browser_specific_settings"]) {
    delete m[k];
    delete plain[k];
  }
  assert.deepEqual(m, plain);
  for (const f of filesOf(join(dir, "dist")).filter((f) => !f.endsWith(".png"))) assert.ok(!readFileSync(f, "utf8").includes(LIVE_HOST), `${f} names the live server`);
});

test("a test build in which the live server's address stands fails, names the file, and leaves no dist/", () => {
  const { dir } = copyOfExtension(true);
  appendFileSync(join(dir, "src", "content.ts"), `\nconsole.debug(${JSON.stringify(LIVE_ORIGIN)});\n`);
  for (const target of ["", "firefox"]) {
    const r = build(dir, { TESTBUILD: "1", TARGET: target });
    assert.notEqual(r.status, 0, `the ${target || "chrome"} test build passed with the live server in it`);
    assert.ok(r.stderr.includes(`a test build must not name the live server, but ${LIVE_HOST} is in: dist/content.js`), r.stderr);
    assert.ok(!existsSync(join(dir, "dist")), "the build is removed");
  }
  // The same tree builds without the setting: only the test build refuses the live server.
  assert.equal(build(dir, {}).status, 0);
});

test("a build without the setting in which the test server's address stands fails, names the file, and leaves no dist/", () => {
  const { dir } = copyOfExtension(false);
  appendFileSync(join(dir, "src", "content.ts"), `\nconsole.debug(${JSON.stringify(TEST_ORIGIN)});\n`);
  for (const settings of [{}, { TARGET: "firefox" }, { TARGET: "safari" }, { DEBUG: "1" }, { RELEASE: "1" }]) {
    const r = build(dir, settings);
    assert.notEqual(r.status, 0, `${JSON.stringify(settings)} passed with the test server in it`);
    assert.ok(r.stderr.includes(`only a test build (TESTBUILD=1) may name the test server, but ${TEST_HOST} is in: dist/content.js`), r.stderr);
    assert.ok(!existsSync(join(dir, "dist")), "the build is removed");
  }
});

test("a test build is built one way only: no Safari, no DEBUG, UITEST or CARDFILL beside it", () => {
  const { dir } = copyOfExtension(true);
  for (const settings of [{ TARGET: "safari" }, { DEBUG: "1" }, { CARDFILL: "0" }, { CARDFILL: "1" }, { TARGET: "safari", UITEST: "1" }]) {
    const r = build(dir, { TESTBUILD: "1", ...settings });
    assert.notEqual(r.status, 0, JSON.stringify(settings));
    assert.match(r.stderr, /TESTBUILD=1 (is for the Chrome and Firefox builds only|takes no DEBUG, UITEST or CARDFILL)/);
  }
});

test("the store packaging refuses to run with the test build's setting, and still runs without it", () => {
  const { dir } = copyOfExtension(false);
  const run = (settings: Record<string, string>) => {
    const env = { ...process.env };
    for (const k of ["TESTBUILD", "TARGET", "DEBUG", "UITEST", "CARDFILL", "RELEASE"]) delete env[k];
    return spawnSync(process.execPath, ["package.mjs", "--check"], { cwd: dir, env: { ...env, ...settings }, encoding: "utf8" });
  };
  for (const value of ["1", "0", ""]) {
    const r = run({ TESTBUILD: value });
    assert.notEqual(r.status, 0, `TESTBUILD=${value} was packaged`);
    assert.ok(r.stderr.includes("package.mjs packages the store builds and refuses to run with TESTBUILD set: a test build is never a store package"), r.stderr);
    assert.ok(!existsSync(join(dir, "dist")), "nothing was built");
  }
  const ok = run({});
  assert.equal(ok.status, 0, ok.stderr);
  assert.match(ok.stdout, /checked the chrome release build/);
  assert.equal(JSON.parse(readFileSync(join(dir, "dist", "manifest.json"), "utf8")).name, "andvari");
});

test("a test build of a tree with changes says so in its version", () => {
  const { dir, commit } = copyOfExtension(true);
  appendFileSync(join(dir, "src", "content.ts"), "\n");
  assert.equal(build(dir, { TESTBUILD: "1" }).status, 0);
  const m = JSON.parse(readFileSync(join(dir, "dist", "manifest.json"), "utf8")) as { version_name: string };
  assert.ok(m.version_name.endsWith(`dev ${commit} with changes`), m.version_name);
});

test("the test build's public instance is the test server, with no root: same exports and shapes as the live one", () => {
  assert.deepEqual(Object.keys(testServer).filter((k) => k !== "TEST_SERVER_ORIGIN").sort(), Object.keys(live).sort());
  assert.deepEqual(Object.keys(testServer.PUBLIC_INSTANCE), Object.keys(live.PUBLIC_INSTANCE));
  assert.equal(testServer.TEST_SERVER_ORIGIN, TEST_ORIGIN);
  assert.equal(testServer.PUBLIC_INSTANCE.origin, TEST_ORIGIN);
  assert.equal(testServer.PUBLIC_INSTANCE.kind, live.PUBLIC_INSTANCE.kind);
  assert.equal(testServer.bakedRoot(), null, "a test build bakes no card 0: the test server goes through the Trust Gate");
  assert.ok(testServer.PUBLIC_INSTANCE.card0Hash.startsWith("PLACEHOLDER:"));
  assert.equal(testServer.isBakedInstance({ origin: TEST_ORIGIN, card0Hash: "0".repeat(64) }), true);
  assert.equal(testServer.isBakedInstance({ origin: LIVE_ORIGIN, card0Hash: "0".repeat(64) }), false);
  assert.equal(live.PUBLIC_INSTANCE.origin, LIVE_ORIGIN, "the live source is unchanged");
});

test("the worker of a test build: andvari is refused, the test server typed goes to the Trust Gate, no update poll", () => {
  const bg = readFileSync(new URL("./background.ts", import.meta.url), "utf8");
  const choose = bg.slice(bg.indexOf("async function chooseServer("), bg.indexOf("async function confirmServer("));
  assert.match(choose, /const baked = \(typeof __ANDVARI_TEST_SERVER__ !== "string" \|\| msg\.choice === "public"\) && origin === PUBLIC_INSTANCE\.origin;\s*const root = baked \? bakedRoot\(\) : \(\{ root: "typed" \} as const\);\s*if \(root === null\) return \{ ok: false, code: "no_public_instance" \};/);
  assert.match(bg, /if \(typeof __ANDVARI_TEST_SERVER__ === "string" \|\| !selfUpdateChannelAllowed\(\)\) return;/);
  const b = readFileSync(new URL("../build.mjs", import.meta.url), "utf8");
  assert.match(b, /__ANDVARI_TEST_SERVER__: testBuild \? JSON\.stringify\(TEST_SERVER_ORIGIN\) : "null",/, "every other build folds it away");
  assert.match(b, /plugins: testBuild\s*\?/, "only the test build bundles publicinstance.testserver.ts");
});
