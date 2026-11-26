import { spawn } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { endProcess, MailSink } from "./harness";
import { HOOK, LIMITS, type WaitClock, waitFor } from "./wait";

/**
 * The journeys' own waiting (wait.ts, harness.ts): what another process produces is waited for itself, up to a limit a
 * loaded machine meets. Each test here makes the thing arrive late, well past the limits the journeys had before (a
 * mail looked for 20 s, a hook given vitest's 10 s), or never.
 */

/** A clock that only moves when a wait sleeps; [at] runs something "another process" does at a moment of that clock. */
function virtualClock() {
  let t = 0;
  const events: { at: number; run: () => void }[] = [];
  const advance = (ms: number) => {
    t += ms;
    for (const e of events.filter((x) => x.at <= t)) {
      events.splice(events.indexOf(e), 1);
      e.run();
    }
  };
  const clock: WaitClock = {
    now: () => t,
    sleep: async (ms) => advance(ms),
    sleepSync: (ms) => advance(ms),
  };
  return { clock, at: (ms: number, run: () => void) => events.push({ at: ms, run }), elapsed: () => t };
}

const dirs: string[] = [];
function sinkDir(): string {
  const d = mkdtempSync(join(tmpdir(), "andvari-web-sink-"));
  dirs.push(d);
  return d;
}
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

const mailFile = (dir: string, n: number, to: string, template: string, text = "Your code is 123456.") =>
  writeFileSync(join(dir, `1800000000000-${String(n).padStart(6, "0")}-${template}.json`), JSON.stringify({ template, to, subject: "s", text }));

describe("waitFor", () => {
  it("a thing that arrives at 150 s, well past the old limits, is found, and the wait returns at once when it is there", async () => {
    const v = virtualClock();
    let there: string | undefined;
    v.at(150_000, () => (there = "the answer"));
    expect(150_000).toBeGreaterThan(20_000);
    await expect(waitFor("the answer", () => there, { limitMs: LIMITS.mail, clock: v.clock })).resolves.toBe("the answer");
    expect(v.elapsed()).toBeGreaterThanOrEqual(150_000);
    expect(v.elapsed()).toBeLessThan(151_000);
  });

  it("a thing that never arrives fails at the limit, with a sentence that says what was missing and what was there instead", async () => {
    const v = virtualClock();
    const err = await waitFor("the peer's answer", () => undefined, { limitMs: 60_000, clock: v.clock, instead: () => "two log lines" }).catch((e: Error) => e);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toMatch(/^the peer's answer did not arrive within 60 s \(\d+ looks\); there instead: two log lines$/);
    expect(v.elapsed()).toBe(60_000);
  });
});

describe("MailSink", () => {
  it("a mail the sender writes 100 s after the request (past the old 20 s) is found", async () => {
    const dir = sinkDir();
    const v = virtualClock();
    mailFile(dir, 1, "other@example.org", "signup_code");
    v.at(100_000, () => mailFile(dir, 2, "carol@example.org", "signup_existing", "An account exists."));
    const sink = new MailSink(dir, v.clock);
    const m = await sink.awaitMail("carol@example.org", "signup_existing");
    expect(m).toMatchObject({ to: "carol@example.org", template: "signup_existing", text: "An account exists." });
    expect(v.elapsed()).toBeGreaterThanOrEqual(100_000);
  });

  it("a mail that never comes fails with which mail was missing and what the sink held instead", async () => {
    const dir = sinkDir();
    const v = virtualClock();
    mailFile(dir, 1, "dana@example.org", "signup_code");
    mailFile(dir, 2, "dana@example.org", "new_device");
    const err = await new MailSink(dir, v.clock).awaitMail("erin@example.org", "signup_code").catch((e: Error) => e);
    expect((err as Error).message).toMatch(
      /^a signup_code mail to erin@example\.org \(more than 0\) in the mail sink did not arrive within 180 s \(\d+ looks\); there instead: \[\["dana@example\.org","signup_code"\],\["dana@example\.org","new_device"\]\]$/,
    );
    expect(v.elapsed()).toBe(LIMITS.mail);
  });

  it("with [containing], an earlier mail of the same kind is not taken for the one awaited", async () => {
    const dir = sinkDir();
    const v = virtualClock();
    mailFile(dir, 1, "carol@example.org", "new_device", "Device: Firefox on Linux (web)");
    v.at(40_000, () => mailFile(dir, 2, "carol@example.org", "new_device", "Device: Safari on a Mac (web)"));
    const m = await new MailSink(dir, v.clock).awaitMail("carol@example.org", "new_device", 0, { containing: "Safari on a Mac" });
    expect(m.text).toContain("Safari");
    expect(v.elapsed()).toBeGreaterThanOrEqual(40_000);
  });

  it("a file caught half-written is waited for until it reads whole, by the wait and by a plain read", async () => {
    const dir = sinkDir();
    const v = virtualClock();
    const name = join(dir, "1800000000000-000001-signup_code.json");
    writeFileSync(name, '{"template":"signup_code","to":"erin@exa');
    v.at(2_000, () => mailFile(dir, 1, "erin@example.org", "signup_code"));
    const sink = new MailSink(dir, v.clock);
    expect(sink.snapshot().unreadable).toEqual(["1800000000000-000001-signup_code.json"]);
    expect(sink.count("erin@example.org", "signup_code")).toBe(1);
    expect(v.elapsed()).toBeGreaterThanOrEqual(2_000);
  });

  it("a file that never reads whole fails a plain read with its name", () => {
    const dir = sinkDir();
    const v = virtualClock();
    writeFileSync(join(dir, "1800000000000-000001-signup_code.json"), "{");
    expect(() => new MailSink(dir, v.clock).mail()).toThrow(/^every mail file in the sink reading whole did not arrive within 30 s .*unreadable files \["1800000000000-000001-signup_code\.json"\]$/);
  });

  it("a mail another process writes later is found on the real clock", async () => {
    const dir = sinkDir();
    const file = join(dir, "1800000000000-000001-signup_code.json");
    const body = JSON.stringify({ template: "signup_code", to: "late@example.org", subject: "s", text: "Your code is 654321." });
    const writer = spawn(process.execPath, ["-e", `setTimeout(() => require("fs").writeFileSync(${JSON.stringify(file)}, ${JSON.stringify(body)}), 1500)`], { stdio: "ignore" });
    try {
      const m = await new MailSink(dir).awaitMail("late@example.org", "signup_code", 0);
      expect(m.text).toContain("654321");
    } finally {
      await endProcess(writer, "the writer");
    }
    expect(readdirSync(dir)).toHaveLength(1);
  });
});

describe("endProcess", () => {
  it("a process that ignores SIGTERM is ended by SIGKILL past its grace, and the wait returns once it is gone", async () => {
    const p = spawn(process.execPath, ["-e", "process.on('SIGTERM', () => {}); setInterval(() => {}, 1000); console.log('up')"], { stdio: ["ignore", "pipe", "ignore"] });
    await waitFor("the child's first line", () => new Promise<true | undefined>((r) => p.stdout!.once("data", () => r(true))), { limitMs: 30_000 });
    await endProcess(p, "the child", 500);
    expect(p.signalCode).toBe("SIGKILL");
  });
});

describe("the journeys' hooks", () => {
  const here = fileURLToPath(new URL(".", import.meta.url));
  const journeys = readdirSync(here).filter((f) => f.endsWith(".journey.test.ts"));

  it("every beforeAll and afterAll is given a limit that is the sum of what it starts", () => {
    expect(journeys.length).toBeGreaterThanOrEqual(7);
    for (const f of journeys) {
      const text = readFileSync(join(here, f), "utf8");
      const hooks = (text.match(/^ {2}(beforeAll|afterAll)\(/gm) ?? []).length;
      const limited = (text.match(/^ {2}\}, HOOK\.(start|startWithPeer|startThenSignUp|stop)\);$/gm) ?? []).length;
      expect([f, limited]).toEqual([f, hooks]);
      expect(hooks, f).toBeGreaterThanOrEqual(2);
    }
    expect(HOOK.stop).toBeGreaterThan(4 * LIMITS.exit);
    expect(HOOK.start).toBeGreaterThan(LIMITS.setup + LIMITS.health + LIMITS.bootstrap);
  });

  it("the test clock, read by the server and every peer, is replaced whole and never rewritten in place", () => {
    const harness = readFileSync(join(here, "harness.ts"), "utf8");
    const advance = harness.slice(harness.indexOf("  advance(ms: number): void {"), harness.indexOf("  /** `andvari admin"));
    expect(advance).toContain("writeFileSync(tmp, String(next));");
    expect(advance).toContain("renameSync(tmp, this.clockFile);");
    expect(advance).not.toContain("writeFileSync(this.clockFile");
  });

  it("no journey checks the mail sink once for what must not be there, and no peer is left unawaited", () => {
    for (const f of journeys) {
      const text = readFileSync(join(here, f), "utf8");
      expect(text, f).not.toMatch(/expect\(inst\.mailCount\([^)]*\)\)\.toBe\(0\)/);
      expect(text, f).not.toMatch(/^\s+peer\?\.stop\(\);/m);
    }
  });
});
