import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { LIMITS, realClock, type WaitClock, waitFor, waitForSync } from "./wait";

/**
 * The real server in its test mode on 127.0.0.1, for the web journeys (design §7.1, §9.5). `andvari setup --test
 * --stop-at-setup` writes the environment file, the database, the mail sink and the test clock; the server then runs
 * from that environment file as its own process, and every journey talks to it over real HTTP. Nothing leaves the
 * loopback interface and no mail is sent.
 *
 * Two things the web client can never do are done by the engine's own code in a second process
 * (OperatorBootstrap.java, run on the command-line module's classpath): the first operator enrols through the setup
 * link and signs card 0. The web has no link flow and signs no card (§13), and this harness does not either.
 *
 * Both programs come from this working copy's Gradle output. When either is not built the journeys skip themselves
 * and say which command builds it.
 */

const root = fileURLToPath(new URL("../../../", import.meta.url));
const serverLauncher = join(root, "server/build/install/server/bin/server");
const cliLib = join(root, "tools/andvari-cli/build/install/andvari-cli/lib");
const bootstrapSource = fileURLToPath(new URL("./OperatorBootstrap.java", import.meta.url));
const sharePeerSource = fileURLToPath(new URL("./SharePeer.java", import.meta.url));
const assistPeerSource = fileURLToPath(new URL("./AssistPeer.java", import.meta.url));
const policyPeerSource = fileURLToPath(new URL("./PolicyPeer.java", import.meta.url));
const recoveryCliLauncher = join(root, "tools/recovery-cli/build/install/recovery-cli/bin/recovery-cli");

/** Null when the offline tool `recovery-cli` is built; otherwise what to run first. */
export function recoveryCliUnavailable(): string | null {
  return existsSync(recoveryCliLauncher) ? null : "build the offline tool first, from the repository root: :tools:recovery-cli:installDist";
}

/** The SharePeer child: one command line in, one JSON line out. */
export class SharePeerProcess {
  ids: { alice: string; bob: string; vault: string } = { alice: "", bob: "", vault: "" };
  private buf = "";
  private err = "";
  private waiters: (() => void)[] = [];

  constructor(
    private readonly proc: ChildProcess,
    private readonly serverLog: () => string,
  ) {
    proc.stdout!.on("data", (d: Buffer) => {
      this.buf += d.toString();
      for (const w of this.waiters.splice(0)) w();
    });
    proc.stderr!.on("data", (d: Buffer) => (this.err += d.toString()));
    proc.on("exit", () => {
      for (const w of this.waiters.splice(0)) w();
    });
  }

  /** Lines the peer printed that were not its answer (the engine's own log lines), for a failure's sentence. */
  private other: string[] = [];

  /** The peer's next JSON line, waited for until [limitMs]; it wakes on every output and on the peer's exit. */
  async nextLine(limitMs: number = LIMITS.peer): Promise<string> {
    const start = Date.now();
    const deadline = start + limitMs;
    for (;;) {
      const i = this.buf.indexOf("\n");
      if (i >= 0) {
        const line = this.buf.slice(0, i);
        this.buf = this.buf.slice(i + 1);
        if (line.trim().startsWith("{")) return line;
        this.other.push(line);
        continue;
      }
      if (this.proc.exitCode !== null || this.proc.signalCode !== null) {
        throw new Error(`the peer exited (${this.proc.exitCode ?? this.proc.signalCode}) before its answer; it printed instead: ${this.printed()}\n--- server:\n${this.serverLog()}`);
      }
      if (Date.now() >= deadline) {
        throw new Error(`the peer's answer did not arrive within ${Math.round((Date.now() - start) / 1000)} s; it printed instead: ${this.printed()}\n--- server:\n${this.serverLog()}`);
      }
      await new Promise<void>((r) => {
        this.waiters.push(r);
        setTimeout(r, Math.min(1000, Math.max(1, deadline - Date.now())));
      });
    }
  }

  private printed(): string {
    const out = [...this.other.slice(-20), this.buf].filter((l) => l.trim() !== "").join("\n");
    return `${out === "" ? "nothing on stdout" : out}\n--- its stderr:\n${this.err.split("\n").slice(-40).join("\n")}`;
  }

  /** Sends one command as alice and answers its JSON reply. */
  async cmd<T = Record<string, unknown>>(line: string): Promise<T> {
    this.proc.stdin!.write(line + "\n");
    return JSON.parse(await this.nextLine()) as T;
  }

  /** Asks the peer to quit, then ends it, and waits until it is gone. */
  async stop(): Promise<void> {
    if (this.proc.exitCode === null && this.proc.signalCode === null) this.proc.stdin!.end("quit\n");
    await endProcess(this.proc, "the peer");
  }
}

/**
 * Ends [p] (SIGTERM, then SIGKILL past its grace) and waits for its exit; a process that outlives both says so. A
 * process already gone returns at once.
 */
export async function endProcess(p: ChildProcess, name: string, graceMs: number = LIMITS.exit): Promise<void> {
  const gone = () => p.exitCode !== null || p.signalCode !== null;
  if (gone()) return;
  const exited = new Promise<void>((resolve) => p.once("exit", () => resolve()));
  const within = (ms: number) => Promise.race([exited.then(() => true), new Promise<boolean>((r) => setTimeout(() => r(gone()), ms))]);
  p.kill("SIGTERM");
  if (await within(graceMs)) return;
  p.kill("SIGKILL");
  if (await within(graceMs)) return;
  throw new Error(`${name} (pid ${p.pid}) did not exit within ${Math.round((2 * graceMs) / 1000)} s of SIGTERM and then SIGKILL`);
}

/** [spawnSync] with a limit, whose failure says whether the program refused or ran out of time. */
function runSync(what: string, cmd: string, args: string[], limitMs: number, input?: string): { status: number | null; stdout: string; stderr: string; failure: string | null } {
  const r = spawnSync(cmd, args, { encoding: "utf-8", timeout: limitMs, killSignal: "SIGKILL", ...(input !== undefined ? { input } : {}) });
  const timedOut = (r.error as NodeJS.ErrnoException | undefined)?.code === "ETIMEDOUT";
  const failure = timedOut
    ? `${what} did not finish within ${Math.round(limitMs / 1000)} s`
    : r.error
      ? `${what} did not start: ${r.error.message}`
      : r.status !== 0
        ? `${what} exited ${r.status ?? r.signal}`
        : null;
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "", failure };
}

/**
 * The server's mail sink: one JSON file per message, written by the server's sender worker in place (so a file can be
 * caught half-written). Every read waits for such a file to read whole; [awaitMail] waits for the mail itself.
 */
export class MailSink {
  constructor(
    private readonly dir: string,
    private readonly clock: WaitClock = realClock,
  ) {}

  /** What the sink holds now: the messages that read whole, and the files that do not (yet). */
  snapshot(): { mail: Mail[]; unreadable: string[] } {
    const mail: Mail[] = [];
    const unreadable: string[] = [];
    if (!existsSync(this.dir)) return { mail, unreadable };
    for (const n of readdirSync(this.dir).filter((f) => f.endsWith(".json")).sort()) {
      try {
        mail.push(JSON.parse(readFileSync(join(this.dir, n), "utf-8")) as Mail);
      } catch {
        unreadable.push(n);
      }
    }
    return { mail, unreadable };
  }

  /** Every message, oldest first, once every file reads whole. */
  mail(): Mail[] {
    let last = this.snapshot();
    return waitForSync(
      "every mail file in the sink reading whole",
      () => {
        last = this.snapshot();
        return last.unreadable.length === 0 ? last.mail : undefined;
      },
      { limitMs: LIMITS.file, clock: this.clock, instead: () => `unreadable files ${JSON.stringify(last.unreadable)}` },
    );
  }

  count(to: string, template: string): number {
    return this.mail().filter((m) => m.to === to && m.template === template).length;
  }

  /**
   * The newest [template] mail to [to] once more than [seen] of them exist (and, with [containing], the newest whose
   * text holds it). Past [limitMs] it says which mail was missing and what the sink held instead.
   */
  async awaitMail(to: string, template: string, seen = 0, opts: { containing?: string; limitMs?: number } = {}): Promise<Mail> {
    let last = this.snapshot();
    const want = opts.containing === undefined ? `a ${template} mail to ${to}` : `a ${template} mail to ${to} naming "${opts.containing}"`;
    return waitFor(
      `${want} (more than ${seen}) in the mail sink`,
      () => {
        last = this.snapshot();
        const all = last.mail.filter((m) => m.to === to && m.template === template);
        if (all.length <= seen) return undefined;
        if (opts.containing === undefined) return all[all.length - 1]!;
        return all.slice(seen).reverse().find((m) => m.text.includes(opts.containing!));
      },
      {
        limitMs: opts.limitMs ?? LIMITS.mail,
        everyMs: 250,
        clock: this.clock,
        instead: () => `${JSON.stringify(last.mail.map((m) => [m.to, m.template]))}${last.unreadable.length ? `, and files not yet whole ${JSON.stringify(last.unreadable)}` : ""}`,
      },
    );
  }
}

/** Null when both distributions are built; otherwise what to run first. */
export function journeysUnavailable(): string | null {
  const missing: string[] = [];
  if (!existsSync(serverLauncher)) missing.push(":server:installDist");
  if (!existsSync(cliLib)) missing.push(":tools:andvari-cli:installDist");
  if (missing.length === 0) return null;
  return `journeys skipped: build the test server first, from the repository root: ./gradlew --offline ${missing.join(" ")} -q`;
}

export interface Mail {
  to: string;
  template: string;
  text: string;
}

export interface InstanceOptions {
  kind: "public" | "private";
  mode?: "open" | "links" | "closed";
  /** Extra `andvari setup` arguments (for example `--recovery-pubkey`). */
  setupArgs?: string[];
  /** Extra environment variables, written into the environment file before the server starts. */
  env?: Record<string, string>;
  operatorEmail?: string;
  /** False: no operator is enrolled at start, so a journey's own peer (AssistPeer.java) takes the setup link. */
  enrolOperator?: boolean;
}

/** What the operator's bootstrap printed: the operator account, for assertions that the web refuses it. */
export interface OperatorAccount {
  email: string;
  password: string;
  userId: string;
}

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = createServer();
    s.on("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const a = s.address();
      const port = typeof a === "object" && a ? a.port : 0;
      s.close(() => resolve(port));
    });
  });
}

function readEnvFile(path: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of readFileSync(path, "utf-8").split("\n")) {
    const i = line.indexOf("=");
    if (i > 0) out[line.slice(0, i).trim()] = line.slice(i + 1);
  }
  return out;
}

function editEnvFile(path: string, keys: Record<string, string>): void {
  const lines = readFileSync(path, "utf-8").split("\n").filter((l) => l !== "");
  const left = new Map(Object.entries(keys));
  const next = lines.map((l) => {
    const k = l.slice(0, l.indexOf("=")).trim();
    const v = left.get(k);
    if (v === undefined) return l;
    left.delete(k);
    return `${k}=${v}`;
  });
  for (const [k, v] of left) next.push(`${k}=${v}`);
  writeFileSync(path, next.join("\n") + "\n", { mode: 0o600 });
}

export class TestInstance {
  private proc: ChildProcess | null = null;
  private log = "";
  private bumps = 0;
  operator: OperatorAccount | null = null;
  private readonly sink: MailSink;

  private constructor(
    readonly dir: string,
    readonly port: number,
    readonly origin: string,
    readonly setupLink: string,
    readonly envFile: string,
    private readonly clockFile: string,
    mailDir: string,
  ) {
    this.sink = new MailSink(mailDir);
  }

  /** Runs setup, starts the server, and enrols the operator (card 0 signed) with the engine's own code. */
  static async start(opts: InstanceOptions): Promise<TestInstance> {
    const dir = mkdtempSync(join(tmpdir(), "andvari-web-journey-"));
    const port = await freePort();
    const envFile = join(dir, "andvari.env");
    const args = ["setup", "--test", "--stop-at-setup", "--port", String(port), "--env-file", envFile, "--kind", opts.kind, ...(opts.mode ? ["--mode", opts.mode] : []), ...(opts.setupArgs ?? [])];
    const setup = runSync("andvari setup --test", serverLauncher, args, LIMITS.setup);
    if (setup.failure) throw new Error(`${setup.failure}: ${setup.stderr}`);
    const line = setup.stdout.trim().split("\n").pop() ?? "";
    const out = JSON.parse(line) as { origin: string; setupLink: string; clockFile: string; mailSink: string };
    editEnvFile(envFile, { ANDVARI_PORT: String(port), ...(opts.env ?? {}) });
    const inst = new TestInstance(dir, port, out.origin, out.setupLink, envFile, out.clockFile, out.mailSink);
    try {
      await inst.boot();
      if (opts.enrolOperator !== false) inst.operator = inst.enrolOperator(opts.operatorEmail ?? "operator@example.org");
    } catch (e) {
      await inst.stop();
      throw e;
    }
    return inst;
  }

  private async boot(): Promise<void> {
    // The launcher reads the process environment; the environment file is the source of truth (design R7).
    const env = { ...process.env, ...readEnvFile(this.envFile) };
    const proc = spawn(serverLauncher, ["server"], { env, stdio: ["ignore", "pipe", "pipe"] });
    this.proc = proc;
    proc.stdout?.on("data", (d: Buffer) => (this.log += d.toString()));
    proc.stderr?.on("data", (d: Buffer) => (this.log += d.toString()));
    let answer = "no answer yet";
    await waitFor(
      "the test server's answer 200 to /healthz",
      async () => {
        if (proc.exitCode !== null || proc.signalCode !== null) throw new Error(`the server exited (${proc.exitCode ?? proc.signalCode}) at start:\n${this.log}`);
        try {
          const r = await fetch(`${this.origin}/healthz`, { signal: AbortSignal.timeout(10_000) });
          if (r.ok) return true;
          answer = `HTTP ${r.status}`;
        } catch (e) {
          answer = `not answering (${(e as Error).message})`;
        }
        return undefined;
      },
      { limitMs: LIMITS.health, everyMs: 250, instead: () => `${answer}; the server's log:\n${this.serverLog()}` },
    );
  }

  /** Stop the server process, keeping its database and port: the server is unreachable until [resume]. */
  async halt(): Promise<void> {
    await this.kill();
  }

  /** Start the server again on the same database and port after [halt]. */
  async resume(): Promise<void> {
    await this.boot();
  }

  /** Restart on the same database and port after editing the environment file, as `andvari admin signup …` does. */
  async restart(env: Record<string, string>): Promise<void> {
    await this.kill();
    editEnvFile(this.envFile, env);
    await this.boot();
  }

  private enrolOperator(email: string): OperatorAccount {
    const password = "operator horse Battery 9 staple";
    const r = runSync("the operator bootstrap", "java", ["-cp", join(cliLib, "*"), bootstrapSource, this.origin, this.setupLink, email, this.clockFile], LIMITS.bootstrap, password + "\n");
    if (r.failure) throw new Error(`${r.failure}:\n${r.stdout}\n${r.stderr}\n--- server:\n${this.serverLog()}`);
    const last = r.stdout.trim().split("\n").pop() ?? "";
    const o = JSON.parse(last) as { userId: string };
    return { email, password, userId: o.userId };
  }

  /**
   * Two connected native accounts, alice and bob, with alice's vault "Family" shared with bob as a writer
   * (SharePeer.java, the engine's own code). The child stays up and acts as alice on each command.
   */
  async sharePeer(password: string): Promise<SharePeerProcess> {
    const a = this.admin("enrol-link").trim().split("\n").pop()!;
    const b = this.admin("enrol-link").trim().split("\n").pop()!;
    const proc = spawn("java", ["-cp", join(cliLib, "*"), sharePeerSource, this.origin, this.clockFile, a, b], { stdio: ["pipe", "pipe", "pipe"] });
    const peer = new SharePeerProcess(proc, () => this.serverLog());
    proc.stdin!.write(password + "\n");
    const first = JSON.parse(await peer.nextLine(LIMITS.peerStart)) as { alice: string; bob: string; vault: string };
    peer.ids = first;
    return peer;
  }

  /**
   * The native sides of operator-assisted recovery (AssistPeer.java, the engine's own code): the operator, who enrols
   * through the setup link here (start the instance with `enrolOperator: false`), and the person's new native device.
   */
  async assistPeer(operatorEmail: string, password: string): Promise<SharePeerProcess> {
    const proc = spawn("java", ["-cp", join(cliLib, "*"), assistPeerSource, this.origin, this.setupLink, operatorEmail, this.clockFile], { stdio: ["pipe", "pipe", "pipe"] });
    const peer = new SharePeerProcess(proc, () => this.serverLog());
    proc.stdin!.write(password + "\n");
    const first = JSON.parse(await peer.nextLine(LIMITS.peerStart)) as { operator: string };
    this.operator = { email: operatorEmail, password, userId: first.operator };
    return peer;
  }

  /**
   * The operator who writes the server's policy while a journey runs (PolicyPeer.java, the shared code's own operator
   * call): enrols through the setup link here (start the instance with `enrolOperator: false`), then on each command
   * `offline-cache on|off` or `kdf OPS MEM_BYTES` writes that field of the policy.
   */
  async policyPeer(operatorEmail: string, password: string): Promise<SharePeerProcess> {
    const proc = spawn("java", ["-cp", join(cliLib, "*"), policyPeerSource, this.origin, this.setupLink, operatorEmail, this.clockFile], { stdio: ["pipe", "pipe", "pipe"] });
    const peer = new SharePeerProcess(proc, () => this.serverLog());
    proc.stdin!.write(password + "\n");
    const first = JSON.parse(await peer.nextLine(LIMITS.peerStart)) as { operator: string };
    this.operator = { email: operatorEmail, password, userId: first.operator };
    return peer;
  }

  /** The offline tool `recovery-cli` with [args], [input] on standard input; its exit status and both outputs. */
  recoveryCli(args: string[], input: string): { status: number | null; stdout: string; stderr: string } {
    const r = runSync("recovery-cli", recoveryCliLauncher, args, LIMITS.tool, input);
    if (r.status === null) throw new Error(`${r.failure}: ${r.stderr}`);
    return { status: r.status, stdout: r.stdout, stderr: r.stderr };
  }

  /** The server's test clock (milliseconds). The journeys' browsers read it too, so no entry is dated ahead of the server. */
  now(): number {
    return Number(readFileSync(this.clockFile, "utf-8").trim());
  }

  /**
   * Move the server's clock forward. The server re-reads the file when its modification time changes. The server and
   * every peer read the file while the journey runs, so it is replaced whole (written beside it, then renamed over it):
   * a reader never sees it empty or half-written.
   */
  advance(ms: number): void {
    const next = this.now() + ms;
    const tmp = `${this.clockFile}.next`;
    writeFileSync(tmp, String(next));
    const t = new Date(Date.now() + ++this.bumps * 1000);
    utimesSync(tmp, t, t);
    renameSync(tmp, this.clockFile);
  }

  /** `andvari admin <args>` against this server's environment file: its stdout. */
  admin(...args: string[]): string {
    const r = runSync(`andvari admin ${args.join(" ")}`, serverLauncher, ["admin", ...args, "--env-file", this.envFile], LIMITS.admin);
    if (r.failure) throw new Error(`${r.failure}: ${r.stdout}${r.stderr}`);
    return r.stdout;
  }

  /** The mail sink's messages, oldest first, each read whole. */
  mail(): Mail[] {
    return this.sink.mail();
  }

  mailCount(to: string, template: string): number {
    return this.sink.count(to, template);
  }

  /** The newest [template] mail to [to], once more than [seen] of them exist (the sender worker writes it up to a drain pass after the request). */
  async awaitMail(to: string, template: string, seen = 0, opts: { containing?: string } = {}): Promise<Mail> {
    return this.sink.awaitMail(to, template, seen, opts);
  }

  /** The six-digit code of the newest [template] mail to [to]. */
  async awaitCode(to: string, template = "signup_code", seen = 0): Promise<string> {
    const text = (await this.awaitMail(to, template, seen)).text;
    const m = /(?<![0-9])([0-9]{6})(?![0-9])/.exec(text);
    if (!m) throw new Error(`no code in ${text}`);
    return m[1]!;
  }

  serverLog(): string {
    return this.log.split("\n").slice(-60).join("\n");
  }

  private async kill(): Promise<void> {
    const p = this.proc;
    this.proc = null;
    if (!p) return;
    await endProcess(p, "the test server");
  }

  async stop(): Promise<void> {
    await this.kill();
    rmSync(this.dir, { recursive: true, force: true });
  }
}
