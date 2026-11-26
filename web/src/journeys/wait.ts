/**
 * How the journeys wait for what another process produces: the thing itself, looked for again and again until a
 * deadline that a machine under full load meets (several builds beside the journeys). Never a fixed pause, never a
 * single look.
 *
 * The limits are generous on purpose. A wait that succeeds returns as soon as the thing is there, so a long limit costs
 * nothing on a quiet machine; it only decides how long a broken run takes to say what is missing.
 */

/** The limits of each kind of wait, in milliseconds. */
export const LIMITS = {
  /**
   * A mail in the test sink. The server's sender worker drains the outbox every 15 seconds (spec 03 §14.5), so a mail
   * queued just after a pass is written at least 15 s later, and a loaded machine delays the pass itself.
   */
  mail: 180_000,
  /** A file another process is writing, until it reads whole (the sink writes each mail in place). */
  file: 30_000,
  /** The test server answering `/healthz` after its start. */
  health: 180_000,
  /** One JSON line from a peer (SharePeer, AssistPeer): each command runs the engine's own key derivation. */
  peer: 300_000,
  /** The peer's first line: two or three native accounts enrolled with the engine's own code. */
  peerStart: 400_000,
  /** `andvari setup --test --stop-at-setup`. */
  setup: 180_000,
  /** The operator's bootstrap (OperatorBootstrap.java, compiled and run by `java`). */
  bootstrap: 300_000,
  /** One `andvari admin …` command. */
  admin: 120_000,
  /** One run of the offline tool `recovery-cli`. */
  tool: 180_000,
  /** A process to exit after SIGTERM, and again after SIGKILL. */
  exit: 20_000,
} as const;

/** What a hook needs beyond the waits it starts: vitest's own work, the browser's crypto, removing a directory. */
const MARGIN = 60_000;

/** The limits of the journeys' hooks, each the sum of what it starts. */
export const HOOK = {
  /** `TestInstance.start`: setup, the server's start, the operator's bootstrap. */
  start: LIMITS.setup + LIMITS.health + LIMITS.bootstrap + MARGIN,
  /** `TestInstance.start` and then a peer's start. */
  startWithPeer: LIMITS.setup + LIMITS.health + LIMITS.bootstrap + LIMITS.peerStart + MARGIN,
  /** `TestInstance.start` and then a browser's sign-up, which waits for its code in the mail sink. */
  startThenSignUp: LIMITS.setup + LIMITS.health + LIMITS.bootstrap + LIMITS.mail + 2 * MARGIN,
  /** Stopping a peer and the server: each may take SIGTERM's grace and then SIGKILL's. */
  stop: 4 * LIMITS.exit + MARGIN,
} as const;

/** The clock and the pause a wait uses: the real ones, or a test's own (wait.test.ts). */
export interface WaitClock {
  now(): number;
  sleep(ms: number): Promise<void>;
  /** A pause that blocks this thread: only for re-reading a file another process is writing, never for long. */
  sleepSync(ms: number): void;
}

const blocker = new Int32Array(new SharedArrayBuffer(4));

export const realClock: WaitClock = {
  now: () => Date.now(),
  sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
  sleepSync: (ms) => {
    Atomics.wait(blocker, 0, 0, ms);
  },
};

export interface WaitOptions {
  /** The deadline, from the first look. */
  limitMs: number;
  /** Between looks. */
  everyMs?: number;
  clock?: WaitClock;
  /** What was there instead, for the failure's sentence. */
  instead?: () => string;
}

/**
 * Looks for [what] until [look] answers something other than undefined, and answers it. Past the deadline it throws
 * one sentence: what was missing, for how long it was looked for, and what was there instead.
 */
export async function waitFor<T>(what: string, look: () => T | undefined | Promise<T | undefined>, opts: WaitOptions): Promise<T> {
  const clock = opts.clock ?? realClock;
  const start = clock.now();
  const end = start + opts.limitMs;
  for (let looks = 1; ; looks++) {
    const found = await look();
    if (found !== undefined) return found;
    if (clock.now() >= end) {
      const there = opts.instead ? opts.instead() : "nothing to show";
      throw new Error(`${what} did not arrive within ${Math.round((clock.now() - start) / 1000)} s (${looks} looks); there instead: ${there}`);
    }
    await clock.sleep(Math.min(opts.everyMs ?? 250, Math.max(1, end - clock.now())));
  }
}

/** [waitFor] for a value another process writes that is read synchronously (a file being written). */
export function waitForSync<T>(what: string, look: () => T | undefined, opts: WaitOptions): T {
  const clock = opts.clock ?? realClock;
  const start = clock.now();
  const end = start + opts.limitMs;
  for (let looks = 1; ; looks++) {
    const found = look();
    if (found !== undefined) return found;
    if (clock.now() >= end) {
      const there = opts.instead ? opts.instead() : "nothing to show";
      throw new Error(`${what} did not arrive within ${Math.round((clock.now() - start) / 1000)} s (${looks} looks); there instead: ${there}`);
    }
    clock.sleepSync(Math.min(opts.everyMs ?? 50, Math.max(1, end - clock.now())));
  }
}
