import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ANSWER_STALLED, ANSWER_TOO_LONG } from "../ui/copy";
import { answerLimitText } from "../ui/errors";
import { AnswerCutOffError, ApiClient, ApiError, ANSWER_TIMEOUT_MS, NoAnswerInTimeError, PROGRESS_TIMEOUT_MS, RefreshUnansweredError, UPLOAD_FLOOR_BYTES_PER_S } from "./client";
import { WireApi } from "./wireclient";

/**
 * Two kinds of limit on an answer (a second review of the web app's fixes: a limit on the WHOLE time of every answer made
 * the first sync of a large vault on a slow line impossible, and retried it every minute without a word). An answer that is
 * small by its nature keeps a limit of sixty seconds on its whole time. An answer whose size grows with the vault or a file
 * (the sync, a push, an attachment) has a limit on the time WITHOUT PROGRESS, thirty seconds without a byte, and none on
 * its total. Either limit, when it strikes, is said in a sentence of its own. All on a driven clock.
 */

const SYNC_HEAD = '{"rev":1,"full":true,"vaults":[],"grants":[],"items":[],"removedGrants":[]';

/** A fetch whose answer's head comes at once and whose body is [pieces], one every [everyMs] (on the driven clock), then
 *  either the end or, with [stopAfter], nothing more for ever. The body ignores the request's signal on purpose: the
 *  limit must hold even against a body that does not end when the request is aborted. */
function dripping(pieces: () => Iterator<Uint8Array>, everyMs: number, opts: { stop?: boolean; seen?: RequestInit[] } = {}) {
  return vi.fn(async (_url: string, init: RequestInit) => {
    opts.seen?.push(init);
    const it = pieces();
    const body = new ReadableStream<Uint8Array>({
      start(c) {
        const next = () => {
          const r = it.next();
          if (r.done) {
            if (!opts.stop) c.close();
            return;
          }
          try {
            c.enqueue(r.value);
          } catch {
            return; // the reader cancelled the body (a limit struck): the server's side stops too
          }
          setTimeout(next, everyMs);
        };
        next();
      },
    });
    return new Response(body, { status: 200, headers: { "Content-Type": "application/json" } });
  });
}

/** A fetch that never answers until its request is aborted. */
function silent(seen: RequestInit[] = []) {
  return vi.fn(
    (_url: string, init: RequestInit) =>
      new Promise<Response>((_, reject) => {
        seen.push(init);
        const signal = init.signal;
        signal?.addEventListener("abort", () => reject(signal.reason ?? new DOMException("aborted", "AbortError")));
      }),
  );
}

/** A fetch that answers every API call with a 401 head whose body never comes, and the refresh with [refresh] (a third
 *  review's probe: the window paused for the refresh was never started again when no second send followed). */
function headWithoutBody(calls: string[], refresh: () => Response) {
  return vi.fn(async (url: string) => {
    const path = new URL(url).pathname;
    calls.push(path);
    if (path === "/api/v1/auth/refresh") return refresh();
    return new Response(new ReadableStream<Uint8Array>({ start() {} }), { status: 401, headers: { "Content-Type": "application/json" } });
  });
}

/** [p] as an outcome that can be looked at while the clock is driven. */
function watch<T>(p: Promise<T>) {
  const o: { settled: boolean; value?: T; error?: unknown } = { settled: false };
  p.then(
    (v) => Object.assign(o, { settled: true, value: v }),
    (e: unknown) => Object.assign(o, { settled: true, error: e }),
  );
  return o;
}

const enc = new TextEncoder();

function* textPieces(text: string, size: number): Iterator<Uint8Array> {
  for (let i = 0; i < text.length; i += size) yield enc.encode(text.slice(i, i + size));
}

describe("two kinds of limit on an answer", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("the limits are a minute on a small answer's whole time, and thirty seconds without a byte on an answer that grows", () => {
    const client = new ApiClient("https://family.example");
    expect(client.answerTimeoutMs).toBe(ANSWER_TIMEOUT_MS);
    expect(ANSWER_TIMEOUT_MS).toBe(60_000);
    expect(client.progressTimeoutMs).toBe(PROGRESS_TIMEOUT_MS);
    expect(PROGRESS_TIMEOUT_MS).toBe(30_000);
  });

  it("a 20 MB first sync at a slow, steady rate (16 KiB a second, about 21 minutes) finishes", async () => {
    const piece = enc.encode(" ".repeat(16 * 1024));
    const total = 20 * 1024 * 1024;
    function* pieces(): Iterator<Uint8Array> {
      yield enc.encode(SYNC_HEAD);
      for (let sent = 0; sent < total; sent += piece.length) yield piece;
      yield enc.encode("}");
    }
    vi.stubGlobal("fetch", dripping(pieces, 1_000));
    const client = new ApiClient("https://family.example");
    client.setTokens({ accessToken: "a", refreshToken: "r" });
    const o = watch(new WireApi(client).sync(0));
    await vi.advanceTimersByTimeAsync(1_300_000);
    expect(o.error).toBeUndefined();
    expect(o.settled).toBe(true);
    expect(o.value?.full).toBe(true);
  });

  it("a sync whose server stops sending is ended thirty seconds after the last byte, and the person reads that it stopped", async () => {
    vi.stubGlobal("fetch", dripping(() => textPieces(SYNC_HEAD, 8), 1_000, { stop: true }));
    const client = new ApiClient("https://family.example");
    client.setTokens({ accessToken: "a", refreshToken: "r" });
    const o = watch(new WireApi(client).sync(0));
    const lastByteAt = (Math.ceil(SYNC_HEAD.length / 8) - 1) * 1_000;
    await vi.advanceTimersByTimeAsync(lastByteAt + 29_900);
    expect(o.settled, "still waiting 29.9 s after the last byte").toBe(false);
    await vi.advanceTimersByTimeAsync(200);
    expect(o.settled).toBe(true);
    expect(o.error).toBeInstanceOf(AnswerCutOffError);
    expect((o.error as AnswerCutOffError).limit).toBe("stalled");
    expect(answerLimitText(o.error)).toBe(ANSWER_STALLED);
  });

  it("a sync that gets no answer at all is ended after thirty seconds, said as no answer (a TypeError) with the sentence that the server stopped", async () => {
    vi.stubGlobal("fetch", silent());
    const client = new ApiClient("https://family.example");
    client.setTokens({ accessToken: "a", refreshToken: "r" });
    const o = watch(new WireApi(client).sync(0));
    await vi.advanceTimersByTimeAsync(29_900);
    expect(o.settled).toBe(false);
    await vi.advanceTimersByTimeAsync(200);
    expect(o.error).toBeInstanceOf(TypeError);
    expect(o.error).toBeInstanceOf(NoAnswerInTimeError);
    expect(answerLimitText(o.error)).toBe(ANSWER_STALLED);
  });

  it("a small answer that drips (a byte every ten seconds) is ended at sixty seconds in all, and the person reads that it took too long", async () => {
    vi.stubGlobal("fetch", dripping(() => textPieces('{"policy":"' + "x".repeat(100) + '"}', 1), 10_000));
    const client = new ApiClient("https://family.example");
    const o = watch(new WireApi(client).clientPolicy());
    await vi.advanceTimersByTimeAsync(59_900);
    expect(o.settled, "a byte every ten seconds is progress, and a small answer is still ended at its whole limit").toBe(false);
    await vi.advanceTimersByTimeAsync(200);
    expect(o.error).toBeInstanceOf(AnswerCutOffError);
    expect((o.error as AnswerCutOffError).limit).toBe("too_long");
    expect(answerLimitText(o.error)).toBe(ANSWER_TOO_LONG);
  });

  it("a small answer that never comes is ended at sixty seconds as no answer (a TypeError), with the sentence that it took too long", async () => {
    vi.stubGlobal("fetch", silent());
    const o = watch(new WireApi(new ApiClient("https://family.example")).clientPolicy());
    await vi.advanceTimersByTimeAsync(59_900);
    expect(o.settled).toBe(false);
    await vi.advanceTimersByTimeAsync(200);
    expect(o.error).toBeInstanceOf(TypeError);
    expect(answerLimitText(o.error)).toBe(ANSWER_TOO_LONG);
  });

  it("an attachment's download at a slow, steady rate takes as long as it needs; one that stops is ended thirty seconds later", async () => {
    const piece = new Uint8Array(4_096);
    function* slow(): Iterator<Uint8Array> {
      for (let i = 0; i < 300; i++) yield piece; // 1.2 MB at 4 KiB a second: five minutes
    }
    vi.stubGlobal("fetch", dripping(slow, 1_000));
    const client = new ApiClient("https://family.example");
    client.setTokens({ accessToken: "a", refreshToken: "r" });
    const ok = watch(new WireApi(client).downloadAttachment("00000000-0000-4000-8000-000000000001"));
    await vi.advanceTimersByTimeAsync(301_000);
    expect(ok.error).toBeUndefined();
    expect((ok.value as Uint8Array).length).toBe(300 * 4_096);

    function* stops(): Iterator<Uint8Array> {
      yield piece;
      yield piece;
    }
    vi.stubGlobal("fetch", dripping(stops, 1_000, { stop: true }));
    const cut = watch(new WireApi(client).downloadAttachment("00000000-0000-4000-8000-000000000001"));
    await vi.advanceTimersByTimeAsync(1_000 + 29_900);
    expect(cut.settled).toBe(false);
    await vi.advanceTimersByTimeAsync(200);
    expect(cut.error).toBeInstanceOf(AnswerCutOffError);
    expect(answerLimitText(cut.error)).toBe(ANSWER_STALLED);
  });

  it("a request with a body is given the body's time at the floor rate before its answer must begin (a browser cannot see a body leave)", async () => {
    const seen: RequestInit[] = [];
    vi.stubGlobal("fetch", silent(seen));
    const client = new ApiClient("https://family.example");
    client.setTokens({ accessToken: "a", refreshToken: "r" });
    const body = new Uint8Array(1024 * 1024); // 1 MiB: 512 s at 2 KiB/s
    const o = watch(new WireApi(client).uploadAttachment("00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002", "00000000-0000-4000-8000-000000000003", body));
    const window = PROGRESS_TIMEOUT_MS + Math.ceil((body.length * 1000) / UPLOAD_FLOOR_BYTES_PER_S);
    await vi.advanceTimersByTimeAsync(window - 100);
    expect(o.settled).toBe(false);
    await vi.advanceTimersByTimeAsync(200);
    expect(o.error).toBeInstanceOf(NoAnswerInTimeError);
    expect(answerLimitText(o.error)).toBe(ANSWER_STALLED);
    expect(seen).toHaveLength(1);
  });

  it("a push (an import's request, a drain) is an answer that grows: it is not ended at sixty seconds while its answer comes", async () => {
    const answer = '{"results":[]}';
    vi.stubGlobal("fetch", dripping(() => textPieces(answer, 1), 20_000)); // 14 bytes, one every 20 s: 260 s in all
    const client = new ApiClient("https://family.example");
    client.setTokens({ accessToken: "a", refreshToken: "r" });
    const o = watch(new WireApi(client).pushMutations([]));
    await vi.advanceTimersByTimeAsync(answer.length * 20_000 + 1_000);
    expect(o.settled).toBe(true);
    expect(answerLimitText(o.error)).toBeNull();
  });

  it("a sync answered 401 whose body never comes, after a refresh answered by a 503 page: it ends at once as a renewal with no answer, not on the 401's body", async () => {
    const calls: string[] = [];
    vi.stubGlobal("fetch", headWithoutBody(calls, () => new Response("busy", { status: 503 })));
    const client = new ApiClient("https://family.example");
    client.setTokens({ accessToken: "a", refreshToken: "r" });
    const o = watch(new WireApi(client).sync(0));
    await vi.advanceTimersByTimeAsync(100);
    // The 401 is not handed back (its callers read it as the session's end): the request fails as one with no answer.
    expect(o.settled).toBe(true);
    expect(o.error).toBeInstanceOf(RefreshUnansweredError);
    expect(o.error instanceof ApiError).toBe(false);
    expect(calls).toEqual(["/api/v1/sync", "/api/v1/auth/refresh"]);
    expect(client.getTokens(), "a 503 page is not the server's refusal: the pair is kept").not.toBeNull();
  });

  it("the same after a refresh the server refuses (the session ended), and after a refresh that left the tab bound to another account", async () => {
    const refused: string[] = [];
    vi.stubGlobal("fetch", headWithoutBody(refused, () => new Response('{"error":"unauthorized"}', { status: 401 })));
    const a = new ApiClient("https://family.example");
    a.setTokens({ accessToken: "a", refreshToken: "r" });
    const o1 = watch(new WireApi(a).sync(0));
    await vi.advanceTimersByTimeAsync(30_100);
    expect(o1.settled).toBe(true);
    expect(refused).toEqual(["/api/v1/sync", "/api/v1/auth/refresh"]);

    const rebound: string[] = [];
    const b = new ApiClient("https://family.example");
    b.boundUserId = "A";
    b.setTokens({ accessToken: "a", refreshToken: "r" });
    vi.stubGlobal(
      "fetch",
      headWithoutBody(rebound, () => {
        b.boundUserId = "B"; // signed out and in as another account while the refresh was out
        return new Response('{"accessToken":"a2","refreshToken":"r2"}', { status: 200, headers: { "Content-Type": "application/json" } });
      }),
    );
    const o2 = watch(new WireApi(b).sync(0));
    await vi.advanceTimersByTimeAsync(30_100);
    expect(o2.settled).toBe(true);
    expect(rebound, "no second send under the other account's token").toEqual(["/api/v1/sync", "/api/v1/auth/refresh"]);
  });

  it("an upload, and a small call, answered 401 with no body after a refresh answered by a page: each ends at once, not on the 401's body", async () => {
    const calls: string[] = [];
    vi.stubGlobal("fetch", headWithoutBody(calls, () => new Response("busy", { status: 503 })));
    const client = new ApiClient("https://family.example");
    client.setTokens({ accessToken: "a", refreshToken: "r" });
    const up = watch(new WireApi(client).uploadAttachment("00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002", "00000000-0000-4000-8000-000000000003", new Uint8Array(1024)));
    await vi.advanceTimersByTimeAsync(100);
    expect(up.settled).toBe(true);
    expect(up.error).toBeInstanceOf(RefreshUnansweredError);

    const small = watch(new WireApi(client).usage());
    await vi.advanceTimersByTimeAsync(100);
    expect(small.settled).toBe(true);
    expect(small.error).toBeInstanceOf(RefreshUnansweredError);
  });

  it("a caller's own deadline is kept as it is (the push before a policy's wipe, an account deletion): no limit of the client's", async () => {
    vi.stubGlobal("fetch", silent());
    const client = new ApiClient("https://family.example");
    client.setTokens({ accessToken: "a", refreshToken: "r" });
    const own = new AbortController();
    const o = watch(new WireApi(client).pushMutations([], { signal: own.signal }));
    await vi.advanceTimersByTimeAsync(10 * 60_000);
    expect(o.settled, "only the caller's own signal ends it").toBe(false);
    own.abort();
    await vi.advanceTimersByTimeAsync(0);
    expect(o.error).not.toBeInstanceOf(TypeError); // the caller's abort reaches it as the caller's
    expect(answerLimitText(o.error)).toBeNull();
  });
});
