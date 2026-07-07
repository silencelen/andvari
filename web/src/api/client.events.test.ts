import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiClient } from "./client";

/**
 * events() reconnect logic against a mocked WebSocket + fetch: fresh single-use
 * ticket per attempt, exponential backoff, fatal-401 stop, clean teardown.
 */

class FakeWS {
  static instances: FakeWS[] = [];
  url: string;
  onopen: (() => void) | null = null;
  onmessage: ((ev: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  closedByCaller = false;
  constructor(url: string) {
    this.url = url;
    FakeWS.instances.push(this);
  }
  close() {
    this.closedByCaller = true;
    this.onclose?.(); // the browser also fires close on a caller-initiated close
  }
}

const flush = async () => {
  for (let i = 0; i < 8; i++) await Promise.resolve();
};

/** Nth fake socket (asserted to exist — tests check counts separately). */
const sock = (i: number): FakeWS => FakeWS.instances[i]!;

describe("ApiClient.events reconnection", () => {
  let mintCount: number;
  let mintStatus: number;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.spyOn(Math, "random").mockReturnValue(1); // deterministic jitter: delay == base
    FakeWS.instances = [];
    mintCount = 0;
    mintStatus = 200;
    vi.stubGlobal("WebSocket", FakeWS as unknown as typeof WebSocket);
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (String(url).endsWith("/api/v1/events/ticket")) {
          mintCount++;
          if (mintStatus !== 200) {
            return {
              ok: false,
              status: mintStatus,
              statusText: "nope",
              json: async () => ({ error: "unauthorized", message: "dead session" }),
            } as unknown as Response;
          }
          return {
            ok: true,
            status: 200,
            text: async () => JSON.stringify({ ticket: `t${mintCount}`, expiresInSeconds: 30 }),
          } as unknown as Response;
        }
        throw new Error(`unexpected fetch ${url}`);
      }),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  const makeClient = () => new ApiClient("http://server", null);

  it("connects with a minted ticket and fires onOpen", async () => {
    const onOpen = vi.fn();
    const close = makeClient().events(vi.fn(), vi.fn(), onOpen);
    await flush();
    expect(mintCount).toBe(1);
    expect(FakeWS.instances).toHaveLength(1);
    expect(sock(0).url).toContain("ticket=t1");
    expect(sock(0).url.startsWith("ws://server/api/v1/events")).toBe(true);
    sock(0).onopen?.();
    expect(onOpen).toHaveBeenCalledTimes(1);
    close();
  });

  it("reconnects after a drop with a FRESH ticket and re-fires onOpen (sync-on-reopen)", async () => {
    const onOpen = vi.fn();
    const close = makeClient().events(vi.fn(), vi.fn(), onOpen);
    await flush();
    sock(0).onopen?.();
    sock(0).onclose?.(); // server deploy / sleep drop
    await vi.advanceTimersByTimeAsync(1_000); // first backoff step
    await flush();
    expect(FakeWS.instances).toHaveLength(2);
    expect(mintCount).toBe(2); // one-shot tickets: re-minted per attempt
    expect(sock(1).url).toContain("ticket=t2");
    sock(1).onopen?.();
    expect(onOpen).toHaveBeenCalledTimes(2);
    close();
  });

  it("backs off exponentially while the server stays down, resets after a good open", async () => {
    const close = makeClient().events(vi.fn(), vi.fn());
    await flush();
    // Cycle 1: drop without opening → retry after 1 s.
    sock(0).onclose?.();
    await vi.advanceTimersByTimeAsync(999);
    await flush();
    expect(FakeWS.instances).toHaveLength(1); // not yet
    await vi.advanceTimersByTimeAsync(1);
    await flush();
    expect(FakeWS.instances).toHaveLength(2);
    // Cycle 2: → 2 s.
    sock(1).onclose?.();
    await vi.advanceTimersByTimeAsync(1_999);
    await flush();
    expect(FakeWS.instances).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(1);
    await flush();
    expect(FakeWS.instances).toHaveLength(3);
    // Cycle 3: → 4 s.
    sock(2).onclose?.();
    await vi.advanceTimersByTimeAsync(4_000);
    await flush();
    expect(FakeWS.instances).toHaveLength(4);
    // A successful open resets the ladder: next drop retries after 1 s again.
    sock(3).onopen?.();
    sock(3).onclose?.();
    await vi.advanceTimersByTimeAsync(1_000);
    await flush();
    expect(FakeWS.instances).toHaveLength(5);
    close();
  });

  it("caps the backoff at 60 s", async () => {
    const close = makeClient().events(vi.fn(), vi.fn());
    await flush();
    for (let i = 0; i < 10; i++) {
      sock(FakeWS.instances.length - 1).onclose?.();
      await vi.advanceTimersByTimeAsync(60_000); // >= every possible capped delay
      await flush();
    }
    expect(FakeWS.instances).toHaveLength(11);
    // Ladder is saturated: another drop reconnects within exactly 60 s.
    sock(10).onclose?.();
    await vi.advanceTimersByTimeAsync(59_999);
    await flush();
    expect(FakeWS.instances).toHaveLength(11);
    await vi.advanceTimersByTimeAsync(1);
    await flush();
    expect(FakeWS.instances).toHaveLength(12);
    close();
  });

  it("stops and surfaces onRevoked when the ticket mint 401s (dead session)", async () => {
    mintStatus = 401;
    const onRevoked = vi.fn();
    const close = makeClient().events(vi.fn(), onRevoked);
    await flush();
    expect(onRevoked).toHaveBeenCalledTimes(1);
    expect(FakeWS.instances).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(600_000);
    await flush();
    expect(mintCount).toBe(1); // no retry loop against a dead session
    close();
  });

  it("keeps retrying quietly on transient mint failures (network down)", async () => {
    const fetchMock = fetch as unknown as ReturnType<typeof vi.fn>;
    fetchMock.mockRejectedValueOnce(new TypeError("network down"));
    const onRevoked = vi.fn();
    const close = makeClient().events(vi.fn(), onRevoked);
    await flush();
    expect(FakeWS.instances).toHaveLength(0);
    expect(onRevoked).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1_000);
    await flush();
    expect(FakeWS.instances).toHaveLength(1); // recovered on the next attempt
    close();
  });

  it("a server 'revoked' frame stops reconnection", async () => {
    const onRevoked = vi.fn();
    const close = makeClient().events(vi.fn(), onRevoked);
    await flush();
    sock(0).onopen?.();
    sock(0).onmessage?.({ data: JSON.stringify({ type: "revoked" }) });
    expect(onRevoked).toHaveBeenCalledTimes(1);
    sock(0).onclose?.(); // server closes the socket after revoking
    await vi.advanceTimersByTimeAsync(600_000);
    await flush();
    expect(FakeWS.instances).toHaveLength(1);
    expect(mintCount).toBe(1);
    close();
  });

  it("caller close() tears down: no reconnect, socket closed", async () => {
    const close = makeClient().events(vi.fn(), vi.fn());
    await flush();
    sock(0).onopen?.();
    close();
    expect(sock(0).closedByCaller).toBe(true);
    await vi.advanceTimersByTimeAsync(600_000);
    await flush();
    expect(FakeWS.instances).toHaveLength(1);
    expect(mintCount).toBe(1);
  });

  it("caller close() during the mint round-trip never opens a socket", async () => {
    const close = makeClient().events(vi.fn(), vi.fn());
    close(); // before the awaited mint resolves
    await flush();
    expect(FakeWS.instances).toHaveLength(0);
  });
});
