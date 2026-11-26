import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { ApiClient } from "../api/client";
import { initSodium } from "../crypto/sodium";
import { DeviceIdentity, memoryStorage } from "../api/devicesecret";
import { WireApi } from "../api/wireclient";
import { beginSignIn, replacedSession, signInForm } from "./tabsession";

const ORIGIN = "https://vault.example.org";
const U = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const OTHER = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const ROW = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";

/**
 * What a sign-in in this tab names as the session it replaces (spec 03 §2 `replacesRefreshToken`): only the pair THIS
 * tab holds, for the same account, on the same row of this browser; never a pair every tab shares (the offline copy),
 * never a pair bound to no account, and nothing otherwise. Over the real transport, the login carries it only then.
 */
describe("a sign-in names only the session this tab holds for the same account", () => {
  beforeAll(async () => {
    await initSodium();
  });
  afterEach(() => vi.unstubAllGlobals());

  it("which pair a tab names", () => {
    const client = new ApiClient(ORIGIN);
    expect(replacedSession(client, () => false), "no pair").toBeNull();
    client.setTokens({ accessToken: "a", refreshToken: "r1" });
    expect(replacedSession(client, () => false), "bound to no account").toBeNull();
    client.boundUserId = U;
    expect(replacedSession(client, () => false)).toEqual({ userId: U, refreshToken: "r1" });
    expect(replacedSession(client, (u) => u === U), "the pair every tab shares (the offline copy is on)").toBeNull();
    beginSignIn(client);
    expect(replacedSession(client, () => false), "a sign-in's placeholder binding").toBeNull();
  });

  async function loginBody(storage: ReturnType<typeof memoryStorage>, replaces: { userId: string; refreshToken: string } | null): Promise<Record<string, unknown>> {
    let body: Record<string, unknown> = {};
    vi.stubGlobal("fetch", async (_url: string, init: RequestInit = {}) => {
      body = JSON.parse(String(init.body)) as Record<string, unknown>;
      return new Response(JSON.stringify({ error: "invalid_credentials", message: "x" }), { status: 401, headers: { "Content-Type": "application/json" } });
    });
    const wire = new WireApi(new ApiClient(ORIGIN), new DeviceIdentity(storage));
    await wire.login("june@example.org", "QUFBQQ==", "Firefox", undefined, undefined, replaces).catch(() => null);
    vi.unstubAllGlobals();
    return body;
  }

  it("the login carries the name only for the same account on this browser's row", async () => {
    const storage = memoryStorage();
    expect(await loginBody(storage, { userId: U, refreshToken: "r1" }), "no row for the email yet").not.toHaveProperty("replacesRefreshToken");
    new DeviceIdentity(storage).remember("june@example.org", U, ROW);
    const named = await loginBody(storage, { userId: U, refreshToken: "r1" });
    expect(named.replacesRefreshToken).toBe("r1");
    expect((named.device as { deviceId?: string }).deviceId).toBe(ROW);
    expect(await loginBody(storage, { userId: OTHER, refreshToken: "r1" }), "another account's pair").not.toHaveProperty("replacesRefreshToken");
    expect(await loginBody(storage, null), "nothing to name").not.toHaveProperty("replacesRefreshToken");
  });

  /** The login bodies a form's submits send, each answered by [answer]: the real transport and wire, only fetch played. */
  function formOver(client: ApiClient, storage: ReturnType<typeof memoryStorage>, answer: () => Response) {
    const bodies: Record<string, unknown>[] = [];
    vi.stubGlobal("fetch", async (_url: string, init: RequestInit = {}) => {
      bodies.push(JSON.parse(String(init.body)) as Record<string, unknown>);
      return answer();
    });
    const wire = new WireApi(client, new DeviceIdentity(storage));
    const form = signInForm(client, () => false);
    const submit = async () => {
      const { flow, replaces } = form.submit();
      await wire.login("june@example.org", "QUFBQQ==", "Firefox", undefined, flow.installed, replaces).catch(() => null);
    };
    return { bodies, submit };
  }

  const refusal = (code: string) => () => new Response(JSON.stringify({ error: code, message: "x" }), { status: 401, headers: { "Content-Type": "application/json" } });

  it("every submit of the form names it: after the server asks for the two-step code, and after a wrong password (the check's P4)", async () => {
    const storage = memoryStorage();
    new DeviceIdentity(storage).remember("june@example.org", U, ROW);
    const client = new ApiClient(ORIGIN);
    client.setTokens({ accessToken: "a", refreshToken: "A-refresh" });
    client.boundUserId = U;
    let answer = refusal("totp_required");
    const { bodies, submit } = formOver(client, storage, () => answer());
    await submit();
    // The client is bound to the sign-in's placeholder now, the pair still held: a fresh read would name nothing.
    expect(replacedSession(client, () => false)).toBeNull();
    await submit(); // the two-step code's submit
    answer = refusal("invalid_credentials");
    await submit(); // a wrong code or password
    await submit(); // and the next try
    expect(bodies.map((b) => b.replacesRefreshToken)).toEqual(["A-refresh", "A-refresh", "A-refresh", "A-refresh"]);
  });

  it("why the record must live across the submits of one form: a record made afresh between two submits names nothing at the second, and the offline copy's shared pair is never named by either", async () => {
    const storage = memoryStorage();
    new DeviceIdentity(storage).remember("june@example.org", U, ROW);
    const client = new ApiClient(ORIGIN);
    client.setTokens({ accessToken: "a", refreshToken: "A-refresh" });
    client.boundUserId = U;
    const { bodies, submit } = formOver(client, storage, refusal("totp_required"));
    await submit();
    // A form rebuilt here (a component mounted afresh) would begin with a record of its own, and the client is bound to
    // the first submit's placeholder by now: it would name nothing.
    const rebuilt = signInForm(client, () => false).submit();
    expect(rebuilt.replaces).toBeNull();
    await submit();
    expect(bodies.map((b) => b.replacesRefreshToken)).toEqual(["A-refresh", "A-refresh"]);
    // With the offline copy on (the pair every tab shares), no record names anything, kept or rebuilt: a form moved
    // between the unlock card's two places (only where the copy is on, sessionend.ts endedByServer) loses nothing.
    const shared = new ApiClient(ORIGIN);
    shared.setTokens({ accessToken: "s", refreshToken: "S-refresh" });
    shared.boundUserId = U;
    const kept = signInForm(shared, () => true);
    expect(kept.submit().replaces).toBeNull();
    expect(kept.submit().replaces).toBeNull();
    expect(signInForm(shared, () => true).submit().replaces).toBeNull();
  });

  it("once the client holds another pair (or none), a later submit names nothing", async () => {
    const storage = memoryStorage();
    new DeviceIdentity(storage).remember("june@example.org", U, ROW);
    const client = new ApiClient(ORIGIN);
    client.setTokens({ accessToken: "a", refreshToken: "A-refresh" });
    client.boundUserId = U;
    const { bodies, submit } = formOver(client, storage, refusal("totp_required"));
    await submit();
    client.setTokens({ accessToken: "b", refreshToken: "B-refresh" }); // a login of this form installed its own pair
    await submit();
    client.setTokens(null); // its way out ended that one
    await submit();
    expect(bodies.map((b) => b.replacesRefreshToken)).toEqual(["A-refresh", undefined, undefined]);
  });
});
