import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiClient, ApiError } from "./client";
import { DeviceIdentity, memoryStorage } from "./devicesecret";
import type { Refusal } from "./wireids";
import { DEVICES_MAX_PAGES, DEVICES_PAGE_ROWS, LIST_TOO_LONG, TRASH_MAX_PAGES, TRASH_PAGE_ROWS, WireApi } from "./wireclient";

/**
 * The two lists that come in pages since 2026-11-16 (spec 03 §16.7 devices, §5.1 trash): every page is read, the list
 * exists only once the last page has arrived, a refused page fails the whole read, and the reading stops at a stated
 * number of pages.
 */

const V1 = "11111111-1111-4111-8111-111111111111";
const uuid = (i: number) => `00000000-0000-4000-8000-${i.toString(16).padStart(12, "0")}`;

function serve(answer: (url: URL) => { status?: number; body: unknown }): URL[] {
  const seen: URL[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      const u = new URL(url);
      seen.push(u);
      const a = answer(u);
      const status = a.status ?? 200;
      const text = JSON.stringify(a.body);
      return { ok: status < 400, status, statusText: String(status), json: async () => JSON.parse(text), text: async () => text } as unknown as Response;
    }),
  );
  return seen;
}

function api(refused: [string, Refusal[]][] = []) {
  return new WireApi(new ApiClient("http://server", { accessToken: "acc", refreshToken: "ref" }), new DeviceIdentity(memoryStorage()), (endpoint, r) => refused.push([endpoint, r]));
}

const device = (i: number) => ({ deviceId: uuid(i), platform: "web", name: `d${i}`, clientVersion: null, createdAt: i, lastSeenAt: null, live: false, how: "password", current: false });

/** The devices of an account of [count] rows, served the way spec 03 §16.7 pages them. */
function devicesServer(count: number, refuse?: (pageNo: number) => number | null) {
  let pageNo = 0;
  return serve((u) => {
    const status = refuse?.(pageNo++) ?? null;
    if (status !== null) return { status, body: { error: "bad_request" } };
    const after = u.searchParams.get("after");
    const start = after === null ? 0 : Number.parseInt(after.slice(-12), 16) + 1;
    const rows: unknown[] = [];
    for (let i = start; i < Math.min(count, start + DEVICES_PAGE_ROWS); i++) rows.push(device(i));
    return { body: rows };
  });
}

afterEach(() => vi.unstubAllGlobals());

describe("the devices list comes in pages (spec 03 §16.7)", () => {
  it("reads every page, asking after the last row of each full one, and shows the whole list", async () => {
    const seen = devicesServer(1003);
    const rows = await api().devices();
    expect(rows).toHaveLength(1003);
    expect(rows[1002]!.deviceId).toBe(uuid(1002));
    expect(seen.map((u) => u.pathname + u.search)).toEqual([
      "/api/v1/account/devices",
      `/api/v1/account/devices?after=${uuid(499)}`,
      `/api/v1/account/devices?after=${uuid(999)}`,
    ]);
  });

  it("a page that ends exactly on the last row is followed by an empty last page", async () => {
    const seen = devicesServer(500);
    expect(await api().devices()).toHaveLength(500);
    expect(seen).toHaveLength(2);
  });

  it("a page counts the rows the server sent: a row dropped for a malformed id does not end the list early", async () => {
    const refused: [string, Refusal[]][] = [];
    let n = 0;
    serve(() => {
      if (n++ > 0) return { body: [device(600)] };
      const rows: unknown[] = [];
      for (let i = 0; i < DEVICES_PAGE_ROWS; i++) rows.push(i === 3 ? { ...device(i), deviceId: "nope" } : device(i));
      return { body: rows };
    });
    const rows = await api(refused).devices();
    expect(rows).toHaveLength(DEVICES_PAGE_ROWS);
    expect(rows.at(-1)!.deviceId).toBe(uuid(600));
    expect(refused.map(([e]) => e)).toEqual(["account/devices"]);
  });

  it("a row seen twice, in one page or across two, is shown once, where it first came", async () => {
    let n = 0;
    serve(() => {
      if (n++ > 0) return { body: [device(2), device(DEVICES_PAGE_ROWS)] };
      const rows: unknown[] = [];
      for (let i = 0; i < DEVICES_PAGE_ROWS - 1; i++) rows.push(device(i));
      rows.push(device(1)); // the first page repeats a row as its last
      return { body: rows };
    });
    const rows = await api().devices();
    expect(rows.map((r) => r.deviceId)).toEqual([...Array.from({ length: DEVICES_PAGE_ROWS - 1 }, (_x, i) => uuid(i)), uuid(DEVICES_PAGE_ROWS)]);
  });

  it("a refused page fails the whole read: no shorter list", async () => {
    devicesServer(1200, (p) => (p === 1 ? 400 : null));
    await expect(api().devices()).rejects.toMatchObject({ status: 400 });
  });

  it("a list that never ends stops at the stated number of pages, as a failed read", async () => {
    const seen = devicesServer(Number.MAX_SAFE_INTEGER);
    const e = await api().devices().catch((x: unknown) => x);
    expect(e).toBeInstanceOf(ApiError);
    expect((e as ApiError).code).toBe(LIST_TOO_LONG);
    expect(seen).toHaveLength(DEVICES_MAX_PAGES);
  });
});

describe("the trash comes in pages (spec 03 §5.1)", () => {
  const tomb = (i: number, deletedAt: number) => ({ itemId: uuid(i), vaultId: V1, deletedAt });

  /** A full first page, newest first: row i deleted at 1,000,000 − i. */
  const fullPage = (): unknown[] => {
    const rows: unknown[] = [];
    for (let i = 0; i < TRASH_PAGE_ROWS; i++) rows.push(tomb(i, 1_000_000 - i));
    return rows;
  };
  const CURSOR_AT = 1_000_000 - (TRASH_PAGE_ROWS - 1);
  const pages = (...ps: unknown[][]) => {
    let n = 0;
    return serve(() => (n < ps.length ? { body: { items: ps[n++] } } : { status: 500, body: { error: "http_500" } }));
  };
  const badResponse = async () => {
    const e = await api().deletedItems().catch((x: unknown) => x);
    expect(e).toBeInstanceOf(ApiError);
    expect((e as ApiError).code).toBe("bad_response");
  };

  it("reads every page with the cursor <deletedAt>:<itemId>, newest first", async () => {
    const seen = pages(fullPage(), [tomb(TRASH_PAGE_ROWS, 10), tomb(7, 1)]);
    const { items } = await api().deletedItems();
    expect(seen.map((u) => u.searchParams.get("after"))).toEqual([null, `${CURSOR_AT}:${uuid(TRASH_PAGE_ROWS - 1)}`]);
    expect(seen[1]!.search).toBe(`?after=${CURSOR_AT}%3A${uuid(TRASH_PAGE_ROWS - 1)}`);
    expect(items).toHaveLength(TRASH_PAGE_ROWS + 1);
    // Item 7 shows twice in the list (restored and deleted again while it paged): once, with its newest time.
    expect(items.find((x) => x.itemId === uuid(7))!.deletedAt).toBe(1_000_000 - 7);
  });

  it("a refused page fails the whole read: no shorter trash", async () => {
    let n = 0;
    const first = fullPage();
    serve(() => (n++ === 0 ? { body: { items: first } } : { status: 400, body: { error: "bad_request" } }));
    await expect(api().deletedItems()).rejects.toMatchObject({ status: 400 });
  });

  it("refuses a page of more than 65,536 rows", async () => {
    const page = fullPage();
    page.push(tomb(TRASH_PAGE_ROWS, 1));
    pages(page);
    await badResponse();
  });

  it("refuses rows that are not strictly descending: a repeated row, a row out of order, an itemId not below the previous at the same time", async () => {
    pages([tomb(1, 50), tomb(1, 50)]);
    await badResponse();
    pages([tomb(1, 40), tomb(2, 50)]);
    await badResponse();
    pages([tomb(1, 50), tomb(2, 50)]); // same deletedAt: itemId must go down
    await badResponse();
    pages([tomb(2, 50), tomb(1, 50), tomb(9, 49)]); // and this order is fine
    expect((await api().deletedItems()).items).toHaveLength(3);
  });

  it("refuses a later page whose first row is not strictly after the cursor's row (a page that loops)", async () => {
    const last = tomb(TRASH_PAGE_ROWS - 1, CURSOR_AT);
    pages(fullPage(), [last]); // starts at the cursor's own row
    await badResponse();
    pages(fullPage(), [tomb(3, CURSOR_AT + 5)]); // above it
    await badResponse();
    pages(fullPage(), [tomb(TRASH_PAGE_ROWS + 5, CURSOR_AT)]); // at its time with a higher itemId
    await badResponse();
// At its time with a lower itemId (one not on the first page): after it.
    pages(fullPage(), [{ itemId: "00000000-0000-4000-7000-000000000001", vaultId: V1, deletedAt: CURSOR_AT }]);
    expect((await api().deletedItems()).items).toHaveLength(TRASH_PAGE_ROWS + 1);
  });

  it("refuses a cursor that cannot be built: a negative or fractional deletedAt, an itemId that is not a uuid", async () => {
    pages([tomb(1, -5)]);
    await badResponse();
    pages([tomb(1, 2.5)]);
    await badResponse();
    const page = fullPage();
    page[page.length - 1] = { itemId: "not-a-uuid", vaultId: V1, deletedAt: 1 };
    pages(page);
    await badResponse();
  });

  it("a row with a malformed id is left out but still counts for the order", async () => {
    const refused: [string, Refusal[]][] = [];
    pages([tomb(9, 50), { itemId: "zzzz", vaultId: V1, deletedAt: 49 }, tomb(1, 48)]);
    const { items } = await api(refused).deletedItems();
    expect(items.map((x) => x.itemId)).toEqual([uuid(9), uuid(1)]);
    expect(refused.map(([e]) => e)).toEqual(["items/deleted"]);
    pages([tomb(9, 50), { itemId: "zzzz", vaultId: V1, deletedAt: 51 }, tomb(1, 48)]); // out of order, malformed or not
    await badResponse();
  });

  it("stops at the stated number of pages, as a failed read", async () => {
    let n = 0;
    const seen = serve(() => {
      const base = 10_000_000 - n++ * TRASH_PAGE_ROWS;
      const rows: unknown[] = [];
      for (let i = 0; i < TRASH_PAGE_ROWS; i++) rows.push(tomb(i, base - i));
      return { body: { items: rows } };
    });
    const e = await api().deletedItems().catch((x: unknown) => x);
    expect((e as ApiError).code).toBe(LIST_TOO_LONG);
    expect(seen).toHaveLength(TRASH_MAX_PAGES);
  }, 60_000);
});
