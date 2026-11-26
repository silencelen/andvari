import type { PinRecord, Root } from "./instancecard.ts";

/**
 * publicinstance.ts as a person's test build bundles it (build.mjs TESTBUILD=1 resolves every import of publicinstance
 * to this file; no other build contains it). A test build of code that is not released starts at the test server, never
 * at the public instance, and knows no card 0 of the test server: [bakedRoot] is null, so the first popup's "andvari"
 * is refused as in a build whose public instance is still a placeholder, and the test server is taken as one's own
 * server, through the Trust Gate (Options), where the person compares its operator key. The live server's address is in
 * no file of a test build (build.mjs checks dist/); the test server's is in no file of any other build.
 *
 * Same exports, same shapes as publicinstance.ts (testbuild.test.ts holds them together).
 *
 * LEAF module: no chrome.
 */
export const TEST_SERVER_ORIGIN = "https://staging.andvaripass.com";

export const PUBLIC_INSTANCE = {
  origin: TEST_SERVER_ORIGIN,
  instanceId: "PLACEHOLDER: a test build knows no card 0 of the test server",
  card0Hash: "PLACEHOLDER: a test build knows no card 0 of the test server",
  kind: "public",
  name: "andvari",
} as const;

/** The display name the first popup offers the public instance under. */
export const PUBLIC_INSTANCE_NAME: string = PUBLIC_INSTANCE.name;

/** Always null: a test build bakes no root, so the test server is pinned only through the Trust Gate. */
export function bakedRoot(): Extract<Root, { root: "baked" }> | null {
  return null;
}

/** As in publicinstance.ts: keyed on the instance (here the test server's origin; the placeholder matches no hash). */
export function isBakedInstance(pin: Pick<PinRecord, "card0Hash" | "origin">): boolean {
  return pin.origin === PUBLIC_INSTANCE.origin || pin.card0Hash === (PUBLIC_INSTANCE as { card0Hash: string }).card0Hash;
}
