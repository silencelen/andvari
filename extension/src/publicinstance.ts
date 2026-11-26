import { isHex64, isUuid } from "./statement.ts";
import type { PinRecord, Root } from "./instancecard.ts";

/**
 * The public instance as store builds bake it (design 2026-11-15-onboarding-trust §0.3, §4.4). The one in-repo
 * source is `spec/public-instance.json`; serverchoice.test.ts ("§0.3") pins these values to it, and package.mjs refuses to
 * package a store build while any of them is a `PLACEHOLDER:` (instanceId and card0Hash are recorded at the cut-over
 * from the device that signed card 0, never from a fetch).
 *
 * A person's test build (build.mjs TESTBUILD=1) bundles publicinstance.testserver.ts in place of this module.
 *
 * LEAF module: no chrome.
 */
export const PUBLIC_INSTANCE = {
  origin: "https://vault.andvaripass.com",
  instanceId: "PLACEHOLDER: the uuid andvari setup writes for the public instance, recorded at the cut-over",
  card0Hash: "PLACEHOLDER: lowercase hex SHA-256 of card 0, taken from the signing device at the cut-over",
  kind: "public",
  name: "andvari",
} as const;

/** The display name the first popup offers the public instance under. */
export const PUBLIC_INSTANCE_NAME: string = PUBLIC_INSTANCE.name;

/** The baked root, or null while this build does not know the public instance's card 0 yet (a placeholder). */
export function bakedRoot(): Extract<Root, { root: "baked" }> | null {
  const { instanceId, card0Hash } = PUBLIC_INSTANCE as { instanceId: string; card0Hash: string };
  return isUuid(instanceId) && isHex64(card0Hash) ? { root: "baked", instanceId, card0Hash } : null;
}

/**
 * Whether a pin is the baked public instance's (§4.4 pin-store rules): keyed on the instance, that is a pin whose
 * `card0Hash` is the baked one or whose origin is the baked origin, however that pin was first made. Store builds
 * never follow a move or a `kind` change of it.
 */
export function isBakedInstance(pin: Pick<PinRecord, "card0Hash" | "origin">): boolean {
  return pin.origin === PUBLIC_INSTANCE.origin || pin.card0Hash === (PUBLIC_INSTANCE as { card0Hash: string }).card0Hash;
}
