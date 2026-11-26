import { isHex64, isUuid } from "../crypto/trust/grammar";

/**
 * The public instance's baked constants (design §0.3, §4.4), byte-equal to `spec/public-instance.json`
 * (pinned by publicinstance.test.ts). A value that starts with `PLACEHOLDER:` does not exist yet: until
 * the cut-over records it, there is no baked root, and the public origin is pinned like any other (behind
 * the Trust Gate).
 */
export const PUBLIC_INSTANCE_SOURCE = {
  origin: "https://vault.andvaripass.com",
  instanceId: "PLACEHOLDER: the uuid andvari setup writes for the public instance, recorded at the cut-over",
  card0Hash: "PLACEHOLDER: lowercase hex SHA-256 of card 0, taken from the signing device at the cut-over",
  kind: "public",
  name: "andvari",
} as const;

export interface BakedInstance {
  readonly origin: string;
  readonly instanceId: string;
  readonly card0Hash: string;
  readonly kind: "public" | "private";
}

/** The baked root, or null while any of its values is still a placeholder. */
export function bakedInstance(): BakedInstance | null {
  const s = PUBLIC_INSTANCE_SOURCE as { origin: string; instanceId: string; card0Hash: string; kind: string };
  if (!isUuid(s.instanceId) || !isHex64(s.card0Hash) || (s.kind !== "public" && s.kind !== "private")) return null;
  return { origin: s.origin, instanceId: s.instanceId, card0Hash: s.card0Hash, kind: s.kind };
}
