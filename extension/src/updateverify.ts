import nacl from "tweetnacl";

/**
 * H2 signed-update channel — extension-side verification of the `/downloads` manifest (design
 * 2026-07-13-signed-updates §D/§M). Before the SW records ANY "update available" signal it verifies
 * a detached Ed25519 signature over the EXACT fetched manifest bytes (§M-D6 — never a re-serialized
 * object) against a PINNED public-key SET the server does not hold. This is the JS mirror of core
 * `UpdateVerify` (Kotlin); the pinned bytes are single-sourced — `updateverify.test.ts` asserts they
 * byte-equal the Kotlin `UpdateVerify.PINNED` / `TEST_PUBKEY` constants.
 *
 * §M-D2: the primitive is tweetnacl `nacl.sign.detached.verify` (already vendored — the box/seal
 * path uses it), NOT @noble (no noble Ed25519 dep is declared). §M-D3: while ONLY the placeholder
 * sentinel is pinned the update path is HARD-DISABLED (fail-closed), never falling through to a
 * forgeable test-key-signed manifest. §M-D7: a key SET so a future rotation overlaps without
 * bricking fielded clients.
 *
 * SECONDARY control by design (§M-D1): the load-bearing H2 fix is store/OS installer signing. This
 * layer kills a FABRICATED nag + validly-signed downgrade-steering; it does not stop a user who
 * hand-downloads a trojan from a compromised server.
 */

/** Placeholder sentinel — mirrors core `UpdateVerify.TEST_PUBKEY`. Pinning ONLY this disables updates. */
export const TEST_PUBKEY = "TEST_KEY_placeholder__pin_the_real_workstation_pubkey_here";

/** The pinned Ed25519 update-signing public key SET (base64url, 32 bytes each) — mirrors core
 *  `UpdateVerify.PINNED` (ceremony 2026-07-14). The private key lives only on the owner's
 *  workstation; each release's manifest is signed there. Byte-pinned to the Kotlin constant. */
export const PINNED_UPDATE_KEYS: readonly string[] = ["e_2TpyoQG4ygtbdVO9RUWbUW4MTHGPO8eXL7Jqc_tHI"];

/** §M-D4b — a signed manifest older than this is treated as a (quiet) STALE channel: withholding a
 *  security update by re-serving a stale-but-signed manifest is irreducible, so make it detectable. */
export const UPDATE_MAX_SIGNED_AGE_MS = 30 * 24 * 60 * 60 * 1000;

/** §M-D3 — true iff at least one pinned key is a REAL key (not the placeholder). A build pinning
 *  only the sentinel offers no updates at all (no path executes), never verifies against a test key. */
export function updatesEnabled(pinned: readonly string[] = PINNED_UPDATE_KEYS): boolean {
  return pinned.some((k) => k !== TEST_PUBKEY);
}

/** Decode a base64/base64url string to bytes; null on any malformed input (fail-closed). Kept local
 *  (mirrors crypto.ts fromB64) so this verify module stays a LEAF — no chrome/noble import chain, so
 *  the node --test runner can load it directly, like the other pinned chrome-free src modules. */
function decodeB64(s: string): Uint8Array | null {
  try {
    const b = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
    const u = new Uint8Array(b.length);
    for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i);
    return u;
  } catch {
    return null;
  }
}

/**
 * True iff [signature] (64 raw bytes) is a valid detached Ed25519 signature over the EXACT
 * [raw] manifest bytes by ANY pinned key. Fail-closed: false if updates are disabled (§M-D3), on a
 * wrong-size sig/key (tweetnacl throws on those — guard + catch), on a base64 decode failure, or on
 * a bad signature. Callers MUST pass the RAW fetched bytes and parse only AFTER this returns true.
 */
export function verifyManifest(raw: Uint8Array, signature: Uint8Array, pinned: readonly string[] = PINNED_UPDATE_KEYS): boolean {
  if (!updatesEnabled(pinned)) return false;
  if (signature.length !== nacl.sign.signatureLength) return false;
  return pinned.some((pk) => {
    const key = decodeB64(pk);
    if (!key || key.length !== nacl.sign.publicKeyLength) return false;
    try {
      return nacl.sign.detached.verify(raw, signature, key);
    } catch {
      return false; // defence in depth — length is already guarded above
    }
  });
}

/** A pinned-key/quiet or an accepted-and-verified verdict over a fetched manifest+sig pair. */
export type ManifestDecision =
  | { kind: "quiet"; reason: "disabled" | "unverified" | "malformed" | "seq_regression" | "stale" }
  | { kind: "accepted"; seq: number; signedAt: string | null; ext: { version?: unknown; chromeUrl?: unknown; firefoxUrl?: unknown } };

export interface EvaluateOpts {
  pinned?: readonly string[];
  /** Highest signed-manifest `seq` this client has ever accepted (§B anti-rollback), 0 on a fresh install. */
  lastAcceptedSeq: number;
  /** Wall clock (ms) for the §M-D4b staleness gate. */
  now: number;
  maxAgeMs?: number;
}

/**
 * The full fail-closed gate (design §D#2-3, §M-D5/D6): verify the detached sig over the RAW bytes
 * FIRST, then — and only then — parse and check the anti-rollback `seq` and the `signedAt`
 * staleness window. Any failure returns a distinct `quiet` reason (never a fabricated "update
 * available"); the caller keeps the popup silent and leaves any previously-verified signal intact.
 * `sigText` is the verbatim body of `manifest.json.sig` (null when that fetch was absent/empty).
 */
export function evaluateSignedManifest(raw: Uint8Array, sigText: string | null, opts: EvaluateOpts): ManifestDecision {
  const pinned = opts.pinned ?? PINNED_UPDATE_KEYS;
  if (!updatesEnabled(pinned)) return { kind: "quiet", reason: "disabled" };
  const sig = sigText != null ? decodeB64(sigText.trim()) : null;
  if (!sig || !verifyManifest(raw, sig, pinned)) return { kind: "quiet", reason: "unverified" };

  // Parse ONLY after the signature verifies (§M-D6) — a hostile body is inert until then.
  let m: { seq?: unknown; signedAt?: unknown; browserExtension?: unknown };
  try {
    m = JSON.parse(new TextDecoder().decode(raw)) as typeof m;
  } catch {
    return { kind: "quiet", reason: "malformed" };
  }
  if (m == null || typeof m !== "object") return { kind: "quiet", reason: "malformed" };

  const seq = m.seq;
  if (typeof seq !== "number" || !Number.isSafeInteger(seq)) return { kind: "quiet", reason: "malformed" };
  // §B anti-rollback: refuse a manifest whose seq is ≤ the highest we ever accepted. A strictly
  // lower seq is a downgrade replay; an equal seq is the SAME manifest we already recorded (benign,
  // its signal already stands) — both simply yield no NEW offer, quietly.
  if (seq <= opts.lastAcceptedSeq) return { kind: "quiet", reason: "seq_regression" };

  const signedAt = typeof m.signedAt === "string" ? m.signedAt : null;
  if (signedAt !== null) {
    const t = Date.parse(signedAt);
    if (Number.isNaN(t)) return { kind: "quiet", reason: "malformed" };
    // §M-D4b: a manifest signed too long ago = a possibly-withheld channel → quiet stale.
    if (opts.now - t > (opts.maxAgeMs ?? UPDATE_MAX_SIGNED_AGE_MS)) return { kind: "quiet", reason: "stale" };
  }

  const be = m.browserExtension;
  const ext = be != null && typeof be === "object" ? (be as { version?: unknown; chromeUrl?: unknown; firefoxUrl?: unknown }) : {};
  return { kind: "accepted", seq, signedAt, ext };
}
