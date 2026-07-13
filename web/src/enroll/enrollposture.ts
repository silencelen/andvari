import { shortFormMatches } from "../crypto/escrow";

/**
 * The fingerprint-provenance model (design 2026-07-12 §F.1) as pure, unit-pinned decision functions —
 * the security-critical part of per-member enrollment. The one rule the whole model rests on:
 *
 *   the enrolling client MUST NEVER treat a SERVER-SOURCED recovery-pubkey fingerprint as
 *   out-of-band-verified. A fingerprint is an anchor only when a HUMAN put it there — a value the
 *   invitee scanned from an IN-PERSON QR (`rfp`), or one they TYPED from a printed sheet.
 *
 * Pinned as pure functions (like Admin's shouldOfferQr / inviteResultView) so a refactor that lets a
 * server fingerprint become the seal anchor, or seals escrow on a waived invite, trips a test instead
 * of silently reopening spec 05 T10.
 */
export type EnrollPosture = "waived" | "required-affirm" | "required-typed";

/** Where the org fingerprint (if any) came from — never "server" on a seal path. */
export type EscrowAnchor = "none" | "in-person-qr" | "typed-sheet";

export interface EscrowGate {
  /** Whether to seal org escrow at all. `false` ⇒ waived (per-member piece only) or a failed check. */
  seal: boolean;
  anchor: EscrowAnchor;
}

/** Lowercase-hex-normalize a short fingerprint (drop separators), for comparing typed/scanned values. */
export function normalizeShortFp(entry: string): string {
  return entry.toLowerCase().replace(/[^0-9a-f]/g, "");
}

/**
 * Decide the enrollment posture from the two inputs the client actually has:
 *  - `linkRfp`: an rfp on the enroll link ⇒ the invitee scanned an IN-PERSON QR off the admin's
 *    screen (a server-composed emailed link is contractually rfp=null, §F.2) ⇒ one-tap eyeball
 *    affirmation of the displayed rfp;
 *  - `memberHasSheet`: no rfp — default WAIVED (frictionless, no admin backstop); a member who was
 *    handed a printed recovery SHEET declares it ⇒ the typed-sheet ceremony (the pre-rfp channel).
 * Either "required" branch anchors on a human value; a missing rfp NEVER auto-trusts the server key.
 */
export function enrollPosture(linkRfp: string | undefined, memberHasSheet: boolean): EnrollPosture {
  if (linkRfp) return "required-affirm";
  return memberHasSheet ? "required-typed" : "waived";
}

/**
 * The escrow-seal gate — the concrete enforcement of "never auto-trust a server-sourced fingerprint".
 * The two server values (`serverFullFp` = policy.recoveryFingerprint, `pubShortFp` = the short
 * fingerprint of the fetched /recovery-pubkey) are only ever the thing CHECKED, never the anchor:
 *  - waived           → seal NOTHING (there is no org pubkey to substitute);
 *  - required-affirm  → seal iff the scanned `linkRfp` equals the fetched pubkey's short fingerprint
 *                       (a mismatch = the server served a different key than the admin showed → fail
 *                       closed). The human anchor is the QR value.
 *  - required-typed   → seal iff the printed-sheet value the member TYPED matches the server's
 *                       advertised full fingerprint (the pre-rfp ceremony; the typed value is the
 *                       anchor, the server value the check).
 */
export function escrowGate(p: {
  posture: EnrollPosture;
  linkRfp?: string;
  typedSheet: string;
  serverFullFp: string;
  pubShortFp: string;
}): EscrowGate {
  switch (p.posture) {
    case "waived":
      return { seal: false, anchor: "none" };
    case "required-affirm": {
      const rfp = normalizeShortFp(p.linkRfp ?? "");
      return rfp.length === 16 && rfp === p.pubShortFp
        ? { seal: true, anchor: "in-person-qr" }
        : { seal: false, anchor: "none" };
    }
    case "required-typed":
      return shortFormMatches(p.typedSheet, p.serverFullFp)
        ? { seal: true, anchor: "typed-sheet" }
        : { seal: false, anchor: "none" };
  }
}
