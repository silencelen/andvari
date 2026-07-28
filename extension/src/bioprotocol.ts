/**
 * The SW ⇄ connector-window RPC shapes for the biometric quick-unlock ceremony
 * (design 2026-07-18-biometric-quick-unlock.md §5). TYPES ONLY — `import type` erases entirely, so
 * neither bundle grows and the connector page keeps its chrome-free, dependency-free character.
 *
 * It exists because the two ends hand-declared the same two unions and had already drifted:
 * background.ts had `error?: string` (optional) where connector.ts had `error: string` (required),
 * i.e. the receiver's own type said a field could be missing that the sender's said always lands.
 * Resolved toward REQUIRED: every failure the broker invents already carries a reason string, and
 * a failure without one tells the log nothing. One declaration, two importers.
 */

/** The op the SW hands the connector in its sender-verified "ready" reply. */
export type BioReq =
  | { op: "enroll"; prfSalt: string; userHandleB64: string; userName: string; reuse?: { credentialId: string; prfSalt: string } }
  | { op: "eval"; credentialId: string; prfSalt: string };

/** The connector's "result" post — or, for a failure the SW invents itself (no connector could be
 *  opened, the window closed first, the host permission is withheld), the broker's own answer. */
export type BioResult =
  | { ok: true; op: "enroll"; credentialId: string; prfEnabled: boolean; prfSalt: string; secretB64: string }
  | { ok: true; op: "eval"; secretB64: string }
  | { ok: false; error: string };
