/**
 * The once-per-account personal-vault QUESTION (security review 2026-10, root cause A §8.5, as amended by the
 * A5 review, H-1) — twin of core `PersonalVaultMigration.kt`, pinned by `spec/test-vectors/personalwrap.json`.
 *
 * There is NO automatic pick: the old auto rule let the server's label decide whenever it withheld the wrap,
 * and the client then minted a genuine wrap for that pick. With no wrap served and none cached on this
 * device, the client asks; the human's answer is the only thing that mints. The choices are every held vault
 * keyed from a UVK wrap on our own grant row (no seal), regardless of label or role, which neither filter nor
 * order them: the last-used vault first (if it is a choice), then by vaultId.
 */

export interface PersonalCandidate {
  vaultId: string;
  ownUvkWrap: boolean;
  name: string | null;
  itemCount: number;
}

export function personalVaultChoices(candidates: PersonalCandidate[], lastUsedPersonalVaultId: string | null): PersonalCandidate[] {
  const cmp = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
  return candidates
    .filter((c) => c.ownUvkWrap)
    .sort((a, b) => {
      const la = a.vaultId === lastUsedPersonalVaultId ? 0 : 1;
      const lb = b.vaultId === lastUsedPersonalVaultId ? 0 : 1;
      return la !== lb ? la - lb : cmp(a.vaultId, b.vaultId);
    });
}

// ---- A5b (A5 re-review M-2): what the human sees when choosing (core `PersonalChoice.kt` twin) ----

/** Another account the server reports as holding a vault. Informs the human; decides nothing. */
export interface CoHolder {
  userId: string;
  displayName: string;
  email: string;
  role: string;
}

/** One vault as the personal-vault question and the Settings list show it. */
export interface PersonalChoiceInfo {
  vaultId: string;
  name: string | null;
  itemCount: number;
  /** "received": the vault's last ownership transfer names this account as the new owner. */
  origin: "created" | "received";
  /** Everyone else the server reports on the vault; null until loaded. */
  coHolders: CoHolder[] | null;
  /** The vault this browser already had as personal (its cached wrap, else the last one used) (L-1). */
  onThisDevice: boolean;
}

/** A pending, not yet confirmed designation. Only the store that issued it, while still pending, accepts it. */
export interface PersonalVaultProposal {
  readonly vaultId: string;
  readonly name: string | null;
  readonly origin: "created" | "received";
  readonly coHolders: readonly CoHolder[];
  readonly replacing: string | null;
}

/** A served wrap naming another vault than this browser's (status "changed"). */
export interface PersonalChange {
  currentVaultId: string;
  servedVaultId: string;
}
