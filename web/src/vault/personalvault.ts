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
