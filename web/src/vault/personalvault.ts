/**
 * The once-per-account personal-vault migration (security review 2026-10, root cause A §8.5) — twin of
 * core `PersonalVaultMigration.kt`, pinned by `spec/test-vectors/personalwrap.json`.
 *
 * A candidate (1) is labelled `personal` by the server and (2) has a VK that opened from a UVK wrap on our
 * OWN grant row, from no seal. Mint automatically only when exactly one vault meets (1) and (2), its
 * decrypted name is exactly `Personal`, and (when this device remembers one) it is the personal vault last
 * used here. Otherwise ask the human, listing only vaults that meet (1) and (2).
 */

export const ENROLMENT_NAME = "Personal";

export interface PersonalCandidate {
  vaultId: string;
  labelledPersonal: boolean;
  ownUvkWrap: boolean;
  name: string | null;
  itemCount: number;
}

export type PersonalDecision = { kind: "auto"; vaultId: string } | { kind: "ask"; choices: PersonalCandidate[] };

export function decidePersonalVault(candidates: PersonalCandidate[], lastUsedPersonalVaultId: string | null): PersonalDecision {
  const eligible = candidates
    .filter((c) => c.labelledPersonal && c.ownUvkWrap)
    .sort((a, b) => (a.vaultId < b.vaultId ? -1 : a.vaultId > b.vaultId ? 1 : 0));
  if (eligible.length === 1) {
    const only = eligible[0]!;
    if (only.name === ENROLMENT_NAME && (!lastUsedPersonalVaultId || lastUsedPersonalVaultId === only.vaultId)) {
      return { kind: "auto", vaultId: only.vaultId };
    }
  }
  return { kind: "ask", choices: eligible };
}
