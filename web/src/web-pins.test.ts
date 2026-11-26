import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * Design §13's source pin: the web client has no code path for identity binding. It never creates, opens or answers
 * links, never runs or approves device links, never signs instance cards. Scanned: every production source file of
 * the bundle. Left out: tests, `journeys/` (its Java helpers run engine link flows on purpose, to set up the other
 * side of a journey), `e2e/` and `vendor/`.
 */
const ROOT = fileURLToPath(new URL(".", import.meta.url));
const SKIP_DIRS = new Set(["journeys", "e2e", "vendor"]);

function sources(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) {
      if (!SKIP_DIRS.has(name)) out.push(...sources(p));
    } else if (/\.(ts|tsx)$/.test(name) && !/\.test\.tsx?$/.test(name) && !name.endsWith(".d.ts")) {
      out.push(p);
    }
  }
  return out;
}

const files = sources(ROOT).map((p) => ({ rel: relative(ROOT, p).split("\\").join("/"), text: readFileSync(p, "utf-8") }));


describe("web source pins (design §13)", () => {
  it("scans the bundle's sources and leaves out journeys/", () => {
    expect(files.length).toBeGreaterThan(50);
    expect(files.some((f) => f.rel.startsWith("journeys/"))).toBe(false);
    expect(files.some((f) => f.rel === "vault/store.ts")).toBe(true);
  });

  it("no link, device-link or card-signing route is called", () => {
    const routes = /["'`]\/(device-)?links\b|\/instance\/card\b/;
    expect(files.filter((f) => routes.test(f.text)).map((f) => f.rel)).toEqual([]);
  });

  it("no link answer, device-link approval or instance-card signing code", () => {
    const actions = /\b(answerLink|createLink|approveDeviceLink|claimDeviceLink|pickupDeviceLink|signInstanceCard|signCard)\s*\(/;
    expect(files.filter((f) => actions.test(f.text)).map((f) => f.rel)).toEqual([]);
  });

  it("the old invite-enrolment code is gone (design §15's web row), and nothing imports it", () => {
    const imports = /from\s+["'](\.\.?\/)+(enroll\/|enrolllink|enrollcheck|enrollposture)/;
    expect(files.filter((f) => imports.test(f.text)).map((f) => f.rel)).toEqual([]);
    expect(files.filter((f) => f.rel.startsWith("enroll/")).map((f) => f.rel)).toEqual([]);
  });

  it("the old contact pins (vault/contacts.ts) are gone (design §15's web row), and nothing imports them", () => {
    // Contacts are the account-state records of contactbook.ts (§6.9); the typed, QR and enrolment pins went first.
    expect(files.some((f) => f.rel === "vault/contacts.ts")).toBe(false);
    const imports = /from\s+["'](\.\.?\/)+(vault\/)?contacts["']/;
    expect(files.filter((f) => imports.test(f.text)).map((f) => f.rel)).toEqual([]);
  });

  it("the store's non-log key paths are gone: no grant re-evaluation, no held-name peek, addGrant only for the personal vault", () => {
    // Design §3.6: a shared vault's key comes from its verified log alone. The store opens a grant row in two places,
    // the pull and the hydrate, and both skip every vault that is not the personal one.
    expect(files.filter((f) => /\b(reevaluateGrants|peekHeldName)\b/.test(f.text)).map((f) => f.rel)).toEqual([]);
    const store = files.find((f) => f.rel === "vault/store.ts")!.text;
    expect(store.match(/\.addGrant\(/g)).toHaveLength(2);
    expect(store.match(/if \(grant\.vaultId !== this\.account\.personalVaultId\) \{/g)).toHaveLength(2);
  });

  it("the personal-vault designation is gone (design §5.3, §15's web row): no vault/personalvault.ts, no question, no proposal, no re-designation", () => {
    expect(files.some((f) => f.rel === "vault/personalvault.ts")).toBe(false);
    const imports = /from\s+["'](\.\.?\/)+(vault\/)?personalvault["']/;
    expect(files.filter((f) => imports.test(f.text)).map((f) => f.rel)).toEqual([]);
    const names =
      /\b(personalVaultChoices|personalCandidates|decidePersonalLocally|designatedPersonalVaultId|proposePersonalVault|confirmPersonalVault|cancelPersonalProposal|redesignatePersonalVault|redesignationChoices|describePersonalChange|personalChoiceInfo|refreshPersonalChoiceDetails|PersonalVaultBanner|PersonalChangeDetails)\b/;
    expect(files.filter((f) => names.test(f.text)).map((f) => f.rel)).toEqual([]);
  });

  it("the account holds no designation states and nothing mints or sends a personal wrap (design §5.3, §15's web row)", () => {
    const names =
      /\b(holdPersonalProposal|holdPersonalChange|applyCachedPersonalWrap|acceptPersonalChange|installDesignatedPersonalWrap|buildPersonalWrap|personalWrapMintedHere|pendingPersonalChange|proposedAgainstDesignation|putPersonalWrap)\b/;
    expect(files.filter((f) => names.test(f.text)).map((f) => f.rel)).toEqual([]);
    expect(files.filter((f) => /\/account\/personal-wrap\b/.test(f.text)).map((f) => f.rel)).toEqual([]);
    const account = files.find((f) => f.rel === "vault/account.ts")!.text;
    expect(account).toMatch(/^export type PersonalStatus = "confirmed" \| "absent" \| "unreadable";$/m);
  });

  it("the device-local legacy trust records (vault/trustrecords.ts) are gone, and nothing imports them (design §15's web row)", () => {
    expect(files.some((f) => f.rel === "vault/trustrecords.ts")).toBe(false);
    const imports = /from\s+["'](\.\.?\/)+(vault\/)?trustrecords["']/;
    expect(files.filter((f) => imports.test(f.text)).map((f) => f.rel)).toEqual([]);
    const store = files.find((f) => f.rel === "vault/store.ts")!.text;
    expect(store).not.toMatch(/grant\.(legacy\.authorized|declined|held\.keys|member\.granted|issued\.tombstones)|freezeOnce|flushMemberReceived/);
  });

  it("the escrow re-seal banner (ReSealBanner) is gone: no source renders or defines it, and the vault takes no escrow-staleness props", () => {
    expect(files.filter((f) => /\bReSealBanner\b/.test(f.text)).map((f) => f.rel)).toEqual([]);
    expect(files.filter((f) => /\bescrow(Stale|NeedsV2)=\{|escrowFingerprint=["{]/.test(f.text)).map((f) => f.rel)).toEqual([]);
  });

  it("the lifecycle proofs (crypto/lifecycleproof.ts) are gone, and nothing imports them (design §15's web row)", () => {
    expect(files.some((f) => f.rel === "crypto/lifecycleproof.ts")).toBe(false);
    const imports = /from\s+["'](\.\.?\/)+(crypto\/)?lifecycleproof["']/;
    expect(files.filter((f) => imports.test(f.text)).map((f) => f.rel)).toEqual([]);
    expect(files.filter((f) => /\b(lifecycleKeyFor|decideRemoval)\b/.test(f.text)).map((f) => f.rel)).toEqual([]);
  });

  it("the v2 pin-verified grant and the v1 seal (crypto/signedgrant.ts, crypto/sharedgrant.ts) are gone, and the account applies only its own personal-vault row (design §3.6, §3.12, §15)", () => {
    for (const mod of ["signedgrant", "sharedgrant"]) {
      expect(files.some((f) => f.rel === `crypto/${mod}.ts`), mod).toBe(false);
      const imports = new RegExp(`from\\s+["'](\\.\\.?\\/)+(crypto\\/)?${mod}["']`);
      expect(files.filter((f) => imports.test(f.text)).map((f) => f.rel), mod).toEqual([]);
    }
    const gone =
      /\b(openSignedGrant|openSharedGrant|sealSharedGrant|canonicalGrantPayload|decideLegacyGrant|LEGACY_IN_WINDOW|grantPins|surfaceGrantStates|signedGrantSender|authorizeLegacyKey|rememberHeldKey|heldKeyTagsSnapshot|vouchGate|selfWrapAuthorized|needsSelfWrap|buildSelfWrap|buildSignedGrant|wrapVkForMember|keyArrivedByMemberGrant|forgetKeyMemory|isLegacyReadOnly|pendingGrants|grantAnomalies|keyUnreadable|VaultGrantKeyUnreadableError|openGrantVk)\b/;
    expect(files.filter((f) => gone.test(f.text)).map((f) => f.rel)).toEqual([]);
    expect(files.filter((f) => /["']grant-anomaly["']|["']key-unreadable["']/.test(f.text)).map((f) => f.rel)).toEqual([]);
    const account = files.find((f) => f.rel === "vault/account.ts")!.text;
    expect(account).not.toMatch(/\bsealedVk\b|\bsignedGrant\b/);
    expect(files.find((f) => f.rel === "crypto/fingerprint.ts")!.text).toMatch(/^export async function identityFingerprint\(/m);
  });

  it("the v1 seal's wire field and the unsigned shared-vault create are gone: a shared vault is made only through its signed log (design §3)", () => {
    const types = files.find((f) => f.rel === "api/types.ts")!.text;
    const wireGrant = types.slice(types.indexOf("export interface WireGrant {"), types.indexOf("}", types.indexOf("export interface WireGrant {")));
    expect(wireGrant).not.toMatch(/\bsealedVk\b/);
    expect(files.filter((f) => /\bbuildCreateSharedVault\b/.test(f.text)).map((f) => f.rel)).toEqual([]);
  });

  it("the dead bookkeeping is gone: the legacy-grant freeze, removal nonces and liveSince, the old escrow re-seal, the self-wrap and grant re-issue routes (design §3.12, §4.5)", () => {
    const gone = /\b(freezeDone|setFreezeDone|grantFreezeDone|consumedNonces\(\)|addConsumedNonce|setLiveSince|liveSinces|markLiveVaults|deviceConsumed|resealEscrowFor|putEscrow|putGrantSelfWrap|reissueGrant)\b/;
    expect(files.filter((f) => gone.test(f.text)).map((f) => f.rel)).toEqual([]);
    expect(files.filter((f) => /\bliveSince\b|consumedNonce:/.test(f.text)).map((f) => f.rel)).toEqual([]);
    // The escrow re-seal the design keeps (§4.5: a rotation, with its chain) is the wire client's.
    expect(files.find((f) => f.rel === "api/wireclient.ts")!.text).toMatch(/putEscrowSelf\(req: EscrowSelfPut\)/);
  });

  it("the dead lookups are gone: user lookup and served identity, their response and refusal, the legacy-grant hint, the added notice's adder label", () => {
    // The server has no /users/lookup or /users/{id}/identity route since the cut-over; nothing in production called them.
    const gone = /\b(lookupUser|userIdentity|UserLookupResponse|refusedUser|legacyGrant)\b/;
    expect(files.filter((f) => gone.test(f.text)).map((f) => f.rel)).toEqual([]);
    expect(files.filter((f) => /\bbyLabel\?:|n\.byLabel\b/.test(f.text)).map((f) => f.rel)).toEqual([]);
    // VaultKeyNotVerifiedError's message is a marked placeholder in copy.ts, no longer inline wording.
    expect(files.find((f) => f.rel === "vault/account.ts")!.text).toContain("super(VAULT_KEY_NOT_VERIFIED);");
  });

  it("design §15's web row: no public_login_requires_totp copy, no ui/Admin.tsx, and Welcome has no enrol link, consent card or in-person code", () => {
    expect(files.filter((f) => /public_login_requires_totp|PUBLIC_LOGIN_REQUIRES_TOTP/.test(f.text)).map((f) => f.rel)).toEqual([]);
    expect(files.some((f) => f.rel === "ui/Admin.tsx")).toBe(false);
    const welcome = files.find((f) => f.rel === "ui/Welcome.tsx")!.text;
    expect(welcome).not.toMatch(/\benrol(l)?(Link|link|Ceremony|Posture)|inPersonCode|in-person code|ConsentCard|inviteToken/);
  });

  it("the transport has no item routes of its own: the store's item layer is the wire client (ItemWire)", () => {
    const client = files.find((f) => f.rel === "api/client.ts")!.text;
    const itemMethod = /^\s+(async\s+)?(sync|pushMutations|push|itemVersions|deletedItems|restoreItem|purgeItem|uploadAttachment|downloadAttachment)\s*\(/m;
    expect(itemMethod.test(client)).toBe(false);
    expect(files.find((f) => f.rel === "api/wireclient.ts")!.text).toMatch(/^\s+async sync\(/m); // the scan sees a method when there is one
    expect(files.find((f) => f.rel === "vault/store.ts")!.text).toMatch(/private wire: ItemWire = noItemWire\(\)/);
  });
});
