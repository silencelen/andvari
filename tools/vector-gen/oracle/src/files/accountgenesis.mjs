// accountgenesis.json: the genesis record (design §5.1) and the checks every unlock makes (§5.2),
// one verdict per check in §2.4's order, and the personal wrap against the genesis (§5.3).

import { b64u, mustUnb64u, utf8 } from '../bytes.mjs';
import { envelopeSeal, edSignNegated, edNegate } from '../prims.mjs';
import { verifyGenesis, personalWrapInForce } from '../genesis.mjs';
import { personalWrapAd } from '../grant.mjs';
import { assembleFrame, signedMessage, splitFrame, signatureValid, signerMapsTo, signerEquals, PURPOSE_CODES } from '../frame.mjs';
import { ZERO_HASH } from '../vaultlog.mjs';
import { signed, signedRaw, tokens, withToken, withoutKey, rawStatement, nameOf } from '../build.mjs';
import { alice, bob, operator, ids, fixed, T0, describe } from '../cast.mjs';

export const file = 'accountgenesis.json';

const GENESIS = PURPOSE_CODES['account-genesis'];
const UVK = fixed('accountgenesis/uvk/alice');
const VK = fixed('accountgenesis/personal-vk');
const values = (overrides = {}) => ({
  userId: alice.userId, identityKey: alice.key, instanceId: ids.instance, personalVaultId: ids.personalVault, createdAt: T0, ...overrides,
});

function buildRows() {
  const rows = [];
  const names = new Set();
  const good = signed('account-genesis', alice, values());
  const flip = (frame) => {
    const out = frame.slice();
    out[37 + 10] ^= 0x01;
    return out;
  };
  const wrapFor = (vaultId, key = UVK, userId = alice.userId) => ({
    vaultId, wrappedVk: envelopeSeal(key, fixed('accountgenesis/nonce/' + vaultId, 24), personalWrapAd(vaultId, userId), VK),
  });
  const goodWrap = wrapFor(ids.personalVault);

  /**
   * `verdict` is every client's: each device of the account binds the signer by byte equality with
   * the Ed25519 key it derives from the seed (§2.4, the Signer binding row 0x05), the extension
   * included, so expect.extensionVerdict is the same verdict on every row. The builder checks the
   * oracle returns exactly this.
   */
  const add = (name, verdict, why, made, context = {}) => {
    const frame = made.frame ?? made;
    const wrap = context.wrap === undefined ? goodWrap : context.wrap;
    const input = {
      frame,
      seed: alice.seed,
      sessionUserId: context.sessionUserId ?? alice.userId,
      pinnedInstanceId: context.pinnedInstanceId ?? ids.instance,
      servedWrapVaultId: wrap ? wrap.vaultId : null,
    };
    const got = verifyGenesis(input).verdict;
    const extension = verdict;
    if (got !== verdict) throw new Error(`accountgenesis "${name}": the design says ${verdict}, the oracle says ${got}`);
    if (names.has(name)) throw new Error('accountgenesis: duplicate name ' + name);
    names.add(name);
    const inForce = verdict === 'ok' ? personalWrapInForce({ wrap, uvk: UVK, userId: alice.userId, personalVaultId: made.values ? made.values.personalVaultId : ids.personalVault }) : undefined;
    const row = { name, why };
    if (made.signer) row.signer = made.signer.name;
    if (made.signerNote) row.signer = made.signerNote;
    if (made.statement !== undefined) row.statementUtf8 = made.statement;
    row.genesisB64 = b64u(frame);
    row.sessionUserId = input.sessionUserId;
    row.pinnedInstanceId = input.pinnedInstanceId;
    row.personalWrap = wrap ? { vaultId: wrap.vaultId, wrappedVkB64: b64u(wrap.wrappedVk) } : null;
    row.expect = verdict === 'ok' ? { verdict, extensionVerdict: extension, personalVaultInForce: inForce } : { verdict, extensionVerdict: extension };
    rows.push(row);
  };
  const raw = (signer, mutate, overrides) => signedRaw(GENESIS, signer, rawStatement(mutate(tokens('account-genesis', values(overrides)))));

  // ---- accepted ----
  add('valid', 'ok', 'alice\'s genesis, her session, the pinned instance, and a personal wrap that names personalVaultId and opens: the personal vault is in force, with no question, on any device.', good);
  add('valid-no-wrap-served', 'ok', 'The server withholds the personal wrap. The genesis checks pass (the wrap check applies only if a wrap is served); the account has no personal vault until one is served: an anomaly, not the identity fault.', good, { wrap: null });
  add('valid-wrap-does-not-open', 'ok', 'A served wrap that names personalVaultId but does not open under the account\'s UVK: the genesis checks pass and no personal vault is in force.', good, { wrap: wrapFor(ids.personalVault, fixed('accountgenesis/uvk/other')) });

  // ---- the §2 parse ----
  add('truncated', 'bad_frame', 'The genesis cut off inside its signature.', { frame: good.frame.slice(0, 70) });
  add('another-format-version', 'unknown_format', 'Format byte 0x03 in the magic.', { frame: (() => { const f = good.frame.slice(); f[3] = 0x03; return f; })() });
  add('card-frame-served-as-genesis', 'bad_frame', 'A well-formed instance-card frame (purpose 0x04) served as the genesis.',
    signed('instance-card', operator, { instanceId: ids.instance, seq: 0, prev: ZERO_HASH, origin: 'https://vault.example.org', name: nameOf('Example Vault'), kind: 'private', operator: operator.userId, operatorSignKey: b64u(operator.signPub), recoveryFp: 'none', issuedAt: T0 }));
  add('white-space', 'non_canonical', 'A genesis alice signed with a space after a colon.', signedRaw(GENESIS, alice, good.statement.replace('"userId":', '"userId": ')));
  add('no-personal-vault-id', 'non_canonical', 'A signed genesis with no personalVaultId key.', raw(alice, (t) => withoutKey(t, 'personalVaultId')));
  add('version-3', 'bad_statement', 'A canonical genesis with "v":3.', raw(alice, (t) => withToken(t, 'v', '3')));

  // ---- the signer ----
  add('signed-by-another-account', 'signer_not_pinned_key', 'A signer that is not the identity: the statement is alice\'s word for word, but bob\'s key signed it.', signed('account-genesis', bob, values()));
  add('another-accounts-genesis', 'signer_not_pinned_key', 'bob\'s own, valid genesis served on alice\'s account: the signer does not map to her seed-derived key.',
    signed('account-genesis', bob, values({ userId: bob.userId, identityKey: bob.key })));
  const negated = good.signerPub.slice();
  negated[31] ^= 0x80;
  add('signer-negated-point', 'signer_not_pinned_key', 'signerPub replaced by -A, under the signature alice made as A. Every client compares signerPub with the Ed25519 key it derives from the seed, byte for byte, and stops at the signer. (-A has the X25519 image of A, so a comparison through the image would bind it, and this frame would then fail the signature only because nobody signed again; the row genesis-signed-under-the-negated-key is the one that tells the two apart.)',
    { frame: assembleFrame(GENESIS, negated, good.signature, utf8(good.statement)), statement: good.statement, signerNote: 'alice; signerPub then replaced by -A' });
  // -A with a VALID signature: what the key's holder, and nobody else, can make (prims.edSignNegated).
  const underNegated = edSignNegated(alice.seed, signedMessage(GENESIS, edNegate(alice.signPub), utf8(good.statement)));
  const negatedFrame = assembleFrame(GENESIS, underNegated.signerPub, underNegated.signature, utf8(good.statement));
  const negatedParts = splitFrame(negatedFrame, GENESIS);
  if (!signatureValid(negatedParts) || !signerMapsTo(negatedParts.signerPub, alice.identityPub) || signerEquals(negatedParts.signerPub, alice.signPub)) {
    throw new Error('accountgenesis: the genesis under -A must verify, map to alice\'s identity key through the X25519 image, and not be her Ed25519 key');
  }
  const addNegatedRow = () => add('genesis-signed-under-the-negated-key', 'signer_not_pinned_key', 'alice\'s genesis, word for word, VALIDLY signed under -A, the negation of her Ed25519 key: signed with the negated secret scalar, so the signature verifies under signerPub = -A. -A has the X25519 image of A, so a check through the image passes it (the server, which holds no seed, checks that way and registers it). Every client compares signerPub with the Ed25519 key it derives from the seed, byte for byte, and refuses it: signer_not_pinned_key, on the full clients and in the extension alike.',
    { frame: negatedFrame, statement: good.statement, signerNote: 'alice, under the negated key -A' });
  add('signature-flipped', 'bad_signature', 'alice\'s genesis with one signature bit flipped.', { frame: flip(good.frame), statement: good.statement, signerNote: 'alice, then one signature bit flipped' });
  const changedCreatedAt = good.statement.replace(String(T0), String(T0 + 1));
  add('statement-changed-after-signing', 'bad_signature', 'createdAt changed after signing (still canonical).',
    { frame: assembleFrame(GENESIS, good.signerPub, good.signature, utf8(changedCreatedAt)), statement: changedCreatedAt, signerNote: 'alice signed another statement' });

  // ---- one verdict per field check ----
  add('identity-key-is-another', 'identity_mismatch', 'alice signed it, but its identityKey names bob\'s key: identityKey must equal the seed-derived key.', signed('account-genesis', alice, values({ identityKey: bob.key })));
  add('changed-user-id', 'user_mismatch', 'A changed userId: alice signed a genesis for another userId than her session\'s.', signed('account-genesis', alice, values({ userId: bob.userId })));
  add('session-is-another-user', 'user_mismatch', 'The genesis is right, but the session the server opened is for another userId.', good, { sessionUserId: bob.userId });
  add('changed-instance-id', 'instance_mismatch', 'A changed instanceId: the genesis names another instance than the pinned card.', signed('account-genesis', alice, values({ instanceId: ids.otherInstance })));
  add('pinned-card-is-another-instance', 'instance_mismatch', 'The genesis is right, but this device pinned a card of another instance for this origin.', good, { pinnedInstanceId: ids.otherInstance });
  add('changed-personal-vault-id', 'personal_vault_mismatch', 'A changed personalVaultId: the genesis names another vault than the served personal wrap.', signed('account-genesis', alice, values({ personalVaultId: ids.otherPersonalVault })));
  add('wrap-names-another-vault', 'personal_vault_mismatch', 'The served personal wrap names another vault than the genesis: the server cannot move the personal vault.', good, { wrap: wrapFor(ids.otherPersonalVault) });
  add('unopenable-wrap-names-another-vault', 'personal_vault_mismatch', 'The same with a wrap that would not open: the check is on the served vaultId.', good, { wrap: wrapFor(ids.otherPersonalVault, fixed('accountgenesis/uvk/other')) });

  // ---- the order: two things wrong at once ----
  add('order-parse-before-signer', 'non_canonical', 'Not canonical and signed by bob.', signedRaw(GENESIS, bob, good.statement.replace('"userId":', '"userId": ')));
  add('order-signer-before-signature', 'signer_not_pinned_key', 'Signed by bob, with the signature broken as well.', { frame: flip(signed('account-genesis', bob, values()).frame), signerNote: 'bob, then one signature bit flipped' });
  add('order-signature-before-identity', 'bad_signature', 'identityKey names bob\'s key and the signature is broken.', { frame: flip(signed('account-genesis', alice, values({ identityKey: bob.key })).frame), signerNote: 'alice, then one signature bit flipped' });
  add('order-identity-before-user', 'identity_mismatch', 'identityKey and userId are both bob\'s, signed by alice.', signed('account-genesis', alice, values({ identityKey: bob.key, userId: bob.userId })));
  add('order-user-before-instance', 'user_mismatch', 'Another userId and another instanceId.', signed('account-genesis', alice, values({ userId: bob.userId, instanceId: ids.otherInstance })));
  add('order-instance-before-personal-vault', 'instance_mismatch', 'Another instanceId and another personalVaultId.', signed('account-genesis', alice, values({ instanceId: ids.otherInstance, personalVaultId: ids.otherPersonalVault })));

  // ---- new on 2026-11-15 (third batch), at the end ----
  addNegatedRow();
  return rows;
}

export function build() {
  return {
    _about: [
      'The account genesis record of design 2026-11-15-onboarding-trust §5 (purpose 0x05).',
      'Hand-authored from the independent oracle in tools/vector-gen/oracle (Node WebCrypto and @noble; no andvari code). Regenerate with `npm run generate` there; `npm run check` fails on any difference.',
      'Every row is one unlock of alice\'s account: the identity seed `account.seedB64` is already derived, `genesisB64` is the served (or cached) genesis frame, `sessionUserId` the session\'s userId, `pinnedInstanceId` the pinned card\'s instanceId, and `personalWrap` the served wrap {vaultId, wrappedVkB64} or null when none is served.',
      'expect.verdict is the first failing check, in §2.4\'s order (VR-13): the parse verdicts (bad_frame, unknown_format, non_canonical, bad_statement); signer_not_pinned_key (signerPub is not, byte for byte, the Ed25519 signing key derived from the seed, `account.signPubB64`; §2.4, the Signer binding row 0x05); bad_signature; identity_mismatch (identityKey is not the seed-derived key); user_mismatch; instance_mismatch; personal_vault_mismatch (a served personalWrap.vaultId is not personalVaultId). Every failure shows the same IDENTITY_MISMATCH copy.',
      'The signer\'s expected key: every device of the account holds the identity seed, derives its Ed25519 signing key from it (crypto_sign_seed_keypair, `account.signPubB64`) and requires signerPub to equal it byte for byte, on every client. The X25519 identity key (`account.identityPubB64`, crypto_box_seed_keypair of the same seed) is what identityKey must equal, and is never the signer\'s comparison on a device: -A, the negation of the Ed25519 key, has the same X25519 image as A, and the key\'s holder can sign validly under either. (The server, which holds no seed, checks the signer through the image of identityPub; it is not graded by this file.)',
      'expect.extensionVerdict is the same unlock in the extension. It equals expect.verdict on every row: the extension and the full clients bind the signer the same way. The field is kept so that a reader of the file\'s earlier shape still finds it.',
      'Changed on 2026-11-15, with the rule that every client checks the genesis signer as an Ed25519 key (design §2.4, spec 01 §5.1): full clients compared through the X25519 image until then, and the extension by bytes. (1) signer-negated-point: expect.verdict was bad_signature and is now signer_not_pinned_key, its extensionVerdict as before; its `why` was reworded. No other row\'s verdict or extensionVerdict changed, and no row now has an extensionVerdict that differs from its verdict. (2) genesis-signed-under-the-negated-key is new, at the end: alice\'s genesis validly signed under -A (with the negated secret scalar), signer_not_pinned_key for every client. The other 27 rows are unchanged byte for byte.',
      'expect.personalVaultInForce, on ok rows: §5.3. A served wrap that names personalVaultId AND opens under the UVK with AD andvari/v1|vk-personal|{vaultId}|{userId} is in force on any device. A withheld or unopenable wrap passes the genesis checks and leaves no personal vault (an anomaly, not the identity fault).',
      'The extension grades every row of this file (§17).',
    ],
    account: { ...describe(alice), uvkB64: b64u(UVK) },
    instanceId: ids.instance,
    personalVaultId: ids.personalVault,
    personalVkB64: b64u(VK),
    rows: buildRows(),
  };
}

export function grade(doc) {
  const failures = [];
  let rows = 0;
  const expect = (cond, what) => {
    rows++;
    if (!cond) failures.push(what);
  };
  const seed = mustUnb64u(doc.account.seedB64);
  const uvk = mustUnb64u(doc.account.uvkB64);
  const names = new Set();
  for (const row of doc.rows) {
    expect(!names.has(row.name), `row ${row.name}: duplicate name`);
    names.add(row.name);
    const input = {
      frame: mustUnb64u(row.genesisB64), seed, sessionUserId: row.sessionUserId, pinnedInstanceId: row.pinnedInstanceId,
      servedWrapVaultId: row.personalWrap ? row.personalWrap.vaultId : null,
    };
    const full = verifyGenesis(input);
    expect(full.verdict === row.expect.verdict, `row ${row.name}: oracle says ${full.verdict}`);
    // Every client binds the signer the same way, the extension included.
    expect(row.expect.extensionVerdict === row.expect.verdict, `row ${row.name}: extensionVerdict differs from verdict`);
    if (row.expect.verdict === 'ok' && full.verdict === 'ok') {
      const wrap = row.personalWrap ? { vaultId: row.personalWrap.vaultId, wrappedVk: mustUnb64u(row.personalWrap.wrappedVkB64) } : null;
      const inForce = personalWrapInForce({ wrap, uvk, userId: doc.account.userId, personalVaultId: full.genesis.personalVaultId });
      expect(inForce === row.expect.personalVaultInForce, `row ${row.name}: personalVaultInForce`);
    }
  }
  // The genesis under -A is validly signed and binds through the X25519 image: only the byte
  // comparison with the seed's Ed25519 key refuses it.
  const negatedRow = doc.rows.find((row) => row.name === 'genesis-signed-under-the-negated-key');
  const negatedParts = negatedRow && splitFrame(mustUnb64u(negatedRow.genesisB64), GENESIS);
  expect(negatedParts && negatedParts.verdict === 'ok' && signatureValid(negatedParts) && signerMapsTo(negatedParts.signerPub, mustUnb64u(doc.account.identityPubB64))
    && !signerEquals(negatedParts.signerPub, mustUnb64u(doc.account.signPubB64)), 'genesis-signed-under-the-negated-key: a valid signature under -A');
  return { rows, failures };
}
