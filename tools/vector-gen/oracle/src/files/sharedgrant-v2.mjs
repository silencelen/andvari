// next/sharedgrant-v2.json (rewritten): a sealed grant checked against the vault's log, in the
// order of design §3.5.

import { b64u, mustUnb64u, utf8 } from '../bytes.mjs';
import { boxSeal } from '../prims.mjs';
import { verifyGrant } from '../grant.mjs';
import { verifyLog, vkCommit } from '../vaultlog.mjs';
import { assembleFrame, PURPOSE_CODES } from '../frame.mjs';
import { LogBuilder, signed, signedRaw, tokens, withToken, withoutKey, rawStatement } from '../build.mjs';
import { alice, bob, carol, dave, ids, fixed, T0, MINUTE, DAY, describe } from '../cast.mjs';

export const file = 'next/sharedgrant-v2.json';

const GRANT = PURPOSE_CODES['vault-grant'];
const VK = fixed('sharedgrant/vk');
const OTHER_VK = fixed('sharedgrant/other-vk');
const id16 = (label) => b64u(fixed('sharedgrant/' + label, 16));
const at = (minutes) => T0 + minutes * MINUTE;

const G = {
  bob: id16('grant/bob'),
  carol: id16('grant/carol'),
  bobAgain: id16('grant/bob-again'),
  bobByCarol: id16('grant/bob-by-carol'),
  bobOtherKey: id16('grant/bob-other-key'),
  unknown: id16('grant/unknown'),
};

function buildLogs() {
  const logs = {};
  const make = (name, why, steps) => {
    const log = new LogBuilder(ids.vault);
    for (const [signer, fields] of steps) log.append(signer, fields);
    const result = verifyLog({ vaultId: ids.vault, frames: log.frames });
    if (result.verdict !== 'ok') throw new Error(`sharedgrant log "${name}" does not verify: ${result.verdict}`);
    logs[name] = { why, log, state: result.states.length ? result.states[result.states.length - 1] : null };
  };
  const genesis = [alice, { kind: 'genesis', actor: alice.userId, at: at(0), ownerKey: alice.key, vkCommit: vkCommit(VK, ids.vault) }];
  const add = (owner, when, member, grantId, key = member.key) =>
    [owner, { kind: 'add', actor: owner.userId, at: when, member: member.userId, memberKey: key, role: 'writer', grantId }];
  const transferToCarol = (start) => [
    [alice, { kind: 'offer', actor: alice.userId, at: at(start), to: carol.userId, toKey: carol.key, offerId: id16('offer/carol'), expiresAt: at(start) + DAY }],
    [carol, { kind: 'accept', actor: carol.userId, at: at(start + 1), offerId: id16('offer/carol') }],
  ];
  const base = [genesis, add(alice, at(1), bob, G.bob), add(alice, at(2), carol, G.carol)];

  make('base', 'alice creates the vault, adds bob (the grant under test answers this add) and carol.', base);
  make('bob-removed', 'base, then the owner removes bob.', [...base, [alice, { kind: 'remove', actor: alice.userId, at: at(3), member: bob.userId }]]);
  make('bob-left', 'base, then bob leaves.', [...base, [bob, { kind: 'leave', actor: bob.userId, at: at(3) }]]);
  make('bob-readded', 'base, the owner removes bob, then adds him again with a new grantId.', [
    ...base,
    [alice, { kind: 'remove', actor: alice.userId, at: at(3), member: bob.userId }],
    add(alice, at(4), bob, G.bobAgain),
  ]);
  make('owner-changed-after-the-add', 'base, then alice hands the vault to carol: the add of bob was signed while alice was the owner.', [...base, ...transferToCarol(3)]);
  make('added-by-the-new-owner', 'alice adds carol and hands her the vault; carol, now the owner, adds bob.', [
    genesis, add(alice, at(1), carol, G.carol), ...transferToCarol(2), add(carol, at(4), bob, G.bobByCarol),
  ]);
  make('bob-left-and-readded', 'base, bob leaves, then the owner adds him again with a new grantId.', [
    ...base,
    [bob, { kind: 'leave', actor: bob.userId, at: at(3) }],
    add(alice, at(4), bob, G.bobAgain),
  ]);
  make('bob-readded-and-removed', 'base, the owner removes bob, adds him again with a new grantId, and removes him again.', [
    ...base,
    [alice, { kind: 'remove', actor: alice.userId, at: at(3), member: bob.userId }],
    add(alice, at(4), bob, G.bobAgain),
    [alice, { kind: 'remove', actor: alice.userId, at: at(5), member: bob.userId }],
  ]);
  make('grant-id-used-twice', 'alice adds bob and hands the vault to carol; carol removes bob and adds him again with the SAME grantId (an honest owner never reuses one, but a verifier must still decide).', [
    genesis, add(alice, at(1), bob, G.bob), add(alice, at(2), carol, G.carol), ...transferToCarol(3),
    [carol, { kind: 'remove', actor: carol.userId, at: at(5), member: bob.userId }],
    add(carol, at(6), bob, G.bob),
  ]);
  make('add-names-another-key', 'alice adds bob, but the add names dave\'s key as memberKey.', [genesis, add(alice, at(1), bob, G.bobOtherKey, dave.key)]);
  make('no-add-of-bob', 'alice adds only carol.', [genesis, add(alice, at(1), carol, G.carol)]);
  make('no-entries', 'No entry at all.', []);

  // Logs that do NOT verify: the grant is then not evaluated, and the result is the log's own verdict.
  const broken = (name, why, frames, verdict, failedAt) => {
    const result = verifyLog({ vaultId: ids.vault, frames });
    if (result.verdict !== verdict || result.failedAt !== failedAt) throw new Error(`sharedgrant broken log "${name}": expected ${verdict} at ${failedAt}, the oracle says ${result.verdict} at ${result.failedAt}`);
    logs[name] = { why, frames, verdict, failedAt };
  };
  const baseFrames = logs.base.log.frames;
  const flipped = baseFrames[2].slice();
  flipped[37 + 10] ^= 0x01;
  broken('broken-signature-after-the-add', 'base with one signature bit flipped in its third entry, AFTER the add of bob.', [baseFrames[0], baseFrames[1], flipped], 'bad_signature', 2);
  broken('entry-missing', 'base without its second entry: the add of carol follows the genesis directly.', [baseFrames[0], baseFrames[2]], 'bad_seq', 1);
  const byMember = new LogBuilder(ids.vault);
  byMember.append(...genesis);
  byMember.append(...add(alice, at(1), carol, G.carol));
  const forgedAdd = byMember.draft(carol, { kind: 'add', actor: carol.userId, at: at(2), member: bob.userId, memberKey: bob.key, role: 'writer', grantId: G.bob });
  broken('add-signed-by-a-member', 'alice adds carol; then an add of bob that carol, a writer, signed as herself.', [...byMember.frames, forgedAdd.frame], 'not_authorized', 2);
  return logs;
}

function buildCases(logs) {
  const cases = [];
  const grantValues = (overrides = {}) => ({
    from: alice.userId, to: bob.userId, toKey: bob.key, vaultId: ids.vault, grantId: G.bob, issuedAt: at(1), vk: b64u(VK), ...overrides,
  });
  const seal = (name, plaintext, recipient = bob) => boxSeal(recipient.identityPub, plaintext, fixed('sharedgrant/ephemeral/' + name));
  const flip = (frame) => {
    const out = frame.slice();
    out[37 + 10] ^= 0x01;
    return out;
  };

  /**
   * `plain` is what gets sealed: a `signed` result, or { frame, statement?, signerNote? }, or raw bytes.
   * `verdict` is what §3.5 says; the builder checks the oracle agrees before writing the row.
   */
  const add = (name, verdict, logName, why, plain, options = {}) => {
    const frame = plain.frame ?? plain;
    const sealed = options.sealed ?? seal(name, frame, options.sealTo ?? bob);
    const rowVaultId = options.rowVaultId ?? ids.vault;
    const result = verifyGrant({ me: bob, rowVaultId, sealed, logFrames: logs[logName].frames ?? logs[logName].log.frames });
    if (result.verdict !== verdict) throw new Error(`sharedgrant case "${name}": the design says ${verdict}, the oracle says ${result.verdict}`);
    const row = { name, why, me: 'bob', rowVaultId, log: logName };
    if (plain.signer) row.signer = plain.signer.name;
    if (plain.signerNote) row.signer = plain.signerNote;
    if (plain.statement !== undefined) row.statementUtf8 = plain.statement;
    row.sealedB64 = b64u(sealed);
    row.expect = verdict === 'ok'
      ? { verdict, vkB64: result.vk, from: result.from, grantId: result.grantId, issuedAt: result.issuedAt }
      : { verdict };
    cases.push(row);
  };
  const grant = (signer, overrides) => signed('vault-grant', signer, grantValues(overrides));
  const raw = (signer, mutate, overrides) => signedRaw(GRANT, signer, rawStatement(mutate(tokens('vault-grant', grantValues(overrides)))));

  // ---- accepted ----
  add('valid', 'ok', 'base', 'The owner alice added bob and sealed him the vault key.', grant(alice));
  add('valid-after-the-owner-changed', 'ok', 'owner-changed-after-the-add', 'carol owns the vault now, but bob\'s latest add was signed by alice while she was the owner: O is that add\'s actor and K the owner key AT THAT ENTRY, so alice\'s grant still verifies.', grant(alice));
  add('valid-from-the-new-owner', 'ok', 'added-by-the-new-owner', 'carol became the owner and then added bob: her grant verifies.', grant(carol, { from: carol.userId, grantId: G.bobByCarol, issuedAt: at(4) }));
  add('valid-after-a-re-add', 'ok', 'bob-readded', 'bob was removed and added again; the grant for the second add verifies.', grant(alice, { grantId: G.bobAgain, issuedAt: at(4) }));
  add('valid-after-leaving-and-a-re-add', 'ok', 'bob-left-and-readded', 'bob left and was added again; the grant for the second add verifies.', grant(alice, { grantId: G.bobAgain, issuedAt: at(4) }));
  add('re-add-with-the-same-grant-id', 'ok', 'grant-id-used-twice', 'Two adds of bob carry the same grantId (an honest owner never reuses one). Only bob\'s LATEST add counts: its actor is carol, so carol\'s grant verifies.', grant(carol, { from: carol.userId, issuedAt: at(6) }));

  // ---- 1 unopenable ----
  add('sealed-to-another-key', 'unopenable', 'base', 'The seal was made to carol\'s key.', grant(alice), { sealTo: carol });
  add('seal-truncated', 'unopenable', 'base', 'The first 40 bytes of a seal.', grant(alice), { sealed: seal('seal-truncated', grant(alice).frame).slice(0, 40) });
  const damaged = seal('seal-damaged', grant(alice).frame);
  damaged[damaged.length - 1] ^= 0x01;
  add('seal-damaged', 'unopenable', 'base', 'A seal with its last byte changed.', grant(alice), { sealed: damaged });

  // ---- 2 bad_frame ----
  add('vault-log-frame-inside', 'bad_frame', 'base', 'The seal opens to a valid vault-log frame (purpose 0x03), not a grant.', logs.base.log.entries[1]);
  add('escrow-frame-inside', 'bad_frame', 'base', 'The seal opens to a signed escrow-uvk frame (purpose 0x02).',
    signed('escrow-uvk', alice, { userId: alice.userId, identityKey: alice.key, recoveryFp: 'a'.repeat(64), issuedAt: at(1), key: b64u(VK) }));
  add('short-plaintext', 'bad_frame', 'base', 'The seal opens to the first 60 bytes of a grant frame.', { frame: grant(alice).frame.slice(0, 60) });
  add('three-byte-plaintext', 'bad_frame', 'base', 'The seal opens to three bytes: shorter than the magic.', { frame: grant(alice).frame.slice(0, 3) });
  add('bare-json-inside', 'unknown_format', 'base', 'The seal opens to a bare JSON statement (first byte {), as a pre-cut-over grant would: the magic is wrong, which §2.4 calls unknown_format for every purpose.', { frame: utf8(grant(alice).statement), statement: grant(alice).statement });
  const otherVersion = grant(alice).frame.slice();
  otherVersion[3] = 0x03;
  add('another-format-version', 'unknown_format', 'base', 'The grant frame with format byte 0x03 in its magic.', { frame: otherVersion });

  // ---- 3 the strict parse ----
  add('white-space', 'non_canonical', 'base', 'A grant the owner signed with a space after a colon.',
    signedRaw(GRANT, alice, grant(alice).statement.replace('"from":', '"from": ')));
  add('no-vk', 'non_canonical', 'base', 'A signed grant with no vk key.', raw(alice, (t) => withoutKey(t, 'vk')));
  add('vk-of-31-bytes', 'non_canonical', 'base', 'vk is base64url of 31 bytes: it fails its type, so step 9\'s "vk is 32 bytes" is never reached with a short key.',
    raw(alice, (t) => withToken(t, 'vk', '"' + b64u(VK.slice(0, 31)) + '"')));
  add('from-equals-to', 'bad_statement', 'base', 'A canonical grant from bob to bob, signed by bob: from != to is a template rule.', grant(bob, { from: bob.userId }));
  add('version-3', 'bad_statement', 'base', 'A canonical grant with "v":3.', raw(alice, (t) => withToken(t, 'v', '3')));

  // ---- 4 misaddressed ----
  add('to-another-account', 'misaddressed', 'base', 'The grant names carol and her key, but sits on bob\'s row and is sealed to bob.', grant(alice, { to: carol.userId, toKey: carol.key, grantId: G.carol }));
  add('to-me-with-another-key', 'misaddressed', 'base', 'to is bob, toKey is carol\'s key.', grant(alice, { toKey: carol.key }));

  // ---- 5 vault_mismatch ----
  add('another-vault-in-the-statement', 'vault_mismatch', 'base', 'The statement names another vault than the row it arrived on.', grant(alice, { vaultId: ids.otherVault }));

  // ---- 6 no_add_entry ----
  add('grant-id-not-in-the-log', 'no_add_entry', 'base', 'A grant whose grantId has no add.', grant(alice, { grantId: G.unknown }));
  add('add-is-for-another-member', 'no_add_entry', 'base', 'The log has an add with this grantId, but for carol.', grant(alice, { grantId: G.carol }));
  add('add-names-another-key', 'no_add_entry', 'add-names-another-key', 'The log\'s add for bob names another memberKey than bob\'s seed-derived key.', grant(alice, { grantId: G.bobOtherKey }));
  add('no-add-of-me', 'no_add_entry', 'no-add-of-bob', 'The log has no add of bob at all.', grant(alice));
  add('first-grant-after-a-re-add', 'no_add_entry', 'bob-readded', 'The grant for the FIRST add, after bob was removed and added again. Only the account\'s latest add can match: a grant bound to an earlier add is no_add_entry. Otherwise a server could put the old grant back on the row, and the accept prompt would name whoever owned the vault at the earlier add.', grant(alice));
  add('first-grant-after-leaving-and-a-re-add', 'no_add_entry', 'bob-left-and-readded', 'The grant for the FIRST add, after bob left and was added again.', grant(alice));
  add('first-grant-after-a-re-add-and-a-removal', 'no_add_entry', 'bob-readded-and-removed', 'bob was added, removed, added again and removed again. The grant for the FIRST add is no_add_entry (step 6), not removed (step 10): only the latest add can match.', grant(alice));

  add('log-is-empty', 'no_add_entry', 'no-entries', 'The server serves no log entry at all: nothing fails to verify, and there is no add.', grant(alice));
  add('log-broken-after-the-add', 'bad_signature', 'broken-signature-after-the-add', 'A grant whose log does not verify is not evaluated at all: the result is the LOG\'s own verdict, here bad_signature, even though the add of bob lies before the broken entry.', grant(alice));
  add('log-misses-an-entry', 'bad_seq', 'entry-missing', 'The served log skips an entry: the log\'s verdict, bad_seq.', grant(alice));
  add('log-add-signed-by-a-member', 'not_authorized', 'add-signed-by-a-member', 'The add of bob was signed by carol, a writer. The log itself is not_authorized at that entry, so the grant (which carol also signed) is never evaluated.', grant(carol, { from: carol.userId, issuedAt: at(2) }));

  // ---- 7 not_authorized ----
  add('non-owner-signer', 'not_authorized', 'base', 'A non-owner signer: carol, a writer, grants the key and signs as herself. from is not the actor of the add.', grant(carol, { from: carol.userId }));
  add('owner-named-member-signed', 'not_authorized', 'base', 'from names the owner, but carol\'s key signed: the signer must map to the owner key at the add.', grant(carol));
  add('new-owner-for-an-older-add', 'not_authorized', 'owner-changed-after-the-add', 'carol owns the vault now and signs a grant for the add alice made: from must be the actor of THAT add.', grant(carol, { from: carol.userId }));
  add('old-owner-for-a-newer-add', 'not_authorized', 'added-by-the-new-owner', 'alice, no longer the owner, signs a grant for the add carol made.', grant(alice, { grantId: G.bobByCarol }));
  add('old-owner-grant-after-a-re-add-with-the-same-grant-id', 'not_authorized', 'grant-id-used-twice', 'alice\'s grant for the FIRST of two adds of bob with the same grantId. It passes step 6 only because the latest add carries that grantId too; O is the actor of the LATEST add, carol, so alice\'s grant is not_authorized.', grant(alice));

  // ---- 8 bad_signature ----
  add('signature-flipped', 'bad_signature', 'base', 'The owner\'s grant with one signature bit flipped.', { frame: flip(grant(alice).frame), statement: grant(alice).statement, signerNote: 'alice, then one signature bit flipped' });
  const swapped = grant(alice);
  const otherVkStatement = swapped.statement.replace(b64u(VK), b64u(OTHER_VK));
  add('vk-changed-after-signing', 'bad_signature', 'base', 'The owner signed one key; the statement in the frame carries another (still canonical).',
    { frame: assembleFrame(GRANT, swapped.signerPub, swapped.signature, utf8(otherVkStatement)), statement: otherVkStatement, signerNote: 'alice signed another statement' });

  // ---- 9 vk_commit_mismatch ----
  add('key-fails-the-commitment', 'vk_commit_mismatch', 'base', 'A key that fails the commitment: the owner really signed this grant, but its vk is not the key the genesis committed to.', grant(alice, { vk: b64u(OTHER_VK) }));

  // ---- 10 removed ----
  add('after-removal', 'removed', 'bob-removed', 'A grant after removal: the log removes bob after the add.', grant(alice));
  add('after-leaving', 'removed', 'bob-left', 'bob left after the add.', grant(alice));
  add('second-grant-after-a-re-add-and-a-removal', 'removed', 'bob-readded-and-removed', 'bob was added, removed, added again and removed again. The grant for the SECOND add matches the latest add and is then removed.', grant(alice, { grantId: G.bobAgain, issuedAt: at(4) }));

  // ---- the order: two things wrong at once ----
  add('order-frame-before-parse', 'bad_frame', 'base', 'An escrow-purpose frame whose statement is also not canonical.',
    signedRaw(PURPOSE_CODES['escrow-uvk'], alice, grant(alice).statement.replace('"from":', '"from": ')));
  add('order-parse-before-addressing', 'non_canonical', 'base', 'Not canonical, and addressed to carol.',
    signedRaw(GRANT, alice, grant(alice, { to: carol.userId, toKey: carol.key }).statement.replace('"from":', '"from": ')));
  add('order-addressing-before-vault', 'misaddressed', 'base', 'Addressed to carol and naming another vault.', grant(alice, { to: carol.userId, toKey: carol.key, vaultId: ids.otherVault }));
  add('order-vault-before-add', 'vault_mismatch', 'base', 'Another vault and an unknown grantId.', grant(alice, { vaultId: ids.otherVault, grantId: G.unknown }));
  add('order-add-before-signer', 'no_add_entry', 'base', 'An unknown grantId, signed by a non-owner, with a broken signature.',
    { frame: flip(grant(carol, { from: carol.userId, grantId: G.unknown }).frame), signerNote: 'carol, then one signature bit flipped' });
  add('order-signer-before-signature', 'not_authorized', 'base', 'A non-owner signer whose signature is also broken.',
    { frame: flip(grant(carol, { from: carol.userId }).frame), signerNote: 'carol, then one signature bit flipped' });
  add('order-signature-before-commitment', 'bad_signature', 'base', 'A key that fails the commitment under a broken signature.',
    { frame: flip(grant(alice, { vk: b64u(OTHER_VK) }).frame), signerNote: 'alice, then one signature bit flipped' });
  add('order-log-before-the-seal', 'bad_signature', 'broken-signature-after-the-add', 'The log does not verify AND the seal was made to carol\'s key. The log is replayed before any grant is opened, so the result is the log\'s own verdict, not unopenable.', grant(alice), { sealTo: carol });
  add('order-log-before-the-frame', 'bad_seq', 'entry-missing', 'The log does not verify and the seal opens to a bare JSON statement: the log\'s verdict, not unknown_format.', { frame: utf8(grant(alice).statement), statement: grant(alice).statement });
  add('order-log-before-the-parse', 'bad_signature', 'broken-signature-after-the-add', 'The log does not verify and the grant is not canonical: the log\'s verdict, not non_canonical.',
    signedRaw(GRANT, alice, grant(alice).statement.replace('"from":', '"from": ')));
  add('order-log-before-addressing', 'bad_seq', 'entry-missing', 'The log does not verify and the grant is addressed to carol: the log\'s verdict, not misaddressed.', grant(alice, { to: carol.userId, toKey: carol.key }));
  add('order-log-before-the-vault', 'not_authorized', 'add-signed-by-a-member', 'The log does not verify and the statement names another vault: the log\'s verdict, not vault_mismatch.', grant(alice, { vaultId: ids.otherVault }));
  add('order-add-before-removed', 'no_add_entry', 'bob-removed', 'An unknown grantId, for a member the log has removed: no_add_entry (step 6) comes before removed (step 10).', grant(alice, { grantId: G.unknown }));
  add('order-commitment-before-removed', 'vk_commit_mismatch', 'bob-removed', 'A key that fails the commitment, for a member the log has removed.', grant(alice, { vk: b64u(OTHER_VK) }));
  return cases;
}

export function build() {
  const logs = buildLogs();
  return {
    _about: [
      'Signed vault grants of design 2026-11-15-onboarding-trust §3.5 (purpose 0x01; the statement template is unchanged, its binding is the vault log). This file REPLACES spec/test-vectors/sharedgrant-v2.json at integration; until then it lives in spec/test-vectors/next/ and the old file stays where the old tests read it.',
      'Hand-authored from the independent oracle in tools/vector-gen/oracle (Node WebCrypto and @noble; no andvari code). Regenerate with `npm run generate` there; `npm run check` fails on any difference. Every seal uses a fixed ephemeral key, so the sealed bytes reproduce.',
      'Each case: account `me` opens `sealedB64` (crypto_box_seal to its identity key) from its grant row for vault `rowVaultId`, with the vault\'s log `logs[log].frames` as served. The log is replayed BEFORE the grant is opened: if it does not verify, the grant is not evaluated at all and the result is the log\'s own verdict, even when the grant has a fault of its own. Then the checks run in §3.5\'s order and the FIRST failure is the verdict: 1 unopenable, 2 bad_frame / unknown_format, 3 non_canonical / bad_statement, 4 misaddressed, 5 vault_mismatch, 6 no_add_entry, 7 not_authorized, 8 bad_signature, 9 vk_commit_mismatch, 10 removed. On ok the row gives the key and the fields a caller acts on.',
      'In step 6 only this account\'s LATEST add can match: it must carry the statement\'s grantId and name this account\'s key. A grant bound to an earlier add of the account, or to none, is no_add_entry. O is the actor of that add and K is the owner key AT THAT ENTRY (the state before it), not the current owner key.',
      'Verifying a grant is not adopting the vault: adoption is §3.6 (a current contact, the accept prompt, the account\'s vault record).',
      'Step 2 uses the frame checks of §2.4, which hold for every purpose: a plaintext with another magic is unknown_format, and bad_frame is a short or over-long plaintext or a frame of another purpose.',
      'logs: each named log gives its frames and its own verdict: ok with the final state (null for a log with no entries), or the verdict and index at which it stops.',
      'The extension opens no grant and has no consumer for this file.',
    ],
    vaultId: ids.vault,
    otherVaultId: ids.otherVault,
    vkB64: b64u(VK),
    vkCommitHex: vkCommit(VK, ids.vault),
    accounts: { alice: describe(alice), bob: describe(bob), carol: describe(carol), dave: describe(dave) },
    logs: Object.fromEntries(Object.entries(logs).map(([name, l]) => [name, l.log
      ? { why: l.why, frames: l.log.frames.map(b64u), verdict: 'ok', state: l.state }
      : { why: l.why, frames: l.frames.map(b64u), verdict: l.verdict, failedAt: l.failedAt }])),
    cases: buildCases(logs),
  };
}

export function grade(doc) {
  const failures = [];
  let rows = 0;
  const expect = (cond, what) => {
    rows++;
    if (!cond) failures.push(what);
  };
  const accounts = { bob };
  for (const [name, log] of Object.entries(doc.logs)) {
    const result = verifyLog({ vaultId: doc.vaultId, frames: log.frames.map(mustUnb64u) });
    if (log.verdict === 'ok') {
      const last = result.states.length ? result.states[result.states.length - 1] : null;
      expect(result.verdict === 'ok' && JSON.stringify(last) === JSON.stringify(log.state), `log ${name}`);
    } else {
      expect(result.verdict === log.verdict && result.failedAt === log.failedAt, `log ${name}: oracle says ${result.verdict} at ${result.failedAt}`);
    }
  }
  const names = new Set();
  for (const row of doc.cases) {
    expect(!names.has(row.name), `case ${row.name}: duplicate name`);
    names.add(row.name);
    const me = accounts[row.me];
    expect(me && b64u(me.seed) === doc.accounts[row.me].seedB64, `case ${row.name}: account`);
    const result = verifyGrant({ me, rowVaultId: row.rowVaultId, sealed: mustUnb64u(row.sealedB64), logFrames: doc.logs[row.log].frames.map(mustUnb64u) });
    expect(result.verdict === row.expect.verdict, `case ${row.name}: oracle says ${result.verdict}`);
    if (row.expect.verdict === 'ok' && result.verdict === 'ok') {
      expect(result.vk === row.expect.vkB64 && result.from === row.expect.from && result.grantId === row.expect.grantId && result.issuedAt === row.expect.issuedAt, `case ${row.name}: fields`);
    }
  }
  return { rows, failures };
}
