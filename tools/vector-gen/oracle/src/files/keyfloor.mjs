// keyfloor.json: the inputs a client must REFUSE under spec 01 "Keys in memory and the lock", rule 4
// ("An all-zero key is never a key"). Each row is an all-zero input that a normative row of another file
// carried until 2026-11-16, with the operation it is refused at. The near-zero rows that took their places
// (31 zero bytes and one 0x01) are derived in those files as ordinary rows.

import { b64u, mustUnb64u } from '../bytes.mjs';
import { deriveLink } from '../links.mjs';
import { deriveDeviceLink } from '../devicelink.mjs';
import { vkCommit } from '../vaultlog.mjs';
import { KeyFloorRefusal, isAllZero } from '../keyfloor.mjs';
import { ids } from '../cast.mjs';

export const file = 'keyfloor.json';

const ZERO = new Uint8Array(32);

/** The operations of this file: the oracle's own derivation for each, from the row's input. */
const OPERATIONS = {
  'links.derive': (input) => deriveLink(mustUnb64u(input.secretB64)),
  'devicelink.derive': (input) => deriveDeviceLink(mustUnb64u(input.secretB64)),
  'vaultlog.vkCommit': (input) => vkCommit(mustUnb64u(input.vkB64), input.vaultId),
};

/** The input bytes the floor looks at, per operation. */
const KEY_OF = {
  'links.derive': (input) => mustUnb64u(input.secretB64),
  'devicelink.derive': (input) => mustUnb64u(input.secretB64),
  'vaultlog.vkCommit': (input) => mustUnb64u(input.vkB64),
};

/** Whether the oracle refuses the row's operation at the key floor (and with that operation's name). */
function refused(row) {
  try {
    OPERATIONS[row.operation](row.input);
    return false;
  } catch (e) {
    if (e instanceof KeyFloorRefusal) return e.operation === row.operation;
    throw e;
  }
}

function buildRows() {
  const rows = [
    {
      name: 'links-derive-zero-secret',
      why: 'A link secret of 32 zero bytes. Nothing is derived from it: not linkId, offerKey, answerKey, registerToken or tokenHash. Rule 4: an HKDF input key of zeros is refused before the platform\'s provider is called; a link whose secret is zeros is a bad link where the link is read.',
      operation: 'links.derive',
      refusedAt: 'the link derivation of design section 2.3 (secret -> linkId, offerKey, answerKey, registerToken), before its first HKDF',
      input: { secretB64: b64u(ZERO) },
      formerly: 'links.json derive[2], until 2026-11-16; that place now holds the near-zero secret (31 zero bytes and one 0x01)',
      expect: { refused: true },
    },
    {
      name: 'devicelink-derive-zero-secret',
      why: 'A device-link secret of 32 zero bytes. Nothing is derived from it: not linkId or macKey. Rule 4: an HKDF input key of zeros is refused before the platform\'s provider is called; a device link whose secret is zeros is a bad link where the link is read, and a device-link MAC under wiped link keys is refused.',
      operation: 'devicelink.derive',
      refusedAt: 'the device-link derivation of design sections 2.3 and 8 (secret -> linkId, macKey), before its first HKDF',
      input: { secretB64: b64u(ZERO) },
      formerly: 'devicelink.json derive[2], until 2026-11-16; that place now holds the near-zero secret (31 zero bytes and one 0x01)',
      expect: { refused: true },
    },
    {
      name: 'vaultlog-vkcommit-zero-key',
      why: 'A vault key of 32 zero bytes. No commitment is computed from it. Rule 4: an HKDF input key of zeros is refused before the platform\'s provider is called, and a zero key matches no vault-key commitment.',
      operation: 'vaultlog.vkCommit',
      refusedAt: 'the vault-key commitment of design section 3.4 (hexLower(HKDF(VK, "andvari/v2|vk-commit|" + vaultId))), before the HKDF',
      input: { vkB64: b64u(ZERO), vaultId: ids.vault },
      formerly: 'vaultlog.json vkCommit.derive[3], until 2026-11-16; that place now holds the near-zero key (31 zero bytes and one 0x01)',
      expect: { refused: true },
    },
  ];
  for (const row of rows) if (!refused(row)) throw new Error('keyfloor: the oracle does not refuse ' + row.name);
  return rows;
}

export function build() {
  return {
    _about: [
      'The key floor of spec 01 "Keys in memory and the lock", rule 4: an all-zero key is never a key. No legitimate key is all zeros, so a client refuses one before the platform\'s crypto provider is called. Hand-authored from the independent oracle in tools/vector-gen/oracle (Node WebCrypto and @noble; no andvari code), which applies the rule at these three operations. Regenerate with `npm run generate` there; `npm run check` fails on any difference.',
      'refuse: one row per input that must be refused. `operation` names the operation (links.derive: links.json\'s `derive`; devicelink.derive: devicelink.json\'s `derive`; vaultlog.vkCommit: vaultlog.json\'s `vkCommit.derive`), `refusedAt` says where in it the refusal falls, and `input` holds the operation\'s inputs under the names that file\'s rows use. expect.refused = true: the operation gives no value at all; in the shared code it throws KeysGoneException, never a derived value and never an error that reads as a wrong key or damaged data. `formerly` names the normative row that carried this input until 2026-11-16, before the rule; its place there holds the near-zero input (31 zero bytes and one 0x01), the lowest input the floor accepts, derived as an ordinary row.',
      'These rows grade the derivation itself. Where the same zeros arrive as data, rule 4 refuses them where they are read, as what they are: a link or device link whose secret is zeros is a bad link (bad_link), and a zero key matches no vault-key commitment (the check of a candidate key, vaultlog.json\'s `vkCommit.check`, answers false for it; it does not throw). Those answers belong to the files that grade reading links and checking keys, and none of their rows holds a zero key today.',
    ],
    refuse: buildRows(),
  };
}

export function grade(doc) {
  const failures = [];
  let rows = 0;
  const expect = (cond, what) => {
    rows++;
    if (!cond) failures.push(what);
  };
  expect(JSON.stringify(Object.keys(doc).sort()) === JSON.stringify(['_about', 'refuse']), 'sections: _about and refuse, and no other');
  for (const row of doc.refuse) {
    const known = Object.hasOwn(OPERATIONS, row.operation);
    expect(known, 'refuse: unknown operation ' + row.operation + ' (' + row.name + ')');
    if (!known) continue;
    expect(row.expect && row.expect.refused === true && Object.keys(row.expect).length === 1, 'refuse: expect is {refused: true}: ' + row.name);
    expect(isAllZero(KEY_OF[row.operation](row.input)), 'refuse: the input key is all zeros: ' + row.name);
    expect(refused(row), 'refuse: the oracle refuses it at the key floor: ' + row.name);
  }
  return { rows, failures };
}
