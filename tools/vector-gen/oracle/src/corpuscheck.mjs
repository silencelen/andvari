// Checks the oracle's primitives against the committed corpus, for the conventions the design says
// are unchanged: the seed-derived identity and joint signing keys (spec 01 §5), the signed
// statement frame (spec 01 §5.1), the AEAD envelope (spec 02 §2) and the sealed box (spec 04 §3).
// It reads vector files only, never implementation code.

import fs from 'node:fs';
import path from 'node:path';
import { b64u, mustUnb64u, hex, utf8, bytesEqual } from './bytes.mjs';
import * as p from './prims.mjs';
import { signFrame, signedMessage, DOMAIN } from './frame.mjs';
import { alice, bob, carol } from './cast.mjs';

export function checkAgainstCorpus(vectorDir) {
  const failures = [];
  const expect = (cond, what) => {
    if (!cond) failures.push('corpus: ' + what);
  };
  const load = (name, required = true) => {
    const file = path.join(vectorDir, name);
    if (!fs.existsSync(file)) {
      if (required) failures.push(`corpus: ${name} is missing, so the unchanged conventions it pins cannot be cross-checked`);
      return null;
    }
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  };

  const seal = load('seal.json');
  if (seal) {
    const key = p.boxKeypairFromSeed(mustUnb64u(seal.recoverySeedB64));
    expect(b64u(key.publicKey) === seal.recoveryPubB64 && b64u(key.secretKey) === seal.recoveryPrivB64, 'seal.json crypto_box_seed_keypair');
    expect(hex(p.sha256(key.publicKey)) === seal.fingerprint, 'seal.json recovery fingerprint');
    for (const row of seal.open) {
      const opened = p.boxSealOpen(key.publicKey, key.secretKey, mustUnb64u(row.sealedB64));
      expect(opened !== null && b64u(opened) === row.plaintextB64, 'seal.json sealed box opens');
    }
    const wrong = p.boxKeypairFromSeed(mustUnb64u(seal.rejectWrongKey.wrongSeedB64));
    expect(p.boxSealOpen(wrong.publicKey, wrong.secretKey, mustUnb64u(seal.rejectWrongKey.sealedB64)) === null, 'seal.json wrong key refused');
    // Our own sealer, opened again: the layout round-trips.
    const message = utf8('oracle sealed-box round trip');
    const sealed = p.boxSeal(key.publicKey, message, p.sha256('corpus-check/ephemeral'));
    expect(bytesEqual(p.boxSealOpen(key.publicKey, key.secretKey, sealed), message), 'sealed box round trip');
  }

  const envelope = load('envelope.json');
  if (envelope) {
    for (const row of envelope.seal) {
      const made = p.envelopeSeal(mustUnb64u(row.keyB64), mustUnb64u(row.nonceB64), row.adUtf8, mustUnb64u(row.plaintextB64));
      expect(b64u(made) === row.envelopeB64, 'envelope.json seal ' + row.name);
      const opened = p.envelopeOpen(mustUnb64u(row.keyB64), row.adUtf8, mustUnb64u(row.envelopeB64));
      expect(opened !== null && b64u(opened) === row.plaintextB64, 'envelope.json open ' + row.name);
    }
    for (const row of envelope.reject) {
      expect(p.envelopeOpen(mustUnb64u(row.keyB64), row.adUtf8, mustUnb64u(row.envelopeB64)) === null, 'envelope.json reject ' + row.reason);
    }
  }

  const signed = load('signedstatement.json');
  if (signed) {
    const seed = mustUnb64u(signed.jointKey.seedB64);
    expect(bytesEqual(seed, alice.seed), 'signedstatement.json jointKey is the cast seed of alice');
    expect(b64u(alice.identityPub) === signed.jointKey.identityPubB64 && b64u(alice.signPub) === signed.jointKey.signPubB64, 'joint key of alice');
    expect(b64u(bob.identityPub) === signed.jointKey.other.identityPubB64 && b64u(bob.signPub) === signed.jointKey.other.signPubB64, 'joint key of bob');
    expect(b64u(p.edPubToX25519(alice.signPub)) === signed.jointKey.curveOfSignPubB64, 'ed25519_pk_to_curve25519');
    expect(b64u(p.edPubToX25519(mustUnb64u(signed.jointKey.negatedSignPubB64))) === signed.jointKey.identityPubB64, 'the negated point has the same Montgomery image');
    expect(signed.domainAscii === DOMAIN, 'signed statement domain string');
    for (const row of signed.valid) {
      const made = signFrame(row.purposeCode, seed, row.statementUtf8);
      expect(hex(made.message) === row.messageHex, 'signedstatement.json M ' + row.name);
      expect(b64u(made.signature) === row.signatureB64, 'signedstatement.json signature ' + row.name);
      expect(b64u(made.frame) === row.frameB64, 'signedstatement.json frame ' + row.name);
      expect(p.edVerify(made.signerPub, signedMessage(row.purposeCode, made.signerPub, utf8(row.statementUtf8)), made.signature), 'signedstatement.json verify ' + row.name);
    }
  }

  // The pre-overhaul grant file names carol's seed; it is replaced at integration, so it is optional here.
  const grant = load('sharedgrant-v2.json', false);
  if (grant && grant.third && grant.third.seedB64) {
    expect(b64u(carol.seed) === grant.third.seedB64 && b64u(carol.identityPub) === grant.third.identityPubB64 && b64u(carol.signPub) === grant.third.signPubB64, 'joint key of carol');
  }

  const wrap = load('wrap.json');
  if (wrap) {
    const key = p.boxKeypairFromSeed(mustUnb64u(wrap.identitySeedB64));
    expect(b64u(key.publicKey) === wrap.identityPubB64 && b64u(key.secretKey) === wrap.identityPrivB64, 'wrap.json identity key pair');
  }

  return failures;
}
