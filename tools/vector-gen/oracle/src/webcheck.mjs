// Replays the primitive journal (prims.mjs) through Node's WebCrypto, a second implementation of
// SHA-256, SHA-512, HMAC, HKDF, Ed25519 and X25519. Any value the vectors were built from that the
// two implementations compute differently fails the run.

import { webcrypto } from 'node:crypto';
import { unhex, hex, concat, mustUnb64u } from './bytes.mjs';

const subtle = webcrypto.subtle;
const ED_PKCS8 = unhex('302e020100300506032b657004220420');
const X_PKCS8 = unhex('302e020100300506032b656e04220420');

async function edPrivate(seed) {
  return subtle.importKey('pkcs8', concat(ED_PKCS8, seed), { name: 'Ed25519' }, true, ['sign']);
}
async function xPrivate(scalar) {
  return subtle.importKey('pkcs8', concat(X_PKCS8, scalar), { name: 'X25519' }, true, ['deriveBits']);
}
async function publicOf(privateKey) {
  const jwk = await subtle.exportKey('jwk', privateKey);
  return mustUnb64u(jwk.x);
}

async function recompute(e) {
  switch (e.op) {
    case 'sha256':
      return hex(new Uint8Array(await subtle.digest('SHA-256', unhex(e.input))));
    case 'sha512':
      return hex(new Uint8Array(await subtle.digest('SHA-512', unhex(e.input))));
    case 'hmac': {
      const key = await subtle.importKey('raw', unhex(e.key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      return hex(new Uint8Array(await subtle.sign('HMAC', key, unhex(e.input))));
    }
    case 'hkdf': {
      const key = await subtle.importKey('raw', unhex(e.ikm), 'HKDF', false, ['deriveBits']);
      const bits = await subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: unhex(e.info) }, key, e.length * 8);
      return hex(new Uint8Array(bits));
    }
    case 'ed25519.pub':
      return hex(await publicOf(await edPrivate(unhex(e.seed))));
    case 'ed25519.sign':
      return hex(new Uint8Array(await subtle.sign('Ed25519', await edPrivate(unhex(e.seed)), unhex(e.message))));
    case 'ed25519.verify': {
      try {
        const key = await subtle.importKey('raw', unhex(e.pub), { name: 'Ed25519' }, false, ['verify']);
        return await subtle.verify('Ed25519', key, unhex(e.signature), unhex(e.message));
      } catch {
        return false;
      }
    }
    case 'x25519.base':
      return hex(await publicOf(await xPrivate(unhex(e.scalar))));
    case 'x25519.dh': {
      const peer = await subtle.importKey('raw', unhex(e.peer), { name: 'X25519' }, false, []);
      const bits = await subtle.deriveBits({ name: 'X25519', public: peer }, await xPrivate(unhex(e.scalar)), 256);
      return hex(new Uint8Array(bits));
    }
    default:
      throw new Error('webcheck: unknown journal op ' + e.op);
  }
}

/** Returns { checked, failures: [description…] }. Identical journal entries are recomputed once. */
export async function replayJournal(journal) {
  const seen = new Set();
  const failures = [];
  let checked = 0;
  for (const entry of journal) {
    const key = JSON.stringify(entry);
    if (seen.has(key)) continue;
    seen.add(key);
    const got = await recompute(entry);
    checked++;
    if (got !== entry.out) failures.push(`${entry.op}: @noble gave ${entry.out}, WebCrypto gave ${got}`);
  }
  return { checked, failures };
}
