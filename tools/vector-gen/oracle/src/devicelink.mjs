// Device linking (design §8) with §2.4's verdict strings: the derivations of §2.3, the three MACs,
// the committed code, the /d URL, what the existing device checks on a claim, what the new device
// checks on `outer` before any password prompt and on the genesis and the bundle after the pickup.

import { b64u, unb64u, mustUnb64u, utf8, utf8DecodeStrict, hex, bytesEqual } from './bytes.mjs';
import { sha256, hmacSha256, hkdfSha256, boxSealOpen, envelopeOpen, boxKeypairFromSeed, isLowOrderX25519 } from './prims.mjs';
import { isUuid, isB64_32, isHex64, isMs, isInt, isOrigin, isName, isPlatform, emailNorm } from './grammar.mjs';
import { codeCommit, codeFromInput, parseFragment, typedCodeIs } from './links.mjs';
import { verifyGenesis } from './genesis.mjs';
import { keyFloor } from './keyfloor.mjs';

export const BUNDLE_MAX_BYTES = 65536;
export const BUNDLE_MAX_ENTRIES = 1000;

// ---- §2.3 derivations ----

export function deriveDeviceLink(secret) {
  keyFloor('devicelink.derive', secret);
  return {
    linkId: b64u(hkdfSha256(secret, 'andvari/v2|device-link|id', 16)),
    macKey: hkdfSha256(secret, 'andvari/v2|device-link|mac', 32),
  };
}
export const bundleKey = (uvk, linkId) => hkdfSha256(uvk, 'andvari/v2|device-link|bundle|' + linkId, 32);
export const bundleAd = (linkId) => 'andvari/v2|device-link-bundle|' + linkId;

// ---- MAC inputs (§8.2). Keys and nonces are their base64url text; digests are lowercase hex. ----

export const claimMacInput = ({ linkId, nPub, name, platform, commitN }) =>
  ['andvari/v2|device-link|claim', linkId, nPub, name, platform, commitN].join('|');
export const proofInput = ({ linkId, nPub }) => ['andvari/v2|device-link|pickup', linkId, nPub].join('|');
export const approveMacInput = ({ linkId, outer }) => ['andvari/v2|device-link|approve', linkId, hex(sha256(outer))].join('|');
export const mac = (macKey, input) => b64u(hmacSha256(macKey, input));
/** proofHash = hexLower(SHA-256 over the 43 ASCII characters of `proof`). */
export const proofHash = (proof) => hex(sha256(proof));

export const deviceCodeInput = ({ linkId, nPub, nonceN, nonceE }) =>
  ['andvari/v2|device-link|code', linkId, nPub, b64u(nonceN), b64u(nonceE)].join('|');
export { codeCommit, codeFromInput };

/**
 * The text typed into the existing device against the code the new device shows (§8.2 step 5). It
 * is compared as text under §6.11's rule, the one a link's typed code is under: every ASCII space is
 * removed, and what is left must be exactly the six ASCII digits of the code. Unlike a link's, a
 * wrong code here is a verdict: code_mismatch, which cancels the link.
 */
export const typedCodeVerdict = (code, typed) => (typedCodeIs(typed, code) ? 'ok' : 'code_mismatch');

/** https://andvaripass.com/d#v2.<O>.<S>: exactly three parts. Total parse, as for /l links. */
export const composeDeviceLink = ({ origin, secret }) => `https://andvaripass.com/d#v2.${b64u(utf8(origin))}.${b64u(secret)}`;
export const parseDeviceLink = (input) => parseFragment(input, 3);

// ---- compact JSON: the text form of `outer` and of the bundle ----
// No white space outside strings; strings escape only `"` and `\`; numbers in the int or ms text form;
// keys in any order; no key twice at any level.

class Refused extends Error {}

export function parseCompactJson(text) {
  let pos = 0;
  const fail = () => {
    throw new Refused();
  };
  const string = () => {
    if (text[pos] !== '"') fail();
    pos++;
    let out = '';
    for (;;) {
      if (pos >= text.length) fail();
      const c = text[pos++];
      if (c === '"') return out;
      if (c.charCodeAt(0) < 0x20) fail();
      if (c === '\\') {
        const e = text[pos++];
        if (e !== '"' && e !== '\\') fail();
        out += e;
      } else out += c;
    }
  };
  const value = () => {
    const c = text[pos];
    if (c === '{') {
      pos++;
      const obj = {};
      if (text[pos] === '}') {
        pos++;
        return obj;
      }
      for (;;) {
        const key = string();
        if (Object.hasOwn(obj, key)) fail();
        if (text[pos] !== ':') fail();
        pos++;
        obj[key] = value();
        if (text[pos] === ',') {
          pos++;
          continue;
        }
        if (text[pos] === '}') {
          pos++;
          return obj;
        }
        fail();
      }
    }
    if (c === '[') {
      pos++;
      const arr = [];
      if (text[pos] === ']') {
        pos++;
        return arr;
      }
      for (;;) {
        arr.push(value());
        if (text[pos] === ',') {
          pos++;
          continue;
        }
        if (text[pos] === ']') {
          pos++;
          return arr;
        }
        fail();
      }
    }
    if (c === '"') return string();
    const m = /^(0|[1-9][0-9]*)/.exec(text.slice(pos));
    if (!m) fail(); // also true, false, null, a sign, a bare word
    const after = text[pos + m[0].length];
    if (after === '.' || after === 'e' || after === 'E' || (after >= '0' && after <= '9')) fail();
    pos += m[0].length;
    const n = Number(m[0]);
    if (!Number.isSafeInteger(n)) fail();
    return n;
  };
  try {
    const v = value();
    if (pos !== text.length) fail();
    return { ok: true, value: v };
  } catch (e) {
    if (e instanceof Refused) return { ok: false };
    throw e;
  }
}

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const hasExactly = (obj, keys) => isObject(obj) && Object.keys(obj).length === keys.length && keys.every((k) => Object.hasOwn(obj, k));

/** `outer`: exactly {v, origin, userId, email}, v the number 2, an origin, a uuid, an email that is its own emailNorm. */
export function decodeOuter(bytes) {
  const text = utf8DecodeStrict(bytes);
  if (text === null) return null;
  const parsed = parseCompactJson(text);
  if (!parsed.ok) return null;
  const o = parsed.value;
  if (!hasExactly(o, ['v', 'origin', 'userId', 'email'])) return null;
  if (o.v !== 2 || !isOrigin(o.origin) || !isUuid(o.userId) || typeof o.email !== 'string' || emailNorm(o.email) !== o.email) return null;
  return o;
}

const BUNDLE_KEYS = ['v', 'origin', 'instanceId', 'card', 'userId', 'email', 'identityPub', 'personalVaultId', 'contacts', 'vaults', 'accountState', 'issuedAt'];

/** The strict decode of §8.3. Returns the bundle or null (bad_bundle). */
export function decodeBundle(bytes) {
  if (bytes.length > BUNDLE_MAX_BYTES) return null;
  const text = utf8DecodeStrict(bytes);
  if (text === null) return null;
  const parsed = parseCompactJson(text);
  if (!parsed.ok) return null;
  const b = parsed.value;
  if (!hasExactly(b, BUNDLE_KEYS)) return null;
  const ok = b.v === 2 && isOrigin(b.origin) && isUuid(b.instanceId) && isUuid(b.userId) && isUuid(b.personalVaultId)
    && typeof b.email === 'string' && emailNorm(b.email) === b.email && isB64_32(b.identityPub) && isMs(b.issuedAt)
    && hasExactly(b.card, ['seq', 'hash']) && isInt(b.card.seq) && isHex64(b.card.hash)
    && hasExactly(b.accountState, ['seq', 'hash']) && isInt(b.accountState.seq) && isHex64(b.accountState.hash)
    && Array.isArray(b.contacts) && b.contacts.length <= BUNDLE_MAX_ENTRIES
    && b.contacts.every((c) => hasExactly(c, ['userId', 'keyHash', 'verifiedAt']) && isUuid(c.userId) && isHex64(c.keyHash) && isMs(c.verifiedAt))
    && Array.isArray(b.vaults) && b.vaults.length <= BUNDLE_MAX_ENTRIES
    && b.vaults.every((v) => hasExactly(v, ['vaultId', 'seq', 'hash']) && isUuid(v.vaultId) && isInt(v.seq) && isHex64(v.hash));
  return ok ? b : null;
}

// ---- the existing device, on the claim it reads back ----

/**
 * bad_claim (a field outside its type: nPub a b64_32 that is not a low-order X25519 point, §2.4),
 * then bad_mac.
 */
export function checkClaim({ secret, claim }) {
  const typed = isObject(claim) && isB64_32(claim.nPub) && !isLowOrderX25519(mustUnb64u(claim.nPub)) && isName(claim.name) && isPlatform(claim.platform) && isHex64(claim.commitN) && isB64_32(claim.mac);
  if (!typed) return 'bad_claim';
  const { linkId, macKey } = deriveDeviceLink(secret);
  return mac(macKey, claimMacInput({ linkId, ...claim })) === claim.mac ? 'ok' : 'bad_mac';
}

/** The existing device, on the revealed nonce. */
export const checkDeviceReveal = (commitN, nonceN) => (nonceN.length === 32 && codeCommit(nonceN) === commitN ? 'ok' : 'bad_reveal');

/** E fixed the claim when it drew nonceE; a later poll that shows another one cancels the link. */
export function claimStill(fixed, later) {
  return ['nPub', 'name', 'platform', 'commitN'].every((k) => fixed[k] === later[k]) ? 'ok' : 'claim_changed';
}

// ---- the new device, before any password prompt ----

/**
 * bad_mac first (approveMac covers the raw sealed bytes, so it is checked before anything is opened
 * or parsed); outer_unopenable; bad_outer; origin_mismatch.
 */
export function openOuter({ outer, nPub, nSec, pinnedOrigin, secret, approveMac }) {
  const { linkId, macKey } = deriveDeviceLink(secret);
  if (mac(macKey, approveMacInput({ linkId, outer })) !== approveMac) return { verdict: 'bad_mac' };
  const plain = boxSealOpen(nPub, nSec, outer);
  if (plain === null) return { verdict: 'outer_unopenable' };
  const o = decodeOuter(plain);
  if (o === null) return { verdict: 'bad_outer' };
  if (o.origin !== pinnedOrigin) return { verdict: 'origin_mismatch' };
  return { verdict: 'ok', outer: o };
}

// ---- the new device, after the pickup and the unlock ----

/**
 * The genesis verdicts first: the genesis is verified when the device unlocks, as at every unlock,
 * before the bundle is touched. Then bundle_unopenable; bad_bundle; identity_mismatch (the bundle's
 * userId, identityPub or personalVaultId is not the session's, the seed-derived key or the verified
 * genesis's); pin_mismatch (the bundle's origin, instanceId or card checkpoint disagrees with the pin
 * made before the claim, also when the verified chain ends below the checkpoint).
 * `chain` holds the hash at each seq of the card chain this device has verified for the pinned origin.
 */
export function openBundle({ inner, uvk, secret, sessionUserId, seed, genesis, pin, chain }) {
  const g = verifyGenesis({ frame: genesis, seed, sessionUserId, pinnedInstanceId: pin.instanceId, servedWrapVaultId: null });
  if (g.verdict !== 'ok') return { verdict: g.verdict };

  const { linkId } = deriveDeviceLink(secret);
  const plain = envelopeOpen(bundleKey(uvk, linkId), bundleAd(linkId), inner);
  if (plain === null) return { verdict: 'bundle_unopenable' };
  const b = decodeBundle(plain);
  if (b === null) return { verdict: 'bad_bundle' };

  const identity = boxKeypairFromSeed(seed).publicKey;
  if (b.userId !== sessionUserId || !bytesEqual(mustUnb64u(b.identityPub), identity) || b.personalVaultId !== g.genesis.personalVaultId) {
    return { verdict: 'identity_mismatch' };
  }

  const cardInChain = b.card.seq < chain.length && chain[b.card.seq] === b.card.hash;
  if (b.origin !== pin.origin || b.instanceId !== pin.instanceId || !cardInChain) return { verdict: 'pin_mismatch' };
  return { verdict: 'ok', bundle: b };
}

/** contacts[].keyHash: SHA-256 over the raw 32 key bytes. */
export const keyHash = (identityPub) => hex(sha256(identityPub));

/** The bundle confers currency, never contacts: only where the merged account state holds that userId with the same key hash. */
export function currentFromBundle(bundleContacts, stateContacts) {
  return bundleContacts
    .filter((c) => Object.hasOwn(stateContacts, c.userId) && keyHash(mustUnb64u(stateContacts[c.userId].identityPub)) === c.keyHash)
    .map((c) => c.userId);
}

/**
 * The accountState checkpoint {seq, hash}: a high-water mark of the document's in-blob seq, with
 * hash = SHA-256 over the ASCII bytes of the served sealedState string. A served state below it is
 * a rollback; another hash at the same seq is a fork.
 */
export function checkAccountStateCheckpoint(checkpoint, served) {
  return {
    rollback: served.seq < checkpoint.seq,
    fork: served.seq === checkpoint.seq && hex(sha256(served.sealedState)) !== checkpoint.hash,
  };
}

export { unb64u };
