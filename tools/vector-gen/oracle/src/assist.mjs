// The whole `recovery-cli assist` run (spec 04 §7 step 3, with §4 "Opening an escrow offline"), from
// the corrected text: the command line as it is read (§7 step 3.0), its own three request arguments,
// §4 step 0, the request code and the clock (§7 step 3.2), the identity file as it is read (§4 "Reading
// the identity file"), the seed (§4 step 1), §4 steps 2 to 8, the typed RECOVER confirmation, and the
// answer. Every refusal has the name the text gives it ("Every refusal has a name"). Choices the text
// does not settle are marked CHOICE.

import { unb64u, utf8DecodeStrict } from './bytes.mjs';
import { isUuid, isB64_16, isB64_32 } from './grammar.mjs';
import { isLowOrderX25519 } from './prims.mjs';
import { requestCode } from './recovery.mjs';
import { openRecoveryCopy, trimTyped } from './recoverycopy.mjs';
import { makeAnswer } from './answer3.mjs';

/** The options of `assist` that take a value, in the order the rows' command line gives them. */
const VALUE_FLAGS = [
  ['--instance', 'instance'], ['--request', 'request'], ['--request-key', 'requestKey'], ['--request-code', 'requestCode'],
  ['--user', 'user'], ['--identity-fp', 'identityFp'], ['--identity-file', 'identityFile'], ['--email', 'email'],
];

/**
 * The command line a row stands for: each named argument that is not null as its flag and its value,
 * in VALUE_FLAGS order; then --no-identity-anchor when set; then the row's extraArgs exactly as given.
 */
export function commandLine(args, extraArgs = []) {
  const argv = [];
  for (const [flag, key] of VALUE_FLAGS) if (args[key] != null) argv.push(flag, args[key]);
  if (args.noIdentityAnchor) argv.push('--no-identity-anchor');
  return [...argv, ...extraArgs];
}

/**
 * §7 step 3.0: the command line itself, as it is read, before any value is checked. An option assist
 * does not have is unknown_option, the old --legacy is legacy_refused, a second copy given is
 * more_than_one_copy, whichever comes first. A flag given last with no value is an absent argument,
 * named later by its own check ("Every refusal has a name").
 */
export function readCommandLine(argv) {
  const flags = new Map(VALUE_FLAGS);
  const values = {};
  let noIdentityAnchor = false;
  let copy = null;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (flags.has(a)) {
      values[flags.get(a)] = i + 1 < argv.length ? argv[++i] : null;
    } else if (a === '--no-identity-anchor') {
      noIdentityAnchor = true;
    } else if (a === '--legacy') {
      return { verdict: 'legacy_refused' };
    } else if (a.startsWith('--')) {
      return { verdict: 'unknown_option' };
    } else if (copy !== null) {
      return { verdict: 'more_than_one_copy' };
    } else {
      copy = a;
    }
  }
  return { verdict: 'read', values, noIdentityAnchor, copy };
}

/** A copy as text: canonical unpadded base64url exactly as given, and not empty (§4 step 0.5, "bad_copy"). */
const copyBytes = (text) => {
  const b = typeof text === 'string' ? unb64u(text) : null;
  return b !== null && b.length > 0 ? b : null;
};

/**
 * §7 step 3.2: the typed request code. The command line removes spaces, tabs and dashes and compares
 * its letters without regard to case; any other character (a line break, a no-break space) is no match.
 */
export const codeMatches = (typed, rPub) => typeof typed === 'string' && typed.replace(/[ \t-]/g, '').toLowerCase() === requestCode(rPub).code;

/**
 * §4 "Reading the identity file" (before the seed is asked for): it cannot be read (bytes null), is not
 * strict UTF-8, or is not a recovery-copy download {userId, sealed, encryptedIdentitySeed, identityPub}
 * with each field in its grammar ("Files": userId a lowercase uuid, encryptedIdentitySeed canonical
 * base64url): bad_identity_file; its userId is not --user: identity_file_mismatch; its identityPub is not
 * 32 bytes of canonical base64url: identity_check_failed; the copy it carries, or the one given in its
 * place, is not canonical base64url: bad_copy.
 * CHOICE: a field the download does not have in the text is passed over (the text lists the four it
 * must have, not whether others are refused; no row depends on it). CHOICE: with a copy given in its
 * place, only the copy that is opened is checked (no row depends on it).
 */
export function readIdentityFile(bytes, user, givenCopy) {
  const text = bytes === null ? null : utf8DecodeStrict(bytes);
  if (text === null) return { verdict: 'bad_identity_file' };
  let dl;
  try {
    dl = JSON.parse(text);
  } catch {
    return { verdict: 'bad_identity_file' };
  }
  if (dl === null || typeof dl !== 'object' || Array.isArray(dl)) return { verdict: 'bad_identity_file' };
  if (!['userId', 'sealed', 'encryptedIdentitySeed', 'identityPub'].every((k) => typeof dl[k] === 'string')) return { verdict: 'bad_identity_file' };
  if (!isUuid(dl.userId)) return { verdict: 'bad_identity_file' };
  const encryptedIdentitySeed = copyBytes(dl.encryptedIdentitySeed);
  if (encryptedIdentitySeed === null) return { verdict: 'bad_identity_file' };
  if (dl.userId !== user) return { verdict: 'identity_file_mismatch' };
  const identityPub = unb64u(dl.identityPub);
  if (identityPub === null || identityPub.length !== 32) return { verdict: 'identity_check_failed' };
  const sealed = copyBytes(givenCopy ?? dl.sealed);
  if (sealed === null) return { verdict: 'bad_copy' };
  return { verdict: 'read', identityFile: { encryptedIdentitySeed, identityPub }, sealed };
}

/**
 * §4 step 1: the seed as typed. CHOICE: space and tab are removed from its ends, as from every typed
 * line ("Who reads what a person typed"); then it must be 32 bytes of canonical base64url (bad_seed).
 * The rows give a seed of the wrong length only.
 */
export function readSeed(typed) {
  const b = typeof typed === 'string' ? unb64u(trimTyped(typed)) : null;
  return b !== null && b.length === 32 ? b : null;
}

/** The download a row's identity file stands for: its four fields, as JSON text in UTF-8. */
export function downloadBytes({ userId, sealedB64, encryptedIdentitySeedB64, identityPubB64 }) {
  return new TextEncoder().encode(JSON.stringify({ userId, sealed: sealedB64, encryptedIdentitySeed: encryptedIdentitySeedB64, identityPub: identityPubB64 }));
}

/**
 * input: { argv, readFile (path -> bytes, or null when the file cannot be read), seedTyped,
 *   unanchoredAck, confirmation, clock, commit, ephemeral, recovery } (the last three only make the
 *   answer reproducible). Returns { verdict: 'ok', answer } or { verdict } (plus copyEmail for
 *   email_mismatch).
 */
export function runAssist(input) {
  // §7 step 3.0: the command line as it is read.
  const line = readCommandLine(input.argv);
  if (line.verdict !== 'read') return line;
  const a = line.values;
  // §7 step 3.1: assist's own three request arguments, in this order (absent or malformed), exactly as given.
  if (typeof a.instance !== 'string' || !isUuid(a.instance)) return { verdict: 'bad_instance' };
  if (typeof a.request !== 'string' || !isB64_16(a.request)) return { verdict: 'bad_request_id' };
  if (typeof a.requestKey !== 'string' || !isB64_32(a.requestKey)) return { verdict: 'bad_request_key' };
  const rPub = unb64u(a.requestKey);
  if (isLowOrderX25519(rPub)) return { verdict: 'low_order_request_key' };
  // §4 step 0, in its order (items 1 to 4); nothing is read or opened. The identity file only has to be given here.
  const step0 = openRecoveryCopy({
    mode: 'assist', user: a.user, identityFp: a.identityFp, noIdentityAnchor: line.noIdentityAnchor, identityFile: a.identityFile == null ? null : {},
    email: a.email, stopAfterStep0: true,
  });
  if (step0.verdict !== 'step0_ok') return step0;
  // §4 step 0.5: a copy given on the command line in place of the download's.
  if (line.copy !== null && copyBytes(line.copy) === null) return { verdict: 'bad_copy' };
  // §7 step 3.2: the request code, then the clock, before the identity file is read or the seed asked for.
  if (!codeMatches(a.requestCode, rPub)) return { verdict: 'request_code_mismatch' };
  if (!(Number.isInteger(input.clock) && input.clock >= 1e12 && input.clock < 1e13)) return { verdict: 'bad_clock' };
  // §4 "Reading the identity file".
  const file = readIdentityFile(input.readFile(a.identityFile), a.user, line.copy);
  if (file.verdict !== 'read') return file;
  // §4 step 1: the seed.
  const seed = readSeed(input.seedTyped);
  if (seed === null) return { verdict: 'bad_seed' };
  // §4 steps 2 to 8.
  const opened = openRecoveryCopy({
    mode: 'assist', user: a.user, identityFp: a.identityFp, noIdentityAnchor: line.noIdentityAnchor, unanchoredAck: input.unanchoredAck,
    identityFile: file.identityFile, email: a.email, recoverySeed: seed, sealed: file.sealed,
  });
  if (opened.verdict !== 'ok') return opened;
  // §4 step 9: RECOVER <first 8 characters of the userId>, space and tab removed from both ends, then compared exactly.
  if (trimTyped(input.confirmation) !== 'RECOVER ' + opened.userId.slice(0, 8)) return { verdict: 'not_confirmed' };
  // §7 step 3.4: the answer signs the time item 2 checked.
  const answer = makeAnswer({
    recovery: input.recovery, instanceId: a.instance, userId: opened.userId, emailB64: opened.emailB64, requestId: a.request,
    requestKey: a.requestKey, commit: input.commit, uvkB64: opened.uvkB64, issuedAt: input.clock, ephemeral: input.ephemeral,
  });
  return { verdict: 'ok', opened, answer };
}
