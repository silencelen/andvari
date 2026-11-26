// The one shared reader of an answer (spec 04 §7 step 3, "Reading an answer"): the console,
// `andvari-cli operator fulfil` and the web console each read the operator's text with it before the
// master password is asked. Written from the specification text of 2026-11-16 alone, before that
// day's corrections, then made to follow its corrected text of the same day (on wrapped lines, bare answers and a file's bytes);
// every choice the text still leaves open is marked CHOICE.

import { unb64u } from './bytes.mjs';
import { isB64_16, isB64_32, isHex64 } from './grammar.mjs';
import { answerSizes, emailCharsOf, TOKEN_PREFIX, TOKEN_VERSION } from './answer3.mjs';

/** U+FEFF, the byte-order mark, as a code unit (no literal in the source, so nothing invisible). */
export const BOM = 0xfeff;

/** "base64url characters only": CHOICE, the 64 characters of RFC 4648 §5, no `=`, at least one. */
export const isB64urlRun = (s) =>/^[A-Za-z0-9_-]+$/.test(s);
/** A line after the token line: base64url characters and ':' only, at least one. */
export const isTokenRun = (s) => /^[A-Za-z0-9_:-]+$/.test(s);
/** Base64url-only text is answer_bare from this many characters (all lines together). */
export const BARE_MIN = 100;

/**
 * A file's bytes: read as UTF-8, and bytes that are not UTF-8 are not_an_answer; then
 * readAnswer. CHOICE: "not UTF-8" is WHATWG's fatal UTF-8 decoder (overlong forms, surrogates, code
 * points past U+10FFFF and cut sequences refused); a UTF-8 byte-order mark becomes U+FEFF, which
 * step 1 drops as the text's first code point.
 */
export function readAnswerFile(bytes, request) {
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return { verdict: 'not_an_answer' };
  }
  return readAnswer(text, request);
}

/**
 * Step 1 alone, for the vector files: the lines the reader works on. CHOICE: the U+FEFF dropped is
 * the text's very first code unit, before any other step; a line is trimmed of U+0020 and U+0009
 * only; CR LF is one line end, and a lone CR and a lone LF are one each.
 */
export function answerLines(text) {
  const t = text.charCodeAt(0) === BOM ? text.slice(1) : text;
  return { text: t, lines: t.split(/\r\n|\n|\r/).map((l) => l.replace(/^[ \t]+|[ \t]+$/g, '')).filter((l) => l.length > 0) };
}

/**
 * Read an answer. `request` = { requestId, rPub, email } (a listed row whose fields passed their
 * grammar; `email` is its emailNorm). Returns { verdict: 'ok', requestId, requestKey, commitHash,
 * sealed } or a refusal: answer_empty, answer_is_the_copy, not_an_answer, answer_bare,
 * answer_other_request (with the id the token carries), answer_other_request_key, answer_cut_short,
 * answer_too_long. In order, the first failure deciding.
 */
export function readAnswer(text, request) {
  // 1
  const { text: body, lines } = answerLines(text);
  if (lines.length === 0) return { verdict: 'answer_empty' };
  // 2 (CHOICE: "the text" is the operator's whole text after the U+FEFF, searched as written, quotes included)
  if (lines[0].startsWith('{')) {
    return { verdict: body.includes('"encryptedIdentitySeed"') || body.includes('"identityPub"') ? 'answer_is_the_copy' : 'not_an_answer' };
  }
  // 3 (CHOICE: lines before the token line are passed over, whatever they hold)
  const marked = lines.map((l, i) => [l, i]).filter(([l]) => l.startsWith(TOKEN_PREFIX + ':'));
  if (marked.length > 1) return { verdict: 'not_an_answer' };
  let token;
  if (marked.length === 1) {
    const at = marked[0][1];
    const tail = lines.slice(at + 1);
    // A wrapped line may hold base64url characters and ':' (a wrap inside the head too); step 4 decides.
    if (!tail.every(isTokenRun)) return { verdict: 'not_an_answer' };
    token = lines[at] + tail.join('');
  } else {
    // Base64url characters only AND at least BARE_MIN characters together.
    const bare = lines.every(isB64urlRun) && lines.reduce((n, l) => n + l.length, 0) >= BARE_MIN;
    return { verdict: bare ? 'answer_bare' : 'not_an_answer' };
  }
  // 4
  const parts = token.split(':');
  if (parts.length !== 6) return { verdict: 'not_an_answer' };
  const [prefix, version, requestId, requestKey, commitHash, sealed] = parts;
  if (prefix !== TOKEN_PREFIX || version !== TOKEN_VERSION || !isB64_16(requestId) || !isB64_32(requestKey) || !isHex64(commitHash) || !isB64urlRun(sealed)) {
    return { verdict: 'not_an_answer' };
  }
  // 5
  if (requestId !== request.requestId) return { verdict: 'answer_other_request', tokenRequestId: requestId };
  if (requestKey !== request.rPub) return { verdict: 'answer_other_request_key' };
  // 6
  const want = answerSizes(emailCharsOf(request.email)).sealed;
  const decoded = unb64u(sealed);
  if (decoded !== null && decoded.length === want) return { verdict: 'ok', requestId, requestKey, commitHash, sealed };
  const L = decoded !== null ? decoded.length : Math.floor((3 * sealed.length) / 4);
  if (L < want) return { verdict: 'answer_cut_short' };
  if (L > want) return { verdict: 'answer_too_long' };
  return { verdict: 'not_an_answer' };
}
