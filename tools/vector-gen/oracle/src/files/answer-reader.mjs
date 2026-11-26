// answer-reader.json: the one shared reader of an answer (spec 04 §7 step 3, "Reading an answer").
// The desktop console and `andvari-cli operator fulfil` read the
// operator's text with it, before the master password is asked, and upload exactly the four parts it
// yields. Written from the specification text of 2026-11-16 alone, before that day's corrections;
// corrected to its text as corrected the same day.

import { b64u, mustUnb64u, utf8, concat } from '../bytes.mjs';
import { x25519Base, envelopeSeal } from '../prims.mjs';
import { emailB64Of, identitySeedAd, sealRecoveryCopy } from '../recoverycopy.mjs';
import { makeAnswer } from '../answer3.mjs';
import { readAnswer, readAnswerFile, answerLines, BOM, BARE_MIN } from '../answerreader.mjs';
import { alice, bob, recoveryA, fixed, ids, T0, HOUR } from '../cast.mjs';

export const file = 'answer-reader.json';

const ALICE = 'alice@example.org';
const BOB = 'bob@example.org';
const CAROL = 'carol@example.org';
const ISSUED = T0 + 200 * HOUR;
const bomChar = String.fromCharCode(BOM);
const nbsp = String.fromCharCode(0xa0);
const wrap = (text, width) => text.match(new RegExp('.{1,' + width + '}', 'g'));

export function build() {
  const rPub = x25519Base(fixed('recovery/request-secret'));
  const otherRPub = x25519Base(fixed('recovery/other-request-secret'));
  const requestId = b64u(fixed('recovery/request-id', 16));
  const otherRequestId = b64u(fixed('recovery/other-request-id', 16));
  const uvk = fixed('recovery/uvk');
  const answerFor = (label, overrides = {}) => makeAnswer({
    recovery: recoveryA, instanceId: ids.instance, userId: alice.userId, emailB64: emailB64Of(ALICE), requestId, requestKey: b64u(rPub),
    commit: fixed('recovery-v3/commit'), uvkB64: b64u(uvk), issuedAt: ISSUED, ephemeral: fixed('recovery-v3/ephemeral/' + label), ...overrides,
  });
  // The tokens of recovery-v3.json's answers "alice" and "bob" (the same inputs, so the same bytes).
  const answer = answerFor('alice');
  const bobAnswer = answerFor('bob', { userId: bob.userId, emailB64: emailB64Of(BOB), uvkB64: b64u(fixed('escrow-v3/uvk/bob')), commit: fixed('recovery-v3/commit/bob') });
  const T = answer.token;
  const S = b64u(answer.sealed);
  const H = answer.commitHash;
  const K = b64u(rPub);
  const head = `andvari-answer:3:${requestId}:${K}:${H}:`;
  if (head + S !== T || head.length !== 149) throw new Error('answer-reader: the token is not what the text says');
  const tokenWith = (parts) => ['andvari-answer', '3', requestId, K, H, S].map((p, i) => (Object.hasOwn(parts, i) ? parts[i] : p)).join(':');
  const otherRequest = answerFor('reader/other-request', { requestId: otherRequestId });
  const otherKey = answerFor('reader/other-key', { requestKey: b64u(otherRPub) });
  const carol = answerFor('reader/carol', { emailB64: emailB64Of(CAROL) });

  const toolOutput = (eol) => [
    `Answer for request ${requestId}`,
    `Account ${alice.userId}, ${ALICE} (the address the recovery copy names, signed by the account)`,
    'Only the person\'s device can open this answer. Upload the last line with the console or andvari-cli operator fulfil.',
    T,
  ].join(eol) + eol;

  // The recovery copy itself, as POST /admin/accounts/{userId}/escrow answers it.
  const copy = sealRecoveryCopy({ account: alice, address: ALICE, uvk, recoveryPub: recoveryA.publicKey, issuedAt: T0 + 100 * HOUR, ephemeral: fixed('escrow-v3/ephemeral/alice') });
  const identityFile = {
    userId: alice.userId, sealed: b64u(copy.sealed),
    encryptedIdentitySeed: b64u(envelopeSeal(uvk, fixed('recovery/seed-nonce', 24), identitySeedAd(alice.userId), alice.seed)), identityPub: b64u(alice.identityPub),
  };
  const copyPretty = JSON.stringify(identityFile, null, 2) + '\n';
  const copyCompact = JSON.stringify(identityFile);

  const request = { requestId, rPub: K, email: ALICE };
  const rows = [];
  const names = new Set();
  const OK = { verdict: 'ok', requestId, requestKey: K, commitHash: H, sealed: S };
  const V = (verdict) => ({ verdict });
  const row = (name, want, why, text, req = request) => {
    if (names.has(name)) throw new Error('answer-reader: duplicate row ' + name);
    names.add(name);
    const got = readAnswer(text, req);
    if (JSON.stringify(got) !== JSON.stringify(want)) throw new Error(`answer-reader "${name}": the text says ${JSON.stringify(want)}, the oracle says ${JSON.stringify(got)}`);
    const r = { name, why, text };
    if (req !== request) r.request = req;
    r.expect = want;
    rows.push(r);
  };

  // ---- read ----
  row('token-alone', OK, 'The token, alone, as the last line of the tool\'s output: the reader yields its four parts.', T);
  row('token-and-lf', OK, 'The token and a line feed.', T + '\n');
  row('token-and-crlf', OK, 'The token and CR LF.', T + '\r\n');
  row('token-and-cr', OK, 'The token and a lone CR.', T + '\r');
  row('the-whole-output-lf', OK, 'The tool\'s whole output, the lines before the token included (they are passed over), with LF line ends.', toolOutput('\n'));
  row('the-whole-output-crlf', OK, 'The same with CR LF line ends.', toolOutput('\r\n'));
  row('the-whole-output-cr', OK, 'The same with lone CR line ends.', toolOutput('\r'));
  row('mixed-line-ends', OK, 'The output with LF, CR LF and CR mixed, and the token wrapped: each is one line end.', toolOutput('\r\n').replace('\r\n', '\n').replace('\r\n', '\r').replace(T, wrap(T, 200).join('\r')));
  row('spaces-and-tabs-around', OK, 'Spaces and tabs before and after the token, and blank lines around it.', '\n \t\n  \t' + T + ' \t \n\n');
  row('byte-order-mark', OK, 'A file that starts with U+FEFF: one leading U+FEFF is dropped.', bomChar + T + '\n');
  row('byte-order-mark-and-crlf-output', OK, 'U+FEFF, then the whole output with CR LF.', bomChar + toolOutput('\r\n'));
  row('wrapped-at-200', OK, 'The token wrapped every 200 characters: the line after the token line is base64url only, and is joined on with nothing between.', wrap(T, 200).join('\n'));
  row('wrapped-at-160-with-indent-and-crlf', OK, 'Wrapped every 160 characters, each line indented by two spaces, CR LF: trimmed, then joined.', wrap(T, 160).map((l) => '  ' + l).join('\r\n') + '\r\n');
  row('wrapped-right-after-the-last-colon', OK, 'Wrapped at 149 characters: the first line ends with the colon before the sealed part, and every later line is base64url only.', wrap(T, 149).join('\n'));
  row('wrapped-at-64-after-the-colons', OK, 'The four short parts on the first line, then the sealed part in lines of 64.', head + '\n' + wrap(S, 64).join('\n'));
  row('answer-for-an-address-of-the-same-length', { ...OK, sealed: b64u(carol.sealed), commitHash: carol.commitHash }, 'An answer whose statement names carol@example.org (17 octets, like alice@example.org), for this request: the reader cannot tell (its size is right). It is a convenience, not a boundary: the person\'s device refuses it (request_mismatch).', carol.token);

  // ---- 1: answer_empty ----
  row('empty-text', V('answer_empty'), 'An empty text.', '');
  row('one-line-feed', V('answer_empty'), 'A line feed alone.', '\n');
  row('spaces-tabs-and-line-ends', V('answer_empty'), 'Spaces, tabs, CR LF, LF and CR only.', ' \t\r\n \n\t\r');
  row('byte-order-mark-alone', V('answer_empty'), 'U+FEFF alone.', bomChar);
  row('byte-order-mark-and-blank-lines', V('answer_empty'), 'U+FEFF, then blank lines.', bomChar + '  \r\n\t\n');

  // ---- 2: the copy, or JSON ----
  row('the-recovery-copy', V('answer_is_the_copy'), 'The recovery copy itself (the escrow download, pretty-printed), pasted where the answer belongs.', copyPretty);
  row('the-recovery-copy-on-one-line', V('answer_is_the_copy'), 'The same on one line.', copyCompact);
  row('the-recovery-copy-with-byte-order-mark', V('answer_is_the_copy'), 'The same from a file that starts with U+FEFF and uses CR LF.', bomChar + copyPretty.replace(/\n/g, '\r\n'));
  row('json-with-identity-pub-only', V('answer_is_the_copy'), 'A JSON text whose only tell is "identityPub".', '{"identityPub":"' + b64u(alice.identityPub) + '"}');
  row('json-that-is-not-the-copy', V('not_an_answer'), 'A JSON text holding the sealed answer: it begins with { and names neither key of the copy.', '{"sealed":"' + S + '"}\n');
  row('order-json-before-token', V('not_an_answer'), 'A first line "{" and the token on the next line: step 2 decides on the first line.', '{\n' + T + '\n');
  row('order-copy-before-token', V('answer_is_the_copy'), 'The copy, then the token: step 2 decides.', copyPretty + T + '\n');

  // ---- 3: the token line, or a bare answer ----
  row('bare-sealed-answer', V('answer_bare'), 'The sealed answer alone, as the old tool printed it: no request beside it.', S + '\n');
  row('bare-sealed-answer-wrapped', V('answer_bare'), 'The same wrapped every 64 characters.', wrap(S, 64).join('\n') + '\n');
  row('the-tokens-tail', V('answer_bare'), 'The lines of a wrapped token after its first line: base64url only.', wrap(T, 160).slice(1).join('\n'));
  row('the-commit-hash-alone', V('not_an_answer'), 'The commit hash alone: base64url characters only, but 64 of them, under the 100 a bare answer needs.',H);
  row('one-word', V('not_an_answer'), 'One word of letters ("yes"): base64url characters only, but under 100 of them, so not a bare answer.','yes\n');
  row('the-request-id-alone', V('not_an_answer'), 'The request id alone (22 characters).', requestId + '\n');
  row('the-request-key-alone', V('not_an_answer'), 'The request key alone (43 characters).', K + '\n');
  row('base64url-99-characters', V('not_an_answer'), 'The first 99 characters of the sealed part: one under the bound of a bare answer.', S.slice(0, 99));
  row('base64url-100-characters', V('answer_bare'), 'The first 100 characters of the sealed part: exactly the bound, so answer_bare.', S.slice(0, 100));
  row('base64url-100-characters-on-two-lines', V('answer_bare'), '60 and 40 characters on two lines: the bound counts the lines together.', S.slice(0, 60) + '\n' + S.slice(60, 100) + '\n');
  row('two-words', V('not_an_answer'), 'Two words: a space is not a base64url character.', 'hello world\n');
  row('the-request-code', V('not_an_answer'), 'The request code, six groups of four.', '1a2b 3c4d 5e6f 7a8b 9c0d 1e2f\n');
  row('token-twice', V('not_an_answer'), 'The token pasted twice: two lines begin with andvari-answer:.', T + '\n' + T + '\n');
  row('token-then-a-prompt', V('not_an_answer'), 'The token and the shell prompt after it ("$"): a line after the token that is not base64url.', T + '\n$\n');
  row('token-then-a-word-with-a-dot', V('not_an_answer'), 'The token and "Done.".', T + '\nDone.\n');
  row('token-in-capitals', V('not_an_answer'), 'ANDVARI-ANSWER: in capitals: no line begins with andvari-answer:, and the line is not base64url.', T.replace('andvari-answer', 'ANDVARI-ANSWER'));
  row('token-inside-a-sentence', V('not_an_answer'), 'The token after other words on its line.', 'answer: ' + T);
  row('no-break-space-before-the-token', V('not_an_answer'), 'U+00A0 before the token: only space and tab are removed.', nbsp + T);
  row('wrapped-at-80', OK, 'The token wrapped every 80 characters, as an 80-column terminal would: the second line holds a colon, which a wrapped line may hold, and step 4 reads the six parts.', wrap(T, 80).join('\n'));
  row('wrapped-one-before-the-last-colon', OK, 'Wrapped at 148 characters: the second line begins with the last colon.', wrap(T, 148).join('\n'));
  row('wrapped-at-120-crlf', OK, 'Wrapped every 120 characters with CR LF.', wrap(T, 120).join('\r\n') + '\r\n');
  row('wrapped-at-40', OK, 'Wrapped every 40 characters: the head itself is broken inside its parts, and every later line holds base64url characters and colons only.', wrap(T, 40).join('\n'));
  row('wrapped-at-80-whole-output', OK, 'The tool\'s whole output with its last line wrapped every 80 characters.', toolOutput('\n').replace(T, wrap(T, 80).join('\n')));
  row('token-then-a-colon-line', V('not_an_answer'), 'The token and a line holding one colon: the line is joined on, and the token then has seven parts.', T + '\n:\n');
  row('wrapped-at-80-then-a-prompt', V('not_an_answer'), 'Wrapped every 80 characters, then a shell prompt line: a line after the token that is not token characters.', wrap(T, 80).join('\n') + '\nuser@host:~$\n');
  row('padding-on-the-last-wrapped-line', V('not_an_answer'), 'Wrapped, with "==" on the last line: = is not a base64url character.', wrap(T, 200).join('\n') + '==');

  // ---- 4: six parts ----
  row('five-parts', V('not_an_answer'), 'The token without its commit hash.', ['andvari-answer', '3', requestId, K, S].join(':'));
  row('seven-parts', V('not_an_answer'), 'The token with ":AAAA" after it.', T + ':AAAA');
  row('version-2', V('not_an_answer'), 'andvari-answer:2:…', tokenWith({ 1: '2' }));
  row('version-03', V('not_an_answer'), 'andvari-answer:03:…', tokenWith({ 1: '03' }));
  row('request-id-of-32-bytes', V('not_an_answer'), 'The third part is 32 bytes: not a b64_16.', tokenWith({ 2: K }));
  row('request-key-not-canonical', V('not_an_answer'), 'The fourth part\'s last character carries bits past the 32 bytes: not a b64_32.', tokenWith({ 3: K.slice(0, 42) + (K[42] === 'B' ? 'C' : 'B') }));
  row('commit-hash-in-capitals', V('not_an_answer'), 'The fifth part in upper-case hex: not a hex64.', tokenWith({ 4: H.toUpperCase() }));
  row('sealed-part-empty', V('not_an_answer'), 'The sixth part is empty.', head);
  row('sealed-part-padded', V('not_an_answer'), 'The sixth part ends with "=".', T + '=');
  row('space-inside-the-sealed-part', V('not_an_answer'), 'A space inside the sixth part.', head + S.slice(0, 300) + ' ' + S.slice(300));

  // ---- 5: the request ----
  row('token-for-another-request', { verdict: 'answer_other_request', tokenRequestId: otherRequestId }, 'F1: a token made for another request (of the same address): the reader names the id the token carries.', otherRequest.token);
  row('token-for-another-request-key', V('answer_other_request_key'), 'A token for this request id but another request key.', otherKey.token);
  row('order-request-before-key-and-size', { verdict: 'answer_other_request', tokenRequestId: otherRequestId }, 'Another request id, another key and a cut sealed part.', ['andvari-answer', '3', otherRequestId, b64u(otherRPub), H, S.slice(0, 100)].join(':'));
  row('order-key-before-size', V('answer_other_request_key'), 'Another request key and an over-long sealed part.', ['andvari-answer', '3', requestId, b64u(otherRPub), H, S + 'AAAA'].join(':'));

  // ---- 6: the size ----
  const strayLast = S.slice(0, -1) + 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'['ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'.indexOf(S[S.length - 1]) + 1];
  row('cut-by-one-character', V('answer_cut_short'), 'The last character of the sealed part is missing (730 characters, not canonical: L = floor(3 * 730 / 4) = 547).', T.slice(0, -1));
  row('cut-by-the-last-wrapped-line', V('answer_cut_short'), 'A token wrapped every 200 characters, its last line not copied.', wrap(T, 200).slice(0, -1).join('\n'));
  row('one-byte-short', V('answer_cut_short'), 'The sealed answer less its last byte, re-encoded: canonical, 547 bytes.', head + b64u(answer.sealed.slice(0, -1)));
  row('one-byte-too-long', V('answer_too_long'), 'The sealed answer and one byte more, re-encoded: 549 bytes.', head + b64u(new Uint8Array([...answer.sealed, 0])));
  row('one-character-too-long', V('answer_too_long'), 'One character more (732 characters: canonical, 549 bytes).', T + 'A');
  row('a-line-too-many', V('answer_too_long'), 'The token and a line "AAAA" after it: base64url only, so it is joined on.', T + '\nAAAA\n');
  row('right-length-not-canonical', V('not_an_answer'), 'The right number of characters, but the last one carries bits past the 548 bytes: not canonical, L = floor(3 * 731 / 4) = 548, which is neither smaller nor larger.', head + strayLast);
  row('answer-for-a-shorter-address', V('answer_cut_short'), 'bob\'s answer (15 octets, 545 bytes) for this request id and key, read against alice\'s request (548): the text calls it cut short.', bobAnswer.token);
  row('answer-read-against-a-shorter-address', V('answer_too_long'), 'alice\'s answer read against a request row whose address is bob\'s: the text calls it too long.', T, { requestId, rPub: K, email: BOB });

  for (const r of rows) {
    const { lines } = answerLines(r.text);
    if (lines.some((l) => l !== l.replace(/^[ \t]+|[ \t]+$/g, ''))) throw new Error('answer-reader: a line keeps a space');
  }

  // ---- a file's bytes: read as UTF-8; bytes that are not UTF-8 are not_an_answer ----
  const fileRows = [];
  const fileRow = (name, want, why, bytes) => {
    if (names.has(name)) throw new Error('answer-reader: duplicate row ' + name);
    names.add(name);
    const got = readAnswerFile(bytes, request);
    if (JSON.stringify(got) !== JSON.stringify(want)) throw new Error(`answer-reader file "${name}": the text says ${JSON.stringify(want)}, the oracle says ${JSON.stringify(got)}`);
    fileRows.push({ name, why, bytesB64: b64u(bytes), expect: want });
  };
  const B = (...parts) => concat(...parts.map((p) => (typeof p === 'string' ? utf8(p) : Uint8Array.from(p))));
  fileRow('file-token', OK, 'A file holding the token and a line feed, in UTF-8 (all ASCII).', B(T + '\n'));
  fileRow('file-utf8-bom-and-crlf-output', OK, 'A file that starts with the UTF-8 byte-order mark (EF BB BF), then the whole output with CR LF: the mark is read as U+FEFF and dropped by step 1.', B([0xef, 0xbb, 0xbf], toolOutput('\r\n')));
  fileRow('file-non-ascii-line-before-the-token', OK, 'A line in French before the token ("Réponse :", é as C3 A9): valid UTF-8, and lines before the token are passed over.', B('Réponse :\n', T + '\n'));
  fileRow('file-byte-ff-at-the-end', V('not_an_answer'), 'The token, then the byte FF, which never appears in UTF-8.', B(T, [0xff]));
  fileRow('file-overlong-slash', V('not_an_answer'), 'A line before the token holding C0 AF, an overlong form of "/": not UTF-8.', B([0xc0, 0xaf], '\n' + T + '\n'));
  fileRow('file-lone-continuation-byte', V('not_an_answer'), 'A line before the token holding the lone continuation byte 80.', B([0x80], '\n' + T + '\n'));
  fileRow('file-encoded-surrogate', V('not_an_answer'), 'A line before the token holding ED A0 80, the UTF-8 form of a surrogate (U+D800): not UTF-8.', B([0xed, 0xa0, 0x80], '\n' + T + '\n'));
  fileRow('file-cut-sequence-at-the-end', V('not_an_answer'), 'The token, a line feed, then E2 82, the first two bytes of a three-byte sequence.', B(T + '\n', [0xe2, 0x82]));
  const utf16 = new Uint8Array(2 + 2 * T.length);
  utf16[0] = 0xff;
  utf16[1] = 0xfe;
  for (let i = 0; i < T.length; i++) utf16[2 + 2 * i] = T.charCodeAt(i);
  fileRow('file-utf16le', V('not_an_answer'), 'The token saved as UTF-16 LE with its byte-order mark (FF FE): not UTF-8.', utf16);

  return {
    _about: [
      'The one shared reader of an answer: spec 04 §7 step 3, "Reading an answer", in the specification as corrected on 2026-11-16 (first written from its text of that day before the corrections). The desktop console and `andvari-cli operator fulfil` share it and read the operator\'s text with it before the master password is asked; a client uploads exactly the four parts it yields, and nothing is sent and no password is asked for a refusal.',
      'Generated and graded by the independent oracle in tools/vector-gen/oracle (src/answerreader.mjs), written from the specification text alone: `npm run check` regenerates this file byte for byte and reads every row again. No andvari code was read or run to make it.',
      'Input: `text` is the operator\'s text (a paste or a file\'s text) as a JSON string, and `request` the listed request (requestId, rPub, and email, its emailNorm), the top-level request unless a row has its own. The token andvari-answer:3:<requestId>:<requestKey>:<commitHash>:<sealed> is recovery-v3.json\'s answers "alice" (the same inputs give the same bytes); "bob" is its answers "bob". Its sealed part is 548 bytes, 731 characters (alice@example.org is 17 octets, E = 23).',
      'Steps, in order, the first failure deciding: 1 drop U+FEFF when it is the text\'s first code point, split into lines at CR LF, LF and CR only, remove space and tab (only those) from both ends of each line, drop empty lines; none left is answer_empty. 2 the first line begins with {: answer_is_the_copy when the text (all of it after a dropped U+FEFF, case-sensitive, quotes included) contains "encryptedIdentitySeed" or "identityPub", otherwise not_an_answer. 3 the lines that begin with andvari-answer: : more than one is not_an_answer; exactly one: lines before it are passed over, and the token is that line and every line after it joined with nothing between, each of which must be base64url characters and ":" only (a terminal may wrap the head as well as the sealed part), else not_an_answer; none: answer_bare when every line is base64url characters only and they hold at least 100 characters together (bareMinChars), otherwise not_an_answer. 4 exactly six parts at ":": andvari-answer, 3, a b64_16, a b64_32, a hex64, a non-empty run of base64url characters, else not_an_answer. 5 answer_other_request (expect.tokenRequestId names the id the token carries), then answer_other_request_key (compared as text). 6 the sixth part is canonical unpadded base64url of exactly 525 + E bytes, E the characters of the base64url of the request\'s address; otherwise, with L its decoded length when canonical and floor(3 * characters / 4) when not, smaller is answer_cut_short, larger answer_too_long, equal not_an_answer. "Base64url characters" are A-Z, a-z, 0-9, - and _ (never =).',
      'readFile: a file\'s bytes (bytesB64), read as UTF-8: bytes that are not UTF-8 are not_an_answer; otherwise the text is read as above. The oracle decodes with WHATWG\'s fatal UTF-8 decoder (overlong forms, encoded surrogates and cut sequences refused) and keeps a UTF-8 byte-order mark as U+FEFF, which step 1 drops.',
      'Changed with the specification\'s corrections of 2026-11-16: wrapped-at-80 and wrapped-one-before-the-last-colon are now read (a wrapped line may hold a colon); one-word and the-commit-hash-alone are now not_an_answer (a bare answer needs 100 characters); the readFile table is new (a file\'s bytes). Still pinned as the text says although a client may not expect it: answer-for-a-shorter-address and answer-read-against-a-shorter-address (an answer for another address of another length reads as cut short or too long; the words say both possibilities), and answer-for-an-address-of-the-same-length (the reader cannot tell; the device refuses it).',
    ],
    request,
    requestKeys: { rPubB64: K, otherRPubB64: b64u(otherRPub), otherRequestId },
    token: { text: T, requestId, requestKey: K, commitHash: H, sealedB64: S, sealedBytes: answer.sealed.length, sealedChars: S.length, lastColonAt: head.length },
    bareMinChars: BARE_MIN,
    read: rows,
    readFile: fileRows,
  };
}

export function grade(doc) {
  const failures = [];
  let rows = 0;
  for (const r of doc.read) {
    rows++;
    const got = readAnswer(r.text, r.request ?? doc.request);
    if (JSON.stringify(got) !== JSON.stringify(r.expect)) failures.push(`read ${r.name}: oracle says ${JSON.stringify(got)}`);
  }
  for (const r of doc.readFile) {
    rows++;
    const got = readAnswerFile(mustUnb64u(r.bytesB64), doc.request);
    if (JSON.stringify(got) !== JSON.stringify(r.expect)) failures.push(`readFile ${r.name}: oracle says ${JSON.stringify(got)}`);
  }
  rows++;
  if (mustUnb64u(doc.token.sealedB64).length !== doc.token.sealedBytes || doc.token.text.lastIndexOf(':') + 1 !== doc.token.lastColonAt) failures.push('token');
  return { rows, failures };
}
