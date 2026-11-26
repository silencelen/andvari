// The independent oracle for the onboarding and trust conformance vectors.
//
//   npm run generate   write every vector file into spec/test-vectors (and spec/test-vectors/next)
//   npm run check      regenerate into a scratch directory, fail on any difference from the committed
//                      files, grade every committed row with the oracle's own verifiers, cross-check
//                      the primitives against the existing corpus and against Node's WebCrypto
//
// Written from docs/design/2026-11-15-onboarding-trust.md and spec/*.md alone. It imports no andvari
// code: Node, @noble/ed25519, @noble/curves, @noble/ciphers and @noble/hashes at pinned versions.
// Nothing is random: seeds, keys and nonces are constants (cast.mjs), so two runs give identical bytes.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { journal } from './prims.mjs';
import { replayJournal } from './webcheck.mjs';
import { checkAgainstCorpus } from './corpuscheck.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const vectorDir = path.resolve(here, '../../../../spec/test-vectors');

/** Every vector file this oracle owns, in dependency order. `file` is relative to spec/test-vectors. */
const MODULES = [
  './files/encodings.mjs',
  './files/statement-v2.mjs',
  './files/vaultlog.mjs',
  './files/instancecard.mjs',
  './files/passwordgate.mjs',
  './files/sharedgrant-v2.mjs',
  './files/wrapad.mjs',
  './files/accountgenesis.mjs',
  './files/links.mjs',
  './files/recoverykit.mjs',
  './files/accountstate.mjs',
  './files/signup.mjs',
  './files/recovery.mjs',
  './files/devicelink.mjs',
  './files/logappend.mjs',
  './files/keyfloor.mjs',
  './files/escrow-v3.mjs',
  './files/recovery-v3.mjs',
  './files/answer-reader.mjs',
];

/** JSON text as committed: two-space indent, ASCII only (everything else as \uXXXX), one final newline. */
function serialize(doc) {
  const nonAscii = new RegExp('[' + String.fromCharCode(0x7f) + '-' + String.fromCharCode(0xffff) + ']', 'g');
  return JSON.stringify(doc, null, 2).replace(nonAscii, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')) + '\n';
}

async function loadModules() {
  const out = [];
  for (const spec of MODULES) out.push(await import(spec));
  return out;
}

async function generate(targetDir) {
  const written = [];
  for (const mod of await loadModules()) {
    const text = serialize(mod.build());
    const target = path.join(targetDir, mod.file);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, text);
    written.push({ file: mod.file, bytes: Buffer.byteLength(text) });
  }
  return written;
}

async function check() {
  const failures = [];

  failures.push(...checkAgainstCorpus(vectorDir));

  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'andvari-oracle-'));
  try {
    const written = await generate(scratch);
    for (const { file } of written) {
      const committed = path.join(vectorDir, file);
      if (!fs.existsSync(committed)) {
        failures.push(`${file}: not committed (run npm run generate)`);
        continue;
      }
      if (!fs.readFileSync(committed).equals(fs.readFileSync(path.join(scratch, file)))) {
        failures.push(`${file}: the committed file differs from what the oracle generates`);
      }
    }
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }

  // Grade the COMMITTED bytes as a consumer would: every expected value and every verdict must be
  // what the oracle's own verifier returns for that row.
  let rows = 0;
  for (const mod of await loadModules()) {
    const committed = path.join(vectorDir, mod.file);
    if (!fs.existsSync(committed)) continue;
    const doc = JSON.parse(fs.readFileSync(committed, 'utf8'));
    const result = mod.grade(doc);
    rows += result.rows ?? 0;
    for (const failure of result.failures ?? result) failures.push(`${mod.file}: ${failure}`);
  }

  const replay = await replayJournal(journal);
  failures.push(...replay.failures.map((f) => 'webcrypto: ' + f));

  if (failures.length) {
    for (const failure of failures) console.error('FAIL ' + failure);
    console.error(`\n${failures.length} failure(s)`);
    process.exit(1);
  }
  console.log(`ok: ${MODULES.length} file(s) byte-identical, every row graded, ${replay.checked} primitive results recomputed with WebCrypto`);
}

const command = process.argv[2];
if (command === 'generate') {
  for (const { file, bytes } of await generate(vectorDir)) console.log(`wrote ${file} (${bytes} bytes)`);
} else if (command === 'check') {
  await check();
} else {
  console.error('usage: node src/main.mjs generate|check');
  process.exit(2);
}
