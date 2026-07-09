/**
 * Password generator — port of web/src/crypto/generator.ts with randomBytes on
 * crypto.getRandomValues (no libsodium here). Mirrors core PasswordGenerator; keep the
 * class sets + rejection sampling identical across impls.
 */

class CryptoError extends Error {}

const randomBytes = (n: number): Uint8Array => crypto.getRandomValues(new Uint8Array(n));

export interface GeneratorOptions {
  length: number;
  lower: boolean;
  upper: boolean;
  digits: boolean;
  symbols: boolean;
  avoidAmbiguous: boolean;
}

export const DEFAULT_GENERATOR: GeneratorOptions = {
  length: 20,
  lower: true,
  upper: true,
  digits: true,
  symbols: true,
  avoidAmbiguous: true,
};

const LOWER = "abcdefghijklmnopqrstuvwxyz";
const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS = "0123456789";
const SYMBOLS = "!@#$%^&*-_=+?";
const AMBIGUOUS = "lIO01";

/** Unbiased int in [0, bound) by rejection sampling; mirrors core PasswordGenerator. */
function uniform(bound: number): number {
  if (bound < 1 || bound > 256) throw new CryptoError("uniform bound out of range");
  const limit = 256 - (256 % bound);
  for (;;) {
    const b = randomBytes(1)[0]!;
    if (b < limit) return b % bound;
  }
}

export function generatePassword(options: GeneratorOptions = DEFAULT_GENERATOR): string {
  if (options.length < 8 || options.length > 128) throw new CryptoError("length out of range");
  const classes = [
    options.lower ? LOWER : null,
    options.upper ? UPPER : null,
    options.digits ? DIGITS : null,
    options.symbols ? SYMBOLS : null,
  ]
    .filter((c): c is string => c !== null)
    .map((cls) => (options.avoidAmbiguous ? [...cls].filter((ch) => !AMBIGUOUS.includes(ch)).join("") : cls));
  if (classes.length === 0) throw new CryptoError("at least one character class required");
  if (options.length < classes.length) throw new CryptoError("length shorter than enabled classes");
  const all = classes.join("");

  const chars: string[] = [];
  for (const cls of classes) chars.push(cls[uniform(cls.length)]!);
  for (let i = chars.length; i < options.length; i++) chars.push(all[uniform(all.length)]!);
  for (let i = chars.length - 1; i > 0; i--) {
    const j = uniform(i + 1);
    [chars[i], chars[j]] = [chars[j]!, chars[i]!];
  }
  return chars.join("");
}
