import qrcode from "./qrcode.esm.js";

/**
 * Narrow typed wrapper over the vendored qrcode-generator (see README.md for
 * provenance + pinned hashes). This module is the ONLY import surface for the
 * vendored encoder — nothing else may reach into ./qrcode.esm.js.
 *
 * Client-side only, zero wire change: the QR is a rendering of text the client
 * already holds (otpauth URI, devstore URL) — nothing new leaves the browser.
 */

export type QrEcc = "L" | "M" | "Q" | "H";

// Byte mode encodes via the module-global stringToBytes; upstream's default
// masks charcodes to 8 bits (latin-only). Pin real UTF-8 once at module init —
// the vendored instance is app-private, so this can't clobber anyone else.
const utf8 = qrcode.stringToBytesFuncs["UTF-8"];
if (utf8) qrcode.stringToBytes = utf8;

/**
 * Encode [text] as a QR symbol → square module matrix (true = dark module).
 * typeNumber 0 = auto-size to the smallest version that fits; UTF-8 byte mode.
 * The matrix carries NO quiet zone — the renderer owns that (QrSvg adds the
 * 4-module quiet zone the QR spec requires).
 */
export function qrModules(text: string, ecc: QrEcc = "M"): boolean[][] {
  const qr = qrcode(0, ecc);
  qr.addData(text, "Byte");
  qr.make();
  const n = qr.getModuleCount();
  const rows: boolean[][] = [];
  for (let r = 0; r < n; r++) {
    const row: boolean[] = [];
    for (let c = 0; c < n; c++) row.push(qr.isDark(r, c));
    rows.push(row);
  }
  return rows;
}
