// Types for the vendored encoder (narrowed from upstream qrcode.d.ts to the
// surface index.ts actually uses — the wrapper is the only importer).

export interface QRCode {
  addData(data: string, mode?: "Numeric" | "Alphanumeric" | "Byte" | "Kanji"): void;
  make(): void;
  getModuleCount(): number;
  isDark(row: number, col: number): boolean;
}

export interface QRCodeFactory {
  /** typeNumber 0 = smallest version that fits the data. */
  (typeNumber: number, errorCorrectionLevel: "L" | "M" | "Q" | "H"): QRCode;
  stringToBytes(s: string): number[];
  stringToBytesFuncs: { [encoding: string]: (s: string) => number[] };
}

declare const qrcode: QRCodeFactory;
export default qrcode;
