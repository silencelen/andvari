// The key floor of spec 01 "Keys in memory and the lock", rule 4: "An all-zero key is never a key."
// No legitimate key is all zeros, so a client refuses one before any derivation; data that would put
// zeros there is refused where it is read. The oracle applies the rule at the three derivations whose
// normative rows once carried an all-zero input (keyfloor.json lists them): a link's secret, a device
// link's secret, and a vault key under its commitment.

/** Thrown where rule 4 refuses an input. `operation` names the refused operation, as keyfloor.json does. */
export class KeyFloorRefusal extends Error {
  constructor(operation) {
    super(`${operation}: an all-zero key is never a key (spec 01, Keys in memory and the lock, rule 4)`);
    this.operation = operation;
  }
}

export function isAllZero(bytes) {
  return bytes.length > 0 && bytes.every((b) => b === 0);
}

/** Refuses `key` when every byte of it is zero; returns it otherwise. */
export function keyFloor(operation, key) {
  if (isAllZero(key)) throw new KeyFloorRefusal(operation);
  return key;
}

/** The lowest 32-byte input the floor accepts: 31 zero bytes and one 0x01. */
export function nearZeroKey() {
  const key = new Uint8Array(32);
  key[31] = 1;
  return key;
}
