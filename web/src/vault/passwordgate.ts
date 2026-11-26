import type { PinRoot, PinState } from "./pinstore";

/**
 * The password rule (design §4.4, T2-B1) for the web client: the one decision every web flow asks before it
 * sends a value derived from an account's secrets (prelogin for its email, `authKey`, `currentAuthKey`, a
 * two-step code, a kit's `recoveryAuthKey`) to an origin. Only `proceed` lets the value go. Behaviour twin of
 * core `PasswordGate` restricted to the purposes the web has (§13): sign-in, creating an account,
 * re-authenticating inside a session, and recovering its own account with the kit from "Forgot your master
 * password?". The web opens no link and links no device, so the device-link and assisted-recovery purposes do
 * not exist here, and it has two entry screens only: its first screen and the kit recovery screen, each of which
 * starts only its own flow (the screens are separate code paths, so the entry is not an input of this function).
 *
 * Graded on the passwordgate.json rows of those four purposes on those entries (passwordgate.test.ts).
 */
export type GatePurpose = "sign_in" | "register" | "reauth" | "kit_recovery";

export type GateDecision = "proceed" | "trust_gate" | "refuse_entry";

/** One pin this browser holds: its origin, root and, for a kit or setup pin, the account (`emailNorm`) it is limited to. */
export interface GatePin {
  readonly origin: string;
  readonly root: PinRoot;
  readonly account?: string | null;
  /** A forked or damaged pin: the origin refuses everything. */
  readonly blocked?: boolean;
}

export interface GateInput {
  readonly purpose: GatePurpose;
  readonly origin: string;
  /** The account's `emailNorm`. */
  readonly account: string | null;
  readonly pins: readonly GatePin[];
  /** A session this browser holds for an account at an origin. */
  readonly session: { readonly origin: string; readonly account: string } | null;
}

/** True when [pin] lets [purpose] send a secret-derived value for [account] (§4.4, FS-B1). */
export function isPasswordPin(pin: GatePin, purpose: GatePurpose, account: string | null): boolean {
  switch (pin.root) {
    case "baked":
    case "trust_gate":
      return true;
    case "setup":
      // A setup pin counts only for the operator account it enrolled: signing in to it, or recovering it with its
      // kit. A browser never holds one (it signs no card 0, §13), and never opens an operator session (§9.1).
      return (purpose === "sign_in" || purpose === "kit_recovery") && account !== null && pin.account === account;
    case "kit":
      // A kit pin counts only for recovering the kit's own account (FS-B1). A browser never makes one: the kit
      // root never replaces the pin of the origin that served it (§4.4), so kitflow.ts checks the kit against it.
      return purpose === "kit_recovery" && account !== null && pin.account === account;
    case "link_offer":
    case "enrol":
      return false;
  }
}

/**
 * The decision, pure and total, in core's order: a blocked origin refuses everything; a re-authentication
 * needs a session for that account at that origin; with such a session every purpose proceeds; creating an
 * account proceeds with any pin of the origin; anything else needs a password pin, or the Trust Gate first.
 */
export function decide(input: GateInput): GateDecision {
  if (input.pins.some((p) => p.origin === input.origin && p.blocked === true)) return "refuse_entry";
  const s = input.session;
  const hasSession = s !== null && input.account !== null && s.origin === input.origin && s.account === input.account;
  if (input.purpose === "reauth") return hasSession ? "proceed" : "refuse_entry";
  if (hasSession) return "proceed";
  const pins = input.pins.filter((p) => p.origin === input.origin);
  if (input.purpose === "register") return pins.length > 0 ? "proceed" : "trust_gate";
  return pins.some((p) => isPasswordPin(p, input.purpose, input.account)) ? "proceed" : "trust_gate";
}

/** The gate's view of what the pin store holds for [origin]. */
export function gatePinsOf(origin: string, state: PinState): GatePin[] {
  switch (state.kind) {
    case "none":
      return [];
    case "pinned":
      return [{ origin, root: state.pin.root }];
    case "forked":
      return [{ origin, root: state.pin.root, blocked: true }];
    case "damaged":
      return [{ origin, root: "enrol", blocked: true }];
  }
}

/** Thrown where a flow would send a secret-derived value without `proceed`. Carries no secret. */
export class PasswordRuleError extends Error {
  constructor(readonly decision: Exclude<GateDecision, "proceed">) {
    super(decision === "trust_gate" ? "this server must be confirmed before your master password is used" : "this server is blocked on this device");
    this.name = "PasswordRuleError";
  }
}

/** Throws unless the gate says proceed. Call it before deriving anything from the password that will be sent. */
export function requireProceed(input: GateInput): void {
  const d = decide(input);
  if (d !== "proceed") throw new PasswordRuleError(d);
}
