import { ApiClient } from "../api/client";
import { DeviceIdentity, type KeyValue, memoryStorage } from "../api/devicesecret";
import type { ClientPolicyV2, SessionResponseV2 } from "../api/wire";
import { WireApi } from "../api/wireclient";
import { confirmGroups, confirmMatches, kitGroups } from "../crypto/trust/recoverykit";
import { emailNorm, NONE } from "../crypto/trust/grammar";
import type { OperatorOffer, SettingsSession } from "../vault/settingsflow";
import { createWebContext, type WebContext, writeSignupRecovery } from "../ui/opensession";
import { Account } from "../vault/account";
import type { OpenedAccount } from "../vault/accountopen";
import { AccountStateStore } from "../vault/accountdocstore";
import { memoryClientState } from "../vault/accountstatesync";
import { NullCache } from "../vault/idbcache";
import { VaultStore } from "../vault/store";
import type { SessionHow } from "../vault/contactbook";
import { SharedLogSession } from "../vault/sharedlogs";
import { confirmKit } from "../vault/kitflow";
import { completeSignup, type CopyAtUnlock, settlePin, signIn, type SignInResult, startSignup } from "../vault/onboardflow";
import { PinStore, type WebPin } from "../vault/pinstore";
import { runPow } from "../vault/pow";
import type { SessionKeys, SessionWrap } from "../vault/sessionwrap";
import { recordRecoveryChoice } from "../vault/recoverymirror";
import type { TestInstance } from "./harness";

/**
 * One browser in a journey: its own device storage (a browser profile), the one transport, the post-cut-over wire
 * client and the pin store, all pointed at the origin that "served" it. The journeys drive the web client's flow
 * modules through it, the same functions the screens call, over real HTTP against the test server.
 *
 * Its clock is the server's test clock, as a person's browser and their server share the real time.
 */
export class Browser {
  readonly client: ApiClient;
  readonly wire: WireApi;
  readonly pins: PinStore;
  readonly origin: string;

  constructor(
    readonly inst: TestInstance,
    readonly deviceName = "Firefox on Linux",
    /** The browser profile's device storage; a reload ([reload]) keeps it. */
    readonly storage: KeyValue & { readonly map: Map<string, string> } = memoryStorage(),
    /** The tab's transport; App's own (ui/session.ts makeClient, which persists every rotation) where a journey needs it. */
    transport: ApiClient = new ApiClient(inst.origin),
  ) {
    this.origin = inst.origin;
    // The context as App builds it (its transport gated on the pin, §4.4). No baked instance: a test server is never
    // the public instance, so its first pin is the Trust Gate's.
    const ctx = createWebContext(transport, inst.origin, this.storage, null, new DeviceIdentity(this.storage));
    this.client = ctx.client;
    this.wire = ctx.wire;
    this.pins = ctx.pins;
  }

  /** The same browser profile after a page reload: its device storage stays, the tab's memory (the token pair) is gone. */
  reload(): Browser {
    return new Browser(this.inst, this.deviceName, this.storage);
  }

  /** What every screen works with (ui/opensession.ts WebContext). */
  get ctx(): WebContext {
    return { client: this.client, wire: this.wire, pins: this.pins, origin: this.origin, storage: this.storage };
  }

  now = (): number => this.inst.now();

  /** The first screen: settle the pin of the serving origin; a browser with none confirms the Trust Gate for exactly the chain shown. */
  async settle(): Promise<WebPin> {
    const s = await settlePin(this.pins, this.origin);
    if (s.kind === "pinned") return s.pin;
    if (s.first.kind !== "needs_trust_gate") throw new Error(`the pin did not settle: ${JSON.stringify(s.first)}`);
    const r = this.pins.confirmTrustGate(s.first.ticket);
    if (r.kind !== "pinned") throw new Error(`the Trust Gate did not pin: ${r.kind}`);
    return r.pin;
  }

  /**
   * Sign-up as the screens run it (design §7.2, §7.3, §10): the emailed code, the proof of work the policy asks
   * for, register, the recovery record, and the kit typed back before the vault opens.
   */
  async signUp(
    email: string,
    password: string,
    displayName = email.split("@")[0]!,
    operator: { offer: OperatorOffer; understood: boolean; keepDespiteUnsignedChange: boolean } | null = null,
  ): Promise<{ session: SessionResponseV2; opened: OpenedAccount; pin: WebPin; policy: ClientPolicyV2; kit: Uint8Array; wrap: SessionKeys }> {
    const pin = await this.settle();
    const policy = await this.wire.clientPolicy();
    const seen = this.inst.mailCount(email, "signup_code");
    const started = await startSignup({
      wire: this.wire, pins: this.pins, origin: this.origin, email, ageConfirmed: true, powBits: policy.signup.powBits,
      pow: (e, bits) => runPow(e, bits, this.now()),
    });
    if (started.kind !== "sent") throw new Error(`sign-up did not start: ${JSON.stringify(started)}`);
    const code = await this.inst.awaitCode(email, "signup_code", seen);
    const ticket = await this.wire.signupVerify(email, code);
    const done = await completeSignup({
      wire: this.wire, pins: this.pins, origin: this.origin, pin, policy, email, displayName, password,
      signupTicket: ticket.signupTicket, ageConfirmed: true, deviceName: this.deviceName, nowMs: this.now(), operator,
    });
    if (done.kind !== "registered") throw new Error(`registration failed: ${JSON.stringify(done)}`);
    // The recovery record of a sign-up on this browser, and its mirror (§4.5, §7.7), as the screens write it.
    const choice = operator ? { posture: "operator" as const, fp: operator.offer.fp } : { posture: "private" as const, fp: NONE };
    const w = await writeSignupRecovery(this, done.opened, this.now(), choice);
    if (w !== "written") throw new Error(`the recovery record was not written: ${w}`);
    await this.confirmKit(done.recoverySecret, done.recoveryPieceId);
    return { session: done.session, opened: done.opened, pin, policy, kit: done.recoverySecret, wrap: done.wrap };
  }

  /** The kit confirmation (§10): three groups chosen by the CSPRNG, typed back, then recorded by the server. */
  async confirmKit(secret: Uint8Array, pieceId: string | null): Promise<void> {
    const asked = confirmGroups();
    const groups = kitGroups(secret);
    const typed = asked.map((n) => ` ${groups[n - 1]}\n`);
    if (!confirmMatches(secret, asked, typed)) throw new Error("the typed groups did not match the kit");
    const r = await confirmKit(this.wire, pieceId);
    if (r.kind !== "confirmed") throw new Error(`the kit confirmation was not recorded: ${r.kind}`);
  }

  /** Password sign-in from the first screen. */
  async signIn(email: string, password: string, totp?: string, heldCopy?: (userId: string) => Promise<CopyAtUnlock>): Promise<SignInResult> {
    await this.settle();
    return signIn({ wire: this.wire, pins: this.pins, origin: this.origin, email, password, deviceName: this.deviceName, totp, session: null, knownIdentityPub: null, ...(heldCopy ? { heldCopy } : {}) });
  }

  /** [signIn]'s outcome as one word for an assertion; a refusal carries the server's code, so a failed journey says why. */
  async signInKind(email: string, password: string, totp?: string): Promise<string> {
    const r = await this.signIn(email, password, totp);
    return r.kind === "refused" ? `refused:${r.error.code}` : r.kind === "failed" ? `failed:${String(r.error)}` : r.kind;
  }

  /** The session the Settings flows act for (vault/settingsflow.ts), with the wrap the session keeps (one per session). */
  settings(opened: OpenedAccount, email: string, wrap: SessionWrap): SettingsSession {
    return { wire: this.wire, pins: this.pins, origin: this.origin, account: emailNorm(email)!, opened, wrap };
  }

  /** This browser's account-state store for [opened] (merged on every read, compare-and-set on every write). */
  accountState(opened: OpenedAccount): AccountStateStore {
    return new AccountStateStore(opened.userId, opened.uvk, this.wire, this.storage);
  }

  /**
   * The vault of a session whose unlock checks passed, as the app opens it (ui/opensession.ts): the account's keys
   * and the sync store on this browser's wire client, with no durable cache. Takes ownership of [opened]'s keys.
   */
  async openVault(opened: OpenedAccount, wrap: SessionKeys, how: SessionHow | null = null): Promise<{ account: Account; store: VaultStore; shared: SharedLogSession }> {
    const parts = { userId: opened.userId, uvk: opened.uvk, identity: opened.identity, signing: opened.signing };
    const account = Account.fromOpened(opened, wrap);
    const shared = new SharedLogSession(parts, this.wire, this.storage, account.logKeyRing(), this.now);
    if (how) shared.setSessionHow(how);
    const store = new VaultStore(this.client, account, new NullCache(), memoryClientState(), this.wire);
    store.attachSharedLogs(shared);
    // The held changes are sent again as the app's unlock sends them (ui/opensession.ts), then the first sync.
    await store.resendHeldChanges();
    await store.sync();
    return { account, store, shared };
  }

  /**
   * Sign out: revoke the session, then drop the pair. The route is called through the transport rather than through
   * the app's own `logout()`, whose 5 second deadline is for a person waiting at a screen, not for a loaded test host.
   */
  async signOut(): Promise<void> {
    await this.client.sendRequest("POST", "/api/v1/auth/logout");
    this.client.setTokens(null);
  }
}
