import type { ItemDoc, WireItem, WireVault } from "../api/types";
import type { LogDeleted } from "../api/wire";
import { adVaultMeta, adVk } from "../crypto/ad";
import { toB64, utf8 } from "../crypto/bytes";
import { seal } from "../crypto/envelope";
import { boxKeypairFromSeed, randomBytes, signKeypairFromSeed } from "../crypto/provider";
import { Account } from "./account";
import type { AppendOutcome, HeldChange, LogAction, LogStatus, ResendOutcome } from "./logstore";
import type { SharedLogSession } from "./sharedlogs";
import type { VaultStore } from "./store";

/**
 * A stand-in for the signed vault logs (design §3), for the store tests that are about the store and not about log
 * verification: shared vaults, their keys and roles, removals and the store's own log actions. A test says what the
 * verified log would say (`share`, `remove`, `fail`); the store reads it through the same surface it reads
 * {@link SharedLogSession} through, and the key goes into the account's log key ring as an adoption would put it.
 * Log verification itself is tested against the real log store (logstore.test.ts, the journeys).
 */
export type FakeRole = "owner" | "writer" | "reader";

interface FakeVault {
  vk: Uint8Array;
  role: FakeRole;
  /** live; or removed (by the owner, or a leave); or a log that did not verify. */
  state: "live" | "removed_by_owner" | "left" | "failed";
  deleteId: string | null;
  /** The server's grace end kept beside the standing `delete`, if its answers carried one. */
  grace?: LogDeleted | null;
  /** The deletion was purged, verified through the tombstone's final head (§3.8): when the server says it purged. */
  purgedAt?: number;
  seq: number;
  at: number;
}

export class FakeSharedLogs {
  private readonly vaults = new Map<string, FakeVault>();
  /** Every log action the store signed, in order. */
  readonly appended: { vaultId: string | null; action: LogAction }[] = [];
  /** The answer the next append gets (default: appended). */
  nextAppend: AppendOutcome["kind"] = "appended";
  /** What the next unlock's re-send of the held changes ends in, each with what the change was. */
  resent: { change: HeldChange; outcome: ResendOutcome }[] = [];
  settled: { id: string; change: HeldChange; outcome: ResendOutcome }[] = [];

  constructor(
    private readonly account: Account,
    private readonly clock: () => number = Date.now,
  ) {}

  /** The verified log lists this account in [vaultId] with [role]; the key is adopted at the vault's next vault row. */
  share(vaultId: string, vk: Uint8Array, role: FakeRole = "writer"): void {
    this.vaults.set(vaultId, { vk: vk.slice(), role, state: "live", deleteId: null, seq: 1, at: this.clock() });
  }

  /** The log lists this account in [vaultId], but the share is undecided here (an open ask, a sender not yet current):
   *  nothing is adopted until {@link decide}, and the store re-decides it on every pull. */
  pend(vaultId: string, vk: Uint8Array, role: FakeRole = "writer"): void {
    this.share(vaultId, vk, role);
    this.pending.add(vaultId);
    this.blocked.add(vaultId);
  }

  /** The undecided share is now adoptable (the person accepted, or the sender became current); the store's next
   *  re-decision adopts it. */
  decide(vaultId: string): void {
    this.blocked.delete(vaultId);
  }

  /** Undecided until adopted. */
  private readonly pending = new Set<string>();
  /** Not adoptable yet. */
  private readonly blocked = new Set<string>();

  /** The verified log no longer lists this account: removed by the owner, or left. */
  remove(vaultId: string, byOwner = true): void {
    const v = this.vaults.get(vaultId);
    if (v) this.bump(v, byOwner ? "removed_by_owner" : "left");
  }

  /** The verified log ends in the owner's `delete` (§3.11): the vault is in its grace, this account still listed.
   *  [grace]: the `deleted` the log answers carried (spec 03 §10.6); none from an older server. */
  deleteVault(vaultId: string, grace: LogDeleted | null = null): void {
    const v = this.vaults.get(vaultId);
    if (!v) return;
    v.deleteId = crypto.randomUUID();
    v.grace = grace;
    v.seq++;
    v.at = this.clock();
  }

  /** The deletion in force was purged, and the log verifies through the tombstone's final head (§3.8): deleted for good. */
  purge(vaultId: string, purgedAt: number): void {
    const v = this.vaults.get(vaultId);
    if (!v || v.deleteId === null) return;
    v.purgedAt = purgedAt;
  }

  /** The `deleted` the next log append answers carry (spec 03 §10.3), for this session's own `delete`. */
  nextAppendGrace: LogDeleted | null = null;

  /** The log does not verify (or is withheld): a removal it cannot explain. */
  fail(vaultId: string): void {
    const v = this.vaults.get(vaultId);
    if (v) this.bump(v, "failed");
  }

  /** Attach to [store], as enterVault does with the real layer. */
  attachTo(store: VaultStore): this {
    store.attachSharedLogs(this as unknown as SharedLogSession);
    return this;
  }

  private bump(v: FakeVault, state: FakeVault["state"]): void {
    v.state = state;
    v.seq++;
    v.at = this.clock();
  }

  private stateOf(vaultId: string, v: FakeVault) {
    const members = v.state === "live" ? { [this.account.userId]: { role: v.role } } : {};
    // The owner: this account when it holds the vault as its owner, someone else otherwise.
    const owner = v.role === "owner" ? this.account.userId : "00000000-0000-4000-8000-0000000000ee";
    return { vaultId, owner, head: { seq: v.seq, hash: `${"0".repeat(63)}${v.seq % 10}` }, at: v.at, members, pending: null, deleteId: v.deleteId, latestAdds: {} } as never;
  }

  private status(vaultId: string): LogStatus {
    const v = this.vaults.get(vaultId);
    if (!v) return { kind: "unknown", vaultId };
    const state = this.stateOf(vaultId, v);
    if (v.state === "failed") return { kind: "failed", vaultId, state, verdict: "bad_signature" };
    if (v.state !== "live") return { kind: "removed", vaultId, state, byOwner: v.state === "removed_by_owner" };
    if (v.purgedAt !== undefined) return { kind: "purged", vaultId, state, purgedAt: v.purgedAt };
    return { kind: "verified", vaultId, state, mayBeIncomplete: false };
  }

  /** The account's records of its vaults: none here (no vault of this fake freezes). */
  readonly accountState = { local: () => ({ vaults: new Map<string, unknown>(), accepted: new Map<string, unknown>() }) };

  readonly logs = {
    roleOf: (vaultId: string): FakeRole | null => {
      const v = this.vaults.get(vaultId);
      return v && v.state === "live" && v.deleteId === null ? v.role : null;
    },
    writeAllowed: (vaultId: string): boolean => {
      const r = this.logs.roleOf(vaultId);
      return r === "owner" || r === "writer";
    },
    status: (vaultId: string): LogStatus => this.status(vaultId),
    verifiedState: (vaultId: string) => {
      const s = this.status(vaultId);
      return s.kind === "verified" ? s.state : null;
    },
    serverGraceEnd: (vaultId: string): LogDeleted | null => {
      const v = this.vaults.get(vaultId);
      return v && v.deleteId !== null ? (v.grace ?? null) : null;
    },
    refresh: async (vaultId: string): Promise<LogStatus> => this.status(vaultId),
    noteItemHead: async (vaultId: string): Promise<LogStatus> => this.status(vaultId),
    openOwnWrap: async (): Promise<Uint8Array | null> => null,
    wrapForHolding: (): string | null => null,
    // No vault of this fake freezes, so no own leave of a frozen vault is ever marked.
    ownFrozenLeaveTaken: (): boolean => false,
    forgetOwnFrozenLeave: (): void => {},
    lastRemovalByOwner: (): boolean => true,
    goneTold: (): boolean => false,
    noteGoneTold: (): void => {},
    heldRemoved: (): boolean => false,
    noteHeldRemoved: (): void => {},
    forgetLossTold: (): void => {},
    refusedOffer: (): null => null,
    retryPending: async (): Promise<unknown[]> => this.resent.map((r) => r.outcome),
    resendPending: async () => {
      // As the log store: a change that did not happen is kept as settled until its notice is dismissed.
      for (const r of this.resent) if (r.outcome.kind !== "appended" && r.outcome.kind !== "pending") this.settled.push({ id: crypto.randomUUID(), change: r.change, outcome: r.outcome });
      return this.resent;
    },
    settledChanges: () => [...this.settled],
    dismissSettled: (_vaultId: string, id: string): void => {
      this.settled = this.settled.filter((s) => s.id !== id);
    },
    heldChange: (): null => null,
    withdrawHeld: (): boolean => false,
    withdrawHeldAs: (): null => null,
    watchedVaults: (): string[] => [],
    madeWatches: (): never[] => [],
    dismissWatched: (): void => {},
    heldDeletionsToAsk: (): string[] => [],
    deletionsToAsk: async (): Promise<string[]> => [],
    retryMoveStep: async (): Promise<null> => null,
    settleHeldFromLog: (): string[] => [],
    noteWatchTold: (): void => {},
    giveUpHeldDeletion: async (): Promise<null> => null,
    holdsMoveDelete: (): boolean => false,
    /** The store's write gate (Account.mayWrite); this layer numbers no `add`, so every key it hands over works. */
    attachWriteGate: (_mayWrite: (vaultId: string) => boolean): void => {},
    takeHeldByGate: (): boolean => false,
    heldMoveDeletes: (): string[] => [],
    frozenMoves: (): string[] => [],
    heldHalfMadeDeletes: (): never[] => [],
    dropHeldHalfMadeDelete: (): boolean => false,
    moveRecord: (): null => null,
    saveMoveRecord: (): void => {},
    forgetHeldMoveDelete: (): void => {},
    append: async (vaultId: string | null, action: LogAction): Promise<AppendOutcome> => {
      this.appended.push({ vaultId, action });
      const id = vaultId ?? "";
      if (this.nextAppend !== "appended") {
        const kind = this.nextAppend;
        this.nextAppend = "appended";
        return kind === "not_allowed" ? { kind, reason: "test" } : kind === "refused" ? { kind, vaultId: id, code: "test" } : ({ kind, vaultId: id } as AppendOutcome);
      }
      const v = this.vaults.get(id);
      if (v) {
        if (action.kind === "leave") this.bump(v, "left");
        else if (action.kind === "delete") {
          v.deleteId = crypto.randomUUID();
          v.grace = this.nextAppendGrace;
          this.nextAppendGrace = null;
        } else if (action.kind === "restore") {
          v.deleteId = null;
          v.grace = null;
        }
        else v.seq++;
      }
      return { kind: "appended", vaultId: id, state: v ? this.stateOf(id, v) : ({ at: this.clock() } as never) };
    },
  };

  // ---- the SharedLogSession surface the store calls during a pull ----

  async refreshState(): Promise<string> {
    return "unchanged";
  }

  noteGrantRow(): void {}

  noteVaultMeta(): void {}

  /** A vault row's log brought up to its served head: this fake's logs are always up to date. */
  async refreshLog(): Promise<void> {}

  /** A vault row arrived: a live, verified share is adopted into the account's key ring (design §3.6). */
  async onSharedVault(vaultId: string): Promise<null> {
    const v = this.vaults.get(vaultId);
    if (v && v.state === "live" && !this.blocked.has(vaultId) && !this.account.logKeyRing().has(vaultId)) {
      this.account.logKeyRing().set(vaultId, v.vk.slice());
      this.pending.delete(vaultId);
    }
    return null;
  }

  /** A cached vault row at hydrate: a live, verified share is adopted again (the real layer reads its last verified
   *  state, with nothing fetched); anything else adopts nothing. */
  async onCachedVault(vaultId: string): Promise<null> {
    return this.onSharedVault(vaultId);
  }

  /** A vault's key for its held copy, through this account's own wrap: this fake keeps no wraps. */
  async keyForHolding(): Promise<Uint8Array | null> {
    return null;
  }

  async onRemoved(vaultId: string): Promise<LogStatus> {
    return this.status(vaultId);
  }

  undecided(): string[] {
    return [...this.pending];
  }

  /** Whether an invitation closes a kept copy: this fake hands out no invitation, so it closes nothing. */
  heldClosedByAsk(): boolean {
    return false;
  }

  /** The store's count of changes waiting for a vault (shown with an ask): this fake asks nothing, so it keeps none. */
  attachWaitingCount(_count: (vaultId: string) => number): void {}

  roster(): null {
    return null;
  }
}

/** A throwaway account (no KDF): the session's own account in a store test, or the other member who wrote an item. */
export function testAccount(userId: string = crypto.randomUUID(), personalVaultId: string | null = null): Account {
  const seed = randomBytes(32);
  return Account.fromOpened(
    { userId, uvk: randomBytes(32), identity: boxKeypairFromSeed(seed), signing: signKeypairFromSeed(seed), genesis: null as never, personalVaultId, personalVk: personalVaultId ? randomBytes(32) : null },
    null,
  );
}

/**
 * A vault [account] made, as a test fixture (the product makes shared vaults only through the signed log, design §3):
 * a fresh id and key, the meta document under the key, and the account's own UVK wrap of the key, as a create row
 * would carry them. The key is installed through the log key ring, as the log layer installs it.
 */
export function vaultMadeBy(account: Account, name: string): { vaultId: string; vk: Uint8Array; request: { vaultId: string; metaBlob: string; wrappedVk: string } } {
  const vaultId = crypto.randomUUID();
  const vk = randomBytes(32);
  const uvk = (account as unknown as { uvk: Uint8Array }).uvk;
  const request = {
    vaultId,
    metaBlob: toB64(seal(vk, utf8(JSON.stringify({ name })), adVaultMeta(vaultId))),
    wrappedVk: toB64(seal(uvk, vk, adVk(vaultId, account.userId))),
  };
  account.logKeyRing().set(vaultId, vk.slice());
  return { vaultId, vk, request };
}

/** A shared vault as the server serves it, with its key: the row, and items another member sealed under the key. */
export function sharedVaultFixture(name = "Family") {
  const vaultId = crypto.randomUUID();
  const vk = randomBytes(32);
  const writer = testAccount();
  writer.logKeyRing().set(vaultId, vk.slice());
  writer.attachLogRoles(() => "owner", () => true);
  const vault: WireVault = { vaultId, type: "shared", rev: 2, metaBlob: toB64(seal(vk, utf8(JSON.stringify({ name })), adVaultMeta(vaultId))), createdAt: 0 };
  const item = (doc: ItemDoc, rev: number, itemId: string = crypto.randomUUID()): WireItem => ({
    itemId, vaultId, rev, createdAt: 0, updatedAt: 0, deleted: false, conflict: false, formatVersion: 1, attachmentIds: [],
    blob: writer.sealItem({ kind: "chosen", vaultId }, itemId, doc).blob, // the other member chose this vault
  });
  return { vaultId, vk, vault, item };
}
