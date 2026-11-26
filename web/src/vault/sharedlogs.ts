import type { KeyValue } from "../api/devicesecret";
import { adVaultMeta } from "../crypto/ad";
import { fromB64, fromUtf8, toB64, utf8 } from "../crypto/bytes";
import { open, seal } from "../crypto/envelope";
import type { KeyPairBytes } from "../crypto/provider";
import type { AccountStateWire } from "./accountdocstore";
import { AccountStateStore, stateMayHaveMoved } from "./accountdocstore";
import { latestAddSeq } from "./adoption";
import { ContactBook, ContactCurrency, type SessionHow } from "./contactbook";
import { vaultMetaName } from "./itemdoc-shape";
import { type Adoption, type GrantRowView, type LogHost, type LogStatus, type LogWire, VAULT_META_MOVE_OF, type VaultKeyRing, VaultLogStore } from "./logstore";

/**
 * The session's shared-vault layer (design §3, §6.9, §8.5): the account-state store, this browser's contact currency
 * and the signed vault logs, built together when a vault is entered. The sync store feeds it what each pull served
 * (grant rows, vault rows with their log heads, removals); it decides from the verified logs alone, never from the
 * served rows' role labels or removal reasons.
 */
export type SharedAsk = Extract<Adoption, { kind: "ask" }> & {
  /**
   * How many changes this person made to the vault before a removal wait on this browser (kept with the vault's sealed
   * copy): a yes sends them, so the question says so before it is answered (decided on 22 November 2026).
   */
  readonly waiting: number;
};

export interface SharedLogParts {
  readonly userId: string;
  readonly uvk: Uint8Array;
  readonly identity: KeyPairBytes;
  readonly signing: KeyPairBytes;
}

/** The name in a vault's sealed meta [metaBlob] under [vk], or null when it does not open or names none. */
export function vaultNameUnder(vaultId: string, vk: Uint8Array, metaBlob: string): string | null {
  try {
    return vaultMetaName(JSON.parse(fromUtf8(open(vk, fromB64(metaBlob), adVaultMeta(vaultId))))) ?? null;
  } catch {
    return null;
  }
}

/** One member of a shared vault as far as this browser verified its log (design §3.9 "Member lists"). */
export interface RosterRow {
  readonly userId: string;
  readonly role: "owner" | "writer" | "reader";
  /** The contact's label, only where the log's member key is the key of a contact current on this browser. */
  readonly label: string | null;
  readonly self: boolean;
}

export interface Roster {
  readonly rows: readonly RosterRow[];
  /** An item mentioned history the server has not shown yet (FC-10): the list may understate the audience. */
  readonly mayBeIncomplete: boolean;
  /** The log does not verify now (failed, withheld or frozen): the list is the last verified one. */
  readonly stale: boolean;
  /** The log is frozen here (the server's record of the vault contradicts itself): for good, never "right now". */
  readonly frozen: boolean;
}

export class SharedLogSession {
  readonly accountState: AccountStateStore;
  readonly currency: ContactCurrency;
  readonly contacts: ContactBook;
  readonly logs: VaultLogStore;
  private readonly rows = new Map<string, GrantRowView>();
  private readonly metas = new Map<string, string>();
  private readonly outcomes = new Map<string, Adoption>();
  /**
   * The `add` of each vault whose invitation was answered in this session in a way that opens the kept copy (decided on
   * 23 and 24 November 2026): a decline, from the moment it is given, whatever became of its record, of its leave and
   * of this browser's storage; or an accept whose write the server refused to record (a refused write, or one that kept
   * meeting newer writes). The invitation may stand to be answered again, but it no longer closes the kept copy
   * ({@link heldClosedByAsk}) for that add, whatever the pulls after it bring, so neither a server that does not take the
   * answer nor storage that refuses its writes can hold the copy closed until its day. Only an adoption ends it; a later
   * add is asked afresh. Kept in memory only: a reload or an unlock forgets it.
   */
  private readonly answerOpens = new Map<string, number>();
  private readonly me: string;

  constructor(parts: SharedLogParts, wire: LogWire & AccountStateWire, storage: KeyValue, keys: VaultKeyRing, clock: () => number = Date.now) {
    this.me = parts.userId;
    this.accountState = new AccountStateStore(parts.userId, parts.uvk, wire, storage);
    this.currency = new ContactCurrency(storage, parts.userId);
    this.contacts = new ContactBook(this.accountState, this.currency, clock);
    const host: LogHost = {
      grantRow: (vaultId) => this.rows.get(vaultId) ?? null,
      isCurrentContact: (userId, key) => this.contacts.currentFor(userId, key) !== null,
      currentContact: (userId) => {
        const c = this.contacts.current(userId);
        return c === null ? null : { key: c.record.identityPub, compared: c.record.compared };
      },
      labelFor: (userId, key) => this.contacts.currentFor(userId, key)?.labelText ?? null,
      vaultName: (vaultId, vk) => {
        const blob = this.metas.get(vaultId);
        return blob === undefined ? null : vaultNameUnder(vaultId, vk, blob);
      },
      sealMeta: (vaultId, vk, name, moveOf) => toB64(seal(vk, utf8(JSON.stringify(moveOf === undefined ? { name } : { name, [VAULT_META_MOVE_OF]: moveOf })), adVaultMeta(vaultId))),
      // The post-cut-over sync names no owner: a share from someone who is not a current contact names no one.
      serverOwnerName: () => null,
    };
    this.logs = new VaultLogStore(parts.userId, parts.signing, parts.identity, parts.uvk, wire, storage, this.accountState, host, keys, clock);
  }

  /**
   * The members of [vaultId] from the verified log alone, owner first, then by label (labelled ones first), then by
   * user id. Null when this browser holds no verified state for the vault. Never reads the server's member list.
   */
  roster(vaultId: string, me: string): Roster | null {
    const st = this.logs.status(vaultId);
    if (st.kind === "unknown" || st.state === null) return null;
    const s = st.state;
    const rows: RosterRow[] = Object.entries(s.members).map(([userId, m]) => ({
      userId,
      role: m.role,
      label: userId === me ? null : (this.contacts.currentFor(userId, m.key)?.labelText ?? null),
      self: userId === me,
    }));
    const rank = (r: RosterRow): number => (r.role === "owner" ? 0 : r.self ? 1 : r.label !== null ? 2 : 3);
    rows.sort((a, b) => rank(a) - rank(b) || (a.label ?? "").localeCompare(b.label ?? "") || (a.userId < b.userId ? -1 : a.userId > b.userId ? 1 : 0));
    return {
      rows,
      mayBeIncomplete: st.kind === "verified" && st.mayBeIncomplete,
      stale: st.kind === "failed" || st.kind === "withheld" || st.kind === "frozen",
      frozen: st.kind === "frozen",
    };
  }

  /** How this session came to be (§8.5): decides whether the one-tap contact list is due on this browser. */
  setSessionHow(how: SessionHow): void {
    this.currency.setSessionHow(how);
  }

  /**
   * Reads the account state from the server before a pull's shared vaults are decided on, so an answer or a vault
   * record another device of the account wrote is known. A failed read keeps this browser's copy (it is shown by
   * the store's own anomaly states, never swallowed into a decision: adoption still checks the record it holds).
   * [served]: the pull's `accountStateSeq` (spec 03 §4). When it equals the counter this browser last saw, no other
   * device wrote since and nothing is read ("unchanged"); without it, or when it moved either way, the state is read
   * ({@link stateMayHaveMoved}).
   */
  async refreshState(served?: number | null): Promise<string> {
    if (!stateMayHaveMoved(served, this.accountState.heldCounter())) return "unchanged";
    try {
      return (await this.accountState.read()).kind;
    } catch {
      return "unreachable";
    }
  }

  /** This account's own grant row for a shared vault, as the pull served it (ciphertext only). */
  noteGrantRow(vaultId: string, row: GrantRowView): void {
    this.rows.set(vaultId, row);
    this.logs.noteOwnGrantRow(vaultId, row);
  }

  /** The vault row's sealed meta, read only after §3.6 (a) to (c) passed, to name the vault in a prompt. */
  noteVaultMeta(vaultId: string, metaBlob: string): void {
    this.metas.set(vaultId, metaBlob);
  }

  /**
   * A shared vault row from a pull: its log brought up to the served head (a hint, never a verdict), before anything the
   * pull serves for the vault is applied. Never throws: a transport failure leaves the log's last verified state.
   */
  async refreshLog(vaultId: string, head: { readonly seq: number; readonly hash: string } | null): Promise<void> {
    try {
      await this.logs.refresh(vaultId, head?.seq ?? null, head?.hash ?? null);
    } catch {
      /* the log keeps its last verified state */
    }
  }

  /**
   * A shared vault row from a pull: the log is brought up to the served head (a hint, never a verdict), then §3.6
   * decides whether the key may be used. [refreshed]: this pull already brought the log up ({@link refreshLog}), so it
   * is not fetched again. Never throws: a transport failure leaves the log's last verified state.
   */
  async onSharedVault(vaultId: string, head: { readonly seq: number; readonly hash: string } | null, refreshed = false): Promise<Adoption | null> {
    if (!refreshed) await this.refreshLog(vaultId, head);
    if (this.logs.status(vaultId).kind !== "verified") {
      this.outcomes.delete(vaultId);
      // A withheld or frozen vault: §3.6 decides on its key with the log's status, read-only (nothing is signed on its log).
      return this.readOnlyKept(vaultId, true);
    }
    let a: Adoption;
    try {
      a = await this.logs.adoption(vaultId);
    } catch {
      return null;
    }
    this.note(vaultId, a);
    return a;
  }

  /** [a] is the outcome for [vaultId] now; an adoption ends what this session remembers of an answer that opened its kept copy. */
  private note(vaultId: string, a: Adoption): void {
    this.outcomes.set(vaultId, a);
    if (a.kind === "adopted") this.answerOpens.delete(vaultId);
  }

  /**
   * A shared vault row this browser's copy holds, at hydrate: §3.6 decides on the key from the log's LAST VERIFIED
   * state, with nothing fetched (a reload's first pull is a delta that re-sends no unchanged vault row, and an offline
   * or read-only copy sends nothing). A withheld or frozen log adopts only read-only, through this account's own wrap,
   * with nothing written ({@link VaultLogStore.readOnlyAdoption}); any other log that is not verified adopts nothing.
   * Never throws.
   */
  async onCachedVault(vaultId: string): Promise<Adoption | null> {
    if (this.logs.status(vaultId).kind !== "verified") return this.readOnlyKept(vaultId, false);
    let a: Adoption;
    try {
      a = await this.logs.adoption(vaultId);
    } catch {
      return null;
    }
    this.note(vaultId, a);
    return a;
  }

  /**
   * The key of a vault this browser holds but has not opened, taken through this account's own wrap only to seal the
   * held copy of the vault's removal ({@link VaultLogStore.keyToSealHeldCopy}). It is handed back, never put in the key
   * ring. Null where none opens. Never throws.
   */
  async keyForHolding(vaultId: string): Promise<Uint8Array | null> {
    try {
      return await this.logs.keyToSealHeldCopy(vaultId);
    } catch (e) {
      console.warn(`the key of the vault ${vaultId} was not taken for its held copy`, e);
      return null;
    }
  }

  /** A withheld or frozen vault's key, taken read-only where §3.6 gives it ({@link VaultLogStore.readOnlyAdoption}). Never throws. */
  private async readOnlyKept(vaultId: string, online: boolean): Promise<Adoption | null> {
    try {
      return await this.logs.readOnlyAdoption(vaultId, online);
    } catch (e) {
      console.warn(`the key of the vault ${vaultId}, whose log is not verified here, was not taken (tried again at the next sync)`, e);
      return null;
    }
  }

  /**
   * A vault the pull listed as removed: the log is fetched afresh and the status decided from it alone (a served
   * removal reason is a hint). A removal the log does not show keeps the vault.
   */
  async onRemoved(vaultId: string): Promise<LogStatus> {
    try {
      await this.logs.refresh(vaultId, null, null, true);
    } catch {
      /* decided from the last verified state */
    }
    this.outcomes.delete(vaultId);
    this.rows.delete(vaultId);
    return this.logs.status(vaultId);
  }

  /**
   * Before an account deletion (design §3.11): each membership's log brought up to the head the preview served, so
   * its leave is placed from this browser's own verified head where the log verifies. Never throws.
   */
  async refreshForDeletion(memberships: readonly { readonly vaultId: string; readonly head: { readonly seq: number; readonly hash: string } }[]): Promise<void> {
    for (const m of memberships) {
      try {
        await this.logs.refresh(m.vaultId, m.head.seq, m.head.hash);
      } catch {
        /* that vault's leave is placed from the served head, held to the one-day bound */
      }
    }
  }

  /** Once per unlock, after its first sync: a decline whose leave never got through is carried out again (the log store's). */
  async leaveAgainForDeclines(): Promise<void> {
    await this.logs.leaveAgainForDeclines().catch(() => []);
  }

  /** How many changes made before a removal wait here for a vault: the store's count, attached by the store. */
  private waitingFor: (vaultId: string) => number = () => 0;

  /** The store tells this session how many changes wait for a vault ({@link SharedAsk.waiting}). */
  attachWaitingCount(fn: (vaultId: string) => number): void {
    this.waitingFor = fn;
  }

  /** The shares waiting for the person's answer (the acceptance prompt), oldest vault id first. */
  pendingAsks(): SharedAsk[] {
    const out: SharedAsk[] = [];
    for (const a of this.outcomes.values()) if (a.kind === "ask") out.push({ ...a, waiting: this.waitingFor(a.vaultId) });
    return out.sort((x, y) => (x.vaultId < y.vaultId ? -1 : x.vaultId > y.vaultId ? 1 : 0));
  }

  /**
   * Vaults whose key is not in use yet and whose outcome can change without a new vault row: "connect first" (a
   * contact may become current here, by the one-tap list or a confirmation), an unrecorded answer, or an open ask.
   * The store re-decides them on every pull.
   */
  undecided(): string[] {
    const out: string[] = [];
    for (const [id, a] of this.outcomes) if (a.kind === "connect_first" || a.kind === "not_recorded" || a.kind === "ask") out.push(id);
    return out;
  }

  /**
   * Whether this browser shows an invitation to [vaultId] that its person can answer now (decided on 23 and 24 November
   * 2026): the last outcome this session handed out for the vault asks; it asks about this account's latest `add` in the
   * vault's verified log, so an invitation shown for an earlier add closes nothing for a later one; this account is a
   * member there; no answer to that add in this session opened the copy (a decline, or an accept the server refused:
   * {@link answerOpens}); and the
   * account's record of answers, as this browser holds it, records no answer to that add (an answer given in another tab
   * or on another device ends it). While it holds, the copy this browser kept of the vault since a
   * removal is closed: nothing is copied out of it. It only reads: nothing of it is written or sent, and what it reads of
   * this session is kept in memory, so a reload or an unlock starts from what the offline copy decides again.
   */
  heldClosedByAsk(vaultId: string): boolean {
    const a = this.outcomes.get(vaultId);
    if (a === undefined || a.kind !== "ask") return false;
    const s = this.logs.verifiedState(vaultId);
    if (s === null) return false;
    if (a.addSeq !== latestAddSeq(s, this.me)) return false;
    if (!Object.prototype.hasOwnProperty.call(s.members, this.me)) return false;
    if (this.answerOpens.get(vaultId) === a.addSeq) return false;
    return this.accountState.local().accepted.get(vaultId)?.addSeq !== a.addSeq;
  }

  /** The last adoption outcome for [vaultId] this session saw (connect first, declined, refused...), or null. */
  outcome(vaultId: string): Adoption | null {
    return this.outcomes.get(vaultId) ?? null;
  }

  /**
   * The person answered an acceptance prompt. The answer binds to the `add` it was shown for (FS-R6). A decline is
   * remembered for that add ({@link answerOpens}) before anything of it is written or sent, so one that throws (storage
   * that refuses the write) opens the copy too, and the error is thrown on. An accept whose write the server refused (a
   * refusal, or a write that kept meeting newer ones) is remembered for that add; one whose outcome cannot be told (it
   * went out and no answer told, or it never left), and one that throws, are not, so the next pull asks again and the
   * copy closes again.
   */
  async answer(ask: SharedAsk, accept: boolean): Promise<Adoption> {
    if (!accept) this.answerOpens.set(ask.vaultId, ask.addSeq);
    const a = await this.logs.answerIncoming({ vaultId: ask.vaultId, addSeq: ask.addSeq, owner: ask.owner }, accept);
    if (a.kind === "not_recorded" && writeRefused(a)) this.answerOpens.set(ask.vaultId, ask.addSeq);
    this.note(ask.vaultId, a);
    return a;
  }
}

/**
 * Whether an answer that was not recorded was refused (a refusal's code, or "contended"), as against one whose outcome
 * this browser could not tell (it went out and no answer told, or it never left). Read from the outcome's own marker,
 * which the log store sets from the write's kind, never from its reason: a server's refusal code can be any word, the
 * words "unknown" and "unreachable" included, and a refusal stays a refusal.
 */
function writeRefused(a: Extract<Adoption, { kind: "not_recorded" }>): boolean {
  return a.outcomeNotKnown !== true;
}
