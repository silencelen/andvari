import type { LogWire } from "../vault/logstore";
import type { ItemWire } from "../vault/store";
import type { ApiClient } from "./client";
import type { WireApi } from "./wireclient";

/**
 * Which function of the item wire, the log wire and the api client changes something of a vault on the server, written
 * down once (decided on 22 November 2026). Each table is typed over every function of its interface or class, so a
 * function added to one of them does not pass the type check until it has a row here. A row that changes a vault names
 * what it changes; one that does not says why.
 *
 * The names of the functions that change a vault are each unique in the web app's modules, so that every place naming
 * one can be found by searching for it (the item wire's `push` is called `pushMutations` for that reason). The test
 * beside this file counts every such place, and every place where a request of any other kind can start, in every module
 * of the web app that is not a test, and holds each to a closed list: each place there either asks `mayWrite` for the
 * vault it changes, or is exempt with its reason.
 */

/** A row of the tables: changes a vault (and what), or does not (and why). */
export type SendRow = { readonly changesAVault: true; readonly what: string } | { readonly changesAVault: false; readonly why: string };

/** The names of the functions of [T] (methods, and fields that hold a function). */
type FunctionsOf<T> = { [K in keyof T]-?: NonNullable<T[K]> extends (...args: never[]) => unknown ? K : never }[keyof T];

/** One row for every function of [T], and no other. */
type RowsOf<T> = { readonly [K in FunctionsOf<T>]: SendRow };

const changes = (what: string): SendRow => ({ changesAVault: true, what });
const not = (why: string): SendRow => ({ changesAVault: false, why });

const READ = "a read";
const ACCOUNT = "the account's own records, keys or settings, not a vault's content";
const TRANSPORT = "the transport's own state, a hook the session sets, or a request function (counted on its own)";

/** The item routes (vault/store.ts ItemWire). */
export const ITEM_WIRE_ROWS: RowsOf<ItemWire> = {
  sync: not(READ),
  pushMutations: changes("a vault's items: puts and deletes"),
  itemVersions: not(READ),
  deletedItems: not(READ),
  restoreItem: changes("a vault's items: an item brought back from the trash"),
  purgeItem: changes("a vault's items: an item removed from the trash for good"),
  uploadAttachment: changes("a vault's files: an attachment's bytes"),
  downloadAttachment: not(READ),
};

/** The log routes (vault/logstore.ts LogWire). */
export const LOG_WIRE_ROWS: RowsOf<LogWire> = {
  logPage: not(READ),
  appendLog: changes("a vault's log: every entry (members, roles, a deletion, a move's steps, a leave)"),
  putSelfWrap: changes("this account's own wrap of a vault's key, on its grant row of the vault"),
};

/** The wire client (api/wireclient.ts), whose item and log routes the session hands to the store as its wires. */
export const WIRE_API_ROWS: RowsOf<WireApi> = {
  newDevice: not("makes a value; sends nothing"),
  clientPolicy: not(READ),
  instance: not(READ),
  signupStart: not(ACCOUNT),
  signupVerify: not(ACCOUNT),
  register: not("the account's creation: its personal vault does not exist before it, and no other vault is named"),
  prelogin: not(READ),
  login: not(ACCOUNT),
  accountKeys: not(READ),
  accountState: not(READ),
  putAccountState: not(ACCOUNT),
  changePassword: not(ACCOUNT),
  putRecovery: not(ACCOUNT),
  putEscrowSelf: not(ACCOUNT),
  recoveryPubkey: not(READ),
  devices: not(READ),
  revokeDevice: not(ACCOUNT),
  setRequireLink: not(ACCOUNT),
  totpSetup: not(ACCOUNT),
  totpDisable: not(ACCOUNT),
  recoveryRequests: not(READ),
  vetoRecoveryRequest: not(ACCOUNT),
  deletePreview: not(READ),
  deleteAccountWithLeaves: changes("a leave of each shared vault's log: the account's end carries one signed leave entry per shared vault it is in"),
  recoverySelfVerify: not(READ),
  recoverySelfCommit: not(ACCOUNT),
  recoverySelfSetup: not(ACCOUNT),
  recoverySelfConfirm: not(ACCOUNT),
  sync: not(READ),
  pushMutations: changes("a vault's items: puts and deletes"),
  itemVersions: not(READ),
  deletedItems: not(READ),
  restoreItem: changes("a vault's items: an item brought back from the trash"),
  purgeItem: changes("a vault's items: an item removed from the trash for good"),
  uploadAttachment: changes("a vault's files: an attachment's bytes"),
  downloadAttachment: not(READ),
  usage: not(READ),
  putUsage: not("the usage ledger: sealed under the account's own key, not a vault's content"),
  appendLog: changes("a vault's log"),
  logPage: not(READ),
  fullLog: not(READ),
  members: not(READ),
  deletedVaults: not(READ),
  putVaultMeta: changes("a vault's meta (its name)"),
  putSelfWrap: changes("this account's own wrap of a vault's key"),
};

/** The transport (api/client.ts). */
export const API_CLIENT_ROWS: RowsOf<ApiClient> = {
  trafficGate: not(TRANSPORT),
  assertTrafficAllowed: not(TRANSPORT),
  cutLiveTraffic: not(TRANSPORT),
  fetchStatic: not(TRANSPORT),
  setTokens: not(TRANSPORT),
  useSessionTokens: not(TRANSPORT),
  getTokens: not(TRANSPORT),
  onUpgradeRequired: not(TRANSPORT),
  onRefreshRefused: not(TRANSPORT),
  keepUnconfirmed: not(TRANSPORT),
  isKeptUnconfirmed: not(TRANSPORT),
  sharedRecord: not(TRANSPORT),
  onEndedElsewhere: not(TRANSPORT),
  onRefusedIds: not(TRANSPORT),
  holdsSessionOf: not(TRANSPORT),
  endSession: not("ends this browser's session at the server"),
  sendRequest: not(TRANSPORT),
  requestBytes: not(TRANSPORT),
  prelogin: not(READ),
  register: not("the account's creation (the old route; the web app signs up through the wire client)"),
  login: not(ACCOUNT),
  logout: not("ends this browser's session at the server"),
  accountKeys: not(READ),
  clientPolicy: not(READ),
  createVault: changes("a new vault (an old route with no caller)"),
  accountState: not(READ),
  putAccountState: not(ACCOUNT),
  vaultMembers: not(READ),
  postVaultMember: changes("a vault's members (an old route with no caller)"),
  setVaultMemberRole: changes("a vault's members (an old route with no caller)"),
  deleteVaultMember: changes("a vault's members (an old route with no caller)"),
  deleteVault: changes("a vault's life (an old route with no caller)"),
  restoreVault: changes("a vault's life (an old route with no caller)"),
  deletedVaults: not(READ),
  leaveVault: changes("a vault's members (an old route with no caller)"),
  postTransferOffer: changes("a vault's owner (an old route with no caller)"),
  deleteTransferOffer: changes("a vault's owner (an old route with no caller)"),
  postTransferAccept: changes("a vault's owner (an old route with no caller)"),
  updateVaultMeta: changes("a vault's meta (its name)"),
  recoveryPubkey: not(READ),
  recoverySelfVerify: not(READ),
  recoverySelfCommit: not(ACCOUNT),
  recoverySelfSetup: not(ACCOUNT),
  recoverySelfConfirm: not(ACCOUNT),
  totpStatus: not(READ),
  totpConfirm: not(ACCOUNT),
  changePassword: not(ACCOUNT),
  accountDeletePreview: not(READ),
  deleteAccount: not(
    "the account's end on the older route: it carries no entry of any vault's log and names no vault; the server refuses its body, which lacks the `leaves` the route requires (400 bad_request), so nothing is deleted",
  ),
  adminUsers: not(READ),
  adminInvite: not("an operator's route that names no vault"),
  adminDisableUser: not("an operator's route that names no vault"),
  adminDevices: not(READ),
  adminUserEscrow: not(READ),
  adminEscrowDrill: not("an operator's route that names no vault"),
  adminRevokeDevice: not("an operator's route that names no vault"),
  adminAudit: not(READ),
  adminPolicy: not(READ),
  adminSetPolicy: not("an operator's route that names no vault"),
  adminStatus: not(READ),
  hibpRange: not(READ),
  events: not("the change bell: a read over a WebSocket, which sends only its ticket"),
};

/** Every function name that changes a vault, from the four tables. */
export function namesThatChangeAVault(): string[] {
  const out = new Set<string>();
  for (const rows of [ITEM_WIRE_ROWS, LOG_WIRE_ROWS, WIRE_API_ROWS, API_CLIENT_ROWS] as readonly Record<string, SendRow>[]) {
    for (const [name, row] of Object.entries(rows)) if (row.changesAVault) out.add(name);
  }
  return [...out].sort();
}
