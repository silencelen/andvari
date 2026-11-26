import { decodeItemHomes, decodePersonalWrap, encodeItemHomes } from "./trustrecords";
import { otherSiteConfirmation, otherSiteQuestion } from "./othersite";
import { buildVaultKeys, vaultNameFromMeta, waitingGrantCount } from "./grantkeys";
import { applyServedState, decodeStateMemory, openAccountState, type StateMemory } from "./accountstate";
import { firstPin, MAX_FIRST_PIN_CARDS, verifyChain, verifyForward, type Card } from "./instancecard";
import { confirmKindChange, confirmMove, decodeStoredPin, newStoredPin, PIN_KEY, refreshPinForward, type StoredPin } from "./pinstore";
import { bakedRoot, PUBLIC_INSTANCE } from "./publicinstance";
import { fetchInstanceChain, operatorShortFp } from "./cardfetch";
import { nameText } from "./statement";
import { ownKeysFromSeed, verifyGenesis } from "./genesis";
import { addressNorm, addressRecordName, judgeServed, keyRecordName, readRecord, recordsFor } from "./accountmemory";
import { personalVaultKey, type WrapRecords } from "./wraps";
import { decodeDeviceRecord, deviceKey, deviceObject, emailNorm, LAST_EMAIL_KEY, newDeviceRecord, rememberableEmail, type DeviceRecord } from "./device";
import { wipeOldFormatOnce } from "./formatwipe";
import { admitRows, sealGate, serverItemDecision } from "./itemhome";
import { AndvariApi, ApiError, clampAutoLockSeconds, clampClipboardClearSeconds, type AccountKeys, type MutationResult, type SessionResponse, type SyncResponse } from "./api";
import type { BioReq, BioResult } from "./bioprotocol";
import { brand, cardSubtitle, composeShortExpiry, digitsOnly, luhnValid, padMonth, yearTo4 } from "./card";
import {
  adIdkey,
  adItem,
  adUsage,
  adUvk,
  authKey,
  assertServerKdfParams,
  KdfPolicyError,
  boxKeypairFromSeed,
  deriveMasterKey,
  envelopeStructuralRefusal,
  fromB64,
  open,
  seal,
  toB64,
  usageKey,
  wrapKey,
  type KdfParams,
} from "./crypto";
import { startEvents, type EventsHandle, type WsLike } from "./events";
import { CARD_FORMAT_VERSION, LOGIN_FORMAT_VERSION, MAX_ITEM_FORMAT_VERSION } from "./format";
import { isNewerVersion } from "./version";
import { evaluateSignedManifest, MIN_SEQ, readCappedBody, UPDATE_MANIFEST_MAX_BYTES, UPDATE_SIG_MAX_BYTES, updatesEnabled } from "./updateverify";
import { loginGrantRedeemable, type LoginGrant } from "./fillgrant";
import { gateServedEnvelope } from "./servedblob";
import { DEFAULT_GENERATOR, generatePassword } from "./generator";
import type { CardFieldKind } from "./detect";
import { isCardProviderOrigin } from "./cardproviders";
import { CARD_FILL_OFF } from "./cardfillflag";

/** In-page card fill in this build (build.mjs defines it for every target; cardfillflag.ts). Read here as the define
 *  itself, never through a constant, so that esbuild drops the card path's handlers from a build without it. */
declare const __ANDVARI_CARDFILL__: boolean;
/** The test server's origin in a person's test build (build.mjs TESTBUILD=1), null in every other build (folded away by
 *  esbuild there); undefined where the source runs unbundled. Read as the define itself, like the one above. */
declare const __ANDVARI_TEST_SERVER__: string | null | undefined;
import { cardFillPlan, choicesSpanForms, chosenCardFrames, frameOriginOf, framesWithChoices, kindsOfferedTwice, mayReceiveCard, mayRedeem, pageCardFormsOnly, providerCardFrames, sameFrames, supersededChoices, type CardFrameRecord, type CardGrant } from "./cardrelease";
import type {
  CardFillFields,
  CardFillOutcome,
  CardItem,
  FillOutcome,
  MatchItem,
  PendingCardSave,
  PendingSave,
  QuickUnlockNotice,
  Req,
  Res,
  SaveErrorCode,
  ServerDiag,
  TotpAddCode,
  TabMsg,
  UnlockCode,
} from "./messages";
import { currentCode, isValidTotp, normalizeTotp } from "./totp";
import { isPlainHttp, matchLogins, matchLoginsAt, matchLoginsOnPage, normalizeHost, offeredUris, parseSavedUri } from "./urimatch";
import { itemDocProblem } from "./itemdocshape";
import { revealGate } from "./revealgate";
import { pslResolve } from "./psl"; // A8: the SW is the ONLY bundle that carries the PSL blob
import { resolveSaveAction, saveTargetFor, stepUsernameFor, type StepUsername } from "./savetarget";
import { capturedSiteUri } from "./siteurl";
import { captureBinding, derivedPageOrigin, requestPage, webOriginOfUrl, type OriginSource } from "./senderorigin";
import { senderGate, senderMaySend } from "./sendergate";
import { buildKnownLoginDigests, knownLoginDigest, LOCKED_PENDING_TTL_MS, reofferDecision, siteKeyOfHost, type KnownLoginsRecord } from "./knownlogins";
import { QuickUnlock, PIN_KDF_MIN_MEM_BYTES, PIN_KDF_MIN_OPS, type BeginRedeemOk, type QuBiometric, type QuCoKey, type QuDeps, type QuRecord, type QuStore } from "./quickunlock";
import { canonicalizeServerUrl, NO_SERVER_ORIGIN, nsKey, originKeyFor, originMatchPattern, setServerUrl, SERVER_URL_KEY } from "./serverurl";
import { idbKv, openBoundedIdb, trustedStore, type KvArea } from "./trustedkv";
import { plainSessionArea, SEAL_DB_NAME, SessionSeal } from "./sessionseal";
import { autofillExcludeMatches, dialRefusal, loadServerState, type ServerBlock } from "./serverstate";
import { offerDownloadUrl, readUpdateOffer } from "./updateoffer";
import { quickUnlockCompartment, restrictStorageAccess, type StorageAccessAreas, type StorageAccessVerdict } from "./storageaccess";
import { armGate, withRedeemInFlight } from "./locksequence";
import { conflictCopyId, conflictCopyName } from "./conflictcopy";
import { FLUSH_DEBOUNCE_MS, TEARDOWN_FLUSH_TIMEOUT_MS, mergeUsage, parseUsage, planFlush, recordUse, serializeUsage, type ServerLedger, type UsageMap } from "./usage";
import { applyServerSwitch, isTrustRecord, moveNamespaceRecords, purgeOriginRecords, purgeServerDataFor } from "./serverswitch";
import { BUILD_TARGET, selfUpdateChannelAllowed } from "./buildtarget";
import { appServerToAdopt, appServerToForget, askAppServerDetailed, nativeSender, parseAppServerReply, type AppServerAnswer } from "./appserver";
import { queueSaveToApp, savesThroughApp } from "./appsave";
import { AppVault, vaultFromApp, type AppVaultCardFields, type CardFieldName } from "./appvault";

/**
 * MV3 background service worker — sole custodian of unlocked vault material. Chrome kills an idle
 * SW (~30 s), so the session ALSO lives in chrome.storage.session: memory-backed browser storage —
 * never disk, cleared on browser exit — lazily restored on wake. Since A16 every secret-bearing record there is SEALED
 * (`seal`, sessionseal.ts: AES-GCM under a non-extractable key in the extension origin's own IndexedDB), because that
 * content scripts cannot reach storage.session is not relied on; a record that does not open reads as absent (locked).
 * ZK holds: the master password and mk exist only transiently inside unlock(); what persists is
 * session-scoped custody (tokens, unwrapped vault keys b64, decrypted docs) — the same posture as
 * SW RAM. chrome.storage.local NEVER holds secrets, and since A15 no trust state either: content scripts can read and
 * write that area (Chrome before 140, Firefox always), so durable trust state lives in the extension origin's
 * IndexedDB (`trusted`, trustedkv.ts), which this worker alone reads and writes. (storage.session: Chrome
 * 102+/Firefox 115+, where `chrome` aliases `browser`.)
 *
 * Message protocol = src/messages.ts (THE CONTRACT). Secret egress is `reveal` only, gated on
 * host-match ∨ a one-shot popup fill grant ∨ the popup's own explicit reveal (never a page's —
 * revealgate.ts) — see the contract's trust model. Lock policy: chrome.alarms "autolock" re-armed by every message answered with a live
 * session (client-policy autoLockSeconds; 0 disables), "resync" refreshes items every 5 min —
 * the alarm floor under the live dirty-bell WebSocket (events.ts), which nudges the same resync
 * within ~1–2 s of a peer write while a session exists.
 *
 * Unlock flow (mirrors web Account.unlock): prelogin → Argon2id → login (authKey) → unwrap UVK
 * from accountKeys → sync → unwrap each vault key from its grant → decrypt items under the VK.
 */
// ---- server endpoint + per-origin namespace (design 2026-07-15 §5.1/§4.2; 2026-11-15 §4.4, §12.2) ----
// No build has a default server: the origin is a per-device choice in the trusted store (serverurl.ts), made only with
// a verified card pin (the baked public instance, or a typed address behind the Trust Gate). `serverReady` below loads
// it before any network/namespace use; chooseServer/confirmServer (and Safari's app adoption) are the only switches.
let serverUrl = NO_SERVER_ORIGIN;
let currentOriginKey = originKeyFor(NO_SERVER_ORIGIN);
/** The current origin's card pin (pinstore.ts), as last read or written. Null while no server, or Safari. */
let currentPin: StoredPin | null = null;
/** A storage key under the CURRENT origin's namespace (§4.2/B2-7): quick-unlock/PIN co-key
 *  material and cached per-origin state live under `ns.<originKey>.<key>`, so a server switch can
 *  never read, mint, or wipe another origin's material. Computed at CALL time — the switch path
 *  locks under the OLD key, then flips `currentOriginKey`. */
const nsk = (key: string): string => nsKey(currentOriginKey, key);

/** A15: the trusted store (the extension origin's IndexedDB — trustedkv.ts). Every durable trust record and every
 *  convenience below lives here; a call that fails (no IndexedDB: Firefox private browsing) reads as "no record". */
const trusted = trustedStore();
/** A15: chrome.storage.local, by name, for exactly two jobs: the one-time migration's input and the purge's sweep of
 *  pre-A15 leftovers. Nothing else reads it (storagefence.test.ts). */
const legacyLocal = chrome.storage.local as unknown as KvArea;
/** A16: chrome.storage.session, by name, for exactly two wrappers (storagefence.test.ts): the seal, through which every
 *  secret-bearing record is written and read, and the plain area, which takes only the plain inventory (the idle-lock
 *  notice, the update throttle stamp, the quiet marker) and refuses any other key. */
const sessionRaw = chrome.storage.session as unknown as KvArea;
/** A16: the session seal (sessionseal.ts). Its key is a non-extractable AES-GCM key in the extension origin's IndexedDB
 *  (a database of its own, every operation bounded like the trusted store's). It is replaced when the browser reports a
 *  new browser session (browserSessionReported, below); at any other worker start it is kept only if a record in
 *  storage.session opens under it — for the two global slots that needs the origin, hence `originKey`. Set up now,
 *  beside serverReady: `sessionSeal.ready` settles once worker start found or made the key, or found no key store. */
/** The first-launch wipe (§12.4) clears the seal's key database too, so the seal touches
 *  that database only once the wipe settled (afterFormatWipe): it can never make a key the wipe then deletes. */
let formatWipeSettled: () => void = () => {};
const formatWipeDone = new Promise<void>((resolve) => (formatWipeSettled = resolve));
function afterFormatWipe(area: KvArea): KvArea {
  return {
    get: (keys) => formatWipeDone.then(() => area.get(keys)),
    set: (items) => formatWipeDone.then(() => area.set(items)),
    remove: (keys) => formatWipeDone.then(() => area.remove(keys)),
  };
}
const sealKeyDb = idbKv(() => (globalThis as { indexedDB?: IDBFactory }).indexedDB, SEAL_DB_NAME);
/** The quick-unlock co-key database (the Tier B engine below). */
const IDB_NAME = "andvari-qu";
const IDB_STORE = "cokey";
const sessionSeal = new SessionSeal({ session: sessionRaw, keys: afterFormatWipe(sealKeyDb), originKey: () => serverReady.then(() => currentOriginKey) });
const plainSession = plainSessionArea(sessionRaw);
/** A read where a failure means "absent" (the safe default for every value read this way). Once worker start found no
 *  trusted store, it is not asked again for a best-effort read (a store that timed out would cost every caller the
 *  whole bound again). */
async function trustedGet(key: string): Promise<unknown> {
  if (!trustedStoreOk) return undefined;
  try {
    return (await trusted.get(key))[key];
  } catch {
    return undefined;
  }
}

// A16: storage.session holds four sealed records — the session snapshot (seal kind "session": SessionSnapshot), the tab
// records ("tabs": Record<tabId, TabState>), and per origin the quick-unlock record ("quickUnlock", QKEY) and the
// known-logins digest ("knownLogins", KLKEY) — read and written only through the seal, which owns their slot names; and
// three plain ones (NKEY, ULAST, UQUIET), through plainSession. sessionseal.ts says why each is sealed or plain.
const NKEY = "lockNotice"; // storage.session, plain: { kind:"idle"; seconds } — F26 reason line (E1-7); { kind:"operator" } — §12.2 rule 7; { kind:"not_confirmed" } — a quick unlock that found the session unconfirmed
// storage.session, plain: a number. Design §4.4 (decided on 2026-11-17): how many captured logins and cards a lock or a
// sign-out nobody asked for deleted unsaved (the idle lock; the full sign-out after a session the server ended for good,
// or after the card named the account as the operator). Only the number, never a page's password; the popup says it
// the next time it opens, once (the status read takes it).
const LOST_KEY = "capturesLost";
// Extension quick-unlock Tier B (spec 01 §8.4). QKEY is a DISTINCT storage.session key (breaker B3):
// ensureLoaded MUST NOT hydrate `session` from it, so a locked-armed record leaves every `!session`
// gate reporting fully locked. DKEY is the durable, NON-secret offer-card dismissed-once flag (breaker
// B7). The non-extractable co-key lives in IndexedDB (below) — wiped on every QKEY wipe (breaker A1).
// The five keys below are PER-ORIGIN state and are stored under `nsk(...)` (§4.2/B2-7): the
// quick-unlock record + offer flag belong to the account/server they were minted against, and the
// update-channel state describes ONE origin's /downloads channel (an unscoped USEQ would let one
// origin's seq numbering poison another's anti-rollback). Every read/write goes through nsk().
const QKEY = "quickUnlock"; // storage.session, namespaced, sealed: QuRecord (blob + counter + locked-token stash)
// Known-logins digest (owner decision 2026-08-18; spec 01 §8.4 amendment): truncated HMACs over
// (site key, username) pairs — NO password material — so the LOCKED capture path can tell "a
// re-login to something we already hold" from "a genuinely new login" (knownlogins.ts has the
// derivation + the disclosure bound). Same compartment posture as QKEY: its own storage.session
// key under nsk(), rebuilt from the decrypted items on every persistSession, deliberately
// RETAINED across an idle/manual lock (that survival is its whole function), wiped at sign-out,
// on an untrusted compartment, and by purgeOriginNamespace (H59 — it is per-origin namespaced
// state, so "remove data for this server" has to take it too).
const KLKEY = "knownLogins"; // storage.session, namespaced, sealed: KnownLoginsRecord
const DKEY = "quOfferDismissed"; // trusted store, namespaced (non-secret): the offer card was dismissed once
const BKEY = "quBioCred"; // trusted store, namespaced (non-secret, 0.17.0 amendment 4): { credentialId, prfSalt, userId } — reuse a passkey on re-enroll (avoid TPM/SEP litter). NOT secret: the PRF *output* needs the hardware + OS user-verification; salt/id/userId are public inputs (like a KDF salt).
// A15: the verified offer and the anti-rollback seq are trust state (trusted store); the throttle stamp and the quiet
// marker are not (storage.session — the forced start check re-derives them, and a throttle that works without
// IndexedDB keeps a private-browsing Firefox from re-fetching on every wake). None is migrated from storage.local.
const UKEY = "updateInfo"; // trusted store, namespaced (non-secret): UpdateInfo while a newer build is live
const ULAST = "updateCheckedAt"; // storage.session, namespaced, plain: epoch ms of the last COMPLETED update fetch
const USEQ = "updateAcceptedSeq"; // trusted store, namespaced: highest signed-manifest seq ever accepted (§B anti-rollback)
const UQUIET = "updateChannelQuiet"; // storage.session, namespaced, plain: { reason } — H2 fail-closed-QUIET (§M-D5), never a nag
// M-D4b: ONLY these quiet reasons are ACTIONABLE and may surface a muted popup line. `seq_regression`
// (already-accepted manifest re-polled — the normal steady state) and `disabled` are benign and must
// NEVER render as "couldn't be verified" (permanent false alarm = the alert-fatigue failure M-D4b exists
// to prevent). The write path also refuses to stamp seq_regression; this Set is the belt-and-suspenders.
const SURFACEABLE_QUIET_REASONS = new Set(["unverified", "malformed", "stale", "manifest_fetch_failed"]);
const DEFAULT_AUTOLOCK_SECONDS = 15 * 60; // policy fetch failed/absent — never "no lock at all"
const DEFAULT_CLIPBOARD_CLEAR_SECONDS = 30; // spec 01 §8 policy default; clearing is safety-positive
const CLIPBOARD_CLEAR_ALARM = "clipboardclear"; // SW backstop clear (E1-4); survives idle doLock
const RESYNC_PERIOD_MIN = 5;
/** chrome.alarms floors a delay at 30 s; the deadline keeps the same floor, so it locks exactly when the alarm would. */
const AUTOLOCK_FLOOR_SECONDS = 30;
/** The snapshot's copy of the deadline is rewritten when the live one has moved at least this far past it. */
const LOCK_AT_SAVE_SLACK_MS = 60_000;
const UPDATE_ALARM = "updatecheck";
const UPDATE_PERIOD_MIN = 1440; // ~daily; the SW also opportunistically checks on wake (throttled)
const UPDATE_MIN_GAP_MS = 20 * 60 * 60 * 1000; // floor between real fetches — SWs wake constantly
const GRANT_TTL_MS = 30_000; // popup fill grant: covers the content script's reveal round-trip
const BADGE_BG = "#d0a94a"; //  aged gold on…
const BADGE_INK = "#1a1509"; // …treasury charcoal (web --gold / --btn-ink)
// V4 (design §V4) discovery dot — a card-only page (no login match) is no longer silent. A single
// non-numeric glyph so it can never be confused with a login count; login counts always outrank it
// (refreshTabBadge), and it is the sentinel the [A4] loading handler clears so it never outlives the
// form. Same gold/charcoal chip — no separate color, no new permission.
const CARD_BADGE_TEXT = "•";
// Security review 2026-10 (root cause E): the signup reuse warning's extension-owned signal. It
// outranks the login count while it is live (the user just typed a reused password on this tab);
// the popup shows the sentence and consumes it. Same chip, no new permission.
const REUSE_BADGE_TEXT = "!";
// formatVersion discipline lives in format.ts (MAX_ITEM_FORMAT_VERSION read ceiling;
// LOGIN_FORMAT_VERSION new-login seal fv) — chrome-free so the web pin suite imports it.
// Automated (non-user) messages that must NOT re-arm the idle lock — else a page auto-reloading
// (pageInfo) or the popup's 1 s status/TOTP poll would defer autolock forever while the user is
// away. `status` is here too: merely leaving the popup open (it polls status every second for
// liveness) is not activity; real interaction (reveal/search/save/generate/…) still re-arms.
// [K13]/[C2] `cardChipOffer` belongs here too: it is PAGE-triggered (a focusin the page can drive
// with `HTMLElement.focus()`, which fires *trusted* events at frame rate), not user activity — a
// focus loop would otherwise defer the idle autolock forever. The same rule admits `matches`
// (the login dropdown's open-query rides the SAME trusted focusin, one line above the chip's)
// and `pendingSave` (polled on every top-frame load — an auto-refreshing tab would re-arm per
// reload, exactly the pageInfo case): anything a page can drive with focus() or a load is
// passive. `openPopupForCards` deliberately stays OUT: it rides a real isTrusted click on our
// own chip, i.e. genuine user activity — as do `reveal` (a dropdown pick), `allItems` (search
// typing), `resolvePendingSave`/`openPopupForSave` (banner clicks) and every popup action, so the
// timer keeps its real signal.
// F01 (2026-08-13 audit): `capturedCredential` USED to sit in that sentence, on the reasoning that
// "a submit is a user activity". That reasoning was wrong, and this is the one classification a
// page could exploit: `form.requestSubmit()` fires a submit with isTrusted TRUE and no user
// gesture, so a 1 px form on any frame could re-arm the alarm at will — silently, since a
// username-only capture (password:"") draws no banner. It is page-DRIVEABLE, which is the whole
// test here, so it is passive; the user's real save signal is `resolvePendingSave` (the banner
// click), which still re-arms. The capture path itself is separately gesture-gated content-side
// (content.ts consumeLoginGesture) — the SW cannot see a gesture, so it classifies by reachability.
// H01 (2026-09-13 audit): `passwordReuse` was added in 0.23.0 AFTER F01 and never classified —
// the F01 regression by later addition. It rides a `focusout`, and a page drives trusted focusout
// with `HTMLElement.focus(); blur()` at frame rate on a two-password form it authored itself, so
// a blur loop re-armed the idle autolock forever with nothing on screen (count 0 draws no toast).
// Same test as every entry above: page-DRIVEABLE ⇒ passive. The ask is separately gesture-gated
// content-side (reusealert.ts typedByUser — a trusted keystroke, which no page API can mint), and
// the SW additionally refuses sub-frames and throttles per tab (H02); the classification here is
// the belt the SW can enforce by itself, since it cannot see a gesture.
const PASSIVE_MSGS = new Set<Req["type"]>([
  "pageInfo",
  "totp",
  "ping",
  "status",
  "cardFormInfo",
  "cardChipOffer",
  "matches",
  "pendingSave",
  "capturedCredential",
  "passwordReuse",
  "serverInfo", // A15: the popup header / options render — not user activity
  "appServer", // Safari: the popup asks for the app's server on every open — not user activity
  "appServerAnswer", // Safari: …and relays the app's answer when the worker's own ask did not get one
  "serverDiag",
]);

/** Local sentinel for the spec 01 §5 identityPub derive-and-compare hard-fail (E1-1, web
 *  account.ts:40 parity). The unlock mapper carries it to the popup as code "identity_mismatch" —
 *  a distinct class so it can NEVER be softened into "wrong password". The message is debug-only
 *  detail; the popup renders the canonical sentence from errors.ts. */
class IdentityMismatchError extends Error {
  constructor() {
    super("Server identity key mismatch — possible tampering. Do not proceed; contact your admin.");
    this.name = "IdentityMismatchError";
  }
}

/** The served account is another one than the account this extension knows the address as (accountmemory.ts): code
 *  "remade_account", whose line says both possibilities. Nothing of the served account is opened or kept. */
class RemadeAccountError extends Error {
  /** The account this extension knows the address as (the one "Forget the earlier account on this device" forgets). */
  readonly earlier: string;
  constructor(earlier: string) {
    super("this address is known here as another account");
    this.name = "RemadeAccountError";
    this.earlier = earlier;
  }
}

/** The records of which account an address is and of each account's key could not be read at a sign-in or a quick
 *  unlock (a store that worked at start failed on this read): code "memory_unreadable". Nothing is taken, nothing is
 *  written; a record that cannot be read is never taken as no record. */
class KnownAccountUnreadableError extends Error {
  constructor() {
    super("the records of this server's accounts could not be read");
    this.name = "KnownAccountUnreadableError";
  }
}

/** Local sentinel for audit H67 (core `VaultKeyDamagedException` / web `VaultKeyDamagedError`
 *  parity): the server-stored `wrappedUvk` is not a well-formed envelope at all — undecodable
 *  base64url, too short, or an envelope version/AEAD alg this build does not know. Those refusals
 *  are decided from the blob's PUBLIC header, BEFORE the wrap key is applied, so no password could
 *  have made them pass; mapping them to "bad_credentials" (or the "unknown" retry terminal, which
 *  is where they landed before H67) tells a member with a corrupt or newer-version account row to
 *  reset a password that works. A distinct class so the mapper can carry it to the popup as
 *  "keys_damaged" — terminal copy, never wrong-password and never "try again". The message is
 *  debug-only detail; the popup renders the canonical sentence from errors.ts. */
class VaultKeyDamagedError extends Error {
  constructor(detail: string) {
    super(`account key material is unreadable: ${detail}`);
    this.name = "VaultKeyDamagedError";
  }
}

interface LoginData {
  username?: string;
  password?: string;
  uris?: string[];
  totp?: string;
}
/** Card fields (spec 02 §3, fv 2 docs) — read-only here: the extension lists/copies cards but
 *  never creates or edits them. Field names mirror web api/types CardData / core CardData. */
interface CardData {
  cardholderName?: string;
  number?: string;
  expMonth?: string;
  expYear?: string;
  securityCode?: string;
  brand?: string;
  /** G3 (spec 02 §3 / design 2026-07-23 §G3): typed billing postal code — cross-version-safe
   *  (unknown fields survive re-encrypts via spread; a 0.2.x client can't touch fv2). */
  postalCode?: string;
}
/** Parsed plaintext doc. Unknown fields (notes, favorite, passwordHistory, …) survive re-encrypts
 *  via object spread; `attachments` is typed because a put's wire attachmentIds must mirror it —
 *  an update that sent [] would orphan the item's attachment blobs server-side. */
interface ItemDoc {
  type: string;
  name: string;
  login?: LoginData;
  card?: CardData;
  attachments?: { id: string }[];
}
interface DecryptedItem {
  itemId: string;
  vaultId: string;
  rev: number;
  /** The fv this item was decrypted (or last sealed) at — every re-seal AD-binds and rewires
   *  this same value (monotonic client rule, web Account.itemFv parity; format.ts has the law). */
  formatVersion: number;
  doc: ItemDoc;
}

interface Session {
  userId: string;
  email: string;
  items: DecryptedItem[];
  vaultKeys: Map<string, Uint8Array>;
  /** Grant role per opened vault (G21, 2026-08-30 audit — web Account.vaultRoles twin): "reader"
   *  marks a view-only grant, so the save/link/TOTP-add paths never offer a write the server
   *  would deny. Minted alongside each key in buildVaultKeys and, since H70 (2026-09-13 audit),
   *  REFRESHED on every resync() from the delivered grant rows — unlike vaultKeys, a role needs
   *  no key to read, so there is no reason to make a mid-session demotion wait for a full unlock. */
  vaultRoles: Map<string, string>;
  personalVaultId: string;
  /** Security review 2026-10, branch A11 (q14): vaultId → the vault's meta CIPHERTEXT from the last full sync, so the
   *  save banner can name the destination vault (decrypted on demand under a HELD key, never a server label). */
  vaultMeta?: Map<string, string>;
  /** UVK custody, MEMORY-ONLY (breaker B1) — retained for the unlocked lifetime so quick-unlock enroll
   *  can wrap it; NEVER written to storage.session/local. Absent on a snapshot-restored session (SW was
   *  evicted) → enroll must trigger a fresh full unlock. */
  uvk?: Uint8Array;
  /** §12.2 rule 1: shared vaults whose key the extension does not open (no UVK wrap yet, or no `accept` decision in
   *  the account state) — waiting for a full client. Shown in the popup; recomputed by resync() without the UVK. */
  waitingGrants?: number;
  /** Root cause A §5.1 INV-HOME (A1b): itemId → the vault of the FIRST row this browser applied for it. Durable in
   *  storage.local (per origin and user) and in the snapshot; a later row under another vault is never applied. */
  homes: Map<string, string>;
  /** Design §4.4 "a trust record that cannot be read is not an empty one": false when the durable homes record could
   *  not be read at this session's unlock. Then `homes` is this session's memory only: rows outside the personal vault
   *  are not admitted (nothing can be checked against their homes), and the record is never written back. */
  homesKnown: boolean;
  /** A1b: rows the last snapshot sent under the wrong vault (refused); the popup says so while it is > 0. */
  wrongVault?: number;
  /** How this session was opened. `enroll` COPIES the surviving full-password stamp regardless, but the
   *  provenance makes the "never mint `now` from a QUICK session" invariant (breaker A4) explicit. */
  provenance: "PASSWORD" | "QUICK";
  /** The last full-master-password unlock time. A quick unlock carries the blob's COPIED stamp (never
   *  `now`), so re-enrolling from a QUICK session cannot extend the 24 h quick-unlock window (breaker A4). */
  lastFullUnlockAt: number;
  /** Design §4.4 "A session the server ends does not delete the device's copy": the server ended this session (a
   *  refused refresh, a revoked frame). Its tokens and the quick-unlock record are gone; what it holds stays readable,
   *  with the notice in view; nothing is dialed and nothing is written until the person signs in again. */
  serverEnded?: true;
  /** With serverEnded: no server ended it. A refresh whose answer never came had no try left, so the extension sent
   *  nothing again and ended it itself (api.ts doRefresh); the popup says that end, never "the server signed out". */
  endedUnconfirmed?: true;
  /** The lock's deadline (wall clock, ms). Past it, the session is locked at the next way into the worker
   *  before anything is served (lockIfDue), whether or not the "autolock" alarm fired; the alarm is only what normally
   *  locks it on time. Set at the install, moved by user activity (armAutoLock), kept in the snapshot. */
  lockAt: number;
}

/** What survives SW death (JSON-safe: keys as b64 — Uint8Array doesn't cross chrome.storage). The UVK
 *  is deliberately NOT here (breaker B1 — memory-only custody); provenance + lastFullUnlockAt ride so
 *  the quick-unlock 24 h-window invariant (breaker A4) survives a wake. */
interface SessionSnapshot {
  /** The server origin this snapshot's tokens belong to (§4.1 rule 1). ensureLoaded refuses to
   *  hydrate a snapshot minted against a DIFFERENT origin — e.g. the server was switched while the
   *  SW was dead — so persisted tokens can never replay across a serverUrl change. */
  origin: string;
  access: string;
  refresh: string | null;
  userId: string;
  email: string;
  personalVaultId: string;
  autoLockSeconds: number;
  clipboardClearSeconds: number;
  provenance: "PASSWORD" | "QUICK";
  lastFullUnlockAt: number;
  vaultKeys: Record<string, string>;
  /** Optional: joined the snapshot with G21 (2026-08-30) — a pre-G21 snapshot lacks it, and the
   *  empty default merely restores the pre-fix behavior (every vault treated writable). */
  vaultRoles?: Record<string, string>;
  /** A6: the waiting-grant count (a count, no key material); absent in an older snapshot = 0. */
  waitingGrants?: number;
  /** A1b: the item homes (ids only, no key material); absent in an older snapshot = reloaded from storage.local. */
  homes?: Record<string, string>;
  /** Set when the session's homes record could not be read (Session.homesKnown false); absent = known. */
  homesUnknown?: true;
  wrongVault?: number;
  /** A11 (q14): vault meta ciphertext (no key material); absent in an older snapshot = names refill at the next sync. */
  vaultMeta?: Record<string, string>;
  /** Session.serverEnded: the snapshot then carries no tokens, and a worker restart keeps the session ended. */
  serverEnded?: true;
  /** Session.endedUnconfirmed, kept across a worker restart with the end itself. */
  endedUnconfirmed?: true;
  /** Session.lockAt as last written (the write is skipped while the deadline moved less than LOCK_AT_SAVE_SLACK_MS, so
   *  it is at most that much earlier than the live one). Absent (a snapshot no deadline was kept for) = past. */
  lockAt?: number;
  items: DecryptedItem[];
}

interface TabState {
  /** Username-only capture (multi-step step 1), merged into the password page's capture — but
   *  ONLY a capture on the same site (H13, 2026-09-13 audit: a bare per-tab string leaked site A's
   *  username into a later password-only submit on site B in the same tab). Read through
   *  savetarget.ts stepUsernameFor, which also tolerates the pre-H13 string shape in a persisted
   *  snapshot; cleared by a top-frame pageInfo from another site. */
  lastUsername?: StepUsername;
  /** The tab's pending save. The password stays SW-side — content only ever sees PendingSave.
   *  `frameId` is the frame that captured it: a DIFFERENT frame may not overwrite a live pending,
   *  so a hostile sub-frame can't silently redirect the top frame's Save banner to its own login.
   *  `approvedAt` (unlock-prompt, 2026-08-12): the user clicked Save while the vault was LOCKED —
   *  the click is remembered so the next unlock commits it with no second click, but only within
   *  APPROVED_SAVE_TTL_MS (a shared browser's NEXT unlocker must not silently inherit a long-
   *  abandoned click — stale approvals fall back to the ask-first E1-5 banner). Never sent to
   *  content (publicPending constructs its shape explicitly); rides persistTabs like the rest of
   *  the record, and a browser restart drops storage.session and the approval with it. Only ever
   *  set on a LOCKED-capture pending — doLock's [S3-lock] allow-list drops pendings wholesale, so
   *  an approval can never straddle a lock of a live session.
   *  Locked-capture posture (owner decisions 2026-08-18): `lockedAt` stamps a pending minted
   *  WHILE locked — it holds a plaintext page password in storage.session, so it expires
   *  unoffered after LOCKED_PENDING_TTL_MS. `quiet` marks a locked capture whose (site, user)
   *  pair the known-logins digest recognized: no banner while locked; the unlock-time dedupe in
   *  reofferPendingSaves drops it (unchanged) or offers Update (changed). `offeredAt` throttles
   *  locked re-offers to one per REOFFER_MIN_GAP_MS (knownlogins.ts reofferDecision owns the
   *  ordering). All three are cleared when the unlock re-offer hands the pending to a live
   *  session, and none ride publicPending. */
  pending?: (PendingSave & { password: string; frameId: number; uri?: string; updatesVaultId?: string | null; approvedAt?: number; lockedAt?: number; quiet?: boolean; offeredAt?: number; lost?: LostPut }) | undefined;
  /** S3 per-frame card-form registry: frameId → { the origin the browser reports for the frame (cardrelease.ts
   *  frameOriginOf), ALL its card forms' kinds in document order (Tier 2 §2), the form holding the field the person
   *  chose there and when }. METADATA ONLY (never card values). Only a frame whose origin is a payment provider's
   *  card-entry origin (cardproviders.ts) ever receives a card (owner decision 2026-11-14); the others' records only
   *  let the popup say why it copies instead. Cleared with the tab (onRemoved / lock). [U14]: a persisted pre-update
   *  `{fields}` record is DISCARDED on read (ensureLoaded) — fail-closed, the rescan broadcast restores fresh records. */
  cardForms?: Record<number, { origin: string; forms: CardFieldKind[][]; anchor?: number | null; anchorAt?: number; ancestors?: string[] | null; parent?: number | null; account?: string | null; shown?: boolean }>;
  /** V4 badge: the top frame's BROWSER-SET sender.origin, recorded at pageInfo — the badge's only
   *  origin source ([A4]: never tab.url outside the popup window). Cleared with the registry. */
  topOrigin?: string;
}

let session: Session | null = null;
let autoLockSeconds = DEFAULT_AUTOLOCK_SECONDS;
let clipboardClearSeconds = DEFAULT_CLIPBOARD_CLEAR_SECONDS;
let tabs = new Map<number, TabState>();
/** One-shot popup fill grants, tabId → item+expiry. In-memory only: minted and consumed within
 *  one message exchange, so a SW death in between simply voids the grant (fill re-clicks). The
 *  grant is consumed ONLY by the tab's TOP frame (fillFromPopup targets frameId 0) — a
 *  broadcast-to-all-frames grant would let a hostile cross-origin sub-frame claim the secret.
 *  Security review 2026-10 (A13, q39), the card grant's rule: the grant also records the tab's
 *  top-level ORIGIN at mint, redemption requires the browser-set `sender.origin` to equal it, and a
 *  top-level navigation (status "loading") voids it — so a document that replaced the one the user
 *  picked the login for can never redeem it. */
const grants = new Map<number, LoginGrant>();
/** S3 CARD fill grants, by tab then frame — a store SEPARATE from login `grants` ([A5]). One fill mints one grant per
 *  frame it reaches (every provider frame where the person chose a card field: cardrelease.ts cardFillPlan), each
 *  bound to that frame's id and browser-reported provider origin, and redeemable ONLY by that frame through
 *  `revealCardForFill` (never the login `reveal()`, nor the reverse). One-shot, 30 s, voided when the fill's round trip
 *  ends. Tier 2 §2: a grant FREEZES its frame's form `kinds` + kind-signature `sig` at mint — [U15] redemption composes
 *  against grant.kinds (never the live registry: a mint→redeem rescan could widen egress) and [U12] the content script
 *  fills only a current-sig-matching form. */
const cardGrants = new Map<number, Map<number, CardGrant>>();
/**
 * What this worker heard from each tab's frames since the tab's last navigation (memory-only): whether the top frame
 * reported at all (if not, this extension is not running on the page), the origins of the frames that reported, and the
 * payment providers' origins the top frame's own frames load, by their src. The last is the page's word, a HINT only:
 * it names the site the popup suggests allowing andvari on, and never decides where a card goes.
 */
const cardReports = new Map<number, { top: boolean; origins: Set<string>; hints: string[]; originless?: boolean }>();
/** G2 save-card ([X2-A1]): the tab's pending card save — a MODULE-SCOPE Map, NEVER a `TabState`
 *  field. `persistTabs` serializes the entire tabs map to `storage.session` on every state change,
 *  so a `TabState.pendingCardSave` would write the FULL PAN at rest across a lock (the [iii] hazard).
 *  The full number lives ONLY here, SW-side. Single-slot per tab ([X2-A4] — a new capture REPLACES).
 *  Cleared in doLock ([X2-A2b]), the onUpdated "loading" handler, and onRemoved. */
const pendingCardSave = new Map<
  number,
  { host: string; number: string; expMonth: string; expYear: string; cardholderName: string; postalCode?: string; frameId: number; updatesItemId?: string; updatesItemName?: string; lost?: LostPut }
>();
/** C1 [S2] — tabs whose recorded `topOrigin` is KNOWN-STALE but not yet erased. The onUpdated
 *  "loading" handler can only `delete st.topOrigin` AFTER `await ensureLoaded()`, so between
 *  navigation-start and that microtask the map still holds the PREVIOUS document's top origin —
 *  and the chip gate compares `sender.origin` against exactly that. The tabId is added
 *  SYNCHRONOUSLY in the listener (before the first await) and removed once the clear has landed;
 *  the gate refuses any tab in the set. Memory-only: an SW death that loses the set also loses the
 *  stale record it guards, so there is nothing to fail open into. */
const topOriginPendingClear = new Set<number>();
/** G2 [X2-A5]: per-tab capture dedupe key + timestamp, recorded SYNCHRONOUSLY before any await in
 *  captureCard so a click+submit double-fire of the SAME PAN can't both pass. Memory-only. */
const cardCaptureDedupe = new Map<number, { key: string; t: number }>();
const CARD_CAPTURE_DEDUPE_MS = 1500;
/** In-flight write count — resync must not replace session.items out from under a landing put. */
let writesInFlight = 0;
let loadPromise: Promise<void> | null = null;
/** The idle lock in flight (the auto-lock alarm's, or one the deadline started), so the two are one lock. */
let dueLock: Promise<void> | null = null;
/** Session.lockAt as the snapshot last carried it (persistSession); armAutoLock rewrites it once it lags too far. */
let lockAtSaved = 0;
/** Alarms the browser refused twice in this worker life, for the popup's one line (status.timerNotice). */
const timerRefused = { autolock: false, resync: false };
/** The last alarm request (each is short: a create, once more on a refusal), so the popup's status reads it settled. */
let alarmWork: Promise<void> = Promise.resolve();
/** Live dirty-bell socket handle (events.ts) — held ONLY while a session exists; locked or
 *  logged out = no socket (doLock tears it down first thing). Dies with the SW; T1/T3 revive. */
let events: EventsHandle | null = null;

/** Build the api client for [url] with its custodial handlers attached. A server switch swaps in a
 *  FRESH instance (never a mutated baseUrl — §4.1 rule 1/B1-5: a new instance holds no tokens, so
 *  an Authorization header can never cross a baseUrl change; the old instance becomes garbage). */
function makeApi(url: string): AndvariApi {
  const a = new AndvariApi(url, chrome.runtime.getManifest().version);
  // A16 review R4: while a server is pending (or unknown: dialBlock) the api sends nothing at all — not a session's sync
  // or save, not a refresh, not the socket's ticket. Before, only the sign-in lanes were refused (at dispatch), so a
  // session hydrated under a block (the trusted store timed out while the seal's key answered) still dialed.
  // §4.4: while a session the server ended stands, nothing is sent either (endSessionByServer).
  a.mayDial = () => dialBlock === null && session?.serverEnded !== true;
  // §4.4 "A session the server ends does not delete the device's copy": a definitive refusal of this session's refresh
  // ends the session (endSessionByServer), never deletes what it holds. A redeem's refusal is the redeem's own (it
  // holds no session yet, and wipes the quick-unlock record itself).
  // A refresh whose answer never came and had no try left (`not_confirmed`) ends the session the same way, as an end of
  // its own (never said as the server's), and its token is kept for the next sign-in of that address to name.
  a.onRefreshRefused = (why) => {
    if (why === "not_confirmed" && a.keptUnconfirmed !== null && session !== null) keptUnconfirmed = { email: session.email, refreshToken: a.keptUnconfirmed };
    if (a === api && session !== null && redeemClient !== a) void endSessionByServer(why === "not_confirmed");
  };
  // A10: served rows with malformed ids were refused at the wire (wireids.ts); the full clients raise the notice,
  // the worker logs it (no popup surface for key-state anomalies, see personalChangeText).
  a.onRefusedIds = (endpoint, refused) => console.warn(`[andvari] refused ${refused.length} malformed id(s) on ${endpoint}`);
  // Awaited on every pair mutation — the consumed refresh token must reach the snapshot BEFORE the
  // refresh POST (a stale persisted pair resurrected on SW wake = revoked device). While unlocked it
  // lands in the full SessionSnapshot; DURING a quick-unlock redeem (session still null) it lands in the
  // locked-token stash so a mid-refresh SW death never resurrects a spent token (breaker A5, AM1 parity).
  // A client the server was switched away from keeps its pair to its own server's record (persistStaleTokens).
  const originKey = originKeyFor(url);
  a.onTokensChanged = () => (a === api ? persistTokens() : persistStaleTokens(a, originKey));
  a.onLateRefresh = (consumed, pair) => followLateRefresh(a, originKey, consumed, pair);
  // A 426 min-version pin (spec 03 §1) surfaces via checkForUpdate → the existing update banner is
  // the download surface. checkForUpdate hits the static /downloads route (not api.ts), so it can
  // never itself 426 — no re-entry loop (AM4).
  a.onUpgradeRequired = () => void checkForUpdate(true);
  return a;
}
let api = makeApi(serverUrl);

// A9⊕B5 → A16: the armed quick-unlock record is a crackable UVK blob + a LIVE refresh token, so it may sit in
// storage.session only where a content script could not read it. Since A16 that rests on the seal, not on the area's
// access level: `quCompartmentTrusted` means "the session sealing key is available" (sessionseal.ts — a non-extractable
// key in the extension origin's IndexedDB, so the record is ciphertext to anyone who can only read storage.session),
// AND, as a belt, that `storage.session.setAccessLevel(TRUSTED_CONTEXTS)` RESOLVED where it exists (Chrome; Firefox has
// no such call, and its storage.session content exclusion is not relied on). That is exactly what
// storageaccess.quickUnlockCompartment checks. It gates arm (doLock → armGate) and enroll (enrollQuickUnlock*: no
// enrollment where nothing can arm). Without it nothing arms and every lock is the full erase — NEVER a storage.local
// fallback for the blob (that is the rejected durable Tier C, breaker A9). The same access-level call restricts
// storage.local on Chrome 140+ (defense in depth: since A15 storage.local holds no trust state).
// A16 review R1: the key can be replaced mid-life (a browser-start report), so the verdict is re-decided whenever the
// seal's decision changes (decideCompartment), and it is false while one is pending.
let quCompartmentTrusted = false;
let storageVerdict: StorageAccessVerdict | null = null;
const storageAccess: Promise<StorageAccessVerdict> = restrictStorageAccess(chrome.storage as unknown as StorageAccessAreas);
/** Sets `quCompartmentTrusted` from the access levels and the seal's key as they stand now. */
function decideCompartment(): void {
  quCompartmentTrusted = storageVerdict !== null && quickUnlockCompartment(storageVerdict, sessionSeal.available());
}
/** A16: settles once both the access levels and the seal's key are decided, and sets `quCompartmentTrusted` from them.
 *  Never rejects (neither input does). */
const custodyReady: Promise<void> = Promise.all([storageAccess, sessionSeal.ready]).then(([verdict]) => {
  storageVerdict = verdict;
  decideCompartment();
});

/** While set, the worker dials NO server (serverstate.ts): none chosen, no store, the store did not answer, or the
 *  origin's pin forked or is damaged (design 2026-11-15 §4.4). Set by serverReady and by a fork found at a refresh
 *  (ensureCardFresh); cleared only by a kept pin (switchToPinned) or Safari's app adoption (commitServerUrl). A16
 *  review R4: every request the api makes refuses while it stands (makeApi), and the resync, the socket and
 *  sign-out's revoke do not even start. */
let dialBlock: ServerBlock | null = null;
/** Safari Details (serverDiag): the step worker start is at, and the migration's outcome. Display only. */
let startStage = "storage-access";
let startMigration: string | null = null;
/** Whether worker start found a trusted store (false: none in this browser mode, or it did not answer in time). */
let trustedStoreOk = true;
/** A15 review S1: how long a lock waits for serverReady (the trusted store) — and since A16 for the seal's key
 *  (custodyLoaded) — before it arms or wipes without them. The erase never waits (A16 review R4). */
const LOCK_STORE_WAIT_MS = 1500;
/** A16 review R4: a sign-out never arms, so it may wait longer for the namespace its full wipe lands in, and for the
 *  token pair its revoke rides on — after the erase, which still comes first. */
const SIGNOUT_STORE_WAIT_MS = 5000;
/** A16 review R2: how long a lock waits, after its erase, for the custody epoch it advanced to reach the key store. */
const LOCK_EPOCH_WAIT_MS = 1500;
/** A16 review R4/R1: bumped by every lock and by a browser-start report. A load (ensureLoaded) that began under an older
 *  value installs nothing it read: the lock erased first, and its own copy decides the arm. */
let hydrateGen = 0;

/** Apply the server state worker start computed (serverstate.ts). */
async function applyServerState(storeOutcome: "ok" | "unavailable" | "timedOut"): Promise<void> {
  const st = await loadServerState(storeOutcome, trusted, BUILD_TARGET !== "safari");
  if (st.url !== serverUrl) {
    serverUrl = st.url;
    currentOriginKey = originKeyFor(st.url);
    api = makeApi(st.url);
  }
  currentPin = st.pin;
  dialBlock = st.block;
  // A fork seen earlier in this browser session whose durable write failed still stops the origin, and the
  // write is tried again.
  if (st.pin !== null && !st.pin.fork && st.block === null && (await forkMarked(st.url))) {
    void recordFork(st.url, st.pin, { ...st.pin, fork: true, pending: null });
  }
  // Safari: until the app names a server, nothing is dialed and no autofill is registered, since the exclusion of the
  // person's own vault origin cannot be written yet.
  if (dialBlock === null && noServerChosen()) dialBlock = { kind: "unsettled" };
  if (BUILD_TARGET === "safari" && dialBlock?.kind === "no_server") dialBlock = { kind: "unsettled" };
  trustedStoreOk = st.trustedStore;
  // A block that stands from now on dials nothing — a live socket included.
  if (dialBlock) {
    events?.close();
    events = null;
  }
}

/** Resolves once the storage access levels settled, the one-time A15 migration was settled, the persisted server
 *  origin is loaded and `serverUrl`/`currentOriginKey`/`api`/`dialBlock` reflect it (plus the §4.2 one-shot legacy-key
 *  adoption). EVERY path that touches the api, the per-origin namespace, or the network awaits this first
 *  (ensureLoaded, checkForUpdate) — the module-eval placeholders above exist only so the symbols are never undefined.
 *  A lock waits for it only within LOCK_STORE_WAIT_MS (doLock, A15 review S1). Never rejects. */
const serverReady: Promise<void> = (async () => {
  await storageAccess;
  startStage = "format";
  try {
    // Design 2026-11-15 §12.4: the first start of a new-format build deletes every pre-cut-over local store, once.
    // The quick-unlock co-key database and the session-seal key database are old stores too.
    const coKeyDb = idbKv(() => (globalThis as { indexedDB?: IDBFactory }).indexedDB, IDB_NAME, { storeName: IDB_STORE });
    const storeOutcome = await wipeOldFormatOnce(trusted, [legacyLocal, sessionRaw], [coKeyDb, sealKeyDb]);
    formatWipeSettled();
    startMigration = storeOutcome;
    startStage = "server-state";
    await applyServerState(storeOutcome);
  } catch {
    dialBlock = { kind: "unsettled" }; // unreachable in practice (both leaves never throw) — dial nothing
  } finally {
    formatWipeSettled();
  }
  startStage = "ready";
})();
/** A16: what a lock needs before it can arm or wipe in the right namespace: the origin (serverReady), the access levels
 *  and the seal's key (custodyReady). doLock waits for it at most LOCK_STORE_WAIT_MS. Never rejects. */
const custodyLoaded: Promise<unknown> = Promise.all([serverReady, custodyReady]);

// ---- quick-unlock Tier B engine (spec 01 §8.4) ----
// The non-extractable co-key (breaker A1) persists in IndexedDB — a service worker CAN open IDB, and
// IDB round-trips a non-extractable CryptoKey via structured clone without ever exposing its bytes. (IDB_NAME and
// IDB_STORE are declared above, beside the session seal: the first-launch wipe clears this database too.)
const IDB_KEY = "k_nonexp";

/** A15 review S1: bounded like the trusted store's opens (the same IndexedDB) — an open that never settles rejects,
 *  so a lock's quick-unlock wipe cannot hang on it. */
function idbOpen(): Promise<IDBDatabase> {
  return openBoundedIdb(() => (globalThis as { indexedDB?: IDBFactory }).indexedDB, IDB_NAME, IDB_STORE);
}
function idbRun<T>(mode: IDBTransactionMode, fn: (store: IDBObjectStore) => IDBRequest | null): Promise<T> {
  return idbOpen().then(
    (db) =>
      new Promise<T>((resolve, reject) => {
        const tx = db.transaction(IDB_STORE, mode);
        let result: T;
        const r = fn(tx.objectStore(IDB_STORE));
        if (r) r.onsuccess = () => (result = r.result as T);
        tx.oncomplete = () => {
          db.close();
          resolve(result);
        };
        tx.onerror = () => {
          db.close();
          reject(tx.error ?? new Error("idb tx failed"));
        };
        tx.onabort = () => {
          db.close();
          reject(tx.error ?? new Error("idb tx aborted"));
        };
      }),
  );
}

// Both quick-unlock stores key by the CURRENT origin's namespace at CALL time (§4.2/B2-7): a
// server switch leaves the old origin's record + co-key standing under its own keys — redeemable
// again on return, bounded by the staleness ceiling — and every wipe-class event (sign-out,
// exhausted attempts) erases ONLY the origin it happened under.
const quCoKey: QuCoKey = {
  async generate() {
    const k = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, /* extractable */ false, ["encrypt", "decrypt"]);
    await idbRun<void>("readwrite", (s) => s.put(k, nsk(IDB_KEY)));
    return k;
  },
  async get() {
    try {
      return (await idbRun<CryptoKey | undefined>("readonly", (s) => s.get(nsk(IDB_KEY)))) ?? null;
    } catch {
      return null; // IDB unavailable / co-key gone → treated as a corrupt blob at redeem
    }
  },
  async delete() {
    try {
      await idbRun<void>("readwrite", (s) => s.delete(nsk(IDB_KEY)));
    } catch {
      /* nothing to delete / IDB unavailable */
    }
  },
};

/** The DISTINCT storage.session record slot (breaker B3), sealed (A16): a record that does not open — tampered,
 *  swapped in from another slot or origin, plaintext, or with no key — reads as absent (not enrolled). `remove` deletes
 *  the key DIRECTLY (breaker A7/A10/B7) — never via persistSession, which early-returns when session===null — and
 *  without waiting for the key. A write that was not kept (no key store, or a wipe landed first) throws, so an arm or a
 *  reserved attempt that did not reach storage fails closed. A16 review R1: a record read before the seal's key was
 *  replaced (a browser-start report) is never written back under the new key — an arm or a reserved attempt that read
 *  it before and writes after throws the same way; an enrollment's fresh record was never read, and is kept.
 *  The same for a record REMOVED after it was read (a wipe — a disable, a sign-out, an exhausted counter —
 *  landing while an arm, a re-stamp, a token change or a redeem's completion had it in hand) and for one read under
 *  another server: the engine changes the record it read and writes it back, and before, that write put a wiped
 *  record back (with its co-key gone), or wrote one server's record into another's slot. The write now throws, as
 *  for a record that was not kept. */
const quReadUnder = new WeakMap<object, { gen: number; originKey: string; removals: number }>();
/** The store for the record of the server [originKeyOf] names when it is asked: the current one ([quStore]), or one fixed
 *  server's (the client of a server switched away from: persistStaleTokens). */
function quStoreAt(originKeyOf: () => string): QuStore {
  return {
    async read() {
      const originKey = originKeyOf();
      const removals = sessionSeal.removalCount("quickUnlock", originKey); // taken before the read: a removal during it counts
      const rec = ((await sessionSeal.get("quickUnlock", originKey)) as QuRecord | undefined) ?? null;
      if (rec !== null && typeof rec === "object") quReadUnder.set(rec, { gen: sessionSeal.generation(), originKey, removals });
      return rec;
    },
    async write(rec) {
      const originKey = originKeyOf();
      const readUnder = quReadUnder.get(rec);
      if (readUnder !== undefined) {
        if (readUnder.gen !== sessionSeal.generation()) throw new Error("the quick-unlock record was read under a replaced key");
        if (readUnder.originKey !== originKey) throw new Error("the quick-unlock record was read under another server");
        if (sessionSeal.removalCount("quickUnlock", originKey) !== readUnder.removals) throw new Error("the quick-unlock record was removed after it was read");
      }
      if (!(await sessionSeal.set("quickUnlock", originKey, rec))) throw new Error("the quick-unlock record was not kept");
    },
    remove: () => sessionSeal.remove("quickUnlock", originKeyOf()),
    removals: () => sessionSeal.removalCount("quickUnlock", originKeyOf()),
  };
}
const quStore: QuStore = quStoreAt(() => currentOriginKey);

/** One-shot enroll bench (breaker B8). Pure-JS Argon2id is ~linear in memBytes at fixed ops (and 64 MiB
 *  is multi-second), so a 4-candidate scan would cost ~15 s. Instead: measure ONE derive at the FLOOR
 *  (32 MiB / ops 2), then scale memory linearly toward the ~1 s target, capped at 64 MiB and never below
 *  the floor. So a fast machine gets stronger params (toward 64 MiB) while a slow one uses the honest
 *  floor (accepting > 1 s rather than dropping below 32 MiB). Enroll-time only; the result is re-checked
 *  by assertPinKdfParams before it is ever persisted (2 derives total: this measure + the real K_pin). */
async function benchPinParams(): Promise<KdfParams> {
  const targetMs = 1000;
  const CAP_MEM_BYTES = 67_108_864; // 64 MiB — the master floor; never pick PIN params stronger than that
  const STEP = 16 * 1024 * 1024; // round memory to a 16 MiB step
  const floor: KdfParams = { v: 1, alg: "argon2id13", ops: PIN_KDF_MIN_OPS, memBytes: PIN_KDF_MIN_MEM_BYTES };
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const t0 = Date.now();
  try {
    await deriveMasterKeyAsync("andvari-quick-unlock-bench", floor, salt);
  } catch {
    return floor; // couldn't even bench the floor — use it (never go below)
  }
  const floorMs = Math.max(1, Date.now() - t0);
  if (floorMs >= targetMs) return floor; // even the floor is at/over the target — use the floor
  // time ∝ memBytes at fixed ops → the memory that lands ~targetMs, capped + floored + step-rounded.
  const budget = Math.floor((PIN_KDF_MIN_MEM_BYTES * targetMs) / floorMs);
  const memBytes = Math.max(PIN_KDF_MIN_MEM_BYTES, Math.min(CAP_MEM_BYTES, Math.floor(budget / STEP) * STEP));
  return { v: 1, alg: "argon2id13", ops: PIN_KDF_MIN_OPS, memBytes };
}

// ---- biometric quick-unlock connector broker (0.17.0, spec docs/design/2026-07-18-biometric-quick-unlock.md) ----
// WebAuthn create()/get() cannot run in the SW (no navigator.credentials) NOR the action popup (the OS
// prompt closes the popup — spike 2026-07-18), so the ceremony runs in a dedicated connector WINDOW.
// The engine's injected QuBiometric dep is an RPC to that window: open it, hand it the op via a
// sender-verified "ready" reply, receive the PRF secret in its "result" post. The connector self-drives
// under its own gesture; the SW never touches WebAuthn. The 32-byte PRF secret is base64 on the wire and
// zeroized the moment K_bio is derived (engine side). Device-binding is the co-key (breaker A1), not the
// PRF — a synced passkey on another device re-derives the PRF but cannot open the co-key-wrapped blob.
// quality-deadcode--5: BioReq/BioResult are DECLARED ONCE, in bioprotocol.ts — the hand-duplicated
// pair here and in connector.ts had already drifted on `error`'s optionality.
let pendingBio: { req: BioReq; resolve: (r: BioResult) => void; windowId?: number } | null = null;
const CONNECTOR_URL = chrome.runtime.getURL("connector.html");
/** This extension's own page prefix (`chrome-extension://<id>/`, `moz-extension://<uuid>/`) — the
 *  A14 sender gate's notion of "one of our pages" (sendergate.ts). */
const EXTENSION_BASE = chrome.runtime.getURL("");
/** bug-ext-gating--4: the RP-ID claim rides the manifest's install-time host permission for the
 *  reference instance (design 2026-07-18 §3 — deliberately independent of the configured server, so
 *  a self-hoster's domain never has to be dragged through an optional-permission prompt). But that
 *  permission can be RUNTIME-WITHHELD (Chrome "site access: on click"; Firefox optional-by-default
 *  host perms), and the design mandates a probe on that exact ground: without it the ceremony
 *  throws SecurityError, which the engine maps to bio_cancelled, which renders as "Setup was
 *  cancelled — try again when you're ready." A capability that CANNOT work, reported forever as if
 *  the user had dismissed a prompt. The probe turns it into the honest bio_unsupported line, which
 *  also points at the PIN. Same literal as connector.ts's RP_ID: one origin, derived in both. */
const BIO_RP_ORIGIN_PATTERN = `${PUBLIC_INSTANCE.origin}/*`;
async function bioRpPermissionHeld(): Promise<boolean> {
  try {
    return await chrome.permissions.contains({ origins: [BIO_RP_ORIGIN_PATTERN] });
  } catch {
    return true; // no permissions API to ask (Firefox event page edge) — never block on the probe
  }
}

/** Resolve (and clear) the in-flight ceremony exactly once — from a connector "result" post OR from
 *  the window being closed (onRemoved) BEFORE a result arrived (→ cancel = bio_cancelled). */
function resolvePendingBio(r: BioResult): void {
  const p = pendingBio;
  pendingBio = null;
  p?.resolve(r);
}

/** Open the connector window and await its ceremony result. One at a time (the redeem/enroll lanes are
 *  single-flighted above this, but guard anyway so a stray second call can never orphan a window). */
function brokerBioCeremony(req: BioReq): Promise<BioResult> {
  if (pendingBio) return Promise.resolve({ ok: false, error: "ceremony already in flight" });
  return new Promise<BioResult>((resolve) => {
    pendingBio = { req, resolve };
    // 600×760, not a slim popup: Chrome renders its passkey chooser/consent dialogs INSIDE this window
    // (anchored top-center, ~450 px wide, taller with account lists) — a ~380-wide window CLIPS them
    // (owner-observed on Windows, 2026-07-18 E2E). The OS Hello/Touch-ID prompt itself is a native
    // dialog and doesn't care, but the in-window chooser needs the room.
    chrome.windows
      .create({ url: CONNECTOR_URL, type: "popup", width: 600, height: 760, focused: true })
      .then((w) => {
        if (pendingBio) pendingBio.windowId = w?.id;
      })
      .catch(() => resolvePendingBio({ ok: false, error: "could not open connector" }));
  });
}

// The connector window closed without posting a result → the user dismissed the OS prompt / closed it
// → cancel. (A posted result clears pendingBio first, so this no-ops for the normal path.)
atLoad("windows.onRemoved", () => chrome.windows.onRemoved.addListener((wid) => {
  if (pendingBio && pendingBio.windowId === wid) resolvePendingBio({ ok: false, error: "connector closed" });
}));

/** Sender-verified connector RPC. Only our own connector PAGE may drive a ceremony. The gate is the
 *  sender's extension-origin URL — NOT `sender.tab === undefined`: a `chrome.windows.create({type:
 *  'popup'})` extension page IS a tab (empirically verified on Chromium, 2026-07-18 review), so a
 *  tab-absence check would reject the connector itself. A content script's sender.url is the WEB
 *  page's (http/https) → refused; other extensions/pages can't reach onMessage at all (no
 *  externally_connectable — they'd arrive via onMessageExternal); our popup/options don't match
 *  the connector URL → refused. sender.id is belt-and-suspenders. */
async function handleBioConnector(msg: { __bio: string } & Record<string, unknown>, sender: chrome.runtime.MessageSender): Promise<unknown> {
  if (sender.id !== chrome.runtime.id || !(sender.url ?? "").startsWith(CONNECTOR_URL)) return { error: "unauthorized" };
  if (msg.__bio === "ready") return pendingBio ? pendingBio.req : null; // hand the connector its op
  if (msg.__bio === "result") {
    resolvePendingBio(msg as unknown as BioResult);
    return { ack: true };
  }
  return { error: "unknown" };
}

// ---- QuBiometric dep: brokers the ceremony; caches the enroll-time secret so the engine's follow-up
//      evalPrf needs no THIRD OS prompt (enroll already did create()+get() in one window). ----
let enrollSecretCache: { credentialId: string; secret: Uint8Array } | null = null;
let lastBioEnroll: { credentialId: string; prfSaltB64: string } | null = null; // for the amendment-4 reuse record
function dropEnrollSecretCache(): void {
  if (enrollSecretCache) {
    enrollSecretCache.secret.fill(0);
    enrollSecretCache = null;
  }
}
/** Read-and-clear the dep-set enroll record. A function boundary (not an inline read) so the handler
 *  gets the DECLARED union type — the dep mutates this during an await, which TS's control-flow can't see. */
function takeLastBioEnroll(): { credentialId: string; prfSaltB64: string } | null {
  const v = lastBioEnroll;
  lastBioEnroll = null;
  return v;
}

const biometricDep: QuBiometric = {
  async enroll(prfSalt) {
    dropEnrollSecretCache();
    lastBioEnroll = null;
    // bug-ext-gating--4: the designed probe. A withheld RP host permission is a CAPABILITY loss,
    // not a cancellation — answer it through the existing prfEnabled=false channel, which
    // QuickUnlock.enrollBio already maps to bio_unsupported ("This device can't do biometric quick
    // unlock — set up a PIN instead."). Nothing is written either way, so the prior record is safe.
    if (!(await bioRpPermissionHeld())) return { credentialId: "", prfEnabled: false, prfSalt };
    const userId = session?.userId ?? "";
    // A stable, non-reversible user handle (WebAuthn stores it in the passkey; we key by credentialId).
    const userHandleB64 = toB64(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode("andvari-bio|" + userId))));
    const reuse = await readBioCred(userId); // amendment 4: reuse an on-record passkey if one exists
    const r = await brokerBioCeremony({
      op: "enroll",
      prfSalt: toB64(prfSalt),
      userHandleB64,
      userName: session?.email ?? "andvari",
      reuse: reuse ? { credentialId: reuse.credentialId, prfSalt: reuse.prfSalt } : undefined,
    });
    if (!r.ok || r.op !== "enroll") throw new Error("bio enroll ceremony failed");
    if (r.prfEnabled) {
      enrollSecretCache = { credentialId: r.credentialId, secret: fromB64(r.secretB64) };
      lastBioEnroll = { credentialId: r.credentialId, prfSaltB64: r.prfSalt };
    }
    return { credentialId: r.credentialId, prfEnabled: r.prfEnabled, prfSalt: fromB64(r.prfSalt) };
  },
  async evalPrf(credentialId, prfSalt) {
    // Enroll's own get() already produced this secret — hand it off (one-shot; the engine zeroizes it).
    if (enrollSecretCache && enrollSecretCache.credentialId === credentialId) {
      const s = enrollSecretCache.secret;
      enrollSecretCache = null;
      return s;
    }
    // bug-ext-gating--4, redeem lane: the same probe, but the redeem has no "unsupported" code to
    // return (BeginRedeemBio's union is deliberately narrow), so this stays a throw → bio_cancelled
    // → the master-password fallback the user needs anyway. The BUTTON is what must not lie: the
    // popup's probeBioCapable runs the same check, so a withheld permission hides it rather than
    // offering an unlock that can only ever fail.
    if (!(await bioRpPermissionHeld())) throw new Error("bio RP host permission withheld");
    const r = await brokerBioCeremony({ op: "eval", credentialId, prfSalt: toB64(prfSalt) });
    if (!r.ok || r.op !== "eval") throw new Error("bio eval ceremony failed");
    return fromB64(r.secretB64);
  },
};

// ---- amendment-4 reuse record (namespaced, trusted store since A15; non-secret — see BKEY) ----
type BioCred = { credentialId: string; prfSalt: string; userId: string };
async function readBioCred(userId: string): Promise<BioCred | null> {
  try {
    const rec = (await trustedGet(nsk(BKEY))) as BioCred | undefined;
    return rec && rec.userId === userId && typeof rec.credentialId === "string" && typeof rec.prfSalt === "string" ? rec : null;
  } catch {
    return null; // reuse is best-effort — a miss just mints a fresh passkey
  }
}
async function writeBioCred(rec: BioCred): Promise<void> {
  try {
    await trusted.set({ [nsk(BKEY)]: rec });
  } catch {
    /* best-effort litter reduction */
  }
}
async function clearBioCred(): Promise<void> {
  try {
    await trusted.remove(nsk(BKEY));
  } catch {
    /* */
  }
}

const quDeps: QuDeps = {
  store: quStore,
  coKey: quCoKey,
  deriveKPin: (pin, params, salt) => deriveMasterKeyAsync(pin, params, salt),
  biometric: biometricDep,
  benchPinParams,
  now: () => Date.now(),
  randomBytes: (n) => crypto.getRandomValues(new Uint8Array(n)),
};
const quickUnlock = new QuickUnlock(quDeps);

/** Set only while a quick-unlock redeem is between its forced refresh and the session rebuild — the
 *  window where api token mutations must land in the locked-token stash, not the (absent) session.
 *  It names the client the redeem runs on, not a flag for the whole worker. After a server
 *  switch the old server's redeem may still be on the wire, and the flag routed the NEW client's token changes (a
 *  password sign-in's refresh there) into the new server's record, which then held another account's pair. */
let redeemClient: AndvariApi | null = null;
/** Whose pair each client holds — set wherever a client is given a pair (a sign-in, a
 *  redeem, a hydrated snapshot). A client the server was switched away from keeps its pair to its own server's record
 *  only where that record is the same account's (persistStaleTokens). */
const pairUser = new WeakMap<AndvariApi, string>();
/** The open session whose quick-unlock record still holds a token stash, because the
 *  write that clears it at the unlock failed (a redeem's update, a sign-in's re-stamp). That pair is live while the
 *  vault is open, against the record's rule (null while unlocked), and it goes stale at the session's next refresh: a
 *  worker that then stops with no snapshot would come back with a record armed on a spent token, whose PIN unlock
 *  would present it to the server. The clear is tried again at every token change of that session (before the old
 *  refresh token is spent: the change is persisted before the refresh is sent) and after every sync. */
let stashOwed: Session | null = null;

/** Clears the stash [s]'s record still holds (see [stashOwed]); never throws. Only while [s] is the session in front
 *  (a lock arms the record itself), only a stash (never arms one) and only the same account's record. */
async function clearOwedStash(s: Session): Promise<void> {
  try {
    await quickUnlock.setLockedTokens({ access: null, refresh: null }, { onlyIfStashed: true, forUser: s.userId, stillCurrent: () => session === s });
    if (stashOwed === s && session === s) stashOwed = null;
  } catch {
    /* still owed: tried again at the next token change or sync */
  }
}
/** Single-flight for the quick-unlock redeem (mirrors AndvariApi.refreshInFlight) — two racing popups
 *  submitting a PIN must not each start a redeem and double-spend the attempt counter (breaker A5⊕B4). */
let pinUnlockInFlight: Promise<Res<"unlockWithPin">> | null = null;
/** Single-flight for the biometric redeem (0.17.0). Separate slot from the PIN's — only ONE method is
 *  ever armed per device (one-method-at-a-time enroll), so the two lanes cannot race; both funnel into
 *  the shared finishRedeem, whose redeemInFlight flag is therefore never touched concurrently. */
let bioUnlockInFlight: Promise<Res<"unlockWithBio">> | null = null;
/** TOTP unlock seam (0.16.3): a TOTP-enrolled login returns 401 totp_required — we hold the ALREADY-
 *  DERIVED {authKey, wrapKey} so the code retry needs no second ~6 s Argon2id, and let the popup
 *  render a code field. This lives in SW MEMORY ONLY, NEVER storage.session: breaker B1 keeps the
 *  UVK (and UVK-equivalent wrapKey) out of at-rest storage, and while quick-unlock is armed the
 *  storage compartment already holds the plaintext token pair — persisting wrapKey there too would
 *  let a storage-read alone recover the UVK with no PIN and no TOTP. Memory-only means its lifetime
 *  (SW alive — held by the open popup port) exactly matches when the retry can succeed: if the SW is
 *  evicted (popup closed >~30 s while grabbing the code), it's gone → status reports no challenge →
 *  the popup shows the full form → a fresh sign-in. Origin-bound + 5-min fused; every read re-checks. */
const PENDING_TOTP_TTL_MS = 5 * 60 * 1000;
let pendingTotp: { origin: string; email: string; authKey: Uint8Array; wrapKey: Uint8Array; device: { rec: DeviceRecord; key: string | null }; replaces: string | null; expiresAt: number } | null = null;
let totpUnlockInFlight: Promise<Res<"unlockTotp">> | null = null;
/** Read the live challenge, dropping it if it has expired or the server was switched under it (the
 *  §4.1 origin guard, applied at READ like ensureLoaded does for the session snapshot). */
function livePendingTotp(): typeof pendingTotp {
  if (pendingTotp && (pendingTotp.origin !== serverUrl || Date.now() >= pendingTotp.expiresAt)) pendingTotp = null;
  return pendingTotp;
}
/** Drop the challenge (and its in-memory authKey/wrapKey). Called on every transition to a live
 *  session (full unlock, TOTP redeem, PIN redeem), on sign-out, on server switch, and on cancel. */
function clearPendingTotp(): void {
  pendingTotp = null;
}
/** owns() generation (breaker A5⊕B4): bumped by every lock / sign-out / full unlock. A redeem that
 *  reads a different value after its async KDF/network discards itself rather than clobber new state. */
let redeemGen = 0;

/** onTokensChanged custodian. Unlocked → the full SessionSnapshot. Mid-redeem (session still null) →
 *  the quick-unlock locked-token stash (breaker A5/AM1). Otherwise (locked, not redeeming) → nothing:
 *  there is no live session to attach a stray mutation to. */
function persistTokens(): Promise<void> {
  if (session && stashOwed === session) return Promise.all([persistSession(), clearOwedStash(session)]).then(() => {});
  if (session) return persistSession();
  if (redeemClient !== null && redeemClient === api) return quickUnlock.setLockedTokens(api.getTokens());
  return Promise.resolve();
}

/** A token change from a client that is no longer the current one — the server was switched while its
 *  refresh was on the wire (a quick unlock's, say). Before, it went through persistTokens, which reads the CURRENT
 *  client's pair into the CURRENT server's record: the new server's armed record took the new client's empty pair (and
 *  was disarmed), while the old server's kept the pair the refresh had just spent, so its next quick unlock was refused
 *  and wiped. Now the client's own pair goes to its own server's record, and only where that record holds a stash (it
 *  is locked-armed: never arms one), and never while that server is the current one again (its current client is in
 *  charge there). A write that fails leaves the old server's record as it was before this fix: its next quick unlock is
 *  refused as a session that ended and sends the person to the master password, which is where this failure shows. */
function persistStaleTokens(a: AndvariApi, originKey: string): Promise<void> {
  if (originKey === currentOriginKey) return Promise.resolve();
  // And only into a record of the account whose pair the client holds. A password sign-in of
  // another account at that server, left behind by the switch, refreshed its pair into the record of the account whose
  // quick unlock was armed there, and that account's PIN then opened nothing (or spent the other account's token).
  const forUser = pairUser.get(a);
  if (forUser === undefined) return Promise.resolve();
  const atOrigin = new QuickUnlock({ ...quDeps, store: quStoreAt(() => originKey) });
  return atOrigin.setLockedTokens(a.getTokens(), { onlyIfStashed: true, forUser }).catch(() => {});
}
/**
 * A lock waits for a refresh on the wire at most LOCK_STORE_WAIT_MS, and past that it
 * arms the record on the consumed pair (no refresh token) and clears the client, so the refresh's answer was dropped and
 * the next quick unlock, holding no refresh token, was taken for a revoked session and wiped. Now the answer follows the
 * record: the client hands it here (AndvariApi.onLateRefresh), and it replaces exactly the stash armed on that consumed
 * pair, of the same account, at the client's own server; the next quick unlock waits for it (lockRefreshSettled). Never
 * throws.
 */
async function followLateRefresh(a: AndvariApi, originKey: string, consumed: string, pair: { access: string; refresh: string | null }): Promise<void> {
  const forUser = pairUser.get(a);
  if (forUser === undefined) return;
  const atOrigin = originKey === currentOriginKey ? quickUnlock : new QuickUnlock({ ...quDeps, store: quStoreAt(() => originKey) });
  await atOrigin.setLockedTokens(pair, { onlyIfStashed: true, forUser, replacingConsumed: consumed }).catch(() => {});
}
/** The refresh a lock stopped waiting for (settled at once when there was none): a quick unlock waits for it, bounded by
 *  REDEEM_FOLLOWS_REFRESH_MS, before it reads the record. */
let lockRefreshSettled: Promise<void> = Promise.resolve();
const REDEEM_FOLLOWS_REFRESH_MS = 15_000;

// ---- one-time per SW life; listeners MUST register synchronously (MV3 wake requirement) ----

/**
 * One top-level registration. An engine that lacks the API (iOS Safari has no badge text colour, and may lack others)
 * throws here, and at top level one throw ends the whole background page: every listener after it never registers and
 * no message is answered. So each registration stands alone, and a failure is recorded where the Safari build's
 * Details can show it (safari-boot.js).
 */
function atLoad(label: string, register: () => void): void {
  try {
    register();
  } catch (e) {
    try {
      (globalThis as { __andvariBootRecord?: (label: string, e: unknown) => void }).__andvariBootRecord?.(label, e);
    } catch {
      /* nowhere to record it */
    }
  }
}

atLoad("action.setBadgeBackgroundColor", () => void chrome.action.setBadgeBackgroundColor({ color: BADGE_BG }));
atLoad("action.setBadgeTextColor", () => void chrome.action.setBadgeTextColor({ color: BADGE_INK }));

// ---- G4 context menu + keyboard command (design 2026-07-23 §G4) ----
// Data-free discovery: both the "andvari" editable-context menu item and the manifest
// `_execute_action` command merely OPEN the popup — no in-page picker, no new egress. The popup
// computes offers against the ACTIVE tab, so opening it as anything other than the popup would break
// the sole-grant-surface assumption. [X4-A3] idempotent registration at EVERY background load
// (top-level, not onInstalled-only — Chrome/Firefox event-page persistence differs): removeAll →
// create. onClicked registers SYNCHRONOUSLY here (MV3 wake requirement) → chrome.action.openPopup()
// wrapped in try/catch with an explicit NO-OP degrade ([X4-A2]; FORBID tabs.create of popup.html).
const CTX_MENU_ID = "andvari";
try {
  chrome.contextMenus.onClicked.addListener((info) => {
    if (info.menuItemId !== CTX_MENU_ID) return;
    try {
      // openPopup lands on Chrome 127 (the bumped minimum_chrome_version) / Firefox; older/absent →
      // NO-OP (optional-chain skips the call). NEVER chrome.tabs.create/windows.create of popup.html
      // ([X4-A2]). The `.catch` delivers the NO-OP degrade for a PRESENT-but-REJECTING call (no
      // active window) — a sync try/catch can't catch the returned promise's rejection.
      void (chrome.action as unknown as { openPopup?: () => Promise<unknown> }).openPopup?.()?.catch(() => {});
    } catch {
      /* openPopup unsupported here — NO-OP */
    }
  });
} catch {
  /* contextMenus unavailable on this engine — the toolbar action + keyboard command still open the popup */
}
try {
  chrome.contextMenus.removeAll(() => {
    try {
      chrome.contextMenus.create({ id: CTX_MENU_ID, title: "andvari", contexts: ["editable"] });
    } catch {
      /* create failed / already exists — the next load's removeAll→create reconciles */
    }
  });
} catch {
  /* contextMenus unavailable on this engine */
}
// (The storage.session TRUSTED_CONTEXTS precondition for quick unlock is set up beside serverReady, above: A15 awaits
// it, and serverReady/doLock wait for it.)

atLoad("runtime.onMessage", () => chrome.runtime.onMessage.addListener((msg: Req, sender, sendResponse) => {
  // 0.17.0 biometric connector RPC — a PRIVATE protocol (not part of Req), handled before the normal
  // dispatch and gated on a same-extension connector-page sender inside handleBioConnector.
  // A session past the lock's deadline is locked before anything here is served (handle() checks it again
  // after the load, for a worker that has just restored one).
  const due = lockIfDue();
  const bio = msg as unknown as { __bio?: unknown };
  if (bio && typeof bio.__bio === "string") {
    due
      .then(() => handleBioConnector(bio as { __bio: string } & Record<string, unknown>, sender))
      .then(sendResponse)
      .catch((e: unknown) => sendResponse({ error: String(e) }));
    return true;
  }
  // Safari Details: answered from variables, before anything that waits on worker start (which is what it diagnoses).
  if ((msg as { type?: unknown }).type === "serverDiag") {
    sendResponse(senderMaySend("serverDiag", sender, EXTENSION_BASE) ? serverDiag() : null);
    return false;
  }
  handle(msg, withPageOrigin(sender), due)
    .then(sendResponse)
    .catch((e: unknown) => sendResponse({ ok: false, error: String(e) }));
  return true; // keep the channel open for the async response
}));

/** Safari: how often each source gave a page's origin, and the last message that needed one (the popup's Details). */
const pageOriginSeen: Record<OriginSource, number> = { origin: 0, url: 0, none: 0 };
let pageOriginLast: string | null = null;
/** Safari Details (round-13 review): whether the browser set `sender.origin` for the last payment provider frame. */
let providerFrameDiag: string | null = null;

/**
 * Safari (L8): a tab sender with no browser-set `origin` gets its top frame's origin from that frame's own browser-set
 * URL, never the tab's (senderorigin.ts, derivedPageOrigin, has the rules). Every handler then makes its usual checks
 * of `sender.origin`.
 * Other builds, and the extension's own pages (no tab), are passed through untouched.
 */
function withPageOrigin(sender: chrome.runtime.MessageSender): chrome.runtime.MessageSender {
  if (BUILD_TARGET !== "safari" || sender.tab === undefined) return sender;
  const d = derivedPageOrigin(sender);
  pageOriginSeen[d.source]++;
  pageOriginLast = d.source;
  if (d.source === "origin" || d.origin === null) return sender;
  // A copy of the fields the handlers read, named one by one: an engine's sender may keep them as getters.
  return { id: sender.id, tab: sender.tab, frameId: sender.frameId, url: sender.url, origin: d.origin };
}

atLoad("alarms.onAlarm", () => chrome.alarms.onAlarm.addListener((alarm) => {
  // Every way in checks the lock's deadline first (lockIfDue); the auto-lock alarm is one lock with it.
  if (alarm.name === "autolock") void idleLock();
  else if (alarm.name === "resync") {
    void resync(); // the ≤5-min staleness floor…
    void ensureSocket(true); // …and the guaranteed live-socket revival after SW death (T3)
  } else {
    void lockIfDue(); // the other alarms serve no vault content, but a worker woken by one locks a session past its time
    if (alarm.name === UPDATE_ALARM) void checkForUpdate();
    else if (alarm.name === CLIPBOARD_CLEAR_ALARM) void clearClipboardBackstop();
  }
}));

// The self-update check runs on its OWN daily schedule, independent of lock state (it reads only
// the public downloads manifest — no vault, no session). A reload/update fires onInstalled, which
// re-checks against the NEW installed version and so clears a now-satisfied signal immediately.
// Both hooks also reconcile the dynamic autofill registration (B2-5) — install/update is exactly
// when a stale or missing registration is most likely.
atLoad("runtime.onInstalled", () => chrome.runtime.onInstalled.addListener(() => {
  // A16 review R1: an install, update, reload or browser update — storage.session is the browser's fresh one.
  browserSessionReported();
  const ready = serverReady.catch(() => {});
  void ready.then(() => checkForUpdate(true));
  void ready.then(registerAutofillScripts);
}));
atLoad("runtime.onStartup", () => chrome.runtime.onStartup.addListener(() => {
  browserSessionReported(); // A16 review R1: a browser start — storage.session is the browser's fresh one
  void checkForUpdate(true);
  void serverReady.then(registerAutofillScripts);
}));
void (async () => {
  // Survive SW recycling without resetting the period on every wake (that would starve a
  // 1440-min alarm): create it only when absent. The wake-path check is throttled by ULAST.
  try {
    if (!(await chrome.alarms.get(UPDATE_ALARM))) {
      await chrome.alarms.create(UPDATE_ALARM, { periodInMinutes: UPDATE_PERIOD_MIN });
    }
  } catch {
    /* alarms.get unsupported here — the throttled wake check below still yields ~daily coverage */
  }
  void checkForUpdate();
})();

// T1: EVERY SW start (browser startup, install, popup/content-message/alarm wake) re-establishes
// the live dirty-bell socket if a restorable session exists — no-op when locked or logged out.
void ensureSocket();

// ---- dynamic autofill registration (design §5.1, B2-5 — security-critical) ----
// The static manifest `content_scripts` entry is GONE from both manifests: a static entry's
// exclude_matches is immutable at runtime, so keeping it would inject the autofill UI into every
// SELF-HOSTED vault origin (and adding a dynamic twin would double-inject everywhere else).
// Autofill registers dynamically instead, excludeMatches recomputed from the configured server
// origin + the shipped default. Effective injection is additionally bounded by GRANTED host
// permissions (Chrome: optional_host_permissions granted at runtime; Firefox MV3: all host
// permissions are optional-by-default) — the wave-3 options/grant flow widens the effective set,
// and permissions.onAdded below re-reconciles the moment a grant lands.
const AUTOFILL_SCRIPT_ID = "autofill";

/** Reconcile the registered autofill content script with the current serverUrl. Runs on every SW
 *  start, on install/update, on every server switch, and on every host-permission grant — a
 *  registration that failed (or predates a switch) is detected and self-healed here (§5.1
 *  corollary: a failure means no autofill until the SW next runs, never a mis-scoped injection). */
/** One reconcile at a time (A15 review, found by the live check): worker start and onInstalled both reconcile on an
 *  update, and two overlapping runs both saw "not registered", so the second register threw a duplicate id and its
 *  fail-closed catch unregistered the first — no autofill until the next worker start. F1 adds callers (the late
 *  migration, "Not mine", the gate's commit), so every call now queues behind the one before. */
let autofillChain: Promise<void> = Promise.resolve();
function registerAutofillScripts(): Promise<void> {
  autofillChain = autofillChain.then(reconcileAutofillScripts, reconcileAutofillScripts);
  return autofillChain;
}

async function reconcileAutofillScripts(): Promise<void> {
  // The dialed origin, the shipped default, and (A15 review F1) a pending server awaiting its confirm. Null = fail
  // CLOSED to "no autofill anywhere" rather than inject into a vault UI we failed to exclude: an origin that cannot be
  // expressed as a match pattern (an IPv6-literal host), or a store that did not answer (the vault origin is unknown).
  const excludeMatches = autofillExcludeMatches(serverUrl, dialBlock, PUBLIC_INSTANCE.origin);
  if (excludeMatches === null) {
    await unregisterAutofillScripts();
    return;
  }
  const desired: chrome.scripting.RegisteredContentScript = {
    id: AUTOFILL_SCRIPT_ID,
    // Plain http included on purpose (loopback, intranet boxes): the browser injects only where a host permission is
    // held, and on a plain-http page only an address saved as http matches (F4, spec 05 autofill (e); grantflow.ts).
    matches: ["http://*/*", "https://*/*"],
    excludeMatches,
    js: ["content.js"],
    runAt: "document_idle",
    allFrames: true,
    persistAcrossSessions: true, // survives browser restarts; the SW-start reconcile covers the rest
  };
  try {
    const existing = (await chrome.scripting.getRegisteredContentScripts({ ids: [AUTOFILL_SCRIPT_ID] }))[0];
    if (!existing) {
      await chrome.scripting.registerContentScripts([desired]);
    } else if (!sameStringSet(existing.excludeMatches ?? [], excludeMatches)) {
      await chrome.scripting.updateContentScripts([desired]);
    }
  } catch {
    // Fail CLOSED (review 2026-07-16 D1): a failed register/update must NOT leave a STALE registration
    // whose excludeMatches are the OLD origin while serverUrl has moved to a new (un-excluded) vault
    // origin — that would inject content.js into the new vault's own UI (content.ts has no self-guard).
    // Drop to "no autofill anywhere"; the next SW-start / permissions.onAdded reconcile retries.
    await unregisterAutofillScripts();
  }
}

async function unregisterAutofillScripts(): Promise<void> {
  try {
    await chrome.scripting.unregisterContentScripts({ ids: [AUTOFILL_SCRIPT_ID] });
  } catch {
    /* not registered */
  }
}

function sameStringSet(a: string[], b: string[]): boolean {
  return a.length === b.length && [...a].sort().join("\n") === [...b].sort().join("\n");
}

// B2-5: every SW start reconciles the registration (module scope runs on install, browser
// startup, and every wake — including after a serverUrl change landed while this worker was dead).
void serverReady.then(registerAutofillScripts);
// A runtime host-permission grant (the wave-3 options flow; Firefox's first-run grant) can land
// while the SW is alive — reconcile immediately so autofill starts without a browser restart.
try {
  chrome.permissions.onAdded.addListener(() => void serverReady.then(registerAutofillScripts));
} catch {
  /* permissions events unavailable on this engine — the SW-start reconcile covers it */
}

// ---- server switch (§4.1 origin-clean rules) ----
// A15: the ONLY writer of the server choice is the `setServerUrl` message (commitServerUrl below), which the sender
// gate admits from our own pages only and the options page sends after the Trust Gate's Connect. Before A15 the
// worker switched on any storage.local write of the key (storage.onChanged), and a content script could make that
// write too. Serialized: two rapid switches apply in order, each locking under ITS old namespace first.
let switchChain: Promise<void> = Promise.resolve();

/**
 * Safari only: commit the andvari app's server origin (adoptAppAnswer). The app ran its own Trust Gate and card checks,
 * and the Safari extension inherits them through the app's snapshot (design §12.2), so no pin is made here.
 * Canonicalize, persist to the trusted store FIRST — a choice that cannot be kept changes nothing — then run the
 * origin-clean switch on the chain, answering only once it applied.
 */
async function commitServerUrl(raw: unknown): Promise<{ ok: boolean; url?: string; code?: "invalid" | "storage" }> {
  const canonical = typeof raw === "string" ? canonicalizeServerUrl(raw) : null;
  if (canonical === null || canonical === NO_SERVER_ORIGIN) return { ok: false, code: "invalid" };
  try {
    await setServerUrl(canonical, trusted);
  } catch {
    return { ok: false, code: "storage" };
  }
  trustedStoreOk = true;
  switchChain = switchChain.then(() => applyServerChange(canonical)).catch(() => {});
  await switchChain;
  // Lifted only once the switch took effect; a switch that did not apply leaves the server unknown in this worker life.
  if (serverUrl === canonical) dialBlock = null;
  else if (dialBlock !== null) dialBlock = { kind: "unsettled" };
  await registerAutofillScripts();
  return { ok: true, url: canonical };
}

/** No server has been chosen: the worker holds the never-resolving placeholder (serverurl.ts). */
function noServerChosen(): boolean {
  return serverUrl === NO_SERVER_ORIGIN;
}

/** What the pages show — the origin this worker's api is built for (what is in effect, not a store read), whether a
 *  server choice can be kept here at all, and a block: while one stands, no server is dialed. */
function serverInfo(): Res<"serverInfo"> {
  return { url: noServerChosen() ? "" : serverUrl, trustedStore: trustedStoreOk, block: dialBlock, name: currentPin === null ? null : nameText(currentPin.pin.name) };
}

// ---- the server choice and its card pin (design 2026-11-15 §4.4, §12.2 rule 3, §12.3) ----

const pinKeyFor = (origin: string): string => nsKey(originKeyFor(origin), PIN_KEY);
const clientHeader = (): string => `extension/${chrome.runtime.getManifest().version}`;

/** The stored pin for [origin], or null when the trusted store cannot be read (never "no pin"). */
async function readPin(origin: string): Promise<ReturnType<typeof decodeStoredPin> | null> {
  const k = pinKeyFor(origin);
  try {
    return decodeStoredPin((await trusted.get(k))[k], origin);
  } catch {
    return null;
  }
}

/** The Trust Gate's verified candidate for a typed origin, in memory only, until the person connects or goes. */
let gateCandidate: { origin: string; record: StoredPin; at: number } | null = null;
const GATE_TTL_MS = 10 * 60_000;
/** The last refresh found the chain ending below the pin (a state, shown; not a stop). Memory only. */
let cardWithheld = false;
/** The last refresh of the current origin found a chain that does not verify forward from the pin (a card after it with
 *  a bad signer or signature, a broken link). Not a stop: the pin stays at the last card checked, and the popup says so
 *  (before, a session's refresh swallowed this and nothing reached the popup). */
let cardInvalid = false;
/** "Not now" at a `kind` change (approved wording, entry 10): the notice for this card at this origin stays closed until
 *  the next unlock, and the old `kind` stays in force. Memory only: a worker restart shows the notice again, which is the
 *  side to err on. */
let kindDeferred: { origin: string; hash: string } | null = null;

/** Asked with the same match pattern the popup requests and autofill excludes
 *  (serverurl.ts originMatchPattern, no port): Firefox match patterns cannot carry a port, so a pattern with one never
 *  matched there and a server on a non-default port always answered `no_permission`. Not run in Firefox. */
async function hostPermitted(origin: string): Promise<boolean> {
  const pattern = originMatchPattern(origin);
  if (pattern === null) return false;
  try {
    return await chrome.permissions.contains({ origins: [pattern] });
  } catch {
    return false;
  }
}

/** Fetch [origin]'s chain and verify it whole, for a FIRST pin: a chain longer than MAX_FIRST_PIN_CARDS is refused
 *  before anything is verified (one long chain froze the worker for ~19 s). */
async function servedCards(origin: string): Promise<{ ok: true; cards: readonly Card[] } | { ok: false; code: "unavailable" | "card_invalid" | "chain_too_long" } | { ok: false; code: "redirected"; to: string | null }> {
  const fetched = await fetchInstanceChain(origin, clientHeader());
  if (!fetched.ok) return fetched;
  if (fetched.frames.length > MAX_FIRST_PIN_CARDS) return { ok: false, code: "chain_too_long" };
  const chain = verifyChain(fetched.frames);
  return chain.ok ? { ok: true, cards: chain.cards } : { ok: false, code: "card_invalid" };
}

/** Fetch [origin]'s chain and verify it forward from [stored]'s pin: the prefix by hash, then only the cards
 *  after the pin. A refresh's verdict, or why there is none. */
async function servedAgainstPin(origin: string, stored: StoredPin): Promise<{ ok: true; refreshed: ReturnType<typeof refreshPinForward> } | { ok: false; code: "unavailable" | "card_invalid" } | { ok: false; code: "redirected"; to: string | null }> {
  const fetched = await fetchInstanceChain(origin, clientHeader());
  if (!fetched.ok) return fetched;
  const fwd = verifyForward(fetched.frames, stored.pin);
  return fwd.ok ? { ok: true, refreshed: refreshPinForward(stored, fwd) } : { ok: false, code: "card_invalid" };
}

/** A chain that could not be had, as `chooseServer` answers it: a redirect carries where it points, when that is known. */
function refusedServe(r: { code: "unavailable" | "card_invalid" | "chain_too_long" } | { code: "redirected"; to: string | null }): Res<"chooseServer"> {
  if (r.code === "redirected") return r.to === null ? { ok: false, code: "redirected" } : { ok: false, code: "redirected", redirectTo: r.to };
  return { ok: false, code: r.code };
}

/** Make [origin] the server, with its stored pin [stored] already written: persist the choice, switch, lift the block. */
async function switchToPinned(origin: string, stored: StoredPin): Promise<Res<"confirmServer">> {
  try {
    await setServerUrl(origin, trusted);
  } catch {
    return { ok: false, code: "storage" };
  }
  switchChain = switchChain.then(() => applyServerChange(origin)).catch(() => {});
  await switchChain;
  if (serverUrl !== origin) return { ok: false, code: "storage" };
  currentPin = stored;
  cardWithheld = false;
  cardInvalid = false;
  dialBlock = stored.fork ? { kind: "fork", origin } : null;
  await registerAutofillScripts();
  await refuseHeldOperator(); // §12.2 rule 7: a refreshed or followed card may name this account the operator
  return { ok: true, url: origin };
}

/**
 * The first popup's two choices (§12.2): "andvari" pins the baked public instance from its `card0Hash`; "Your own
 * server" verifies the typed origin's chain and returns the Trust Gate's card line. A server this device already pinned
 * is refreshed against that pin and never re-pinned (a root never replaces an existing pin, §4.4). The public origin
 * typed by hand takes the baked root too. Nothing is sent but the unauthenticated `GET /instance`.
 */
async function chooseServer(msg: Extract<Req, { type: "chooseServer" }>): Promise<Res<"chooseServer">> {
  if (BUILD_TARGET === "safari") return { ok: false, code: "not_allowed" };
  await serverReady;
  if (!trustedStoreOk) return { ok: false, code: "storage" };
  const origin = msg.choice === "public" ? PUBLIC_INSTANCE.origin : canonicalizeServerUrl(typeof msg.origin === "string" ? msg.origin : "");
  if (origin === null || origin === NO_SERVER_ORIGIN) return { ok: false, code: "invalid" };
  // A test build knows no card 0 of the test server (publicinstance.ts): its "andvari" choice is refused as a build
  // without the public instance's card 0 refuses it, and the test server typed as one's own goes through the Trust Gate.
  const baked = (typeof __ANDVARI_TEST_SERVER__ !== "string" || msg.choice === "public") && origin === PUBLIC_INSTANCE.origin;
  const root = baked ? bakedRoot() : ({ root: "typed" } as const);
  if (root === null) return { ok: false, code: "no_public_instance" };
  if (!(await hostPermitted(origin))) return { ok: false, code: "no_permission" };
  const existing = await readPin(origin);
  if (existing === null) return { ok: false, code: "storage" };
  if (existing.kind === "damaged") return { ok: false, code: "pin_damaged" };
  if (existing.kind === "pin" && existing.stored.fork) return { ok: false, code: "fork" };
  if (existing.kind === "pin") {
    const served = await servedAgainstPin(origin, existing.stored);
    if (!served.ok) return refusedServe(served);
    const r = served.refreshed;
    if (r.verdict === "fork") {
      // The one fork routine: re-choosing the current server stops it at once, like a refresh does.
      await recordFork(origin, existing.stored, r.stored);
      return { ok: false, code: "fork" };
    }
    try {
      await trusted.set({ [pinKeyFor(origin)]: r.stored });
    } catch {
      return { ok: false, code: "storage" };
    }
    const out = await switchToPinned(origin, r.stored);
    cardWithheld = r.verdict === "withheld";
    return out;
  }
  const served = await servedCards(origin);
  if (!served.ok) return refusedServe(served);
  const first = firstPin(served.cards, root, origin);
  // Entry 8's wording names both addresses: the one dialed, and the one the newest card of the chain that just verified
  // names (never one from the page or an unverified answer).
  if (first.verdict === "origin_mismatch") return { ok: false, code: "origin_mismatch", mismatch: { dialed: origin, named: first.cardOrigin } };
  if (first.verdict !== "ok") return { ok: false, code: first.verdict };
  if (root.root === "baked") {
    // Store builds never follow a kind change of the baked public instance (§4.4), not even into a first pin.
    if (first.pin.kind !== PUBLIC_INSTANCE.kind) return { ok: false, code: "changed" };
    const stored = newStoredPin("baked", first.pin);
    try {
      await trusted.set({ [pinKeyFor(origin)]: stored });
    } catch {
      return { ok: false, code: "storage" };
    }
    return switchToPinned(origin, stored);
  }
  gateCandidate = { origin, record: newStoredPin("typed", first.pin), at: Date.now() };
  return {
    ok: true,
    gate: {
      origin,
      name: nameText(first.pin.name) ?? "",
      operatorShortFp: operatorShortFp(first.pin.operatorSignKey),
      hash: first.pin.hash,
      switching: !noServerChosen(),
    },
  };
}

/** The Trust Gate's Connect (§4.4 typed-address root): keep the candidate the gate showed, named by its card hash. */
async function confirmServer(msg: Extract<Req, { type: "confirmServer" }>): Promise<Res<"confirmServer">> {
  if (BUILD_TARGET === "safari") return { ok: false, code: "not_allowed" };
  const c = gateCandidate;
  if (c === null || c.origin !== msg.origin || c.record.pin.hash !== msg.hash || Date.now() - c.at > GATE_TTL_MS) return { ok: false, code: "stale" };
  gateCandidate = null;
  const existing = await readPin(c.origin);
  if (existing === null) return { ok: false, code: "storage" };
  if (existing.kind !== "none") return { ok: false, code: "stale" }; // a pin appeared meanwhile: choose again (refresh, never replace)
  try {
    await trusted.set({ [pinKeyFor(c.origin)]: c.record });
  } catch {
    return { ok: false, code: "storage" };
  }
  return switchToPinned(c.origin, c.record);
}

/** "Forget this server" (§12.3): remove the current server's pin and data, and choose none. The way out of a fork.
 *  The remembered email goes too (decided on 2026-11-16): after it, nothing in the browser names the account.
 *  It is one key for the whole browser, not one per server, so it goes whichever account it names; a sign-out keeps it
 *  (spec 05 A15 (c), a kept convenience). */
async function forgetServer(): Promise<Res<"forgetServer">> {
  if (BUILD_TARGET === "safari") return { ok: false };
  await serverReady;
  if (noServerChosen()) return { ok: true };
  const originKey = currentOriginKey;
  // A sign-in or a quick unlock in flight is left from here, before the first removal is
  // dispatched, not only from the switch below: one answered while the removal is under way would otherwise pass its
  // generation checks and write the device record or the remembered email back after it.
  redeemGen++;
  try {
    await trusted.remove([SERVER_URL_KEY, LAST_EMAIL_KEY]);
  } catch {
    return { ok: false };
  }
  switchChain = switchChain.then(() => applyServerChange(NO_SERVER_ORIGIN)).catch(() => {});
  await switchChain;
  await purgeOriginNamespace(originKey).catch(() => {});
  currentPin = null;
  cardWithheld = false;
  cardInvalid = false;
  dialBlock = { kind: "no_server" };
  await registerAutofillScripts();
  return { ok: true };
}

/** The person confirmed the pending move or `kind` change of a non-baked instance (§4.4). */
async function followServerChange(msg: Extract<Req, { type: "followServerChange" }>): Promise<Res<"followServerChange">> {
  if (BUILD_TARGET === "safari") return { ok: false, code: "not_allowed" };
  const stored = currentPin;
  const origin = serverUrl;
  if (stored === null || dialBlock !== null || stored.pending === null || stored.pending.card.hash !== msg.hash) return { ok: false, code: "none" };
  if (stored.pending.change === "kind") {
    const next = confirmKindChange(stored);
    if (next === null) return { ok: false, code: "none" };
    try {
      await trusted.set({ [pinKeyFor(origin)]: next });
    } catch {
      return { ok: false, code: "storage" };
    }
    currentPin = next;
    await refuseHeldOperator(); // §12.2 rule 7
    // §4.4: a card that also moved leaves the pin at its card with the accepted kind; the move is its own prompt, so
    // re-judge the served chain now rather than at the next refresh (CardTrust.kt acceptKindChange). Its failures are
    // the refresh's own (a fork blocks and locks there); the accepted kind stands either way.
    if (next.pin.hash !== stored.pending.card.hash) await ensureCardFresh().catch(() => {});
    return { ok: true, url: origin };
  }
  const moved = confirmMove(stored);
  if (moved === null) return { ok: false, code: "none" };
  // §4.4: the target is checked before either pin is touched — its origin grammar (a card's origin passed the
  // statement grammar, but the placeholder origin must never become a server), that a pin can be kept for it (a store,
  // and no pin there already: a move never replaces one, `pin_conflict`), and the host permission.
  if (canonicalizeServerUrl(moved.origin) !== moved.origin || moved.origin === NO_SERVER_ORIGIN) return { ok: false, code: "invalid" };
  if (!trustedStoreOk) return { ok: false, code: "storage" };
  const there = await readPin(moved.origin);
  if (there === null) return { ok: false, code: "storage" };
  if (there.kind !== "none") return { ok: false, code: "pin_conflict" };
  if (!(await hostPermitted(moved.origin))) return { ok: false, code: "no_permission" };
  // §4.4 "A namespace's trust records move with its pin": the marks, vault records, homes, device records and the rest
  // go to the new namespace with the new pin, in one write; the choice follows; the old namespace goes last, once the
  // switch took. A failure before the choice is kept takes the copy back, so the old origin stays as it was.
  const fromKey = currentOriginKey;
  let written: string[];
  try {
    written = await moveNamespaceRecords(trusted, fromKey, originKeyFor(moved.origin), { [pinKeyFor(moved.origin)]: moved.stored });
  } catch {
    return { ok: false, code: "storage" };
  }
  try {
    await setServerUrl(moved.origin, trusted);
  } catch {
    await trusted.remove(written).catch(() => {});
    return { ok: false, code: "storage" };
  }
  const out = await switchToPinned(moved.origin, moved.stored);
  if (out.ok) await purgeOriginNamespace(fromKey).catch(() => {});
  return out;
}

/** "Not now" at the `kind` change notice (entry 10; §4.4 "until the person confirms, the client keeps using the old
 *  kind"): the notice for that pending card closes until the next unlock. Nothing is written; the pin is untouched. */
function deferServerChange(msg: Extract<Req, { type: "deferServerChange" }>): Res<"deferServerChange"> {
  if (BUILD_TARGET === "safari") return { ok: false };
  const p = currentPin;
  if (p === null || dialBlock !== null || p.pending?.change !== "kind" || p.pending.card.hash !== msg.hash) return { ok: false };
  kindDeferred = { origin: serverUrl, hash: msg.hash };
  return { ok: true };
}

/** The plain storage.session marker of a fork seen at [origin] (sessionseal.ts `forkSeen`). */
const forkMarkKey = (origin: string): string => nsKey(originKeyFor(origin), "forkSeen");
/** Waits between the tries of a fork's durable write. */
const FORK_WRITE_RETRY_MS = [0, 250, 1000] as const;

/**
 * Design §4.4: the ONE routine for a fork, wherever one is seen (a refresh, re-choosing a
 * server). It stops all traffic to the origin at once when it is the current one — the block (every api call refuses,
 * makeApi), the socket, any sign-in or redeem in flight — and keeps the fork durably: the pin record with `fork` set,
 * with a retried write, and a storage.session marker that keeps the origin stopped across worker restarts in this
 * browser session should every try fail. It does not lock: a fork stops traffic, not reading (§4.4), so what this
 * browser already holds stays readable; nothing is written (putItem) and nothing from the origin is accepted (resync).
 */
async function recordFork(origin: string, judged: StoredPin, forked: StoredPin): Promise<void> {
  // The mark is compare-and-set. It is written only while the pin that was
  // judged is still the one held — in memory for the current origin, and in the store before every try — so a judgement
  // that comes back late (a refresh or a re-choice whose fetch waited across "Forget this server" and a new Trust Gate,
  // or a retried write after a Forget) never replaces a newer pin, nor brings a forgotten one back.
  if (origin === serverUrl && !samePinPosition(currentPin, judged)) return;
  if (origin === serverUrl) {
    currentPin = forked;
    dialBlock = { kind: "fork", origin };
    cardWithheld = false;
    events?.close();
    events = null;
    redeemGen++; // a sign-in or quick redeem in flight sends nothing more and installs nothing
    clearPendingTotp();
  }
  const kFork = forkMarkKey(origin);
  await plainSession.set({ [kFork]: true }).catch(() => {});
  for (const wait of FORK_WRITE_RETRY_MS) {
    if (wait > 0) await delay(wait);
    if (origin === serverUrl && currentPin !== forked) return; // a newer pin, or none (Forget), since: write nothing
    const held = await readPin(origin);
    if (held === null) continue; // the store did not answer: tried again below
    if (held.kind !== "pin" || !samePinPosition(held.stored, judged)) return; // the store holds a newer pin, or none
    try {
      await trusted.set({ [pinKeyFor(origin)]: forked });
      return;
    } catch {
      /* tried again below */
    }
  }
  console.warn("andvari: a fork could not be stored; it holds for this browser session only");
}

/** Whether [a] is the pin [b] at the same card of the same chain (a fork mark or a pending change aside). */
function samePinPosition(a: StoredPin | null, b: StoredPin): boolean {
  return a !== null && a.pin.card0Hash === b.pin.card0Hash && a.pin.seq === b.pin.seq && a.pin.hash === b.pin.hash && a.pin.origin === b.pin.origin;
}

/** At worker start: a fork this browser session saw at [origin] whose durable write never landed (recordFork). */
async function forkMarked(origin: string): Promise<boolean> {
  try {
    return (await plainSession.get(forkMarkKey(origin)))[forkMarkKey(origin)] === true;
  } catch {
    return false;
  }
}

/** Thrown before anything password-derived leaves when the card check stops a sign-in (§4.4). */
class CardStopError extends Error {
  readonly code: "server_fork" | "card_invalid" | "confirm_server";
  constructor(code: "server_fork" | "card_invalid" | "confirm_server") {
    super(code);
    this.code = code;
    this.name = "CardStopError";
  }
}

/**
 * "On every policy probe or sync" (§4.4): fetch the chain and verify it forward from the pin. A fork is stored (durable),
 * blocks the origin and locks any session; a withheld chain is a state; a rename, handover or rotation advances the pin;
 * a move or kind change waits for the person (or, for the baked instance, is never followed). Throws [CardStopError] for
 * a stop and a TypeError (network) when the chain cannot be fetched; resync swallows both, a sign-in does not.
 */
async function ensureCardFresh(): Promise<void> {
  if (BUILD_TARGET === "safari") return;
  await serverReady;
  const origin = serverUrl;
  const stored = currentPin;
  if (dialBlock !== null || stored === null) throw new CardStopError(dialBlock?.kind === "fork" ? "server_fork" : "confirm_server");
  const served = await servedAgainstPin(origin, stored);
  if (!served.ok) {
    if (served.code === "card_invalid") {
      if (serverUrl === origin && currentPin === stored) cardInvalid = true;
      throw new CardStopError("card_invalid");
    }
    throw new TypeError("the server's identity card could not be fetched");
  }
  if (serverUrl !== origin || currentPin !== stored) throw new CardStopError("confirm_server"); // switched meanwhile
  cardInvalid = false;
  const r = served.refreshed;
  if (r.verdict === "fork") {
    await recordFork(origin, stored, r.stored); // blocks and stops traffic; the session stays readable (§4.4)
    throw new CardStopError("server_fork");
  }
  if (r.stored !== stored) {
    currentPin = r.stored;
    await trusted.set({ [pinKeyFor(origin)]: r.stored }).catch(() => {}); // an advance not kept is re-derived next time
  }
  cardWithheld = r.verdict === "withheld";
  await refuseHeldOperator(); // §12.2 rule 7: at every card refresh, not only at unlock
}

/**
 * §12.2 rule 7: whether the newest verified card this browser holds for the current origin names [userId] as the
 * instance's operator. That is the pin, or a verified move or `kind` change still waiting for the person (it is the
 * newest verified card too, and a handover can ride on it). A forked record is not read: nothing on it is trusted.
 */
function cardNamesOperator(userId: string): boolean {
  const p = currentPin;
  if (p === null || p.fork) return false;
  return p.pin.operator === userId || p.pending?.card.operator === userId;
}

/**
 * §12.2 rule 7, by the card: a handover made after sign-in that names the signed-in account as the operator signs it
 * out, as the phone apps do (a full sign-out: the session is revoked, the quick-unlock record wiped), and the popup
 * says why with the sentence the sign-in refusal uses. Run wherever the pin can change under a live session: every
 * card refresh (ensureCardFresh), a server (re)chosen or a move followed (switchToPinned), an accepted `kind` change.
 *
 * What stays open, and why the extension cannot close it alone: between a handover and this browser's next card refresh
 * (every resync, at most RESYNC_PERIOD_MIN apart while the browser is awake, at once on a server bell, and before every
 * sign-in and quick unlock) the browser holds a live session of an account the server now treats as the operator, a
 * token with the operator's powers in a client that must not hold one. The extension never calls an operator route, so
 * refreshing the card more often would narrow the time it is held, not end it: only the server knows the moment of the
 * handover. The server closes it by ending, at the handover, the incoming operator's sessions on clients that refuse
 * that account (it knows them from the client name each sign-in carried), or by ringing every socket when it serves a
 * new card, which makes this browser refresh its card within a second (events.ts bell, then resync).
 */
async function refuseHeldOperator(): Promise<boolean> {
  const s = session;
  if (s === null || !cardNamesOperator(s.userId)) return false;
  await doSignOut(true);
  await plainSession.set({ [NKEY]: { kind: "operator" } }).catch(() => {});
  return true;
}

/** The card notice the popup shows beside a working server (status). */
function cardNotice(): Res<"status">["cardNotice"] {
  const p = currentPin;
  if (BUILD_TARGET !== "safari" && dialBlock?.kind === "fork") return { kind: "fork", origin: dialBlock.origin };
  if (BUILD_TARGET === "safari" || p === null || dialBlock !== null) return null;
  if (p.changed) return { kind: "changed" };
  if (p.pending?.change === "move") return { kind: "move", name: nameText(p.pin.name) ?? "", from: p.pin.origin, to: p.pending.card.origin, hash: p.pending.card.hash };
  if (p.pending?.change === "kind" && !(kindDeferred !== null && kindDeferred.origin === serverUrl && kindDeferred.hash === p.pending.card.hash)) return { kind: "kind", name: nameText(p.pin.name) ?? "", origin: p.pin.origin, to: p.pending.card.kind, hash: p.pending.card.hash };
  if (cardInvalid) return { kind: "invalid" };
  return cardWithheld ? { kind: "withheld" } : null;
}

/** The device record for a sign-in as [email] here (device.ts), written BEFORE the login so the secret the server hashes
 *  is one this browser keeps. Null `key`: nothing can be kept (no store), so this sign-in is a new device. */
/**
 * The session a password sign-in replaces, named in its login (spec 03 §2 `replacesRefreshToken`): the refresh token of
 * the pair a lock stashed on this server for quick unlock, when that record is the same account's (its email) and this
 * browser's row for the email is known (has a deviceId). Null otherwise: nothing else is named, and a record that
 * cannot be read names nothing. On the extension's row the server ends every earlier session of the row at a sign-in
 * anyway; the name adds which session this one replaces, and whether its token had been replaced since (a lost refresh
 * answer, or someone else's use of the token).
 */
async function replacedRefreshToken(email: string, device: DeviceRecord): Promise<string | null> {
  const n = emailNorm(email);
  if (device.deviceId === null || n === null) return null;
  try {
    const kept = keptUnconfirmed !== null && emailNorm(keptUnconfirmed.email) === n ? keptUnconfirmed.refreshToken : null;
    const rec = await quStore.read();
    if (rec === null || emailNorm(rec.email) !== n) return kept;
    return rec.lockedTokens?.refresh ?? kept;
  } catch {
    return null;
  }
}

/** The token of a session that ended here with no try left (api.ts noTryLeft), with the address it was for: kept in this
 *  worker's memory for one use, the next sign-in's name for the session it replaces. Never sent as a refresh. */
let keptUnconfirmed: { email: string; refreshToken: string } | null = null;

/**
 * A person's own sign-out of an account (the session's, or while locked the address the extension remembers): nothing
 * that may still be a live credential of that account stays here after it. Its kept token goes, and so does a token
 * whose refresh got no answer and is still held (the sign-out never spends either). True when there was one: the
 * sign-out then says that the end of that session could not be confirmed with the server, and how to end it. Another
 * account's kept token stays.
 */
async function dropKeptAtSignOut(): Promise<boolean> {
  const who = session?.email ?? (await readRememberedEmail());
  const email = who === null ? null : emailNorm(who);
  const kept = keptUnconfirmed !== null && email !== null && emailNorm(keptUnconfirmed.email) === email;
  if (kept) keptUnconfirmed = null;
  return kept || (session !== null && api.unansweredRefreshToken() !== null);
}

async function deviceRecordFor(email: string, current: () => boolean = () => true): Promise<{ rec: DeviceRecord; key: string | null }> {
  const n = emailNorm(email);
  if (n === null) return { rec: newDeviceRecord(), key: null };
  const key = nsk(deviceKey(n));
  try {
    const held = decodeDeviceRecord((await trusted.get(key))[key]);
    if (held !== null) return { rec: held, key };
    const fresh = newDeviceRecord();
    // [current] is the sign-in's own check (the attempt and its server). A sign-in left behind while the
    // store was read (a lock, a switch, "Forget this server") writes no record into a namespace that may be gone.
    if (!current()) return { rec: fresh, key: null };
    await trusted.set({ [key]: fresh });
    return { rec: fresh, key };
  } catch {
    return { rec: newDeviceRecord(), key: null };
  }
}

/** After a login: remember the device row the server created or reused, so the next sign-in is a known device. */
async function rememberDevice(dev: { rec: DeviceRecord; key: string | null }, deviceId: string): Promise<void> {
  if (dev.key === null || dev.rec.deviceId === deviceId) return;
  await trusted.set({ [dev.key]: { deviceSecret: dev.rec.deviceSecret, deviceId } }).catch(() => {});
}

// ---- Safari: the andvari app's server (appserver.ts) ----

/** The app's bundle id. Safari routes a native message to the containing app's extension handler whatever this says. */
const SAFARI_NATIVE_APP = "com.silencelen.andvari";

let appServerInFlight: Promise<Res<"appServer">> | null = null;
/** Safari: whether this iOS offers to save passwords to andvari itself (26.2 and later; the handler says). While it
 *  does, this extension captures nothing and shows no save prompt. Null until the handler has answered once. */
let systemSavesPasswords: boolean | null = null;
/** The last ask, for the popup's Details (serverDiag). No secret: kinds, an error text and what adopting came to. */
const appServerDiag: Pick<ServerDiag, "native" | "nativeError" | "app" | "adopt"> = { native: "not_asked", nativeError: null, app: null, adopt: null };
/** How long an ask waits for worker start before it gives up (start is bounded step by step; this bounds the whole). */
const APP_SERVER_START_WAIT_MS = 12_000;

/** What the popup's Details shows. Reads variables only, so it answers while worker start is still running. */
function serverDiag(): ServerDiag {
  return {
    stage: startStage, migration: startMigration, block: dialBlock?.kind ?? null, store: trustedStoreOk, url: serverUrl, ...appServerDiag,
    vaultOpen: APP_VAULT?.diag.open ?? null, vaultSecret: APP_VAULT?.diag.secret ?? null,
    pageOrigin: pageOriginLast === null ? null : `last from ${pageOriginLast} (origin ${pageOriginSeen.origin}, frame url ${pageOriginSeen.url}, none ${pageOriginSeen.none})`,
    providerFrame: providerFrameDiag,
  };
}

/**
 * The trusted store cannot keep a choice in this worker life (no IndexedDB, or it does not answer), and the app named
 * its server. Use it for this worker life without keeping it: the same origin-clean switch, and the block lifts once
 * the switch applied. A15 holds: the origin came from the app's own storage through the native handler, which no page
 * or content script can write, and the app ran the Trust Gate on it. The cost is that nothing is remembered, so every
 * worker start asks the app again and stays on its start state until the app answers.
 */
async function adoptAppServerUnkept(canonical: string): Promise<boolean> {
  switchChain = switchChain.then(() => applyServerChange(canonical)).catch(() => {});
  await switchChain;
  if (serverUrl !== canonical) return false;
  dialBlock = null;
  await registerAutofillScripts();
  return true;
}

/**
 * Safari: the app has no server now, so the one this extension adopted from it goes too (spec 03 §13: an account deleted
 * in the app leaves the device as a fresh install, with nothing of the account's server). The kept choice goes FIRST,
 * with the remembered email (as "Forget this server" does: nothing here names the account afterwards): if the store
 * holds them and will not let them go, nothing changes and the next ask tries again. Then the app's vault is closed, the
 * worker returns to the placeholder origin through the origin-clean switch, whatever it kept under the old origin is
 * removed, and the block a first install starts with stands again until the app names a server. True when no server is
 * in effect afterwards.
 */
async function forgetAppServer(): Promise<boolean> {
  const oldKey = currentOriginKey;
  // A sign-in or a quick unlock in flight is left from here, as "Forget this server" leaves it.
  redeemGen++;
  try {
    await trusted.remove([SERVER_URL_KEY, LAST_EMAIL_KEY]);
  } catch {
    if (trustedStoreOk) return false;
    // No store in this worker life: the server was never kept, only used (adoptAppServerUnkept).
  }
  APP_VAULT?.close();
  switchChain = switchChain.then(() => applyServerChange(NO_SERVER_ORIGIN)).catch(() => {});
  await switchChain;
  if (!noServerChosen()) return false;
  await purgeOriginNamespace(oldKey).catch(() => {});
  dialBlock = { kind: "unsettled" };
  // A block that stands dials nothing, a live socket included (as at worker start).
  events?.close();
  events = null;
  await registerAutofillScripts();
  return true;
}

/**
 * Safari on iOS: ask the andvari app for the server it chose and adopt it when this worker dials another, through
 * commitServerUrl (the trusted store, then the origin-clean switch) and with no Trust Gate of its own: the person
 * confirmed this origin in the app. Asked at worker start and on every popup open; concurrent asks share one round
 * trip. Other builds answer "unavailable" and send nothing.
 */
function syncAppServer(): Promise<Res<"appServer">> {
  if (BUILD_TARGET !== "safari") return Promise.resolve({ app: "unavailable" });
  appServerInFlight ??= (async (): Promise<Res<"appServer">> => {
    try {
      appServerDiag.native = "waiting_for_start";
      const started = await Promise.race([serverReady.then(() => true), delay(APP_SERVER_START_WAIT_MS).then(() => false)]);
      if (!started) return { app: "unavailable" };
      // Never while the earlier build's session is still being retired: adopting a server switches the origin, and
      // the retirement must lock and revoke under the old one.
      await Promise.race([ownSessionRetired, delay(APP_SERVER_START_WAIT_MS)]);
      appServerDiag.native = "asking";
      const askedAt = Date.now();
      const asked = await askAppServerDetailed(nativeSender(globalThis as Parameters<typeof nativeSender>[0], SAFARI_NATIVE_APP));
      appServerDiag.native = asked.call;
      if (asked.call === "resolved") systemSavesPasswords = asked.nativeSave;
      appServerDiag.nativeError = asked.error;
      appServerDiag.app = asked.answer.kind;
      return await adoptAppAnswer(asked.answer, "", askedAt);
    } catch (e) {
      appServerDiag.adopt = `failed: ${String(e).slice(0, 200)}`;
      return { app: "unavailable" };
    } finally {
      appServerInFlight = null;
    }
  })();
  return appServerInFlight;
}

/** One adoption at a time: the worker's own ask and an answer the popup relays can arrive together. */
let appAdoptChain: Promise<unknown> = Promise.resolve();
/** When the newest answer handled so far was asked for (round-5 review L8): an answer asked for earlier is stale. */
let newestAppAnswerAt = 0;

/**
 * Adopt what the app answered, when it names a server other than the one in effect (commitServerUrl: the trusted store,
 * then the origin-clean switch). [via] is added to the Details' account of it ("" for the worker's own ask). [askedAt]
 * is when that answer was asked for: answers are handled one at a time, and one asked for before the newest already
 * handled is dropped, so a slow ask cannot move the extension back to what the app said earlier.
 */
function adoptAppAnswer(answer: AppServerAnswer, via: string, askedAt: number): Promise<Res<"appServer">> {
  const run = async (): Promise<Res<"appServer">> => {
    if (!(askedAt >= newestAppAnswerAt)) {
      appServerDiag.adopt = `an older answer was dropped${via}`;
      return { app: dialBlock === null && !noServerChosen() ? "set" : "unavailable" };
    }
    newestAppAnswerAt = askedAt;
    const adopt = appServerToAdopt(answer, dialBlock === null ? serverUrl : null, BUILD_TARGET);
    if (adopt === null) {
      // The app has no server (an account deleted in it leaves the device as a fresh install): the one adopted from it
      // goes from here too.
      if (appServerToForget(answer, !noServerChosen(), BUILD_TARGET)) {
        const forgotten = await forgetAppServer();
        appServerDiag.adopt = `${forgotten ? "forgotten: the app has no server" : "the app has no server, but this one could not be forgotten"}${via}`;
        return { app: "none" };
      }
      if (answer.kind === "set") appServerDiag.adopt = `already in effect${via}`;
      else if (via === "") appServerDiag.adopt = null;
      return { app: answer.kind };
    }
    const r = await commitServerUrl(adopt);
    if (r.ok) {
      // commitServerUrl lifts the block only when the switch applied; say so when it did not.
      const applied = serverUrl === adopt && dialBlock === null;
      appServerDiag.adopt = `${applied ? "adopted" : "kept, but the switch did not apply"}${via}`;
      return { app: applied ? "set" : "unavailable" };
    }
    if (r.code === "storage" && (await adoptAppServerUnkept(adopt))) {
      appServerDiag.adopt = `adopted for this session (the store did not keep it)${via}`;
      return { app: "set" };
    }
    appServerDiag.adopt = `not adopted (${r.code ?? "unknown"})${via}`;
    return { app: "unavailable" };
  };
  const next = appAdoptChain.then(run, run);
  appAdoptChain = next.catch(() => {});
  return next;
}

/**
 * Safari: the popup asked the app itself and relays the answer (on a device the worker's own ask timed out while the
 * popup's, a moment later, resolved: the worker then kept no server). Only this extension's own pages may send it
 * (sendergate.ts); content scripts cannot. The answer is read with the same parser as the worker's own and adopted the
 * same way, after worker start and the retirement of an earlier build's session, as the worker's own ask waits for.
 */
async function adoptRelayedAppServer(msg: Extract<Req, { type: "appServerAnswer" }>): Promise<Res<"appServerAnswer">> {
  if (BUILD_TARGET !== "safari") return { app: "unavailable" };
  const answer = parseAppServerReply({ ok: true, type: "appServer", url: msg.url });
  if (answer.kind === "unavailable") return { app: "unavailable" };
  const started = await Promise.race([serverReady.then(() => true), delay(APP_SERVER_START_WAIT_MS).then(() => false)]);
  if (!started) return { app: "unavailable" };
  await Promise.race([ownSessionRetired, delay(APP_SERVER_START_WAIT_MS)]);
  if (typeof msg.nativeSave === "boolean") systemSavesPasswords = msg.nativeSave;
  const askedAt = typeof msg.askedAt === "number" && Number.isFinite(msg.askedAt) ? msg.askedAt : 0;
  return adoptAppAnswer(answer, " (the popup's answer)", askedAt);
}

// Safari: the earlier build's own session is retired first (ownSessionRetired), under the origin it was made at. A
// handler that has not answered yet (it is started on demand) is asked again a little later, twice at most.
void serverReady.then(async () => {
  for (const wait of [0, 5_000, 20_000]) {
    if (BUILD_TARGET !== "safari") return;
    if (wait > 0) await delay(wait);
    await syncAppServer();
    if (appServerDiag.native === "resolved") return;
  }
});

/** Apply a server change. Order is the whole story (§4.1): lock under the OLD origin
 *  first — the armed branch stashes the live token pair into the OLD origin's quick-unlock record
 *  (PRESERVED per B2-7, never wiped: an A→B→A round trip keeps A's PIN, bounded by the staleness
 *  ceiling) — then swap in a FRESH api (a new instance carries no tokens, so no Authorization
 *  header can cross the change) + the new namespace key, then recompute the autofill exclusions.
 *  Old-origin namespaces are wiped ONLY through purgeOriginNamespace: "Forget this server", a followed move's old
 *  namespace, the Safari retirement, and (trust records kept) "Remove data for this server". */
async function applyServerChange(nextUrl: string): Promise<void> {
  await ensureLoaded();
  clearPendingTotp(); // a challenge belongs to the OLD origin — never carry its authKey across a switch
  // The §4.1 origin-clean swap ORDER (bump redeemGen → lock-under-OLD → adopt new origin → swap in a
  // FRESH api for it → re-register autofill) lives in the serverswitch leaf, so serverswitch.test.ts
  // drives it with a real AndvariApi and proves no Authorization header crosses the change (B1-5).
  // background wires the chrome-coupled dependencies; the no-op-when-unchanged check is inside the leaf.
  await applyServerSwitch<AndvariApi>({
    nextUrl,
    currentUrl: serverUrl,
    hasSession: session !== null,
    bumpRedeemGen: () => {
      redeemGen++; // an in-flight PIN redeem belongs to the old origin — it discards itself (owns() guard)
    },
    lock: () => doLock("manual"), // still under the OLD originKey: the stash lands in the old namespace
    makeApi,
    installApi: (a) => {
      api = a;
    },
    setOrigin: (u) => {
      serverUrl = u;
      currentOriginKey = originKeyFor(u);
    },
    registerAutofill: registerAutofillScripts,
  });
}

/** Wave-3 hook (§4.2): the ONLY destructive per-origin path. "Forget this server", a followed move (the old namespace),
 *  the Safari retirement and, with `keepTrust`, the options page's "Remove data for this server" call this with THAT
 *  origin's key. Removes that origin's namespaced keys everywhere (the trusted store + storage.local's pre-A15
 *  leftovers + storage.session + the IDB co-key) and touches nothing else; safe for current and
 *  non-current origins alike. A15: by prefix as well as by the fixed list, so the per-user records
 *  (item homes, the personal wrap, a pending change) go too — the fixed list never had them. */
export async function purgeOriginNamespace(originKey: string, opts: { keepTrust?: boolean } = {}): Promise<void> {
  // H59 (2026-09-13 audit): KLKEY belongs on this list and was missing from it — the classic
  // "control written for the set of keys that existed at the time, reopened by an addition"
  // (the known-logins digest landed 2026-08-18, after this purge path). The record is exactly
  // the per-origin state this action promises to erase: a random 16-byte HMAC key beside
  // truncated (site, username) digests, whose stated disclosure bound is that someone who can
  // read the locked compartment can test GUESSED (site, username) pairs against it. Leaving it
  // standing meant options.ts's "This removes only this browser's PIN / quick-unlock and cached
  // state for that server." was false about the one piece of cached state with a disclosure
  // bound of its own, and a re-connect to the same origin reused the stale digests as-is.
  // KLKEY is storage.session-only, so the local.remove below is a harmless no-op for it; the
  // list stays SINGLE on purpose, so a future namespaced key cannot be swept from one area and
  // forgotten in the other.
  const keys = [QKEY, KLKEY, DKEY, BKEY, UKEY, ULAST, USEQ, UQUIET].map((k) => nsKey(originKey, k));
  try {
    await chrome.storage.local.remove(keys);
  } catch {
    /* best-effort */
  }
  try {
    await sessionSeal.removeKeys(keys); // A16: through the seal, so a sealed write still in flight for this origin is dropped
  } catch {
    /* storage.session unavailable */
  }
  // Removing the record is only half the wipe: the HMAC key is ALSO cached in SW memory, and a
  // later refreshKnownLogins() for this origin would re-mint the very digests we just erased
  // under the very key we just erased. Null it so the next rebuild mints a fresh key — the same
  // pairing doLock's sign-out branch already does (wipe + `knownLoginsKey = null` together).
  // Guarded on the current origin because the cache only ever holds THAT origin's key.
  if (originKey === currentOriginKey) knownLoginsKey = null;
  // A15: every `ns.<originKey>.` record in every store, per-user ones included (serverswitch.purgeOriginRecords).
  // "Remove data for this server" (keepTrust) keeps the trust records (isTrustRecord).
  await purgeOriginRecords(originKey, [trusted, legacyLocal, sessionSeal.purgeArea()], opts.keepTrust === true ? isTrustRecord : null);
  try {
    await idbRun<void>("readwrite", (s) => s.delete(nsKey(originKey, IDB_KEY)));
  } catch {
    /* IDB unavailable */
  }
}

// Re-offer a pending save once the post-login navigation lands. Belt: the content script also
// polls pendingSave on load; braces: this reaches SPAs that "complete" without a fresh script.
atLoad("tabs.onUpdated", () => chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status !== "complete") return;
  void (async () => {
    await ensureLoaded();
    const st = tabs.get(tabId);
    if (!st) return;
    // 2026-08-18: TTL / quiet / once-per-gap throttle — the every-page-load re-offer was the
    // second amplifier of the locked over-prompting (the digest suppression being the first).
    const pending = gateReoffer(tabId, st);
    if (!pending) return;
    const msg: TabMsg = { type: "offerPendingSave", pending: publicPending(pending) };
    try {
      // Frame 0 only — the render is isTop-gated content-side anyway, so the wide broadcast only
      // ever delivered the pending metadata into every cross-origin frame's content script.
      await chrome.tabs.sendMessage(tabId, msg, { frameId: 0 });
    } catch {
      /* content not injected in that tab (yet) — its own pendingSave poll covers it */
    }
  })();
}));

// S3 registry hygiene (F28, Tier 1 §7): a top-level navigation invalidates every frame's recorded
// card form AND any armed card grant — clear both the moment the tab starts LOADING, before the
// new document could be offered against a stale record. Reads ONLY `changeInfo.status` — NEVER
// `changeInfo.url`/`tab.url` ([A4], pinned [T15]: a url read outside the popup-open activeTab
// window would be a `tabs`-permission bump; the status === "complete" listener above is the
// permission-less precedent). bfcache back-navigations never re-fire content init — there the
// [T4] rescanCardForms sig reset is what restores the offer.
atLoad("tabs.onUpdated", () => chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status !== "loading") return;
  grants.delete(tabId); // q39: a navigation voids the login grant too — it was minted for the OLD document
  cardGrants.delete(tabId);
  cardReports.delete(tabId); // the frames that reported were the OLD document's
  // C1 [S2]: the topOrigin erase below is ASYNC (it must await ensureLoaded), so mark the tab
  // stale SYNCHRONOUSLY — right here, before the first await — or the chip gate would spend that
  // window comparing the NEW document's sender.origin against the OLD document's recorded origin.
  topOriginPendingClear.add(tabId);
  // [S-rate]/[S4b] the throttle caches are nav-lifetime too: a navigation must invalidate the
  // cached chip verdict exactly as it invalidates cardGrants/pendingCardSave — a replay of the
  // PREVIOUS document's `fillable:true` inside the 250 ms window would void the [S2] check for
  // the new document (and a stale repair stamp could deny a fresh document its [S4b] repair).
  chipOfferLast.delete(tabId);
  chipRepairLast.delete(tabId);
  pendingCardSave.delete(tabId); // [X2-A2b] a top-level nav voids any pending card save (PAN)
  cardCaptureDedupe.delete(tabId);
  reuseNotices.delete(tabId); // the warning was about the page the user left
  // V4 (design §V4): a nav invalidates this tab's card registry (below), so a "card here" dot must
  // not outlive the form — clear it NOW, but ONLY when the badge IS that dot. A login count outranks
  // the dot and is repainted by the destination's own pageInfo, so it is left untouched (getBadgeText/
  // setBadgeText need no new permission). Covers content-less destinations (chrome://, un-granted
  // origins) where no pageInfo would ever arrive to clear a stale dot.
  chrome.action
    .getBadgeText({ tabId })
    .then((cur) => (cur === CARD_BADGE_TEXT || cur === REUSE_BADGE_TEXT ? chrome.action.setBadgeText({ tabId, text: "" }) : undefined))
    .catch(() => {});
  void (async () => {
    try {
      await ensureLoaded();
      const st = tabs.get(tabId);
      if (st === undefined || (st.cardForms === undefined && st.topOrigin === undefined)) return; // nothing recorded — skip the storage write
      if (st.cardForms !== undefined) delete st.cardForms;
      // The badge's recorded top origin dies with the document too — a stale origin could paint
      // the NEXT document's badge off the previous page's identity (review-fold, [A4]-adjacent).
      if (st.topOrigin !== undefined) delete st.topOrigin;
      persistTabs();
    } finally {
      // [S2] close the window in a `finally`: EVERY path above (the nothing-recorded early return,
      // a rejected ensureLoaded) must reopen the gate, or one failed hydrate would blind the chip
      // on that tab for the rest of the SW's life.
      topOriginPendingClear.delete(tabId);
    }
  })();
}));

atLoad("tabs.onRemoved", () => chrome.tabs.onRemoved.addListener((tabId) => {
  grants.delete(tabId);
  cardGrants.delete(tabId);
  cardReports.delete(tabId);
  pendingCardSave.delete(tabId); // [X2-A2b]
  cardCaptureDedupe.delete(tabId);
  // C1 hygiene: the per-tab chip throttles + the [S2] stale marker die with the tab (a closed tab
  // can never send again, so this is memory reclamation only — never a gate that opens).
  topOriginPendingClear.delete(tabId);
  chipOfferLast.delete(tabId);
  reuseAskLast.delete(tabId); // H02: same lifetime as the chip throttle
  reuseNotices.delete(tabId);
  chipRepairLast.delete(tabId);
  void (async () => {
    await ensureLoaded();
    if (tabs.delete(tabId)) persistTabs();
  })();
}));

// ---- session custody ----

/** Lazy wake path: one storage.session read per SW life hydrates session + tab state. A16: both records are sealed —
 *  read through the seal, which waits for its key (bounded) and answers absent for anything that does not open (a
 *  tampered or swapped record, one sealed before the last lock, plaintext): absent means locked. A16 review R4/R1: a
 *  lock or a browser-start report that runs while this load is reading makes it install NOTHING it read (hydrateGen,
 *  checked after the last await, right before the install): the lock erased first, and a report means no session can
 *  exist. */
function ensureLoaded(): Promise<void> {
  loadPromise ??= (async () => {
    const gen = hydrateGen;
    await serverReady; // api/originKey/namespace reflect the persisted origin before any state hydrates
    let snap = (await sessionSeal.get("session", currentOriginKey)) as SessionSnapshot | undefined;
    const tabsRead = (await sessionSeal.get("tabs", currentOriginKey)) as Record<string, TabState> | undefined;
    // §4.1 rule 1 (no token replay across a serverUrl change): a snapshot minted against another
    // origin is DROPPED, not hydrated — the user re-unlocks at the new server. A pre-0.16 snapshot
    // (no `origin` field) fails the same check: fail closed, never guess.
    if (snap && snap.origin !== serverUrl) {
      snap = undefined;
      await sessionSeal.remove("session", currentOriginKey);
    }
    // A1b item homes: a snapshot persisted before they existed carries none; the durable record (trusted store) is
    // reloaded then (A9: an empty map here would have been taken as authoritative and overwritten it). Read before the
    // install below, so nothing is awaited between the hydrateGen check and the install.
    // A record that cannot be read (null) installs nothing: the session stays locked rather than guess its homes.
    const snapHomes = snap && !session ? (snap.homes ? new Map(Object.entries(snap.homes)) : await loadHomes(snap.userId)) : null;
    if (gen !== hydrateGen) return; // a lock or a browser-start report ran meanwhile: install nothing read before it
    // Design §4.4: under a fork what this browser holds stays readable, so the session is restored (it dials nothing:
    // the block refuses every request). Under any other block — a damaged pin above all, where nothing it holds can be
    // checked against anything, or a pin that could not be read — no session is restored.
    const readable = dialBlock === null || dialBlock.kind === "fork";
    // §12.2 rule 7: a session of the account the pin names as operator is never restored (the refresh that stored such
    // a pin signed it out; a worker that stopped half-way through that sign-out restores nothing either).
    if (snap && !session && snapHomes && readable && !cardNamesOperator(snap.userId)) {
      tokenOwner++; // the restored session's pair now owns the api (endAbandonedSignIn)
      api.setTokens(snap.access || null, snap.refresh);
      pairUser.set(api, snap.userId);
      const vaultKeys = new Map(Object.entries(snap.vaultKeys).map(([id, b]) => [id, fromB64(b)]));
      session = {
        userId: snap.userId,
        email: snap.email,
        personalVaultId: snap.personalVaultId,
        // uvk is intentionally absent here (breaker B1 — never persisted): a snapshot-restored session
        // has no UVK, so enroll on it must trigger a fresh full unlock.
        provenance: snap.provenance ?? "PASSWORD",
        lastFullUnlockAt: typeof snap.lastFullUnlockAt === "number" ? snap.lastFullUnlockAt : 0,
        vaultKeys,
        // vaultRoles joined the snapshot with G21 (2026-08-30) — a pre-G21 snapshot lacks it;
        // empty = every vault treated writable, exactly the pre-fix behavior (the server still refuses).
        vaultRoles: new Map(Object.entries(snap.vaultRoles ?? {})),
        waitingGrants: typeof snap.waitingGrants === "number" ? snap.waitingGrants : 0,
        homes: snapHomes,
        homesKnown: snap.homesUnknown !== true,
        wrongVault: typeof snap.wrongVault === "number" ? snap.wrongVault : 0,
        vaultMeta: new Map(Object.entries(snap.vaultMeta ?? {}).filter(([, b]) => typeof b === "string")),
        // formatVersion joined the snapshot in 0.7.0 — a session persisted by ≤0.6.1 lacks it,
        // and that client's read gate only admitted fv≤1, so defaulting 1 is exact, not a guess.
        // spec 02 §3.2: a snapshot persisted by a pre-check build may hold a malformed doc — the
        // restore applies the same shape check decryptItems does (security review 2026-10).
        items: itemsUnderHeldKeys(
          snap.items.filter((i) => itemDocProblem(i.doc) === null).map((i) => ({ ...i, formatVersion: i.formatVersion ?? 1 })),
          vaultKeys,
        ),
        // §4.4: a session the server ended stays ended across a worker restart (its snapshot carries no tokens).
        ...(snap.serverEnded === true ? { serverEnded: true as const } : {}),
        ...(snap.serverEnded === true && snap.endedUnconfirmed === true ? { endedUnconfirmed: true as const } : {}),
        // A snapshot that carries no deadline is past it (fail closed): it is locked at once, below.
        lockAt: typeof snap.lockAt === "number" && Number.isFinite(snap.lockAt) ? snap.lockAt : 0,
      };
      lockAtSaved = session.lockAt;
      // Re-clamp on restore (§2.3/B1-1 defense-in-depth): a snapshot persisted by a pre-clamp
      // build could carry a server value the ceilings would have refused.
      autoLockSeconds = clampAutoLockSeconds(snap.autoLockSeconds, DEFAULT_AUTOLOCK_SECONDS);
      clipboardClearSeconds = clampClipboardClearSeconds(snap.clipboardClearSeconds, DEFAULT_CLIPBOARD_CLEAR_SECONDS);
    }
    const t = tabsRead;
    if (t) {
      tabs = new Map(Object.entries(t).map(([id, st]) => [Number(id), st]));
      // [U14] the Tier-2 registry shape ({forms}) deliberately broke the additive rule — a record
      // persisted by the pre-update build ({fields}) is DISCARDED here, never reinterpreted
      // (fail-closed; the popup's rescan broadcast restores fresh records within one open).
      for (const st of tabs.values()) {
        const reg = st.cardForms;
        if (reg === undefined) continue;
        for (const [fid, rec] of Object.entries(reg)) {
          if (!Array.isArray((rec as { forms?: unknown }).forms)) delete reg[Number(fid)];
        }
        if (Object.keys(reg).length === 0) delete st.cardForms;
      }
    }
    // A restored session past its deadline is locked here, in the install's own step (the tab records are in,
    // so the lock keeps only their page-known half), exactly as the alarm would have locked it; one before it gets its
    // alarm set again for the deadline (a browser that refused it before is asked again, and the popup says if not).
    if (session !== null && Date.now() >= session.lockAt) void idleLock();
    else if (session !== null) {
      void setLockAlarm(session.lockAt);
      if (session.serverEnded !== true) void ensureResyncAlarm();
    }
  })();
  // Every caller, in a warm worker too, has the deadline checked before it goes on to serve anything.
  return loadPromise.then(
    () => lockIfDue().then(() => {}),
    (e: unknown) => lockIfDue().then(() => Promise.reject(e)),
  );
}

/** Persist the live session to storage.session, sealed (A16). RETURNS the write's promise so
 *  api.onTokensChanged can AWAIT the snapshot write before spending a refresh token (a consumed
 *  pair must be persisted before the POST — see AndvariApi.doRefresh). The `!session` guard is
 *  safe for that path: unlock sets tokens before session exists (setTokens vs the session
 *  assignment), but no refresh can run mid-login, so onTokensChanged never fires session-less
 *  there — the guard must NOT be "fixed" by reordering unlock. Fire-and-forget callers ignore it. */
function persistSession(): Promise<void> {
  if (!session) return Promise.resolve();
  const t = api.getTokens();
  const snap: SessionSnapshot = {
    origin: serverUrl, // binds the persisted tokens to their server (§4.1 rule 1 — see ensureLoaded)
    access: t.access ?? "",
    refresh: t.refresh,
    userId: session.userId,
    email: session.email,
    personalVaultId: session.personalVaultId,
    autoLockSeconds,
    clipboardClearSeconds,
    provenance: session.provenance,
    lastFullUnlockAt: session.lastFullUnlockAt,
    vaultKeys: Object.fromEntries([...session.vaultKeys].map(([id, vk]) => [id, toB64(vk)])),
    vaultRoles: Object.fromEntries(session.vaultRoles),
    waitingGrants: session.waitingGrants ?? 0,
    homes: Object.fromEntries(session.homes),
    ...(session.homesKnown ? {} : { homesUnknown: true as const }),
    wrongVault: session.wrongVault ?? 0,
    vaultMeta: Object.fromEntries(session.vaultMeta ?? []),
    ...(session.serverEnded ? { serverEnded: true as const } : {}),
    ...(session.endedUnconfirmed ? { endedUnconfirmed: true as const } : {}),
    lockAt: session.lockAt, // the deadline is kept with the session; a worker that restores it checks it
    items: session.items,
  };
  lockAtSaved = session.lockAt;
  // The known-logins digest tracks the items it is derived from: every persist of the session
  // is exactly "items changed or were (re)installed", so this is the one rebuild choke point.
  void refreshKnownLogins();
  return sessionSeal.set("session", currentOriginKey, snap).then(() => {});
}

/** The digest HMAC key, cached across rebuilds within one SW life. null after sign-out (the
 *  record is wiped with it) and on a cold SW — the next rebuild reuses the stored key or mints
 *  a fresh one; a fresh key merely invalidates old digests, which the same rebuild replaces. */
let knownLoginsKey: Uint8Array | null = null;

/** Rebuild the KLKEY record from the live session's items (knownlogins.ts owns the derivation).
 *  Best-effort by design: a failed rebuild only means a known login banners while locked — the
 *  pre-digest behavior, never a wrong suppression. */
async function refreshKnownLogins(): Promise<void> {
  const s = session;
  if (!s || s.serverEnded) return; // an ended session keeps no digest (endSessionByServer wiped it)
  const ok = currentOriginKey;
  try {
    if (!knownLoginsKey) {
      const rec = (await sessionSeal.get("knownLogins", ok)) as KnownLoginsRecord | undefined;
      // A16: the read can wait for the seal's key; a lock (a sign-out's wipe) or another unlock that landed meanwhile
      // must not see this rebuild mint the digest back.
      if (session !== s || s.serverEnded) return;
      knownLoginsKey = rec?.key ? fromB64(rec.key) : crypto.getRandomValues(new Uint8Array(16));
    }
    const digests = buildKnownLoginDigests(knownLoginsKey, s.items, pslResolve);
    if (session !== s || s.serverEnded) return; // ended while the stored key was read: its wipe stands
    await sessionSeal.set("knownLogins", ok, { key: toB64(knownLoginsKey), digests } satisfies KnownLoginsRecord);
  } catch {
    /* storage hiccup — the stale (or absent) set stands; fail toward the banner, never silence */
  }
}

/** The locked capture path's membership test. Reads the record fresh (the SW may have been born
 *  after the lock that this set survived). Fail-open to "unknown" — the banner is the safe
 *  default; silence is the privilege the digest has to earn. */
async function isKnownLoginWhileLocked(host: string, username: string): Promise<boolean> {
  try {
    const rec = (await sessionSeal.get("knownLogins", currentOriginKey)) as KnownLoginsRecord | undefined;
    if (!rec?.key || !Array.isArray(rec.digests)) return false;
    const site = siteKeyOfHost(host, pslResolve);
    if (!site) return false;
    return rec.digests.includes(knownLoginDigest(fromB64(rec.key), site, username));
  } catch {
    return false;
  }
}

/** One gate for every locked-state RE-offer surface (tabs.onUpdated + the content load poll):
 *  applies reofferDecision (TTL-expire → drop the pending; quiet/throttled → no offer) and
 *  stamps offeredAt on a granted locked offer. The unlock moment (reofferPendingSaves) and the
 *  immediate capture-time banner deliberately do NOT route through this. */
function gateReoffer(tabId: number, st: TabState): (PendingSave & { password: string; frameId: number }) | null {
  const p = st.pending;
  if (!p) return null;
  const verdict = reofferDecision(p, Date.now(), session !== null);
  if (verdict === "expired") {
    st.pending = undefined;
    tabs.set(tabId, st);
    persistTabs();
    return null;
  }
  if (verdict !== "offer") return null;
  if (!session) {
    p.offeredAt = Date.now();
    tabs.set(tabId, st);
    persistTabs();
  }
  return p;
}

/** Design §4.4 (decided on 2026-11-17): the captures not saved to the vault (Res<"status">.unsavedCaptures): every
 *  tab's pending login save, captured while unlocked or while locked, and every tab's pending card save. */
function unsavedCaptures(): number {
  let n = pendingCardSave.size;
  for (const st of tabs.values()) if (st.pending !== undefined) n++;
  return n;
}

function persistTabs(): void {
  // A16: sealed (a pending save holds a page's password); the value is captured now, and writes land in call order.
  void sessionSeal.set("tabs", currentOriginKey, Object.fromEntries([...tabs].map(([id, st]) => [String(id), st]))).catch(() => {});
}

/** Lock: drop in-memory vault material + the full storage.session snapshot (pending saves hold
 *  plaintext passwords — they lock too). `reason` records WHY for the F26 unlock-form line (E1-7).
 *  A16, and its review (R4): the ERASE COMES FIRST. Before anything here awaits anything, one synchronous step removes the
 *  sealed snapshot and tab records and advances the seal's custody epoch (sessionseal.ts lockErase, which keeps a copy
 *  of both, ciphertext, for the arm below) and drops the in-memory session. Only then does the lock wait — bounded — for
 *  what the ARM needs (the origin, the key), and it decides the arm from what stood at that instant: the live token
 *  pair, or, in a cold worker that had not hydrated, the lock's own copy of the snapshot, opened under the epoch it was
 *  sealed in. Last it waits, bounded, for the new epoch to reach the key store (A16 review R2).
 *  The "clipboardclear" backstop alarm deliberately SURVIVES (a secret copied just before an idle lock
 *  still clears on schedule, E1-4).
 *
 *  Quick-unlock Tier B (spec 01 §8.4): an idle/manual lock ARMS if a fresh, non-exhausted blob exists —
 *  it stashes the token pair (breaker B3 armed branch) and KEEPS the slim `{blob, counter, tokens}`
 *  record under the DISTINCT QKEY, erasing everything else exactly as today, so the next unlock can be
 *  a PIN. `signout` (an explicit user action / revocation) NEVER arms and full-wipes the blob + co-key.
 *  When quick unlock is not enrolled, an idle/manual lock stays byte-identical to today's full erase.
 *  [seen] (doSignOut) receives the token pair the lock saw, for the revoke that follows the erase. */
async function doLock(reason: "idle" | "manual" | "signout" = "manual", seen?: { tokens?: TokenPair }, sayLost: boolean = reason === "idle"): Promise<void> {
  // ---- one synchronous step: the erase and the in-memory teardown, before any await ----
  hydrateGen++; // a load in flight installs nothing it read before this erase (ensureLoaded)
  const sealGen = sessionSeal.generation();
  // A16: the erase, dispatched HERE — before anything below can wait on IndexedDB (the key, the arm's sealed write, the
  // quick-unlock co-key delete inside wipe()) or on the network (the teardown flush). The session snapshot and the tab
  // records are removed, and the seal's custody epoch advances, so no copy of them taken before this lock opens through
  // a read again; a sealed write still in flight for them is dropped (sessionseal.ts). Awaited only at the end.
  const erase = sessionSeal.lockErase();
  redeemGen++; // any lock invalidates an in-flight quick-unlock redeem (owns() guard, breaker A5⊕B4)
  events?.close(); // live socket + all its timers die FIRST — locked means no bell traffic at all
  events = null;
  const secondsAtLock = autoLockSeconds; // capture before the reset below (web App.tsx:209 parity)
  // Audit G03 → H33 → recheck R43: store what this session recorded BEFORE the TOKENS go — captured
  // here, awaited (bounded) below, just ahead of api.setTokens(null, null). The old `void
  // flushUsage()` dispatched the GET with a live token, but its PUT was issued after that round
  // trip, by which time `api.setTokens(null, null)` had emptied the header: 401 → tryRefresh with
  // a null refresh token → thrown, and the re-arm catch found `session` already null, so the last
  // 15 s of fills were dropped on every manual/idle lock. The first H33 shape awaited the flush
  // BEFORE `session = null`, which kept reveal/fill answering for up to 2 s after the user asked
  // to lock. This is the natives' lock-path shape instead (VaultSession.lock): the round takes an
  // explicitly-captured context, the session and keys drop on the next line, and only the token
  // pair waits — at most TEARDOWN_FLUSH_TIMEOUT_MS; a flush that outlives the bound is abandoned.
  const teardownFlush = flushUsageForTeardown();
  const userAtLock = session?.userId ?? null; // whose session this lock ends: the arm checks the record is that account's
  // With no session, the pair in the client is the record's own only while a quick unlock is
  // under way on this client; otherwise it may be a password sign-in's, between its login and its install, and of
  // another account. Taken in this synchronous step, with the session: the redeem clears its mark when it gives way.
  const redeemAtLock = redeemClient !== null && redeemClient === api;
  const ownerAtLock = tokenOwner; // whose pair the client holds as this lock begins (endAbandonedSignIn's token)
  // A refresh of the session's pair got no answer and its mark stands: the record armed below holds no token (the client
  // hides it), and the lock earns no further try. The token is kept for the next sign-in's name, as a living worker's
  // "no try left" keeps it; the quick unlock then ends as that end does (finishRedeem). A sign-out keeps nothing.
  const unansweredAtLock = session !== null && reason !== "signout" ? api.unansweredRefreshToken() : null;
  if (unansweredAtLock !== null && session !== null) keptUnconfirmed = { email: session.email, refreshToken: unansweredAtLock };
  session = null; // in-memory vault material — INCLUDING the memory-only uvk (breaker B1) — is dropped
  stashOwed = null; // the arm below rewrites (or the wipe removes) any stash an unlock could not clear
  timerRefused.autolock = timerRefused.resync = false; // the next session's alarms are asked for afresh
  clearPendingUsage(); // behavioral records must not outlive the session that produced them
  clearPendingTotp(); // and any in-flight TOTP challenge (covers sign-out; a normal lock has none)
  autoLockSeconds = DEFAULT_AUTOLOCK_SECONDS;
  clipboardClearSeconds = DEFAULT_CLIPBOARD_CLEAR_SECONDS;
  // Design §4.4 (decided on 2026-11-17): which captures this lock deletes unsaved, counted before they go (only which
  // tabs held one, and how many cards: nothing of what they held).
  const capturedTabs = new Set<number>();
  for (const [tabId, st] of tabs) if (st.pending !== undefined) capturedTabs.add(tabId);
  const cardsAtLock = pendingCardSave.size;
  // [S3-lock] Retain ONLY the two PAGE-KNOWN facts across a lock; drop everything else.
  // Rationale (chip review #1): a bare tabs.clear() erased `topOrigin`+`cardForms`, so the chip
  // vanished at the instant of lock and returned a beat later with the locked copy — a page
  // hit-testing elementFromPoint at ~4 Hz got a clean EDGE-TRIGGER for "the vault just locked",
  // which is exactly when a page-drawn fake unlock prompt is most credible. Persisting the records
  // ([S4a]) is what made that edge unambiguous, so this is the other half of that fix: the chip's
  // presence must stay a function of page-known facts ONLY, in every session state.
  // ALLOW-LIST, never a deny-list: each entry is a FRESH object carrying exactly the two fields
  // the page already knows (its own top origin; which card-form kinds its own DOM has). Anything
  // else — `pending` (PLAINTEXT PASSWORD) and `lastUsername` — is structurally absent rather than
  // deleted, so a future TabState field is dropped by default instead of silently surviving.
  for (const [tabId, st] of [...tabs]) {
    if (st.topOrigin === undefined && st.cardForms === undefined) tabs.delete(tabId);
    else tabs.set(tabId, { topOrigin: st.topOrigin, cardForms: st.cardForms });
  }
  grants.clear();
  cardGrants.clear();
  cardReports.clear();
  pendingCardSave.clear(); // [X2-A2b] pending card saves hold the PAN — locked means no PAN at rest
  cardCaptureDedupe.clear();
  reuseNotices.clear(); // a reuse answer is an unlocked-vault fact — it never outlives the session

  // ---- then the waits: for what the arm and the wipes need, never for the erase ----
  // A15: the compartment verdict below is sampled after the awaited access-level calls settled (a lock fired into a
  // cold SW would otherwise read the initial `false` and wipe an enrolled quick unlock). Those are chrome.storage calls.
  await storageAccess;
  // A15 review S1: serverReady loads the origin whose namespace the arm/wipe below lands in, and since A16 custodyReady
  // decides the seal's key (which the arm's sealed record and the lock's copy need) and with it the compartment
  // verdict; a lock waits for both at most LOCK_STORE_WAIT_MS — a healthy store answers in milliseconds, so a cold idle
  // lock still arms. Past that the lock (which has erased already) arms nothing and wipes no quick-unlock record (it
  // cannot tell which origin's namespace is current); an enrolled record is left unarmed, so the next unlock is a full
  // one. A sign-out never arms, so it waits longer (SIGNOUT_STORE_WAIT_MS) for its full wipe's namespace and its revoke.
  const custodyKnown = await Promise.race([custodyLoaded.then(() => true), delay(reason === "signout" ? SIGNOUT_STORE_WAIT_MS : LOCK_STORE_WAIT_MS).then(() => false)]);
  // D3: armGate AWAITS its hydrate BEFORE it samples the tokens for the arm decision, returning both the sampled pair
  // (the armed branch stashes it) and the verdict. An idle-autolock alarm can fire into a COLD SW whose `api` holds no
  // tokens yet; sampling before the hydrate would see {access:null} and WIPE the enrolled quick-unlock instead of arming
  // it — the ordering lives in the locksequence leaf (locksequence.test.ts pins that a non-hydrating load re-wipes).
  // A16 review R4: the hydrate is the lock's OWN copy of the snapshot (taken in the erase's step, opened under the
  // epoch it was sealed in, for the CURRENT origin), not ensureLoaded: the erase came first, so a load now reads
  // nothing. A live pair (a warm worker, or a redeem's) outranks the copy. Opened only with the origin and the key in
  // hand; a browser-start report since the erase makes the copy absent and the compartment untrusted (sealGen).
  let copy: { session?: unknown; tabs?: unknown } = {};
  const { tokens: toks, attempt: attemptArm } = custodyKnown
    ? await armGate({
        hydrate: async () => {
          // A refresh of the locked session's pair on the wire (a sync's 401) has
          // consumed the refresh token; the pair sampled now would be {access, null}, the answer would then be dropped
          // (the pair is cleared below), and the record armed on no refresh token, so its next quick unlock was taken
          // for a revoked session and wiped. A server switch locks first, so it did the same to the old server's
          // record. The arm waits for the answer, bounded like the waits above; past the bound it goes on as before.
          // Past the bound, the answer follows the record when it comes (followLateRefresh), and the next
          // quick unlock waits for it (lockRefreshSettled).
          if (reason !== "signout") {
            lockRefreshSettled = api.refreshSettled();
            await Promise.race([lockRefreshSettled, delay(LOCK_STORE_WAIT_MS)]);
          }
          // Only where there is no live pair (a cold worker): a warm one holds the pair and the tab records in memory.
          // Bounded like the wait above (the key is in hand by now, unless a browser-start report is replacing it).
          if (!api.getTokens().access) copy = await Promise.race([erase.opened(currentOriginKey), delay(LOCK_STORE_WAIT_MS).then(() => ({}))]);
        },
        readTokens: () => {
          // A sign-in or a quick unlock that put its own pair into the client since this lock began owns it;
          // that pair is not this lock's to stash (it may be another account's).
          if (tokenOwner !== ownerAtLock) return { access: null, refresh: null };
          const live = api.getTokens();
          return live.access ? live : snapshotTokens(copy.session);
        },
        isSignout: reason === "signout",
        compartmentTrusted: quCompartmentTrusted && sessionSeal.generation() === sealGen,
      })
    : { tokens: { access: null, refresh: null }, attempt: false };
  if (seen) seen.tokens = toks;
  // [S3-lock], cold worker: the tab records were not in memory, so their page-known half comes from the lock's copy (a
  // record added since, by a handler, is fresher and wins). Without the origin and the key they go whole.
  const copiedTabs = copy.tabs;
  let lostCaptures = capturedTabs.size + cardsAtLock;
  if (copiedTabs !== null && typeof copiedTabs === "object") {
    for (const [id, st] of Object.entries(copiedTabs as Record<string, TabState>)) {
      const tabId = Number(id);
      // A cold worker: a login captured in an earlier worker life is in the lock's copy only.
      if (!capturedTabs.has(tabId) && st !== null && typeof st === "object" && st.pending !== undefined) lostCaptures++;
      if (tabs.has(tabId) || st === null || typeof st !== "object" || (st.topOrigin === undefined && st.cardForms === undefined)) continue;
      tabs.set(tabId, { topOrigin: st.topOrigin, cardForms: st.cardForms });
    }
  }
  // The known-logins digest (KLKEY) deliberately SURVIVES an idle/manual lock — that survival is
  // its whole function (the locked save-prompt check, spec 01 §8.4 amendment 2026-08-18).
  // Sign-out is its wipe choke point, and an untrusted compartment gets the same fail-closed
  // erase as the quick-unlock blob (the record is only worth holding where the seal's key is, A16).
  if (reason === "signout" || !quCompartmentTrusted) {
    knownLoginsKey = null;
    if (custodyKnown) await sessionSeal.remove("knownLogins", currentOriginKey); // S1: no namespace known → left as it stood
  }

  // Arm decision (attemptArm, computed by armGate above). `signout` skips arming and forces a full wipe;
  // idle/manual attempt to arm — but ONLY when the storage.session compartment is trusted-only (breaker
  // A9⊕B5: without that guarantee we must NOT retain a crackable UVK blob + a live refresh token, so we
  // fall back to today's full erase + wipe). arm() fails CLOSED to "declined" if reading the flag throws
  // (breaker B3). On "armed" the record now holds the token stash; "not-enrolled" leaves nothing
  // (byte-identical to today); the snapshot and the tab records were erased above in ALL cases so a locked SW reports
  // locked.
  if (attemptArm) {
    // .catch → "declined": arm() must NEVER throw past the rest of the lock (review F1 — an unexpected throw, e.g. a
    // malformed record, once skipped the erase and left the just-locked session snapshot on disk, rehydratable into an
    // unlocked vault on the next SW wake; since A16 the erase is dispatched before the arm).
    // toks.access is non-null here (attemptArm ⇒ shouldAttemptArm required it); the `!` restates that
    // the extracted gate can't narrow across the armGate call the way an inline `&& toks.access` would.
    // And only a record of the account whose session this is (a warm worker's session, or a cold one's copy).
    // And declined (the record wiped) when the lock knows no account and no quick unlock is under way here.
    const armUser = userAtLock ?? snapshotUserId(copy.session);
    const armed = armUser === null && !redeemAtLock ? "declined" : await quickUnlock.arm({ access: toks.access!, refresh: toks.refresh }, armUser).catch(() => "declined" as const);
    if (armed === "declined") {
      await quickUnlock.wipe(); // stale/ineligible/fail-closed → erase the residue
    }
  } else if (custodyKnown) {
    // signout, no live token, OR an untrusted compartment → full wipe (never leave standing material).
    await quickUnlock.wipe();
  }

  // H33/R43: the tokens are what the teardown PUT rides on — the ONE thing the flush still needs
  // once the session is gone — so they are forgotten only after the bounded await.
  await Promise.race([teardownFlush, delay(TEARDOWN_FLUSH_TIMEOUT_MS)]);
  // The api forgets the pair; while armed it lives ONLY in QKEY.lockedTokens. Only the pair this lock took
  // over; a sign-in that set its own since (the lock waits, above) keeps it.
  if (tokenOwner === ownerAtLock) api.setTokens(null, null);
  await erase.erased; // the full vault snapshot was erased above — locked reports locked
  // A16 review R2: the custody epoch this lock advanced to reaches the key store before the lock returns, so a copy of
  // the snapshot from before it cannot open at the next start (bounded; past the bound the write goes on, and a failed
  // one is retried at every later seal operation — the tab records below are held until it lands).
  await sessionSeal.lockDurable(LOCK_EPOCH_WAIT_MS);
  // …then re-persist the [S3-lock] allow-listed remainder (top origin + card-form KINDS only — no
  // pending, no password, no username). The blanket remove above is what guarantees the sensitive
  // half never survives; this writes back only what the page already knows, so the chip's presence
  // stays lock-invariant even after the SW idles out. Skipped when nothing survived.
  if (tabs.size > 0) persistTabs();
  // Write the reason AFTER the snapshot's removal (a notice only from the idle path — web parity); manual/signout
  // renders no reason line. storage.session clears on browser exit. Plain (A16): no secret, only a reason line.
  if (reason === "idle") {
    await plainSession.set({ [NKEY]: { kind: "idle", seconds: secondsAtLock } });
  } else {
    await plainSession.remove(NKEY);
  }
  // Design §4.4 (decided on 2026-11-17): a lock or sign-out nobody was asked about says what it deleted unsaved.
  if (sayLost && lostCaptures > 0) await addLostCaptures(lostCaptures);
  clearAlarm("autolock");
  clearAlarm("resync");
  try {
    // Quiet toolbar while locked — stale counts would claim matches we can no longer serve.
    for (const t of await chrome.tabs.query({})) {
      if (t.id !== undefined) chrome.action.setBadgeText({ tabId: t.id, text: "" }).catch(() => {});
    }
  } catch {
    /* tab enumeration unavailable — badges refresh on each page's next pageInfo */
  }
}

type TokenPair = { access: string | null; refresh: string | null };

/** The token pair in a session snapshot the lock copied, when it belongs to the dialed origin (§4.1 rule 1, as
 *  ensureLoaded applies it); none otherwise. */
function snapshotTokens(raw: unknown): TokenPair {
  const s = raw as Partial<SessionSnapshot> | undefined;
  if (!s || typeof s !== "object" || s.origin !== serverUrl || typeof s.access !== "string" || s.access === "") return { access: null, refresh: null };
  return { access: s.access, refresh: typeof s.refresh === "string" ? s.refresh : null };
}

/** The account of the lock's copy of the session snapshot, read like [snapshotTokens] (the current server's only); null
 *  when there is no such copy. */
function snapshotUserId(raw: unknown): string | null {
  const s = raw as Partial<SessionSnapshot> | undefined;
  if (!s || typeof s !== "object" || s.origin !== serverUrl || typeof s.userId !== "string" || s.userId === "") return null;
  return s.userId;
}

/** Explicit sign-out / definitive revocation → a FULL wipe of the quick-unlock blob + co-key + tokens,
 *  never the armed-retaining lock (breaker A3⊕B2). Routed here from onRevoked, the popup "Sign out"
 *  action, and every definitive-401 during a quick-unlock redeem. [sayLost]: nobody asked for this sign-out (every caller
 *  but the popup's Sign out, which asked first with the count), so the captures it deletes unsaved are said at the next
 *  popup (LOST_KEY). */
async function doSignOut(sayLost = false): Promise<void> {
  // A16 review R4: the local erase comes FIRST. Before, sign-out waited on the load (handle()'s ensureLoaded) and then on
  // the network — the usage flush and the logout POST, up to 7 s — before doLock erased anything. Now doLock("signout")
  // erases at once; its teardown flush still lands, bounded, before the pair is forgotten (Audit G03 → H33: the flush
  // must precede the revoke, which kills the session its GET+PUT ride on); and the revoke follows, on the pair the lock
  // saw.
  const seen: { tokens?: TokenPair } = {};
  // The origin whose pair the lock collects: the revoke goes there or nowhere. The lock waits on stores and a flush, so a
  // server switch can land meanwhile; before, the revoker was built on the origin current AFTER the lock, so the old
  // origin's pair could be sent to the new one (a token only to its own origin, and only
  // with that origin's pin in force).
  const origin = serverUrl;
  await doLock("signout", seen, sayLost);
  void clearBioCred(); // 0.17.0: explicit sign-out tears down the amendment-4 reuse record too
  // Server-session revocation (Android/desktop parity: both AWAIT a bounded logout with the same 5 s ceiling — without
  // it "Sign out" leaves the refresh token valid server-side for ~30 days). Best-effort + bounded: on the already-revoked
  // routes (onRevoked, definitive-401) the POST is a harmless no-op. Sign-out ONLY — doLock deliberately keeps the
  // session so quick unlock can re-arm. Not while a server is pending (A16 review R4: nothing is dialed then). A fresh
  // api carries only this pair and persists nothing, so whatever the revoke does with it ends here.
  const pair = seen.tokens;
  if (!pair?.access) return;
  await revokePair(origin, pair); // nothing when the origin changed or its pin is not in force (forked, damaged, gone)
}

/** A bounded logout of [pair] at [origin] through a client of its own, sent only while [origin] is the dialed origin
 *  with its pin in force (dialBlock null); the module `api` and its pair are untouched. Sign-out, the operator refusal
 *  and an abandoned sign-in revoke through it. */
async function revokePair(origin: string, pair: TokenPair): Promise<void> {
  if (origin !== serverUrl || dialBlock !== null || pair.access === null) return;
  const revoker = new AndvariApi(origin, chrome.runtime.getManifest().version);
  revoker.mayDial = () => origin === serverUrl && dialBlock === null;
  revoker.setTokens(pair.access, pair.refresh);
  await Promise.race([revoker.logout(), delay(5000)]);
  revoker.setTokens(null, null);
}

/**
 * A16 review R1: the browser reported a new browser session — a start (`runtime.onStartup`), or an install, an update,
 * a reload or a browser update (`runtime.onInstalled`). Neither can be raised by a web page. storage.session is then the
 * browser's fresh one, so nothing sealed in it can be ours and no session can legitimately exist yet: whatever this
 * worker life hydrated or captured before the report came from somebody else's write. Before this, the key was kept
 * whenever storage.session held anything shaped like a sealed record, so a planted `{v:1, iv, ct}` kept it, and with it
 * a copy of the previous browser session's records, openable.
 *
 * In one step: every load in flight installs nothing it read (hydrateGen), an in-flight quick-unlock redeem discards
 * itself (redeemGen), the in-memory custody is dropped WITHOUT arming (nothing here is a lock: no record is written),
 * and the seal drops every sealed record and replaces its key (sessionseal.rotate), dropping any write issued before.
 * The worker may wake for a message before the report or after it, and an event page need not get `onStartup` at all:
 * a session hydrated before the report lives only until it is handled, and where no report comes the seal's own start
 * rule applies (the key is kept only if a record opens under it). spec 05 A16(a) states what that leaves.
 */
function browserSessionReported(): void {
  hydrateGen++;
  redeemGen++;
  events?.close();
  events = null;
  session = null;
  api.setTokens(null, null);
  dropEnrollSecretCache();
  clearPendingUsage();
  clearPendingTotp();
  knownLoginsKey = null;
  autoLockSeconds = DEFAULT_AUTOLOCK_SECONDS;
  clipboardClearSeconds = DEFAULT_CLIPBOARD_CLEAR_SECONDS;
  tabs.clear();
  grants.clear();
  cardGrants.clear();
  cardReports.clear();
  pendingCardSave.clear();
  cardCaptureDedupe.clear();
  reuseNotices.clear();
  const rotated = sessionSeal.rotate();
  decideCompartment(); // undecided while the key is replaced: nothing arms or enrolls meanwhile
  void rotated.then(decideCompartment);
  clearAlarm("autolock");
  clearAlarm("resync");
}

/**
 * Design §4.4 "A session the server ends does not delete the device's copy". The server ended the live session (a
 * definitive refusal of its refresh, or the socket's revoked frame). The session ends: its tokens are dropped, the
 * quick-unlock record (PIN or biometric, which holds a refresh token and a UVK wrap) is wiped, the socket closes and the
 * periodic sync stops; nothing is dialed while it stands so (makeApi's mayDial) and nothing is written (putItem). What
 * the session holds stays: its items in memory and in the sealed snapshot (so a worker restart keeps it, still ended),
 * and every trusted record (the pin, the marks, the homes, the device record). It is read, copied from and filled
 * from with the notice in view, until the person locks (the extension keeps no copy across a lock, by its own rule)
 * or signs out. Signing in again, after a lock, restores a session. A session this browser ended itself is not this.
 */
async function endSessionByServer(unconfirmed = false): Promise<void> {
  const s = session;
  if (s === null || s.serverEnded) return;
  s.serverEnded = true;
  if (unconfirmed) s.endedUnconfirmed = true;
  events?.close();
  events = null;
  clearAlarm("resync");
  api.setTokens(null, null);
  clearPendingTotp();
  dropEnrollSecretCache();
  await quickUnlock.wipe().catch(() => {});
  // Spec 01 §8.4: the known-logins digest is wiped at a definitive 401 with the quick-unlock material (before, it
  // was kept, and rebuilt by the persist below, so the (site, username) digests of an account the server no longer
  // serves outlived the session's own lock). refreshKnownLogins writes none for an ended session.
  knownLoginsKey = null;
  await sessionSeal.remove("knownLogins", currentOriginKey).catch(() => {});
  await persistSession();
}

/** Re-arm the policy idle lock: the deadline first, a fact kept with the session (in memory and, once it
 *  has moved LOCK_AT_SAVE_SLACK_MS past the copy there, in the sealed snapshot, so a worker that restores the session
 *  checks it), then the alarm that normally locks it on time. Before, the alarm was all there was, and its create was
 *  fired and forgotten: a browser that refused it left the vault open for as long as it kept the session, unsaid. */
function armAutoLock(): void {
  const s = session;
  if (s === null) return;
  s.lockAt = Date.now() + lockWindowMs();
  // A failed write leaves the snapshot's deadline earlier than the live one: a restored session then locks early, never late.
  if (s.lockAt - lockAtSaved >= LOCK_AT_SAVE_SLACK_MS) void persistSession().catch(() => {});
  void setLockAlarm(s.lockAt);
}

/** The idle window from now: the policy's, floored as chrome.alarms floors a delay (the clamp never leaves it at 0, and a
 *  server cannot disable the lock, spec 03 §1.1). */
function lockWindowMs(): number {
  return Math.max(autoLockSeconds, AUTOLOCK_FLOOR_SECONDS) * 1000;
}

/**
 * The deadline check every way into the worker makes before it serves anything (a message from the popup or a page, a
 * fill, a save, a sync, a live update, a worker start: ensureLoaded, the message and alarm listeners, the socket's
 * frames). Past the deadline the session is locked first, by the idle lock the alarm would have run, and the caller
 * goes on locked. Answers whether such a lock ran (or was already running). The lock drops the session in its first,
 * synchronous step, so nothing after this call sees it; the promise is for the rest of the lock (the arm, the erase).
 */
function lockIfDue(): Promise<boolean> {
  const s = session;
  if (dueLock === null && (s === null || Date.now() < s.lockAt)) return Promise.resolve(false);
  return idleLock().then(() => true);
}

/** The one idle lock: the alarm's and the deadline's are the same lock, never two (a second, finding no session, would
 *  wipe the quick-unlock record the first armed). */
function idleLock(): Promise<void> {
  dueLock ??= doLock("idle").then(
    () => {
      dueLock = null;
    },
    () => {
      // The lock dropped the session in its first step; a later step that failed (the erase's write, the reason line)
      // leaves at most a snapshot past its deadline, which the next worker start locks again. Nothing to answer here.
      dueLock = null;
    },
  );
  return dueLock;
}

/** chrome.alarms.create, caught: a refusal (a rejected promise, or a throw on an engine that answers synchronously) is
 *  tried once more. Answers whether the alarm is set. */
async function createAlarm(name: string, info: chrome.alarms.AlarmCreateInfo): Promise<boolean> {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      await chrome.alarms.create(name, info);
      return true;
    } catch {
      /* refused: once more, then said (timerRefused) */
    }
  }
  return false;
}

/** chrome.alarms.clear, caught: a refusal leaves at most a stale alarm. A stale resync finds no session and returns; a
 *  stale auto-lock runs the idle lock on a vault already locked, as a second Lock does. */
function clearAlarm(name: string): void {
  try {
    void Promise.resolve(chrome.alarms.clear(name)).catch(() => {});
  } catch {
    /* alarms unavailable here */
  }
}

/** The auto-lock alarm, for the deadline. Refused twice, the popup says so in one line; the deadline keeps the promise. */
function setLockAlarm(lockAt: number): Promise<void> {
  const s = session;
  const run = createAlarm("autolock", { when: lockAt }).then((ok) => {
    if (session === s) timerRefused.autolock = !ok;
  });
  alarmWork = run;
  return run;
}

/** The periodic resync (the ≤5-min staleness floor and the socket's revival). Refused twice, the popup says that changes
 *  made elsewhere may arrive late; the live socket still rings while it is up. */
function startResyncAlarm(): Promise<void> {
  const run = createAlarm("resync", { periodInMinutes: RESYNC_PERIOD_MIN }).then((ok) => {
    timerRefused.resync = !ok;
  });
  alarmWork = run;
  return run;
}

/** A restored session's resync alarm, set again only when the browser holds none (a re-create would restart its period
 *  at every worker start and starve it). */
async function ensureResyncAlarm(): Promise<void> {
  try {
    if (await chrome.alarms.get("resync")) {
      timerRefused.resync = false;
      return;
    }
  } catch {
    /* get unsupported here: create it */
  }
  await startResyncAlarm();
}

/** Periodic refresh while unlocked — new/changed items under keys we already hold. A grant to a
 *  brand-new vault needs uvk/identity (never persisted), so it lands at the next real unlock.
 *  Failures are silent by design: offline now, the next alarm retries.
 *
 *  Removals (security review 2026-10, root cause A §6, branch A7): the extension never reads
 *  `removedGrants` / `removedGrantsInfo` and never verifies a removal or leave proof. It pulls a full
 *  snapshot (since=0) every time, so a vault whose grant was revoked simply stops contributing items,
 *  and its key and its role entry are dropped below in one step (the sealed snapshot with them). A vault
 *  served again later opens only at the next unlock, which rebuilds the key set from the live grants
 *  after its checks; it shows no removal banner, keeps no holding area, consumes
 *  no nonce and keeps no liveSince. Attributing a removal, refusing a replayed proof and the 30-day
 *  holding area are the FULL clients' job (core SyncEngine, web store). */
async function resync(): Promise<void> {
  await ensureLoaded();
  // A16 review R4: while a server is pending (or unknown) nothing is dialed — a session hydrated meanwhile keeps its
  // items in memory and stays unsynced.
  if (dialBlock) return;
  if (!session || writesInFlight > 0) return; // a save is landing — don't race its rev
  if (session.serverEnded) return; // §4.4: the server ended this session — nothing is dialed until a new sign-in
  try {
    // §4.4 "on every policy probe or sync": a fork found here blocks the origin and locks the session.
    await ensureCardFresh().catch((e) => {
      if (e instanceof CardStopError && e.code === "server_fork") throw e;
    });
    if (!session || dialBlock) return;
    // Work that outlives a lock: the feed belongs to the session that asked for it. A lock, a sign-out or
    // another account's sign-in while it was on the wire ends that session, and the feed is then dropped: never
    // decrypted with, nor installed into, the session that holds the worker now.
    const asker = session;
    const sync = await api.sync(0);
    if (writesInFlight > 0 || session !== asker) return; // a write started mid-sync — its result would be clobbered
    // A shared vault this answer no longer grants loses its key here, before anything is decrypted, in the same step
    // that drops its role entry and its opened items, and the sealed snapshot is written again at once without them
    // (that write also rebuilds the known-logins digest from the items left). A vault the server serves
    // again later (the person added again, the vault put back under the same id) then opens only through an unlock and
    // its checks (buildUnlockKeys), never on the server's word inside this session; until then it counts as waiting.
    // The personal vault's key comes from the personal wrap, not from a grant row, and is kept.
    // A key goes only on a list of grants the server sent whole (api.ts sync, grantedVaultIds): an answer without one
    // drops no key, a row refused as malformed still counts as a grant of the vault it names, and a row whose vault id
    // is itself unusable means no key is dropped in this pull.
    const granted = new Set(sync.grants.map((g) => g.vaultId));
    const stillGranted = sync.grantedVaultIds;
    let dropped = false;
    if (stillGranted) {
      for (const vaultId of [...session.vaultKeys.keys()]) {
        if (vaultId !== session.personalVaultId && !stillGranted.has(vaultId)) {
          session.vaultKeys.delete(vaultId);
          dropped = true;
        }
      }
    }
    // The opened items go with their key, through itemsUnderHeldKeys, the one rule of every place that sets the list:
    // from here on the session shows, fills and seals only items of vaults whose key it still holds, also when an older
    // pull that opened such a vault's rows before this drop installs after it. A save still on the wire when this pull
    // resumes from its homes write makes it stop before its install (writesInFlight below); one that already landed
    // is overwritten by the install, until the next pull.
    if (dropped) session.items = itemsUnderHeldKeys(session.items, session.vaultKeys);
    // H70 (2026-09-13 audit): refresh the G21 reader gate's input as well as the item projection.
    // A grant's `role` needs no key to read and the server re-delivers the grant row on every role
    // change (spec 03 §4), but this pull only ever rebuilt the items — so an owner demoting a
    // member to reader mid-session left this client still OFFERING Update / TOTP-add against that
    // vault, and the server's refusal rendered as the pre-G21 lying "Could not save — try again."
    // until the next full unlock. That window is longest here of all four clients: quick-unlock
    // can carry one session across days. Web is the twin that already gets this right (store.ts
    // routes every delivered grant through addGrant, so a role change always applies).
    //
    // Scoped to vaults we hold a key for: a brand-new grant still needs uvk/identity to open and
    // lands at the next real unlock (this function's contract above), and a role for a vault whose
    // items we cannot decrypt would gate nothing. A grant that has VANISHED from the feed loses
    // its role entry, and nothing is offered or sent because of that: this extension writes only
    // to the personal vault (writableItem, putItem), so an item of a shared vault is read-only here
    // whatever its role, and a role is read only for the vault a landed write was made to, before
    // its conflict copy (materializeConflictCopy).
    for (const g of sync.grants) if (session.vaultKeys.has(g.vaultId)) session.vaultRoles.set(g.vaultId, g.role);
    for (const vaultId of [...session.vaultRoles.keys()]) if (!granted.has(vaultId)) session.vaultRoles.delete(vaultId);
    if (dropped) void persistSession();
    // A1b INV-HOME: the snapshot's rows are admitted against this browser's homes BEFORE anything is decrypted.
    const homed = await homeAndDecrypt(sync, session.vaultKeys, session.userId, session.personalVaultId, { homes: session.homes, known: session.homesKnown });
    if (writesInFlight > 0 || session !== asker) return;
    session.items = itemsUnderHeldKeys(homed.items, session.vaultKeys);
    session.wrongVault = homed.wrongVault;
    session.vaultMeta = vaultMetaOf(sync.vaults); // A11 (q14)
    // A6 (§1.7): a new grant waits for a full client; the count needs no UVK, so it stays honest after an eviction.
    session.waitingGrants = waitingGrantCount(sync.grants, new Set(session.vaultKeys.keys()), session.personalVaultId);
    persistSession();
    if (stashOwed === session) void clearOwedStash(session); // a stash an unlock could not clear
    // G04: a landed full snapshot (cursor 0) is the one moment we hold the COMPLETE live item set,
    // so this is the only flush allowed to prune the usage ledger — never the debounce/lock flushes.
    // Built from the RAW sync feed (not session.items), so an item this SW can't decrypt (newer fv,
    // unheld VK) keeps its cross-device usage instead of being pruned away as "gone".
    void flushUsage(new Set(sync.items.filter((it) => !it.deleted).map((it) => it.itemId)));
  } catch {
    /* tolerated */
  }
}

// ---- live change-push (dirty-bell WebSocket — design 2026-07-13-ext-live-sync.md) ----
// A peer edit reaches this SW in ~1–2 s via the server's rev bell instead of the 5-min alarm.
// The bell only NUDGES the existing resync() pull — no new decrypt path, no new secret egress —
// and nothing here may ever call armAutoLock() (bells are not user activity, PASSIVE_MSGS law).

/** Ticket-mint glue for events.ts. A definitive auth refusal folds to null (stop the cycle
 *  quietly — the vault STAYS unlocked serving offline fills, exactly like a failing alarm sync;
 *  a mint 401 must NEVER doLock, or laptop-asleep expiry would punish the user). Anything else
 *  (offline, 5xx) stays a throw = transient → events.ts backs off. The ticket is single-use,
 *  deviceId-bound server-side, and never persisted or logged. */
async function mintTicket(): Promise<string | null> {
  try {
    return (await api.eventsTicket()).ticket;
  } catch (e) {
    if (e instanceof ApiError && (e.status === 401 || e.status === 403)) return null;
    throw e;
  }
}

/** Open (or prod) the live socket — ONLY while a session exists in the SW; locked or logged out
 *  means no socket (doLock cleared the tokens, so no ticket could be minted anyway). Every
 *  trigger funnels here: T1 SW-wake bootstrap (module scope), T2 unlock, T3 resync alarm —
 *  `reset` collapses a pending backoff so those known-good moments reconnect immediately. */
async function ensureSocket(reset = false): Promise<void> {
  await ensureLoaded(); // session may not be hydrated yet on a fresh SW wake
  if (!session || session.serverEnded) return; // §4.4: no socket for a session the server ended
  if (dialBlock) return; // A16 review R4: no socket while a server is pending (or unknown) — nothing is dialed
  if (!events || events.closed) {
    events = startEvents({
      wsUrl: serverUrl.replace(/^http/, "ws") + "/api/v1/events",
      mintTicket,
      // The DOM WebSocket satisfies WsLike at runtime; TS's strict property variance on the on*
      // slots blocks the structural check — bridge it here, at the one real-socket seam.
      makeSocket: (u) => new WebSocket(u) as WebSocket & WsLike,
      onBell: () => void resync(), // debounced in events.ts; the EXISTING pull, nothing else
      // Explicit server revocation frame: the server ended this session (§4.4). Its tokens and the quick-unlock record
      // go (never the armed-retaining lock, breaker A3⊕B2); what it holds stays readable (endSessionByServer).
      // A frame is a way in too: past the lock's deadline the session is locked first (a bell's pull checks
      // it in resync's load), and an ended session is then not left readable.
      onRevoked: () => void lockIfDue().then(() => endSessionByServer()),
    });
  } else {
    events.kick(reset);
  }
}

// ---- self-update signal (tier 1: NOTIFY only) ----
// Unpacked extensions cannot self-install, so the SW never rewrites itself — it only records
// that a newer build sits at /downloads and lets the popup + web hub point the user to it.

interface UpdateInfo {
  latest: string;
  chromeUrl: string | null;
  firefoxUrl: string | null;
}

// The manifest's relative "/downloads/<basename>" paths become absolute links in updateoffer.offerDownloadUrl (A15
// step 0): ONLY `${UPDATE_ORIGIN}/downloads/<basename>`, only while the current server is the public instance. The
// popup is a chrome-extension:// page, so a relative href would resolve against the EXTENSION origin.

/**
 * H2 signed-update check (design 2026-07-13-signed-updates §D/§M). Fetch the manifest as RAW BYTES
 * plus its detached `manifest.json.sig`, verify the Ed25519 signature over the EXACT bytes against
 * the pinned key SET (updateverify.ts), and ONLY THEN parse + enforce the anti-rollback `seq` and
 * the `signedAt` staleness window. On a strictly-newer build it records an [UpdateInfo]; on an
 * equal-or-older build it clears any stale signal.
 *
 * FAIL-CLOSED QUIET (§M-D5/D6): any fetch/verify/seq/staleness failure records a distinct quiet
 * reason and NEVER fabricates or refreshes a nag — an existing previously-VERIFIED signal is left
 * intact (only a clean verified read supersedes it), so a T1 server stripping the sig can DoS the
 * fetch but never conjure a scary banner. Records no vault state, so it is safe to run locked.
 * [force] bypasses the wake throttle. Never throws.
 */
async function checkForUpdate(force = false): Promise<void> {
  try {
    await serverReady; // the channel state below is per-origin (nsk) and the fetch needs serverUrl
    // A15 review F1: while a server is pending (or the store did not answer), no update poll reaches any server.
    if (dialBlock) return;
    const kInfo = nsk(UKEY);
    const kLast = nsk(ULAST);
    const kSeq = nsk(USEQ);
    const kQuiet = nsk(UQUIET);
    if (!force) {
      const seen = (await plainSession.get(kLast))[kLast];
      if (typeof seen === "number" && Date.now() - seen < UPDATE_MIN_GAP_MS) return;
    }
    // §M-D3: a build pinning only the placeholder sentinel has NO update path — do not even fetch.
    if (!updatesEnabled()) return;
    // The Safari build updates through the App Store: no poll, no banner, no download links. Nor does a person's test
    // build poll: it is replaced by hand with the next test build, never by a release.
    if (typeof __ANDVARI_TEST_SERVER__ === "string" || !selfUpdateChannelAllowed()) return;
    // Reference-instance scope (2026-07-18 arming; multi-tenant §9): the pinned key signs OUR
    // `/downloads` only, so the channel runs solely against the shipped default origin. A
    // self-host/custom origin gets NO fetch and NO quiet marker — the exact fail-closed-quiet
    // "disabled" posture the un-armed build gave every origin. (Per-instance keys are later work.)
    if (serverUrl !== PUBLIC_INSTANCE.origin) return;
    // A15: the anti-rollback seq lives in the trusted store and was NOT migrated (a planted storage.local seq could only
    // suppress genuine offers); an absent record is the MIN_SEQ floor below. A15 review F3: a read that FAILS aborts
    // the check before anything is fetched — it is not "absent" (folding it into the floor let the write below lower a
    // genuine higher seq), and without the store nothing verified could be kept anyway (Firefox "Never remember
    // history": no update banner there; Firefox's own update_url still updates the add-on).
    let storedSeq: unknown;
    try {
      storedSeq = (await trusted.get(kSeq))[kSeq];
    } catch {
      return;
    }

    const base = serverUrl + "/downloads/manifest.json";
    let mResp: Response;
    let sResp: Response;
    try {
      // §M-D6: the sig is a SECOND request over the same raw bytes — either fetch failing → quiet.
      // No redirect is followed: a redirect is not ok, so it is stamped quiet below like any answer that is not the server's.
      [mResp, sResp] = await Promise.all([fetch(base, { cache: "no-store", redirect: "manual" }), fetch(base + ".sig", { cache: "no-store", redirect: "manual" })]);
    } catch {
      return; // network (offline / DNS) — transient; keep any prior signal, don't stamp ULAST
    }
    if (!mResp.ok || !sResp.ok) {
      // Reachable server but the manifest or its detached sig errored (404/5xx) — a misconfigured or
      // tampering server, NOT offline. Fail-closed QUIET and STAMP ULAST so the wake-throttle floors it
      // (§M-D5): otherwise, once ULAST ages past UPDATE_MIN_GAP_MS, every SW wake (content message,
      // popup, alarm) would re-hammer two no-store fetches indefinitely. A genuine network reject is
      // caught above and left un-stamped for prompt retry when connectivity returns.
      await plainSession.set({ [kQuiet]: { reason: "manifest_fetch_failed" }, [kLast]: Date.now() });
      return;
    }

    // EXACT bytes — never resp.json() (§M-D6) — and CAPPED while read (A13 review RF6, desktop q19): both bodies are
    // unverified server bytes. An oversized answer is a misbehaving server, the same stamped quiet as a non-OK one.
    const raw = await readCappedBody(mResp, UPDATE_MANIFEST_MAX_BYTES);
    const sigBytes = raw === null ? null : await readCappedBody(sResp, UPDATE_SIG_MAX_BYTES);
    if (raw === null || sigBytes === null) {
      await sResp.body?.cancel().catch(() => undefined);
      await plainSession.set({ [kQuiet]: { reason: "manifest_fetch_failed" }, [kLast]: Date.now() });
      return;
    }
    const sigText = new TextDecoder().decode(sigBytes);
    // §M-D4(a) anti-rollback FLOOR: a fresh install (or a wiped USEQ) starts at MIN_SEQ, not 0, so a
    // T1 server can't steer it to any validly-signed-but-older (known-vuln) manifest below the floor.
    const lastAcceptedSeq = Math.max(typeof storedSeq === "number" ? storedSeq : 0, MIN_SEQ);
    const decision = evaluateSignedManifest(raw, sigText, { lastAcceptedSeq, now: Date.now() });

    // A completed fetch stamps ULAST regardless of verdict (the throttle floors real fetches, §M-D5
    // — a tampering/stale server must not be hammered on every SW wake).
    if (decision.kind === "quiet") {
      if (decision.reason === "seq_regression") {
        // NOT a failure: the fetch verified a genuine, signature-valid, well-formed manifest that is
        // simply not newer than one we already accepted (the normal steady state after every accept).
        // Treat it like a clean verified read — CLEAR any prior quiet marker (healthy channel) and stamp
        // ULAST. Surfacing this as "couldn't be verified" would be a permanent false alarm, and stamping
        // it would also clobber a real prior `unverified`/`stale` signal (fail-open). Leave [UKEY] alone.
        await plainSession.remove(kQuiet);
        await plainSession.set({ [kLast]: Date.now() });
        return;
      }
      // Fail-closed QUIET (unverified/malformed/stale): record the distinct ACTIONABLE reason; leave any
      // prior VERIFIED [UKEY] signal alone.
      await plainSession.set({ [kQuiet]: { reason: decision.reason }, [kLast]: Date.now() });
      return;
    }

    // Fully verified, seq-monotonic, fresh — this read supersedes the stored verdict.
    const ext = decision.ext;
    const latest = typeof ext.version === "string" ? ext.version : null;
    const current = chrome.runtime.getManifest().version;
    await plainSession.remove(kQuiet); // a clean verified read clears the quiet marker
    // Stamp the throttle first, in storage.session (plain: a timestamp): a trusted store that cannot be written (Firefox
    // private browsing) must not turn every wake into another fetch.
    await plainSession.set({ [kLast]: Date.now() });
    if (latest && isNewerVersion(latest, current)) {
      // A15 step 0: the links are built by the offer leaf only — `${UPDATE_ORIGIN}/downloads/<basename>` or none.
      const info: UpdateInfo = { latest, chromeUrl: offerDownloadUrl(ext.chromeUrl, serverUrl), firefoxUrl: offerDownloadUrl(ext.firefoxUrl, serverUrl) };
      await trusted.set({ [kInfo]: info, [kSeq]: decision.seq });
    } else {
      await trusted.remove(kInfo); // up to date (or unreadable version) → no signal
      await trusted.set({ [kSeq]: decision.seq });
    }
  } catch {
    /* unexpected — any existing signal stands until a clean verified read supersedes it */
  }
}

/** Popup query: the stored signal, RE-VALIDATED against the currently-installed version so a
 *  signal recorded before an in-place reload can never linger as a false "update available". When
 *  there is no offer, surface the fail-closed-QUIET update-channel reason from [UQUIET] (M-D4b /
 *  compliance UQUIET-read) so the popup can render ONE muted line — an offer supersedes it
 *  (mutually exclusive, mirroring the desktop's `updateAvailable` vs `updateChannelNotice`). */
async function updateStatus(): Promise<Res<"updateStatus">> {
  const current = chrome.runtime.getManifest().version;
  const kInfo = nsk(UKEY);
  const kQuiet = nsk(UQUIET);
  // A15 step 0: the stored offer is re-checked on EVERY read, not only when it was fetched — the current server is
  // the public instance, the version is strictly newer, and each link is `${UPDATE_ORIGIN}/downloads/<basename>` again.
  const offer = readUpdateOffer(await trustedGet(kInfo), current, serverUrl);
  if (offer) return { current, latest: offer.latest, chromeUrl: offer.chromeUrl, firefoxUrl: offer.firefoxUrl, quietReason: null };
  let quiet: { reason?: unknown } | undefined;
  try {
    quiet = (await plainSession.get(kQuiet))[kQuiet] as { reason?: unknown } | undefined;
  } catch {
    quiet = undefined; // storage.session unavailable — no quiet line
  }
  // Surface ONLY actionable reasons (M-D4b): a benign seq_regression — or any marker a pre-fix build
  // may have persisted — must never render as a scary "couldn't be verified" line.
  const rawReason = quiet && typeof quiet.reason === "string" ? quiet.reason : null;
  const quietReason = rawReason && SURFACEABLE_QUIET_REASONS.has(rawReason) ? rawReason : null;
  return { current, latest: null, chromeUrl: null, firefoxUrl: null, quietReason };
}

// ---- message dispatch ----

async function handle(msg: Req, sender: chrome.runtime.MessageSender, due: Promise<boolean>): Promise<unknown> {
  // A15 review S1: a lock never waits on the trusted store through here — doLock bounds its own wait for the origin.
  // A16 review R4: nor does a sign-out wait on it to erase — doLock erases first, and its own copy supplies the pair.
  // The load checks the lock's deadline (ensureLoaded). A lock or a sign-out past it waits for the idle lock
  // the deadline started; a Lock is then answered by it (a second lock, finding no session, would wipe the record the
  // idle lock armed), and a sign-out goes on to its full wipe.
  if (msg.type !== "lock" && msg.type !== "signOut") await ensureLoaded();
  else if ((await due) && msg.type === "lock") return { ok: true } satisfies Res<"lock">;
  const res = await dispatch(msg, sender);
  // Policy idle window: only genuine user activity re-arms the lock. Automated traffic
  // (pageInfo on every load, the popup's 1 s TOTP poll) must not defer autolock while away —
  // and neither does a message the sender gate refused (A14): a page-side context spamming a
  // popup-only type is not the user.
  if (session && msg.type !== "lock" && !PASSIVE_MSGS.has(msg.type) && senderMaySend(msg.type, sender, EXTENSION_BASE)) armAutoLock();
  return res;
}

async function dispatch(msg: Req, sender: chrome.runtime.MessageSender): Promise<unknown> {
  // Security review 2026-10, A14 (F3/F4/F11): ONE structural gate before any handler. A type no
  // content script sends (unlock, the quick-unlock lanes, lock/signOut, status, cardItems, …) is
  // answered with its own refusal shape unless sender.url is one of this extension's pages. The
  // per-handler checks below stay as a second layer. See sendergate.ts.
  const gate = senderGate(msg.type, sender, EXTENSION_BASE);
  if (gate.refused) return gate.answer;
  // A15 review F1: while a server is pending (a previous one awaits the user's confirm, or the trusted store did not
  // answer), nothing that would reach a server runs — no sign-in lane, no connection test (serverstate.ts).
  const held = dialRefusal(msg.type, dialBlock);
  if (held) return held;
  // Safari on iOS: this extension has no session of its own; the vault is the andvari app's (appvault.ts).
  if (APP_VAULT !== null) {
    const viaApp = await appVaultDispatch(msg, sender);
    if (viaApp !== undefined) return viaApp;
  }
  switch (msg.type) {
    case "ping": {
      // Rendered run 2026-11-16: with no server in force the api refuses to dial and threw, so the popup got a bare
      // error and called the server "unreachable"; the code it reads says "no server confirmed".
      if (dialBlock !== null) return { ok: false, code: "confirm_server" } satisfies Res<"ping">;
      const p = await api.clientPolicy(); // host_permissions + reachability
      return { ok: true, serverTime: p.serverTime } satisfies Res<"ping">;
    }
    case "status": {
      // The F26 reason line only matters while locked (it sits above the unlock form).
      const lockNotice = session ? null : await readLockNotice();
      // Quick-unlock sub-state (spec 01 §8.4) — `armed` drives the LOCKED popup's PIN field vs the
      // master-password field; `enrolled`/`offerDismissed` drive the unlocked Settings toggle + offer.
      // TOTP challenge in progress (0.16.3): read from the SW memory var — its lifetime IS "the retry
      // can still succeed", so a cold-woken SW correctly reports none and the popup shows the full form.
      // Outranks the quick-unlock PIN view (a live challenge is the most-recent intent — see popup).
      const tp = livePendingTotp();
      // An alarm the browser refused twice is said in one line while the vault is open (the auto-lock's
      // first: the deadline still locks on time, at the next way in). Read once the last request settled (bounded).
      await Promise.race([alarmWork, delay(LOCK_STORE_WAIT_MS)]);
      const timerNotice = session === null ? null : timerRefused.autolock ? "autolock" : timerRefused.resync && !session.serverEnded ? "resync" : null;
      return {
        timerNotice,
        unlocked: session !== null,
        count: loginItems().length,
        email: session?.email ?? null,
        cardNotice: cardNotice(),
        lockNotice,
        quickUnlock: await quStateForStatus(),
        totpPending: tp ? { email: tp.email, expiresAt: tp.expiresAt } : null,
        waitingGrants: session?.waitingGrants ?? 0,
        serverEnded: session?.serverEnded === true,
        serverEndedUnconfirmed: session?.endedUnconfirmed === true,
        wrongVault: session?.wrongVault ?? 0,
        rememberedEmail: session ? null : await readRememberedEmail(),
        unsavedCaptures: unsavedCaptures(),
        // Said above the unlock form, once: taken by the popup's render.
        capturesLost: session === null && msg.takeLost === true ? await takeLostCaptures() : 0,
      } satisfies Res<"status">;
    }
    case "lock": {
      await doLock("manual");
      return { ok: true } satisfies Res<"lock">;
    }
    case "signOut": {
      const notConfirmed = await dropKeptAtSignOut();
      await doSignOut(); // explicit full sign-out — wipes the quick-unlock blob + co-key too (breaker A3⊕B2)
      return (notConfirmed ? { ok: true, notice: "session_not_confirmed" } : { ok: true }) satisfies Res<"signOut">;
    }
    case "unlock":
      return unlockWithMapping(msg.email, msg.password);
    case "unlockTotp":
      return unlockTotp(msg.code);
    case "cancelTotp":
      clearPendingTotp(); // popup "start over" / bad-code cap → drop the in-memory challenge
      return { ok: true } satisfies Res<"cancelTotp">;
    case "unlockWithPin":
      return unlockWithPin(msg.pin);
    case "enrollQuickUnlock":
      return enrollQuickUnlock(msg.pin);
    case "unlockWithBio":
      return unlockWithBio();
    case "enrollQuickUnlockBio":
      return enrollQuickUnlockBio();
    case "disableQuickUnlock":
      return disableQuickUnlock();
    case "dismissQuickUnlockOffer":
      return dismissQuickUnlockOffer();
    case "purgeServerData":
      // §4.2/B2-7 — the ONLY destructive per-origin path (the options page's explicit "Remove data for
      // this server"). Trust gate: the sender must be one of OUR extension pages, judged by its
      // extension-origin URL — NOT by `sender.tab === undefined`, which is FALSE for the options page
      // (options_ui open_in_tab: a real tab, so the old tab-based check refused the ONLY legitimate
      // caller — 2026-07-18 review Finding 2). A content script's sender.url is the WEB page's ⇒
      // refused; canonicalize + originKey derivation stay in the serverswitch leaf (a non-origin
      // string yields no key ⇒ no-op; safe for the current origin, never touches another's).
      // Cached state only — the pin, its fork mark, the high-water marks and the item homes
      // stay ("Forget this server" is the only thing that removes a pin).
      return purgeServerDataFor(
        msg.origin,
        !(sender.url ?? "").startsWith(chrome.runtime.getURL("")),
        (originKey) => purgeOriginNamespace(originKey, { keepTrust: true }),
      ) satisfies Promise<Res<"purgeServerData">>;
    case "serverInfo":
      return serverInfo();
    // Design 2026-11-15 §4.4, §12.2: the ONLY ways the server choice changes (the popup and the options page). The sender
    // gate above already refused any sender that is not one of our pages.
    case "chooseServer":
      return chooseServer(msg);
    case "confirmServer":
      return confirmServer(msg);
    case "forgetServer":
      return forgetServer();
    case "forgetEarlierAccount":
      return forgetEarlierAccount(msg.email);
    case "followServerChange":
      return followServerChange(msg);
    case "deferServerChange":
      return deferServerChange(msg);
    case "appServer":
      return syncAppServer();
    case "appServerAnswer":
      return adoptRelayedAppServer(msg);
    case "serverDiag":
      return serverDiag();
    case "scheduleClipboardClear":
      return scheduleClipboardClear();
    case "matches": {
      if (!session) return { locked: true, matches: [] } satisfies Res<"matches">;
      // Security review 2026-10 (root cause E): a page frame's matches are its BROWSER-SET origin's
      // (senderorigin.ts) — `msg.host` is the frame's own claim and named any host it liked. The page is named by its
      // origin, so its scheme decides (F4: a plain-http page matches only an address saved as http).
      const page = requestPage(sender.tab !== undefined, sender.origin, msg.host);
      return { locked: false, matches: page === null ? [] : matchesFor(page).map((i) => toMatchItem(i, true)) } satisfies Res<"matches">;
    }
    case "allItems": {
      // Popup ONLY (security review 2026-10): the in-page search-all that once needed the whole
      // inventory in every frame now hands off to the popup, so a page frame gets nothing here.
      if (sender.tab !== undefined) return { locked: !session, items: [] } satisfies Res<"allItems">;
      if (!session) return { locked: true, items: [] } satisfies Res<"allItems">;
      const q = (msg.query ?? "").trim().toLowerCase();
      const items = loginItems()
        .filter(
          (i) =>
            !q ||
            i.doc.name.toLowerCase().includes(q) ||
            (i.doc.login?.username ?? "").toLowerCase().includes(q) ||
            (i.doc.login?.uris ?? []).some((u) => u.toLowerCase().includes(q)),
        )
        .map((i) => toMatchItem(i, false));
      return { locked: false, items } satisfies Res<"allItems">;
    }
    case "cardItems": {
      if (!session) return { locked: true, items: [] } satisfies Res<"cardItems">;
      const q = (msg.query ?? "").trim().toLowerCase();
      const items = cardItems()
        .map(toCardItem)
        .filter((c) => !q || c.name.toLowerCase().includes(q) || c.subtitle.toLowerCase().includes(q));
      return { locked: false, items } satisfies Res<"cardItems">;
    }
    case "reveal":
      return reveal(msg, sender);
    case "revealCardField":
      return revealCardField(msg, sender);
    case "fillFromPopup":
      return fillFromPopup(msg.itemId, sender, typeof msg.confirmedOtherSite === "string" ? msg.confirmedOtherSite : null, typeof msg.page === "string" ? msg.page : null);
    case "capturedCredential":
      return capturedCredential(msg, sender);
    case "captureCard":
      return captureCard(msg, sender);
    case "resolvePendingCardSave":
      return resolvePendingCardSave(msg.action, sender);
    case "pendingSave": {
      // Top frame only (undefined = the popup, which legitimately asks about the active tab —
      // reveal()'s isTopFrame shape): a cross-origin sub-frame must not read the top frame's
      // captured host/username/vault-item metadata. The render was always isTop-gated
      // content-side; this closes the SW half.
      if (sender.frameId !== undefined && sender.frameId !== 0) return { pending: null } satisfies Res<"pendingSave">;
      const tabId = await contextTabId(sender);
      // 2026-08-18: same TTL/quiet/throttle gate as the onUpdated re-offer — this poll fires on
      // every top-frame load, so ungated it was the other half of the every-page-load nag.
      const st = tabId === undefined ? undefined : tabs.get(tabId);
      const p = st === undefined || tabId === undefined ? null : gateReoffer(tabId, st);
      return { pending: p ? publicPending(p) : null } satisfies Res<"pendingSave">;
    }
    case "resolvePendingSave":
      return resolvePendingSave(msg.action, sender);
    case "openPopupForSave":
      return openPopupForSave(sender); // unlock-prompt 2026-08-12 — rides the banner's isTrusted Save click, deliberately NOT passive
    case "linkUri":
      return linkUri(msg, sender);
    case "generate":
      return { password: generatePassword(DEFAULT_GENERATOR) } satisfies Res<"generate">;
    case "passwordReuse": {
      // UNLOCKED-ONLY (messages.ts contract): no session ⇒ no answer, and deliberately no
      // locked-state digest fallback — that would be a vault-wide PASSWORD oracle living in the
      // locked compartment. The comparison happens HERE, against already-decrypted items in SW
      // memory. Security review 2026-10 (root cause E): the count no longer leaves for the page
      // side at all — the in-page toast it drove was page-readable. A hit is recorded for the tab
      // and shown in extension-owned UI (REUSE_BADGE_TEXT + the popup's `reuseNotice`); every
      // answer to the frame is the same bare `ok`.
      if (!session) return { ok: false } satisfies Res<"passwordReuse">;
      // H02 (2026-09-13 audit): the unlocked side WAS the oracle — the trigger (a trusted
      // focusout) is page-driveable and the answer is page-readable by hit-testing the toast. The
      // real gate is content-side (a trusted keystroke, reusealert.ts typedByUser); this is the
      // SW's belt, in the cardChipOffer idiom: (1) TOP FRAME ONLY — an ad/widget frame gets its
      // own content script and its own toast, so it could run the probe entirely inside itself;
      // (2) one answer per tab per REUSE_ASK_MIN_GAP_MS — a human settles one password at a time,
      // a probe loop wants hundreds a second. Both refusals answer the silent shape (count 0),
      // which records nothing; silence is never an all-clear on this path.
      const tabId = sender.tab?.id;
      if (tabId === undefined || sender.frameId !== 0) return { ok: false } satisfies Res<"passwordReuse">;
      const now = Date.now();
      const last = reuseAskLast.get(tabId);
      if (last !== undefined && now - last < REUSE_ASK_MIN_GAP_MS) return { ok: false } satisfies Res<"passwordReuse">;
      reuseAskLast.set(tabId, now);
      const pw = msg.password;
      if (!pw) return { ok: false } satisfies Res<"passwordReuse">;
      const hits = session.items.filter((i) => i.doc.type === "login" && i.doc.login?.password === pw).length;
      if (hits > 0) reuseNotices.set(tabId, { count: hits });
      else reuseNotices.delete(tabId); // the user changed their mind to a unique one: drop the stale warning
      refreshTabBadge(tabId);
      return { ok: true } satisfies Res<"passwordReuse">;
    }
    case "reuseNotice": {
      // Popup ONLY — the count must never reach a page frame (that was the oracle).
      if (sender.tab !== undefined) return null satisfies Res<"reuseNotice">;
      const tabId = await contextTabId(sender);
      const n = tabId === undefined ? undefined : reuseNotices.get(tabId);
      if (tabId === undefined || n === undefined || !session) return null satisfies Res<"reuseNotice">;
      reuseNotices.delete(tabId); // shown once; the badge goes back to its normal signal
      refreshTabBadge(tabId);
      return { count: n.count } satisfies Res<"reuseNotice">;
    }
    case "totp": {
      // G14 (2026-08-30 audit): POPUP ONLY — enforce the messages.ts "Popup: live TOTP code"
      // contract the way every sibling secret handler does (revealCardField / fillFromPopup /
      // setTotp). Without this, any page frame could pull the live 2FA code for an arbitrary
      // itemId while unlocked; the popup has no tab, so this is behavior-preserving for it.
      if (sender.tab !== undefined) return { ok: false } satisfies Res<"totp">;
      const uri = session?.items.find((i) => i.itemId === msg.itemId)?.doc.login?.totp;
      if (!uri) return { ok: false } satisfies Res<"totp">;
      try {
        const { code, secondsLeft } = currentCode(uri, Date.now());
        // H69 (2026-09-13 audit): copying a one-time code IS a use — desktop (Ui.kt TotpRow
        // onUsed) and Android (MainActivity TotpRow onUsed) both record it under the G37 rule,
        // and web counts it too; the extension was the fourth client that never came in line, so
        // a login the household drives daily from this chip ranked as "never used" everywhere
        // else. Recorded HERE, after the popup-only gate and a successful code, so a refused or
        // malformed answer never counts.
        //
        // ONLY on `forCopy`. This same message is the popup's 1 s display ticker for every
        // visible chip (that is why "totp" is passive), so an unconditional recordUsage would
        // stamp every TOTP item once a second while the popup is open — the staleness column
        // would say "just now" forever. Same batched flush as a fill: no per-use PUT (spec 03 §3
        // forbids turning the ledger blob's updatedAt into a keystroke-grade activity trace).
        if (msg.forCopy === true) recordUsage(msg.itemId);
        return { ok: true, code, secondsLeft } satisfies Res<"totp">;
      } catch {
        return { ok: false } satisfies Res<"totp">; // malformed stored totp
      }
    }
    case "setTotp":
      return setTotp(msg, sender); // TOTP-add 2026-08-12 — popup paste-add, deliberately NOT passive
    case "pageInfo": {
      const locked = session === null;
      // Security review 2026-10 (root cause E): the count is for the sender's browser-set origin.
      const page = requestPage(sender.tab !== undefined, sender.origin, msg.host);
      const matchCount = locked || page === null ? 0 : matchesFor(page).length;
      const tabId = sender.tab?.id;
      // V4: the badge is the tab's ONE authority now (refreshTabBadge — login count precedence, else
      // the card discovery dot). Top frame only — an iframe's load must not repaint the tab's signal.
      // Review-fold ([A4]): record the top origin from the BROWSER-SET sender.origin of the
      // top-frame report — the badge must never read tab.url outside the popup-open window (the
      // pinned [A4] constraint); the same identity source cardFormInfo already trusts.
      if (tabId !== undefined && (sender.frameId === undefined || sender.frameId === 0)) {
        if (typeof sender.origin === "string" && sender.origin !== "" && sender.origin !== "null") {
          const st = tabs.get(tabId) ?? {};
          st.topOrigin = sender.origin;
          // H13: a top-frame load on ANOTHER site ends the multi-step flow the step-1 username
          // belonged to — drop it, so a later password-only capture here cannot inherit it. Same-site
          // loads (step 1 → step 2, a wrong-password retry) keep it: that is what it is for. Read
          // through stepUsernameFor so a pre-H13 bare-string record is dropped too.
          if (st.lastUsername !== undefined) {
            const here = hostOfUrl(sender.origin);
            if (stepUsernameFor(st.lastUsername, here === null ? null : (siteKeyOfHost(here, pslResolve) ?? here)) === "") st.lastUsername = undefined;
          }
          tabs.set(tabId, st);
          // [S4a] SHIPPED-BUG FIX (design 2026-07-26 §C2): this write had NO persistTabs(), so the
          // recorded top origin lived only in SW memory and died with the ~30 s MV3 idle-death —
          // and `pageInfo` fires ONCE at content init, so nothing ever rewrote it. The V4 card
          // discovery dot therefore stopped appearing after the first SW idle, silently. Every
          // other TabState mutation persists; this one now does too (the map is already
          // storage.session-backed — memory-backed browser storage, never disk, and an origin is
          // trusted-chrome metadata, not a secret).
          persistTabs();
        }
        void refreshTabBadge(tabId);
      }
      return { matchCount, locked } satisfies Res<"pageInfo">;
    }
    case "updateStatus":
      return updateStatus();
    // In-page card fill, per build (cardfillflag.ts; owner decision 2026-11-14). Each entry point of the card path is
    // gated on the build's define itself, so a build without card fill answers the fixed refusal and does not even
    // bundle the handler: nothing records a card choice, offers a chip, mints a card grant or releases a card's fields.
    case "cardFormInfo":
      return __ANDVARI_CARDFILL__ ? cardFormInfo(msg, sender) : ({ ok: false } satisfies Res<"cardFormInfo">);
    case "cardChipOffer":
      // C1 §C2 — page-triggered, so it is in PASSIVE_MSGS ([K13])
      return __ANDVARI_CARDFILL__ ? cardChipOffer(sender) : ({ fillable: false, locked: false } satisfies Res<"cardChipOffer">);
    case "openPopupForCards":
      // C1 §C4 — a real isTrusted click, deliberately NOT passive
      return __ANDVARI_CARDFILL__ ? openPopupForCards(sender) : ({ opened: false } satisfies Res<"openPopupForCards">);
    case "openPopupForSearch":
      return openPopupForSearch(sender); // root cause B hand-off — a real, visibility-guarded click; NOT passive
    case "cardFillOffers":
      return __ANDVARI_CARDFILL__ ? cardFillOffers(sender) : ({ fillable: false, origin: null, frames: [], pageFormOnly: false, fillOff: true } satisfies Res<"cardFillOffers">);
    case "clearCardChoices":
      return __ANDVARI_CARDFILL__ ? clearCardChoices(sender) : ({ ok: false } satisfies Res<"clearCardChoices">);
    case "fillCardFromPopup":
      return __ANDVARI_CARDFILL__ ? fillCardFromPopup(msg.itemId, msg.frames, sender) : ({ ok: false, code: "fill_off", error: CARD_FILL_OFF } satisfies Res<"fillCardFromPopup">);
    case "revealCardForFill":
      return __ANDVARI_CARDFILL__ ? revealCardForFill(msg, sender) : ({ ok: false, error: CARD_FILL_OFF } satisfies Res<"revealCardForFill">);
  }
}

// ---- unlock ----

/**
 * Derive the master key in a dedicated Web Worker so the SW event loop stays free during the ~5.8 s
 * Argon2id (fill/save messages keep flowing). Falls back to inline (blocks the SW) if the host won't
 * let the SW spawn a worker (older Chrome / some MV3 runtimes). mk stays inside the extension.
 */
function deriveMasterKeyAsync(password: string, params: KdfParams, salt: Uint8Array): Promise<Uint8Array> {
  return new Promise<Uint8Array>((resolve, reject) => {
    const inline = () => {
      try {
        resolve(deriveMasterKey(password, params, salt));
      } catch (err) {
        reject(err instanceof Error ? err : new Error(String(err)));
      }
    };
    let worker: Worker;
    try {
      // The Safari build's bundles are classic scripts (build.mjs), its worker included.
      worker = new Worker(chrome.runtime.getURL("kdf-worker.js"), { type: BUILD_TARGET === "safari" ? "classic" : "module" });
    } catch {
      inline(); // nested workers not supported here → run inline
      return;
    }
    worker.onmessage = (e: MessageEvent<{ ok: boolean; mk?: Uint8Array; error?: string }>) => {
      worker.terminate();
      if (e.data.ok && e.data.mk) resolve(e.data.mk);
      else reject(new Error(e.data.error ?? "kdf worker failed"));
    };
    worker.onerror = () => {
      worker.terminate();
      inline(); // worker execution failed → don't block unlock, run inline
    };
    worker.postMessage({ password, params, salt });
  });
}

/** spec 01 §5 (web account.ts / core parity): the seed-derived identity key is the one the server
 *  cannot forge — a server-sent identityPub that doesn't equal it is a substitution attempt. Hard-fail
 *  with a DISTINCT sentinel (E1-1), including when the field is malformed (garbage where the identity
 *  key belongs IS the tampering this names). No ctEquals in extension crypto.ts; a length + byte loop
 *  is fine (the comparand is server-supplied, so timing is not load-bearing). Shared by the full unlock
 *  AND the quick-unlock redeem — the redeem re-verifies exactly as strictly (design §1 fail-closed table). */
function verifyServerIdentity(localPub: Uint8Array, identityPubB64: string): void {
  let serverIdentityPub: Uint8Array | null = null;
  try {
    serverIdentityPub = fromB64(identityPubB64);
  } catch {
    /* undecodable → treated as a mismatch below */
  }
  if (serverIdentityPub === null || serverIdentityPub.length !== localPub.length || !localPub.every((b, i) => b === serverIdentityPub![i])) {
    throw new IdentityMismatchError();
  }
}

/**
 * The served account against what this extension knows at the current server (accountmemory.ts judgeServed): throws
 * IdentityMismatchError for the same account under another key (no offer), RemadeAccountError for another account under
 * a known address. A read that fails refuses (KnownAccountUnreadableError): taken as "no record", it let a substitution
 * in and then wrote it over the kept key. (A browser with no store at all never reaches a sign-in: chooseServer refuses.)
 * [email] null: the quick unlock, whose account id is the local record's, compares the served account's key record only.
 */
async function checkKnownAccount(email: string | null, userId: string, verifiedPub: Uint8Array): Promise<void> {
  const names = [nsk(keyRecordName(userId)), ...(email === null ? [] : [nsk(addressRecordName(email))])];
  let got: Record<string, unknown>;
  try {
    got = await trusted.get(names);
  } catch {
    throw new KnownAccountUnreadableError();
  }
  const bound = email === null ? null : readRecord(got[names[1]!]);
  // Keys are compared as their decoded bytes, in one canonical text: the served key is the one verifyServerIdentity has
  // just tied to the seed (its 32 bytes, whatever text the server sent them in), and a kept record is read the same way.
  const verdict = judgeServed({ boundUserId: bound, keyOfServed: canonicalKey(readRecord(got[names[0]!])) }, userId, toB64(verifiedPub));
  if (verdict.ok) return;
  throw verdict.code === "identity_mismatch" ? new IdentityMismatchError() : new RemadeAccountError(bound ?? "");
}

/** The account the last "another account under a known address" refusal named, for its address at its server: what
 *  "Forget the earlier account on this device" may forget (decided on 2026-11-17). Memory only; set by no other refusal
 *  (not the same account under another key, not a quick unlock, not records that could not be read). */
let earlierOffer: { originKey: string; email: string; earlier: string; gen: number } | null = null;
/** After a forgetting, the address whose next taken sign-in says once that the extension now remembers that account. */
let rememberNotice: { originKey: string; email: string } | null = null;
/**
 * The same mark kept at rest, with the server's own records (so "Forget this server" removes it), so that a worker the
 * browser stops between the forgetting and the next sign-in still says it: written only by the forgetting, removed when
 * the notice has been said. Holds nothing but that the address's next sign-in says it.
 */
const rememberNoticeName = (email: string): string => nsk(`accountRemembered:${addressNorm(email)}`);
/** The marks this worker has said (by name): one that could not be removed is not said again in this worker's life. */
const rememberSaid = new Set<string>();

/**
 * "Forget the earlier account on this device" (decided on 2026-11-17; the person's own act, behind the popup's second
 * confirmation). Only for the address and server of a refusal that named another account than the one served, and never
 * while a session of the earlier account is open. Removes, at this server only: the address's record (which account the
 * address is), the earlier account's own records (item homes, personal wrap, account-state memory), the device record
 * kept under the address, the quick-unlock record and the biometric reuse record where they are that account's, and a
 * token kept for that address's next sign-in. KEEPS the record of the earlier account's identity key, the server's pin
 * and every other account's records: it is not "Forget this server" and does not purge the server's namespace. Writes
 * nothing; the next sign-in writes the new account's records only where none is kept. Every read comes first: a read
 * that fails forgets nothing, and a removal that fails is never answered "forgotten".
 */
async function forgetEarlierAccount(email: unknown): Promise<Res<"forgetEarlierAccount">> {
  await ensureLoaded();
  const n = typeof email === "string" ? addressNorm(email) : null;
  const offer = earlierOffer;
  if (offer === null || offer.gen !== redeemGen) earlierOffer = null; // a later attempt, lock or switch cleared it
  if (offer === null || offer.gen !== redeemGen || n === null || offer.email !== n || offer.originKey !== currentOriginKey) return { ok: false, code: "not_offered" };
  const u = offer.earlier;
  if (session !== null && session.userId === u) return { ok: false, code: "open" };
  // Every sign-in, code step and quick unlock under way is left from here, as "Forget this server" leaves them: none of
  // them may record the earlier account again, or open it, after its records went. The offer goes with them.
  redeemGen++;
  offer.gen = redeemGen;
  earlierOffer = offer;
  const addressName = nsk(addressRecordName(n));
  const device = emailNorm(n);
  let qu: { userId: string } | null;
  let bio: unknown;
  let bound: string | null;
  try {
    const got = await trusted.get([addressName, nsk(BKEY)]);
    bound = readRecord(got[addressName]);
    bio = got[nsk(BKEY)];
    qu = await quStore.read();
  } catch {
    return { ok: false, code: "failed" };
  }
  // The address names the earlier account still (or nothing: a forgetting cut before it finished). Anything else: the
  // records changed since the refusal, and nothing is forgotten on what was not offered.
  if (bound !== null && bound !== u) return { ok: false, code: "not_offered" };
  if (session !== null && session.userId === u) return { ok: false, code: "open" }; // opened while the reads were out
  const names = [addressName, nsk(`itemHomes:${u}`), nsk(`personalWrap:${u}`), nsk(`accountStateMemory:${u}`), ...(device === null ? [] : [nsk(deviceKey(device))])];
  if ((bio as { userId?: unknown } | undefined)?.userId === u) names.push(nsk(BKEY));
  try {
    // The quick unlock goes first: a failure after it leaves every protective record as it was (the line for a failure
    // says that the quick unlock may already be gone); then the one removal in the trusted store, all of it or none.
    if (qu !== null && qu.userId === u) await quickUnlock.wipe();
    await trusted.remove(names);
  } catch {
    return { ok: false, code: "failed" };
  }
  if (keptUnconfirmed !== null && emailNorm(keptUnconfirmed.email) === device) keptUnconfirmed = null;
  earlierOffer = null;
  rememberNotice = { originKey: currentOriginKey, email: n };
  rememberSaid.delete(rememberNoticeName(n)); // a new forgetting is said again
  try {
    await trusted.set({ [rememberNoticeName(n)]: true });
  } catch {
    /* not kept at rest: this worker still says it from memory; a stopped one does not */
  }
  return { ok: true };
}

/** A kept key record as its canonical text (the 32 bytes it decodes to, encoded as the record is written), or, where it
 *  does not decode to 32 bytes, a value that never equals a served key. */
function canonicalKey(record: string | null): string | null {
  if (record === null) return null;
  try {
    const b = fromB64(record);
    return b.length === 32 ? toB64(b) : "?";
  } catch {
    return "?";
  }
}

/** Thrown when the account genesis fails §5.2 at an unlock: the identity fault (IDENTITY_MISMATCH copy). */
class GenesisRefused extends Error {
  readonly verdict: string;
  constructor(verdict: string) {
    super(`account genesis refused: ${verdict}`);
    this.verdict = verdict;
    this.name = "GenesisRefused";
  }
}

/** Keys an unlock (full or quick) builds, from the AccountKeys, the UVK, the identity seed and a sync. */
interface UnlockKeys {
  vaultKeys: Map<string, Uint8Array>;
  vaultRoles: Map<string, string>;
  personalVaultId: string;
  waiting: number;
}

/**
 * The extension's reduced rule at every unlock (design 2026-11-15 §12.2 rules 1 and 2, §5.2, §5.3):
 *  1. the account genesis is verified against the extension's own Ed25519 and X25519 keys from the identity seed, the
 *     session's userId, the pinned card's instanceId and the served personal wrap's vaultId — any failure is the
 *     identity fault, before any vault material is used;
 *  2. the personal vault is the genesis's `personalVaultId`, its key the served personal wrap when it names that vault
 *     and opens — or, when the server withholds it or it does not open, the wrap this browser cached the last time it
 *     saw one (UVK-sealed, so the cache is safe; an anomaly is logged); otherwise there is no personal vault;
 *  3. the account state is opened under the UVK and checked against the high-water mark (accountstate.ts); shared-vault
 *     wraps open only under its records (grantkeys.ts buildVaultKeys).
 */
async function buildUnlockKeys(
  keys: AccountKeys,
  uvk: Uint8Array,
  seed: Uint8Array,
  userId: string,
  grants: SyncResponse["grants"],
): Promise<UnlockKeys> {
  const instanceId = currentPin?.pin.instanceId;
  if (instanceId === undefined) throw new CardStopError("confirm_server");
  if (typeof keys.genesis !== "string" || keys.genesis === "") throw new GenesisRefused("absent");
  let frame: Uint8Array;
  try {
    frame = fromB64(keys.genesis);
  } catch {
    throw new GenesisRefused("bad_frame");
  }
  const served = keys.personalWrap ?? null;
  const g = verifyGenesis(frame, { own: ownKeysFromSeed(seed), sessionUserId: userId, pinnedInstanceId: instanceId, servedPersonalVaultId: served?.vaultId ?? null });
  if (!g.ok) throw new GenesisRefused(g.verdict);
  const personalVaultId = g.genesis.personalVaultId;
  const vaultKeys = new Map<string, Uint8Array>();
  const vaultRoles = new Map<string, string>();
  const cacheKey = nsk(`personalWrap:${userId}`);
  let personalVk = served === null ? null : personalVaultKey(served.wrappedVk, served.vaultId, personalVaultId, uvk, userId);
  if (personalVk !== null && served !== null) {
    await trusted.set({ [cacheKey]: { vaultId: served.vaultId, wrappedVk: served.wrappedVk } }).catch(() => {}); // ciphertext only
  } else {
    try {
      const cached = decodePersonalWrap((await trusted.get(cacheKey))[cacheKey]).value;
      if (cached !== null) personalVk = personalVaultKey(cached.wrappedVk, cached.vaultId, personalVaultId, uvk, userId);
    } catch {
      /* no trusted store: no cached wrap */
    }
    console.warn(
      personalVk === null
        ? "andvari: the personal-vault record was withheld or does not open; no personal vault this session"
        : "andvari: the personal-vault record was withheld or does not open; using the one this device already authenticated",
    );
  }
  if (personalVk !== null) {
    vaultKeys.set(personalVaultId, personalVk);
    vaultRoles.set(personalVaultId, "owner");
  }
  const records = await readAccountStateRecords(uvk, userId);
  const shared = buildVaultKeys(grants, uvk, userId, personalVaultId, records);
  for (const [id, vk] of shared.vaultKeys) vaultKeys.set(id, vk);
  for (const [id, role] of shared.vaultRoles) vaultRoles.set(id, role);
  warnKeyState(shared.keyUnreadable, shared.waiting);
  return { vaultKeys, vaultRoles, personalVaultId: personalVk === null ? "" : personalVaultId, waiting: shared.waiting.size };
}

/**
 * The account state's records for shared-vault wraps (§12.2 rule 1, §5.4): served, opened under the UVK, merged into
 * this browser's memory of it (per origin and account: the high-water mark of the in-blob seq and the vaults records),
 * and null — no shared-vault wrap opens — when nothing usable is served, the served copy is below the mark, the memory
 * record is damaged, or the state cannot be read. The memory is written back; a rollback is logged.
 */
async function readAccountStateRecords(uvk: Uint8Array, userId: string): Promise<WrapRecords | null> {
  const memKey = nsk(`accountStateMemory:${userId}`);
  let memory: StateMemory | null = null;
  try {
    const raw = (await trusted.get(memKey))[memKey];
    if (raw !== undefined) {
      memory = decodeStateMemory(raw);
      if (memory === null) {
        console.warn("andvari: this browser's record of the account state is damaged; shared vaults stay closed");
        return null;
      }
    }
  } catch {
    // Design §4.4, §12.2 rule 6: a mark that cannot be read is unknown, never "no mark yet". Shared vaults stay closed,
    // and nothing is written back from what the server serves (that once lowered a stored mark to a replayed state).
    console.warn("andvari: this browser's record of the account state could not be read; shared vaults stay closed");
    return null;
  }
  let servedState: Awaited<ReturnType<typeof api.accountState>>;
  try {
    servedState = await api.accountState();
  } catch {
    return null; // not served this time: shared vaults stay closed (fail safe)
  }
  let state = null;
  if (servedState.sealedState !== null) {
    let blob: Uint8Array | null = null;
    try {
      blob = fromB64(servedState.sealedState);
    } catch {
      blob = null;
    }
    const opened = blob === null ? null : openAccountState(blob, uvk, userId);
    if (opened === null || !opened.ok) {
      console.warn("andvari: the account state does not open or is not this account's; shared vaults stay closed");
      return null;
    }
    state = opened.state;
  }
  const applied = applyServedState(memory, state);
  if (applied.rollback) console.warn("andvari: the server served an older account state than this browser has seen; shared vaults stay closed");
  if (applied.genesisAnomalies.length > 0) console.warn(`andvari: ${applied.genesisAnomalies.length} vault record(s) name another genesis than this browser's; its own are kept`);
  if (applied.memory !== null) await trusted.set({ [memKey]: applied.memory }).catch(() => {});
  return applied.usable;
}

/** Key-state anomalies the popup does not render: the full clients raise those notices. */
function warnKeyState(keyUnreadable: ReadonlySet<string>, waiting: ReadonlySet<string>): void {
  if (keyUnreadable.size > 0) console.warn(`andvari: ${keyUnreadable.size} vault key wrap(s) do not open; those vaults stay locked (no seal fallback)`);
  if (waiting.size > 0) console.info(`andvari: ${waiting.size} shared vault(s) wait for a full client to verify them`);
}

/** Policy fetch — a failed fetch must never mean "no idle lock at all" (web resolveAutoLockSeconds
 *  falls back to a persisted value; here the conservative defaults stand in). Also captures the
 *  clipboard-clear window (E1-4). Shared by unlock + redeem (breaker B6 re-fetches autoLockSeconds
 *  on a quick unlock). Values pass the §2.3/B1-1 CEILINGS (api.ts clamps): with the server now an
 *  arbitrary self-host endpoint, a hostile policy's 0/oversized timer clamps into range — it can
 *  tighten the lock/clear windows but never disable them. */
async function fetchPolicyInto(current: () => boolean = () => true): Promise<void> {
  // [current] — the unlock that asked is still the one in front. A lock in the fetch reset both windows for
  // the locked state, and a switch made them another server's; the late answer writes neither.
  try {
    const p = await api.clientPolicy();
    if (!current()) return;
    autoLockSeconds = clampAutoLockSeconds(p.autoLockSeconds, DEFAULT_AUTOLOCK_SECONDS);
    clipboardClearSeconds = clampClipboardClearSeconds(p.clipboardClearSeconds, DEFAULT_CLIPBOARD_CLEAR_SECONDS);
  } catch {
    if (!current()) return;
    autoLockSeconds = DEFAULT_AUTOLOCK_SECONDS;
    clipboardClearSeconds = DEFAULT_CLIPBOARD_CLEAR_SECONDS;
  }
}

/** How long a locked Save click stays live as an auto-commit approval. Generous for the real flow
 *  (click Save → unlock screen opens → type the master password) while bounding the walk-away tail:
 *  on a shared browser, whoever unlocks LATER must meet the ask-first banner, not silently inherit
 *  someone else's abandoned click into their own vault. */
const APPROVED_SAVE_TTL_MS = 10 * 60_000;

/** E1-5: re-offer any save captured while locked the moment we unlock — otherwise the pending stays
 *  invisible until a navigation. Same uninjected-tab try/catch as the tabs.onUpdated listener.
 *  Unlock-prompt (2026-08-12): a pending the user ALREADY clicked Save on while locked
 *  (`approvedAt`, fresh within APPROVED_SAVE_TTL_MS) skips the re-ask and commits now — the second
 *  Save click was pure friction. A stale approval is dropped and falls through to the banner. */
function reofferPendingSaves(): void {
  for (const [tabId, st] of tabs) {
    if (!st.pending) continue;
    // 2026-08-18: a locked-minted pending past its TTL is dropped even at the unlock moment —
    // the bound on plaintext-at-rest outranks the offer (reofferDecision orders it the same way).
    if (st.pending.lockedAt !== undefined && Date.now() - st.pending.lockedAt > LOCKED_PENDING_TTL_MS) {
      st.pending = undefined;
      persistTabs();
      continue;
    }
    if (st.pending.approvedAt !== undefined) {
      if (Date.now() - st.pending.approvedAt <= APPROVED_SAVE_TTL_MS) {
        void commitApprovedSave(tabId, st, st.pending);
        continue;
      }
      st.pending.approvedAt = undefined; // expired — back to consent-first
      persistTabs();
    }
    // 2026-08-18: the unlock is the first moment matchesFor can answer for a locked capture — an
    // unchanged re-login (2a) is dropped with NO banner ever shown (this is where a quiet pending's
    // loop closes; capture-time ran this same check against an empty vault and couldn't). A changed
    // password falls through to the offer, which resolveSaveAction will land as an Update (A11: only of a
    // personal-vault item; a match the "Save" banner never named in another vault becomes a new personal item).
    const target = saveTargetFor(matchesFor(pendingPage(st.pending)), st.pending.username, st.pending.password, session?.personalVaultId);
    if (target && (target.doc.login?.password ?? "") === st.pending.password) {
      st.pending = undefined;
      persistTabs();
      continue;
    }
    // Handed to a live session: the locked-life stamps are spent (a later re-lock drops the
    // pending wholesale via [S3-lock], so none of them can matter again).
    st.pending.lockedAt = undefined;
    st.pending.quiet = undefined;
    st.pending.offeredAt = undefined;
    // A11 (q14): a locked capture named no vault; the offer it becomes names the personal vault it would land in.
    if (!st.pending.updatesItemId) {
      st.pending.vaultName = destinationOf(session?.personalVaultId ?? "").vaultName;
      st.pending.vaultShared = false;
    }
    persistTabs();
    const m: TabMsg = { type: "offerPendingSave", pending: publicPending(st.pending) };
    // Frame 0 only — same rule as the onUpdated re-offer: the metadata never rides into sub-frames.
    chrome.tabs.sendMessage(tabId, m, { frameId: 0 }).catch(() => {
      /* content not injected in that tab — its own pendingSave poll covers it */
    });
  }
}

/** Per-tab single-flight for the approved auto-commit — a doubled unlock signal must not race two
 *  puts of the same pending (the second would 409 or, on the save-new leg, mint a duplicate).
 *  resolvePendingSave checks it too: a banner Save click landing while the auto-commit's put is
 *  in flight must not start a second put for the same credential. */
const approvedCommitsInFlight = new Set<number>();

/** Land ONE approved pending save post-unlock and tell frame 0 honestly what happened:
 *  a real write → the "pendingSaveCommitted" toast; a 2a suppress → silence (nothing was written,
 *  so there is nothing to claim); still/again locked → keep the approval for the NEXT unlock;
 *  any other failure → drop the approval and fall back to the E1-5 banner re-offer, whose Save
 *  click renders the honest error line (conflict → web-vault copy, etc.). Same uninjected-tab
 *  catch as every tab send. */
async function commitApprovedSave(
  tabId: number,
  st: TabState,
  pending: PendingSave & { password: string; frameId: number; uri?: string; approvedAt?: number },
): Promise<void> {
  if (approvedCommitsInFlight.has(tabId)) return;
  approvedCommitsInFlight.add(tabId);
  try {
    const { res, wrote } = await commitPendingSave(tabId, st, pending);
    if (res.ok) {
      if (!wrote) return; // 2a suppress — pending cleared, nothing to toast
      const m: TabMsg = res.otherAccount === true ? { type: "pendingSaveCommitted", otherAccount: true } : { type: "pendingSaveCommitted" };
      chrome.tabs.sendMessage(tabId, m, { frameId: 0 }).catch(() => {});
      return;
    }
    if (res.code === "locked") return; // re-locked under the await — the approval survives for the next unlock
    pending.approvedAt = undefined; // one shot: a conflict/failed commit goes back to the ask-first banner
    persistTabs();
    const m: TabMsg = { type: "offerPendingSave", pending: publicPending(pending) };
    chrome.tabs.sendMessage(tabId, m, { frameId: 0 }).catch(() => {});
  } finally {
    approvedCommitsInFlight.delete(tabId);
  }
}

async function unlock(email: string, password: string): Promise<Res<"unlock">> {
  redeemGen++; // a full unlock supersedes any in-flight quick-unlock redeem (owns() guard)
  clearPendingTotp(); // a fresh sign-in supersedes any prior TOTP challenge
  const gen = redeemGen; // owns() token: a server switch / lock mid-sign-in bumps this → we abort
  // Design 2026-11-15 §4.4: the chain is fetched and verified forward from the pin BEFORE anything derived from the
  // password is sent; a fork stops here, durably. The pin itself is a password pin (baked or Trust Gate), so the
  // password rule holds: prelogin, authKey and a TOTP code go only to this origin.
  await ensureCardFresh();
  if (gen !== redeemGen || session) return { ok: false, code: "aborted" };
  // The api of the origin whose card was just checked, held for the whole sign-in. A
  // switch replaces the module's `api` (and bumps redeemGen); the KDF takes seconds, so the generation is checked
  // again after it, before the device record and before anything derived from the password is sent.
  const dialer = api;
  const from: SignInOrigin = { origin: serverUrl, owner: tokenOwner };
  const pre = await dialer.prelogin(email);
  assertServerKdfParams(pre.kdfParams); // H1 (spec 05 T1): refuse a weakened/absurd KDF before deriving (also blocks a 4 GiB SW OOM)
  const mk = await deriveMasterKeyAsync(password, pre.kdfParams, fromB64(pre.kdfSalt));
  if (gen !== redeemGen || session || dialer !== api) {
    mk.fill(0);
    return { ok: false, code: "aborted" };
  }
  const ak = authKey(mk);
  const wk = wrapKey(mk); // needed by hydrateSession to open wrappedUvk; mk is otherwise done
  mk.fill(0);
  // The attempt and the server it started under, asked after every wait before anything is written.
  const current = () => gen === redeemGen && !session && dialer === api;
  const device = await deviceRecordFor(email, current);
  if (!current()) return { ok: false, code: "aborted" };
  const replaces = await replacedRefreshToken(email, device.rec);
  if (!current()) return { ok: false, code: "aborted" };
  let s: SessionResponse;
  try {
    s = await dialer.login(email, toB64(ak), deviceObject(device.rec), undefined, replaces);
  } catch (e) {
    // An answer that comes after the attempt was left (a lock, a switch, "Forget this server",
    // another sign-in) is the attempt's no longer: it says "aborted", so nothing names the account afterwards (the
    // caller remembers the email on a "totp_required"; before, a late one put it back after a forget).
    if (!current()) return { ok: false, code: "aborted" };
    // Enrolled second factor: stash the ALREADY-DERIVED {authKey, wrapKey} (no second Argon2id) so
    // the code retry (unlockTotp) can finish; the popup renders a code field. Memory-only — see the
    // pendingTotp declaration for the B1 custody reason. Rethrow → unlockWithMapping → "totp_required".
    if (e instanceof ApiError && e.status === 401 && e.code === "totp_required") {
      pendingTotp = { origin: serverUrl, email, authKey: ak, wrapKey: wk, device, replaces, expiresAt: Date.now() + PENDING_TOTP_TTL_MS };
    }
    throw e;
  }
  // The device record only for an attempt still current at its own server. Before, a login
  // answered after "Forget this server" wrote it back (the email in its key, the device secret and id in its value).
  // A sign-in left behind is ended by hydrateSession's first check. The record is written there, once the served account
  // passed the checks: before, a refused sign-in had already replaced the row id the record named.
  return hydrateSession(email, s, wk, gen, from, { dev: device, current });
}

/** Phase C — shared by the password unlock and the TOTP retry: open the UVK with the derived
 *  wrapKey, verify server identity, sync + decrypt, install the session, arm the session chrome.
 *  `gen` is the caller's owns()-token: a server switch (applyServerChange bumps redeemGen) or a lock
 *  landing during the sign-in must NOT let this install the OLD origin's tokens/vault under the NEW
 *  origin — so we abort on a gen change, before any token/vault material is installed or POSTed.
 *  A throw here (identity mismatch, restricted-session 403, network) crosses to the caller's mapper;
 *  on ANY non-install exit the freshly-minted token pair is cleared so it never lingers while locked. */
async function hydrateSession(
  email: string,
  s: SessionResponse,
  wk: Uint8Array,
  gen: number,
  from: SignInOrigin,
  device: { dev: { rec: DeviceRecord; key: string | null }; current: () => boolean },
): Promise<Res<"unlock">> {
  if (gen !== redeemGen || session) {
    await endAbandonedSignIn(from, { access: s.accessToken, refresh: s.refreshToken }, s.userId, from.owner, false); // superseded before we touched `api`
    return { ok: false, code: "aborted" };
  }
  // §12.2 rule 7: the extension refuses the operator account. Its session is revoked at once (bounded, best effort)
  // and nothing of it is opened, synced or kept. Anything but `member` is refused, as on the web (the field is always
  // on the wire, spec 03 §0.1).
  // The pinned card names the operator account too (a handover the server's role field may not show yet): the same
  // refusal, decided on this browser's own pin, needing no signal from the server.
  if (s.role !== "member" || cardNamesOperator(s.userId)) {
    await revokePair(from.origin, { access: s.accessToken, refresh: s.refreshToken });
    clearPendingTotp();
    return { ok: false, code: "operator_account" };
  }
  const mine = ++tokenOwner;
  const minted: TokenPair = { access: s.accessToken, refresh: s.refreshToken };
  api.setTokens(s.accessToken, s.refreshToken);
  pairUser.set(api, s.userId);
  try {
    // H67: STRUCTURE first, secret second — a wrappedUvk that isn't a well-formed envelope is a
    // damaged/foreign account row, not a credentials failure (see VaultKeyDamagedError).
    let wrapped: Uint8Array;
    try {
      wrapped = fromB64(s.accountKeys.wrappedUvk);
    } catch {
      throw new VaultKeyDamagedError("wrappedUvk is not valid base64url");
    }
    const wrappedRefusal = envelopeStructuralRefusal(wrapped);
    if (wrappedRefusal !== null) throw new VaultKeyDamagedError(`wrappedUvk: ${wrappedRefusal}`);
    const uvk = open(wk, wrapped, adUvk(s.userId));
    // Identity keypair — for member (shared-vault) grants sealed to us. R38: the seed blob gets
    // the SAME structure-first gate as wrappedUvk above — it is the sibling account-key blob in
    // the same row, damaged by the same partial restore or the same too-new envelope version, and
    // an ungated failure here would have landed on the wrong-credentials sentence one line after
    // H67 stopped saying it. A wrong wk cannot reach this line, and a wrong UVK could only fail
    // the AEAD tag, never the public header — so nothing but a damaged row trips it.
    let seedEnvelope: Uint8Array;
    try {
      seedEnvelope = fromB64(s.accountKeys.encryptedIdentitySeed);
    } catch {
      throw new VaultKeyDamagedError("encryptedIdentitySeed is not valid base64url");
    }
    const seedRefusal = envelopeStructuralRefusal(seedEnvelope);
    if (seedRefusal !== null) throw new VaultKeyDamagedError(`encryptedIdentitySeed: ${seedRefusal}`);
    const seed = open(uvk, seedEnvelope, adIdkey(s.userId));
    const identity = boxKeypairFromSeed(seed);
    verifyServerIdentity(identity.publicKey, s.accountKeys.identityPub); // before ANY vault material is synced/persisted
    // Decided on 2026-11-17: the account this extension knows the address as, and the key it knows the served account
    // by, at this server. The same account under another key is the identity fault; another account under a known
    // address is refused with both possibilities said. Before anything is synced or kept.
    await checkKnownAccount(email, s.userId, identity.publicKey);
    // Only once both checks made on this device passed (the seed's key, the kept records): a refused sign-in changes
    // nothing here. Before the first request after the login: a sign-in that fails at the sync still names its row next
    // time (a first sign-in otherwise left one more listed row per failure). Before, the row id was written before any check.
    if (device.current()) await rememberDevice(device.dev, s.deviceId);

    const sync = await api.sync(0);
    if (gen !== redeemGen || session) {
      await endAbandonedSignIn(from, minted, s.userId, mine, true); // a switch/lock landed during sync — install nothing
      return { ok: false, code: "aborted" };
    }
    // §12.2: the genesis verified, the personal wrap, the account state, the shared-vault wraps (buildUnlockKeys).
    const { vaultKeys, vaultRoles, personalVaultId, waiting } = await buildUnlockKeys(s.accountKeys, uvk, seed, s.userId, sync.grants);
    const homed = await homeAndDecrypt(sync, vaultKeys, s.userId, personalVaultId);
    if (gen !== redeemGen || session) {
      await endAbandonedSignIn(from, minted, s.userId, mine, true); // a switch/lock landed meanwhile — install nothing (the sync-time rule above)
      return { ok: false, code: "aborted" };
    }
    // uvk RETAINED in memory (breaker B1) so enroll can wrap it; provenance PASSWORD + a fresh
    // lastFullUnlockAt stamp — the only place that mints `now` (breaker A4).
    session = {
      userId: s.userId,
      email,
      items: itemsUnderHeldKeys(homed.items, vaultKeys),
      vaultKeys,
      vaultRoles,
      personalVaultId,
      uvk,
      waitingGrants: waiting,
      homes: homed.homes,
      homesKnown: homed.known,
      wrongVault: homed.wrongVault,
      vaultMeta: vaultMetaOf(sync.vaults),
      provenance: "PASSWORD",
      lastFullUnlockAt: Date.now(),
      lockAt: Date.now() + lockWindowMs(), // the deadline starts at the install; armAutoLock below moves it
    };
    clearPendingTotp(); // a live session exists — the challenge (if any) is spent

    // From here every write follows a wait (the policy fetch, the record, the snapshot), and a lock, a
    // switch or "Forget this server" can land in any of them. Before, a lock in the policy fetch made the next line
    // throw (the session was gone), and the sign-in answered "network"; a lock in the record's read would have seen
    // the re-stamp disarm the record the lock had just armed. Each write is made only while the session installed
    // above is still the one in front, and a sign-in left behind answers "aborted".
    const installed = session;
    const stillOpen = () => session === installed;
    await fetchPolicyInto(stillOpen);
    if (!stillOpen()) return { ok: false, code: "aborted" };
    // Decided on 2026-11-17: the address now names this account, and the account's key is the one it was taken under
    // (accountmemory.ts). Each only where none is kept: a kept key is never replaced by a sign-in (one transaction). A
    // write that fails leaves the records as they were (the next sign-in writes them again).
    const records = recordsFor(email, s.userId, toB64(identity.publicKey)); // the verified 32 bytes, canonical: not the served text
    await trusted.setWhereAbsent(Object.fromEntries(Object.entries(records).map(([k, v]) => [nsk(k), v]))).catch(() => {});
    if (!stillOpen()) return { ok: false, code: "aborted" };
    // breaker A6 + A11: a full unlock as a DIFFERENT user strands any prior quick-unlock blob → wipe;
    // a surviving same-user blob gets its 24 h window re-stamped to now (the fail-closed "a successful
    // full unlock re-stamps" rule) and its attempt budget refreshed to full.
    const recordUpdated = await quickUnlock.onFullUnlock(s.userId, installed.lastFullUnlockAt, stillOpen);

    // The vault is open from the line that installed the session. A snapshot
    // write that fails (a full or failing storage) threw into the catch below, which answered an error ("unknown") over
    // an open vault and started no resync and no socket. It is said as what it is, and the vault stays open in this
    // worker; one that stops before the next lock comes back locked. Likewise a record the re-stamp above could not
    // write, which before was not said at all.
    if (!stillOpen()) return { ok: false, code: "aborted" };
    const sessionSaved = await persistSession().then(
      () => true,
      () => false,
    );
    if (!stillOpen()) return { ok: false, code: "aborted" };
    if (!recordUpdated) stashOwed = installed; // the record may still hold the stash of the session before this one
    void plainSession.remove(NKEY).catch(() => {}); // a fresh unlock clears the F26 idle-lock notice (E1-7)
    kindDeferred = null; // entry 10: a deferred kind change asks again at the next unlock
    void startResyncAlarm();
    void ensureSocket(true); // T2: live bell up within ~1 s of unlock
    armAutoLock();
    reofferPendingSaves();
    if (!sessionSaved) return { ok: true, notice: "session_not_saved" };
    if (!recordUpdated) return { ok: true, notice: "quick_unlock_not_updated" };
    // After "Forget the earlier account on this device": said once, at the first sign-in taken under that address.
    const remembered = rememberNotice;
    const inMemory = remembered !== null && remembered.originKey === currentOriginKey && remembered.email === addressNorm(email);
    const markName = rememberNoticeName(email);
    let atRest = false;
    try {
      atRest = (await trusted.get(markName))[markName] !== undefined && !rememberSaid.has(markName);
    } catch {
      /* unreadable: said from memory only */
    }
    if (inMemory || atRest) {
      rememberNotice = null;
      // Said now: the mark goes, also where it could not be read (it may still be there), and this worker remembers that
      // it was said, so that a mark that could not be read or removed does not say it a second time.
      rememberSaid.add(markName);
      await trusted.remove(markName).catch(() => {});
      return { ok: true, notice: "account_remembered" };
    }
    return { ok: true };
  } catch (e) {
    // A sign-in refused for an identity reason (the served key against the seed's or the kept record, the genesis, or
    // another account under a known address) ends at the server the session it was given: at its own origin with the pin
    // in force, and only while no session of that account is open here (endAbandonedSignIn's rules).
    if (e instanceof IdentityMismatchError || e instanceof GenesisRefused || e instanceof RemadeAccountError) {
      await endAbandonedSignIn(from, minted, s.userId, mine, true);
    }
    // Another account under a known address (and only that refusal): "Forget the earlier account on this device" may be
    // offered for it, for this address at this server, naming the account the address is tied to here.
    if (e instanceof RemadeAccountError && e.earlier !== "" && e.earlier !== "?" && from.origin === serverUrl) {
      // Stamped with the generation it was raised under: every later sign-in, code step, quick unlock, lock or switch moves
      // the generation on (redeemGen), and the offer is then gone.
      earlierOffer = { originKey: currentOriginKey, email: addressNorm(email), earlier: e.earlier, gen: redeemGen };
    }
    // Never leave live tokens in the api while locked (doUnlockWithPin:1597 parity) — but only this sign-in's own pair:
    // another sign-in that set its pair since owns the api now.
    if (!session && tokenOwner === mine) api.setTokens(null, null);
    throw e;
  }
}

/** Where a password sign-in started: the origin whose card it checked, and the token owner then (endAbandonedSignIn). */
interface SignInOrigin {
  readonly origin: string;
  readonly owner: number;
}

/** Bumped whenever a sign-in or a redeem puts its own pair into the module `api`: an abandoned sign-in clears or
 *  revokes only a pair that is still its own. */
let tokenOwner = 0;

/**
 * A sign-in left behind (a lock, a server switch, another sign-in) after the
 * server already answered its login does not complete (the redeemGen checks), and it does not leave the session it
 * minted alive at the server either. The pair is [pair], or (once this sign-in put it into `api`, as owner [owner]) the
 * api's, possibly rotated. It is revoked with its own token at its own origin, bounded, through a separate client, and
 * only when:
 * - no other sign-in or redeem has put its pair into `api` since this one's [owner] (a revoke ends the device's
 *   session, so it could end theirs), and no session of the same account is installed (the same reason);
 * - its origin is still the one dialed, with its pin in force (§4.4 "No credential goes to an origin without a pin
 *   in force"; after a switch the pair is dropped unsent and the server session lapses on its own).
 *
 * Why an abandoned sign-in after a switch stays unrevoked: the pair lived only in this worker's memory and is dropped
 * there, so nothing can use it; and the server's logout ends every session of this browser's device row at that origin
 * (AuthRoutes `POST /auth/logout` revokes by deviceId), which can include a quick-unlock record kept in the old origin's
 * namespace across the switch, so sending it could sign the person out of a session they still have. What is left is
 * a server session no client holds, which lapses with its refresh token. Ending it exactly would need a logout of one
 * session (the token's own) on the server.
 */
async function endAbandonedSignIn(from: SignInOrigin, minted: TokenPair, userId: string, owner: number, inApi: boolean): Promise<void> {
  if (tokenOwner !== owner) return; // another sign-in owns the api's pair (and may share this device's session)
  let p = minted;
  if (inApi) {
    const held = api.getTokens(); // a refresh during the sync may have rotated it; a lock may have cleared it already
    api.setTokens(null, null);
    if (held.access !== null) p = held;
  }
  if (session !== null && session.userId === userId) return;
  await revokePair(from.origin, p);
}

/** Single-flight for the TOTP code retry (mirrors pinUnlockInFlight): two racing popups / an
 *  Enter+click double-fire must not each POST /login and burn the server's login backoff. */
function unlockTotp(code: string): Promise<Res<"unlockTotp">> {
  totpUnlockInFlight ??= doUnlockTotp(code).finally(() => {
    totpUnlockInFlight = null;
  });
  return totpUnlockInFlight;
}

async function doUnlockTotp(code: string): Promise<Res<"unlockTotp">> {
  await ensureLoaded();
  if (session) return { ok: true }; // a concurrent full unlock already won — nothing to do
  const p = livePendingTotp();
  if (!p) return { ok: false, code: "totp_expired" }; // SW evicted / switched origin / 5-min fuse blew
  redeemGen++; // ONLY once a real challenge exists (a dead no-op must not abort an in-flight PIN redeem)
  const gen = redeemGen;
  const from: SignInOrigin = { origin: p.origin, owner: tokenOwner };
  let s: SessionResponse;
  try {
    s = await api.login(p.email, toB64(p.authKey), deviceObject(p.device.rec), code, p.replaces);
  } catch (e) {
    if (session) return { ok: true }; // lost the race but the vault is open — not an error
    if (e instanceof ApiError) {
      // 401 here is NOT the authKey (proven at stash time) — it's the code (wrong/replayed) or, in a
      // 5-min-window edge, a server-side password change; the popup caps consecutive bad codes and
      // falls back to a full sign-in, which self-heals the edge. 429 gets its own copy; 403 = enroll.
      if (e.status === 401) return { ok: false, code: "totp_bad_code" };
      if (e.status === 429) return { ok: false, code: "totp_rate_limited" };
      return { ok: false, code: mapUnlockError(e) };
    }
    return { ok: false, code: mapUnlockError(e) };
  }
  if (session) return { ok: true }; // a full unlock landed while we were on the wire
  // A server switch during the login POST would have bumped redeemGen AND cleared pendingTotp (both
  // via applyServerChange) — hydrateSession's gen guard is the backstop, but bail early + explicitly.
  if (gen !== redeemGen || !livePendingTotp()) {
    await endAbandonedSignIn(from, { access: s.accessToken, refresh: s.refreshToken }, s.userId, from.owner, false);
    return { ok: false, code: "aborted" };
  }
  try {
    // The device record is written by hydrateSession once the served account passed its checks.
    return await hydrateSession(p.email, s, p.wrapKey, gen, from, { dev: p.device, current: () => gen === redeemGen && !session }); // clears pendingTotp on success
  } catch (e) {
    return { ok: false, code: mapUnlockError(e), error: String(e) };
  }
}

/** Wrap unlock() so its throws cross the seam as a coded Res<"unlock"> (design decision 4): the SW
 *  never ships user-facing sentences — the popup renders copy from errors.ts keyed on `code`. The
 *  raw String(e) rides `error` as debug detail the surfaces never render. */
async function unlockWithMapping(email: string, password: string): Promise<Res<"unlock">> {
  let r: Res<"unlock">;
  const attempt = unlock(email, password); // its first step, before any wait, takes the attempt's generation
  const gen = redeemGen;
  const at = api;
  try {
    r = await attempt;
  } catch (e) {
    r = { ok: false, code: mapUnlockError(e), error: String(e) };
  }
  // A15: the worker remembers the email (the popup used to write it to storage.local, which content scripts can read
  // on Firefox): once the server accepted it — a sign-in, or a password accepted pending the one-time code (else
  // TOTP-enrolled accounts never get it stored). The email only, never the password.
  // And only while the attempt is still the current one, at the server it started under: a
  // lock, a switch or "Forget this server" since (each bumps the generation) leaves it unwritten.
  if ((r.ok || r.code === "totp_required") && gen === redeemGen && at === api) await rememberEmail(email);
  return r;
}

/** A15: the remembered email (non-secret), in the trusted store. Best effort. */
async function rememberEmail(email: unknown): Promise<void> {
  const e = rememberableEmail(typeof email === "string" ? email.trim() : email);
  if (e !== null) await trusted.set({ [LAST_EMAIL_KEY]: e }).catch(() => {});
}
async function readRememberedEmail(): Promise<string | null> {
  return rememberableEmail(await trustedGet(LAST_EMAIL_KEY));
}

function mapUnlockError(e: unknown): UnlockCode {
  if (e instanceof KdfPolicyError) return "kdf_policy"; // H1 (spec 05 T1): server tried to weaken/DoS the KDF
  if (e instanceof IdentityMismatchError || e instanceof GenesisRefused) return "identity_mismatch"; // §5.2: one copy for every verdict
  if (e instanceof RemadeAccountError) return "remade_account"; // another account under a known address
  if (e instanceof KnownAccountUnreadableError) return "memory_unreadable"; // the records could not be read: nothing taken
  if (e instanceof CardStopError) return e.code;
  if (e instanceof VaultKeyDamagedError) return "keys_damaged"; // H67: damaged/foreign key blob — terminal, never wrong-password
  if (e instanceof ApiError) {
    if (e.code === "bad_wire_id") return "bad_wire_id"; // A11 (c18): tampering class, never the "try again" fold
    if (e.code === "upgrade_required") return "upgrade_required"; // 426 min-version pin (any status)
    // Restricted session (server §2.6 row 4): a totpRequired instance let an un-enrolled user's
    // login succeed, then every authed route 403s until they enroll in the web vault. Route there
    // honestly instead of the server_error dead-end (moot on the reference instance — TOTP off).
    if (e.status === 403 && e.code === "totp_enrollment_required") return "totp_enroll_required";
    // §8.7: the password (and any code) verified, but the account only allows linked devices — the extension cannot be.
    if (e.status === 403 && e.code === "link_required") return "link_required";
    if (e.status === 401) return e.code === "totp_required" ? "totp_required" : "bad_credentials";
    // The sign-in's back-off has its own line, as the web's sign-in has (it was folded into "the server had a problem").
    if (e.status === 429) return "rate_limited";
    return "server_error"; // 500/… fold here (strict Welcome-ladder parity, decision 5)
  }
  if (e instanceof TypeError) return "network"; // fetch rejection (web errors.ts:26-33 convention)
  return "unknown";
}

// ---- quick-unlock Tier B: enroll / redeem / disable / status (spec 01 §8.4) ----

/** Enroll a PIN over the in-memory UVK. Gated: unlocked, uvk present (breaker B1 — a snapshot-restored
 *  session has none → a fresh full unlock is required first), and NOT mustChangePassword (breaker A4 /
 *  §8.1-A5 — never let a rescue-issued temp password's UVK get armed). `enroll` COPIES the session's
 *  surviving full-password stamp (breaker A4) — a QUICK session carries the ORIGINAL stamp, so it can
 *  never mint a fresh 24 h window. The blob double-wraps the UVK under Argon2id(PIN) ⊕ a fresh
 *  non-extractable co-key (breaker A1). */
async function enrollQuickUnlock(pin: string): Promise<Res<"enrollQuickUnlock">> {
  await custodyReady; // A16: the compartment verdict is decided (it is, long before anyone is unlocked to ask)
  if (!session) return { ok: false, code: "locked" };
  // A16: no enrollment where nothing can arm (no session sealing key, or Chrome's access level unconfirmed).
  if (!quCompartmentTrusted) return { ok: false, code: "unavailable" };
  if (!session.uvk || session.serverEnded) return { ok: false, code: "need_full_unlock" }; // §4.4: no quick unlock for an ended session
  const r = await quickUnlock.enroll({
    uvk: session.uvk,
    userId: session.userId,
    email: session.email,
    pin,
    lastFullUnlockAt: session.lastFullUnlockAt, // COPIED — never Date.now() from a QUICK session (breaker A4)
    autoLockSeconds,
    stillCurrent: enrolledUnder(session),
  });
  if (!r.ok) {
    if (r.code === "weak_pin") return { ok: false, code: r.code, reason: r.reason };
    return { ok: false, code: r.code === "ended" ? "locked" : "switched_off" }; // switched off meanwhile
  }
  return { ok: true };
}

/** An enrolment belongs to the session it was asked under. A lock, a sign-out, a server switch (which locks)
 *  and a new browser session all drop `session`; a session the server ended is marked. Any of them during the seconds an
 *  enrolment takes (or the minutes a biometric prompt may stay up) and the enrolment writes nothing: before, it went on
 *  to seal that session's UVK into a fresh record after the sign-out had wiped the old one, so the account's quick-unlock
 *  record and its email outlived the sign-out, and the next password sign-in to that account switched it back on. */
function enrolledUnder(s: Session): () => boolean {
  return () => session === s && !s.serverEnded;
}

/** Enroll biometric quick-unlock (0.17.0) — same gates as enrollQuickUnlock (unlocked, in-memory UVK,
 *  !mustChangePassword). The engine opens the connector for create()+PRF via the injected dep. On success
 *  we record the credential for amendment-4 reuse (litter reduction) so a future re-enroll needs only a
 *  get(). Never carries key material: the UVK stays in the SW (breaker B1). */
async function enrollQuickUnlockBio(): Promise<Res<"enrollQuickUnlockBio">> {
  await custodyReady; // A16: the compartment verdict is decided
  if (!session) return { ok: false, code: "locked" };
  // A16: refused before the passkey ceremony — no enrollment where nothing can arm.
  if (!quCompartmentTrusted) return { ok: false, code: "unavailable" };
  if (!session.uvk || session.serverEnded) return { ok: false, code: "need_full_unlock" }; // §4.4: no quick unlock for an ended session
  dropEnrollSecretCache();
  const userId = session.userId;
  const r = await quickUnlock.enrollBio({
    uvk: session.uvk,
    userId,
    email: session.email,
    lastFullUnlockAt: session.lastFullUnlockAt, // COPIED — never Date.now() from a QUICK session (breaker A4)
    autoLockSeconds,
    stillCurrent: enrolledUnder(session),
  });
  dropEnrollSecretCache(); // whether or not evalPrf consumed it
  const enrolled = takeLastBioEnroll(); // read + clear the dep-set record (defeats TS closure-narrowing)
  if (!r.ok) return { ok: false, code: r.code === "ended" ? "locked" : r.code };
  // amendment 4: persist the credential the engine committed to, for reuse on a later re-enroll.
  if (enrolled) await writeBioCred({ credentialId: enrolled.credentialId, prfSalt: enrolled.prfSaltB64, userId });
  return { ok: true };
}

/** Quick-unlock redeem (spec 01 §8.4). Single-flight (breaker A5). The engine's beginRedeem does the
 *  reserve-then-open; this does the server dance: forced refresh FIRST (breaker A3⊕B2), re-assert the
 *  master-KDF floor + re-verify identity + re-fetch policy (breaker B6), then sync + rebuild + persist. */
function unlockWithPin(pin: string): Promise<Res<"unlockWithPin">> {
  pinUnlockInFlight ??= doUnlockWithPin(pin).finally(() => {
    pinUnlockInFlight = null;
  });
  return pinUnlockInFlight;
}

type RedeemDanceResult =
  | { ok: true; notice?: QuickUnlockNotice }
  | { ok: false; code: "aborted" | "revoked" | "not_confirmed" | "network" | "identity_mismatch" | "memory_unreadable" | "kdf_policy" | "server_error" | "stale_uvk" | "keys_damaged" | "confirm_server" | "server_fork" | "card_invalid" | "operator_account" };

function unlockWithBio(): Promise<Res<"unlockWithBio">> {
  bioUnlockInFlight ??= doUnlockWithBio().finally(() => {
    bioUnlockInFlight = null;
  });
  return bioUnlockInFlight;
}

async function doUnlockWithBio(): Promise<Res<"unlockWithBio">> {
  await ensureLoaded();
  earlierOffer = null; // a later attempt clears the offer to forget an earlier account
  if (session) return { ok: true }; // already unlocked (a race)
  await Promise.race([lockRefreshSettled, delay(REDEEM_FOLLOWS_REFRESH_MS)]); // the record's pair, answered late
  if (session) return { ok: true };
  const gen = redeemGen;
  // opens the connector + runs the WebAuthn ceremony; left by a lock or a switch meanwhile → "aborted"
  const begin = await quickUnlock.beginRedeemBio(() => gen === redeemGen && session === null);
  if (!begin.ok) return { ok: false, code: begin.code }; // not_armed | expired | corrupt | bio_cancelled
  // owns() guard: a lock / sign-out / full unlock landed during the ceremony → discard silently.
  if (gen !== redeemGen || session) return { ok: false, code: "aborted" };
  return finishRedeem(begin, supersedeSignIns());
}

/** A quick unlock that has just proved its factor supersedes a password sign-in already under way, as a
 *  password sign-in supersedes a quick unlock (unlock's own `redeemGen++`): the later action wins. Before, the redeem
 *  left the generation alone, so a sign-in started earlier (say on the master-password form while the PIN was being
 *  checked) and the redeem both ran to the end: the sign-in installed its session with its pair, and the redeem then
 *  installed its own session over it while the worker's one client still held the sign-in's pair, so one account's
 *  session ran on another account's tokens. Returns the redeem's own generation. */
function supersedeSignIns(): number {
  return ++redeemGen;
}

async function doUnlockWithPin(pin: string): Promise<Res<"unlockWithPin">> {
  await ensureLoaded();
  earlierOffer = null; // a later attempt clears the offer to forget an earlier account
  if (session) return { ok: true }; // already unlocked (a race) — nothing to redeem
  // A refresh a lock stopped waiting for brings the record's pair when it answers; the redeem reads after it.
  await Promise.race([lockRefreshSettled, delay(REDEEM_FOLLOWS_REFRESH_MS)]);
  if (session) return { ok: true };
  const gen = redeemGen;
  // A lock or a server switch (which locks first) during the derivation leaves the redeem: "aborted".
  const begin = await quickUnlock.beginRedeem(pin, () => gen === redeemGen && session === null);
  if (!begin.ok) {
    return begin.code === "wrong_pin"
      ? { ok: false, code: "wrong_pin", attemptsRemaining: begin.attemptsRemaining }
      : { ok: false, code: begin.code };
  }
  // owns() guard: a lock / sign-out / full unlock intervened during the PIN KDF → discard silently.
  if (gen !== redeemGen || session) return { ok: false, code: "aborted" };
  return finishRedeem(begin, supersedeSignIns());
}

/** The shared quick-unlock server dance — byte-identical for the PIN and biometric lanes (spec §5).
 *  Runs after a verified engine beginRedeem/beginRedeemBio returns the UVK + stashed tokens and the
 *  owns() guard passes: forced refresh (catches rescue/revocation) → getAccountKeys → verifyServerIdentity
 *  → sync → session build under withRedeemInFlight, GUARANTEEING api tokens clear on any locked exit.
 *  Its failure codes are exactly the subset both PinUnlockCode and BioUnlockCode carry. */
async function finishRedeem(begin: BeginRedeemOk, gen: number): Promise<RedeemDanceResult> {
  const mine = ++tokenOwner; // the redeem's pair now owns the api (endAbandonedSignIn)
  api.setTokens(begin.tokens.access, begin.tokens.refresh);
  const dialer = api; // the client the redeem runs on (redeemClient)
  pairUser.set(dialer, begin.userId);
  // withRedeemInFlight sets redeemInFlight for the server dance and GUARANTEES it clears on EVERY exit
  // (success / owns()-abort return / throw) — a mid-redeem switch/lock that bumps redeemGen and aborts
  // here can never STRAND the flag true (which would later misroute a full unlock's initial setTokens
  // into the QKEY locked-token stash). While set, api token mutations route to that stash (persistTokens).
  // The inner try/catch stays INSIDE the body so the catch runs with the flag still set (unchanged); the
  // `if (!session) setTokens(null,null)` cleanup sits in the OUTER finally so it runs AFTER the flag is
  // cleared — the exact order the prior single finally used. locksequence.test.ts pins the guaranteed clear.
  try {
    return await withRedeemInFlight(
      (v) => {
        // true → this client's token mutations land in QKEY.lockedTokens (persistTokens), not a session. Cleared only
        // while it is still this redeem's mark (another server's redeem may hold it after a switch).
        if (v) redeemClient = dialer;
        else if (redeemClient === dialer) redeemClient = null;
      },
      async (): Promise<RedeemDanceResult> => {
        try {
          // The record holds no refresh token: a lock overtook a refresh whose answer never came (its mark stood, so the
          // client handed the lock no token), or the worker stopped while one was out. That is not the server ending the
          // session: before, the refresh below answered "revoked" and the sign-out's wipe ran. Nothing is sent; it ends as
          // a living worker's "no try left" ends: the quick-unlock record and the known-logins digest go (as
          // endSessionByServer drops them), captures stay, and the token the lock kept is named by the next sign-in.
          if (begin.tokens.refresh === null) {
            api.setTokens(null, null);
            await quickUnlock.wipe().catch(() => {});
            knownLoginsKey = null;
            await sessionSeal.remove("knownLogins", currentOriginKey).catch(() => {});
            // A standing mark of this end for the locked popup, kept at rest (a stopped worker still says it), until the
            // next unlock clears it as it clears the idle-lock line.
            await plainSession.set({ [NKEY]: { kind: "not_confirmed" } }).catch(() => {});
            return { ok: false, code: "not_confirmed" };
          }
          // Design 2026-11-15 §4.4: the card chain is checked before the refresh token is spent; a fork stops here.
          await ensureCardFresh();
          if (gen !== redeemGen) return { ok: false, code: "aborted" };
          // §12.2 rule 7: a quick unlock carries no role on the wire, so the card decides. A handover that made this
          // account the operator signs it out (full wipe, the redeem's pair revoked) before any refresh is spent.
          if (cardNamesOperator(begin.userId)) {
            await doSignOut(true);
            await plainSession.set({ [NKEY]: { kind: "operator" } }).catch(() => {});
            return { ok: false, code: "operator_account" };
          }
          // A3⊕B2: forced rotation is the FIRST authenticated server contact. It is also the account-state read that
          // catches a revocation elsewhere — a revoked/rotated refresh → 401.
          const rot = await api.forceRefresh();
          if (gen !== redeemGen) return { ok: false, code: "aborted" };
          if (rot === "revoked") {
            await doSignOut(true); // definitive-401 → FULL wipe (blob + co-key + tokens) → full sign-in
            return { ok: false, code: "revoked" };
          }
          if (rot === "transient") {
            api.setTokens(null, null); // offline / 5xx — blob KEPT; the master password needs the network too
            return { ok: false, code: "network" };
          }

          const keys = await api.getAccountKeys();
          assertServerKdfParams(keys.kdfParams); // breaker B6: re-assert the H1 master-KDF floor on redeem
          // A13 (q38): the served seed blob gets the SAME structure-first gate as the full unlock (R38) before it is
          // opened. A blob that is not base64url or not a readable envelope is a damaged/foreign account row — the
          // server's doing, never the device's key — so it is the terminal keys_damaged refusal with the enrolled blob
          // KEPT, not a wipe blamed on a stale UVK.
          const seedGate = gateServedEnvelope(keys.encryptedIdentitySeed);
          if (!seedGate.ok) throw new VaultKeyDamagedError(`encryptedIdentitySeed: ${seedGate.why}`);
          const seedEnvelope = seedGate.envelope;
          // The seed open throwing = stale/foreign UVK (→ wipe); the compare failing = IdentityMismatchError
          // (→ HARD FAIL, blob KEPT). Same strictness as the full unlock (verifyServerIdentity).
          const seed = open(begin.uvk, seedEnvelope, adIdkey(begin.userId));
          const identity = boxKeypairFromSeed(seed);
          verifyServerIdentity(identity.publicKey, keys.identityPub);
          // The served key against the kept record of this account's key, as on the password road: a server that holds
          // the vault key could otherwise serve a seed of its own under it and be taken here. The account id is the local
          // record's, so only the key record is read; nothing is written. A read that fails refuses (blob KEPT).
          await checkKnownAccount(null, begin.userId, identity.publicKey);
          if (gen !== redeemGen) return { ok: false, code: "aborted" };

          const sync = await api.sync(0);
          await fetchPolicyInto(() => gen === redeemGen); // breaker B6: re-fetch autoLockSeconds — done BEFORE the final owns-check so
          if (gen !== redeemGen) return { ok: false, code: "aborted" };
          // §12.2: the same reduced rule as the full unlock — the genesis verified at every unlock (buildUnlockKeys).
          const { vaultKeys, vaultRoles, personalVaultId, waiting } = await buildUnlockKeys(keys, begin.uvk, seed, begin.userId, sync.grants);
          const homed = await homeAndDecrypt(sync, vaultKeys, begin.userId, personalVaultId);
          if (gen !== redeemGen) return { ok: false, code: "aborted" };
          // Provenance QUICK + the COPIED stamp (breaker A4).
          session = {
            userId: begin.userId,
            email: begin.email,
            items: itemsUnderHeldKeys(homed.items, vaultKeys),
            vaultKeys,
            vaultRoles,
            personalVaultId,
            uvk: begin.uvk, // UVK retained in memory (breaker B1) so a re-enroll from this QUICK session works
            waitingGrants: waiting,
            homes: homed.homes,
            homesKnown: homed.known,
            wrongVault: homed.wrongVault,
            vaultMeta: vaultMetaOf(sync.vaults),
            provenance: "QUICK",
            lastFullUnlockAt: begin.blob.lastFullUnlockAt,
            lockAt: Date.now() + lockWindowMs(), // the deadline starts at the install; armAutoLock moves it
          };
          if (redeemClient === dialer) redeemClient = null; // a session exists now → persistTokens routes to the full snapshot again
          // From here only LOCAL storage awaits remain (no doLock is UI-reachable during a redeem — the popup
          // shows the locked PIN screen, whose Lock/Sign-out buttons are unlocked-only; the gen checks above
          // are defense-in-depth). completeRedeem clears the token stash and keeps the blob for the next lock.
          clearPendingTotp(); // a PIN redeem opened the vault → any stale TOTP challenge is spent
          // The vault is open from here. A record write that fails now (a full or failing storage, a wipe
          // since the read) is not a stale UVK: before, it fell to the catch below, which wiped the record and answered
          // "stale_uvk" over an open vault. It is said as what it is, and the record is left for the next lock to re-arm.
          // The same for the session snapshot's write, the one just before the record's and the
          // larger, so the first to fail in a full storage. The vault stays open in this worker (a worker that stops
          // before the next lock comes back locked, and then the master password opens it); the record is still updated,
          // so it holds no live pair while the vault is open, and the next lock arms it with the pair in use then.
          const installed = session;
          const sessionSaved = await persistSession().then(
            () => true,
            () => false,
          );
          // A lock (or a switch, which locks) that lands in the waits after the install armed the record
          // with the live pair; the redeem's record update would disarm it (or, after a switch, disarm the new server's).
          // Nothing more is written for a session that is no longer the one in front, and the unlock says so.
          const stillOpen = () => session === installed;
          if (!stillOpen()) return { ok: false, code: "aborted" };
          const recordUpdated = await quickUnlock.completeRedeem(autoLockSeconds, stillOpen).then(
            () => true,
            () => false,
          );
          if (!stillOpen()) return { ok: false, code: "aborted" };
          if (!recordUpdated) stashOwed = installed; // the record may still hold the pair stashed for this redeem
          void plainSession.remove(NKEY).catch(() => {}); // the idle-lock line of the last lock; the next lock rewrites it
          kindDeferred = null; // entry 10: a deferred kind change asks again at the next unlock
          void startResyncAlarm();
          void ensureSocket(true);
          armAutoLock();
          reofferPendingSaves();
          return sessionSaved && recordUpdated ? { ok: true } : { ok: true, notice: "quick_unlock_not_updated" };
        } catch (e) {
          if (e instanceof IdentityMismatchError || e instanceof GenesisRefused) return { ok: false, code: "identity_mismatch" }; // blob KEPT (evidence)
          if (e instanceof KnownAccountUnreadableError) return { ok: false, code: "memory_unreadable" }; // blob KEPT, try again
          if (e instanceof CardStopError) {
            api.setTokens(null, null); // nothing was spent: the blob is KEPT for when the server is usable again
            return { ok: false, code: e.code };
          }
          if (e instanceof VaultKeyDamagedError) return { ok: false, code: "keys_damaged" }; // q38: blob KEPT, terminal
          if (e instanceof KdfPolicyError) {
            await doSignOut(true); // the server tried to weaken the master KDF on redeem — wipe, force full sign-in
            return { ok: false, code: "kdf_policy" };
          }
          if (e instanceof ApiError) {
            if (e.status === 401 || e.status === 403) {
              await doSignOut(true); // definitive-401 survived the inner refresh → FULL wipe
              return { ok: false, code: "revoked" };
            }
            return { ok: false, code: "server_error" }; // transient server — blob kept
          }
          if (e instanceof TypeError) return { ok: false, code: "network" }; // fetch rejection — blob kept
          // Generic Error — encryptedIdentitySeed would not open under the recovered UVK: stale/foreign UVK.
          await quickUnlock.wipe();
          return { ok: false, code: "stale_uvk" };
        }
      },
    );
  } finally {
    // A failed redeem must never leave tokens live in the api while locked — but only its own pair: a
    // sign-in that set its pair since (and is still in its sync, so no session yet) owns the api now, and clearing it
    // left that sign-in to install a session with no token at all.
    if (!session && tokenOwner === mine) api.setTokens(null, null);
  }
}

/** Disable quick unlock — a full wipe, NO auth gate (breaker A6 / §8.1 parity: reducing standing secret
 *  material is never gated). */
async function disableQuickUnlock(): Promise<Res<"disableQuickUnlock">> {
  await quickUnlock.wipe();
  await clearBioCred(); // 0.17.0: drop the amendment-4 reuse record too (explicit off = full teardown)
  return { ok: true };
}

/** The quick-unlock sub-state the popup needs in BOTH views (folded into `status`): `armed`
 *  (locked-armed → show the PIN field), `enrolled` + `offerDismissed` (unlocked → Settings toggle +
 *  the one-time offer card). Every read is fail-closed. */
async function quStateForStatus(): Promise<{ enrolled: boolean; armed: boolean; attemptsRemaining: number; offerDismissed: boolean; kind: "pin" | "biometric" | null }> {
  const st = await quickUnlock.status();
  // No trusted store reads as not-dismissed (the offer is best-effort chrome).
  const offerDismissed = (await trustedGet(nsk(DKEY))) === true;
  return { enrolled: st.enrolled, armed: st.armed, attemptsRemaining: st.attemptsRemaining, offerDismissed, kind: st.kind };
}

/** Remember the offer card was dismissed once (breaker B7 — durable, the trusted store, NON-secret). */
async function dismissQuickUnlockOffer(): Promise<Res<"dismissQuickUnlockOffer">> {
  try {
    await trusted.set({ [nsk(DKEY)]: true });
  } catch {
    /* best-effort */
  }
  return { ok: true };
}

/** Design §4.4 (decided on 2026-11-17): [n] more captures deleted unsaved by a lock or sign-out nobody was asked about,
 *  added to any the popup has not said yet. Plain: only the number. Best-effort (storage.session unavailable: unsaid). */
async function addLostCaptures(n: number): Promise<void> {
  try {
    const was = (await plainSession.get(LOST_KEY))[LOST_KEY];
    await plainSession.set({ [LOST_KEY]: (typeof was === "number" && was > 0 ? was : 0) + n });
  } catch {
    /* storage.session unavailable */
  }
}

/** The captures deleted unsaved since the popup last said so, taken: the popup says them once. */
async function takeLostCaptures(): Promise<number> {
  try {
    const n = (await plainSession.get(LOST_KEY))[LOST_KEY];
    if (typeof n !== "number" || n <= 0) return 0;
    await plainSession.remove(LOST_KEY);
    return n;
  } catch {
    return 0;
  }
}

/** The F26 idle-lock reason, read from its own storage.session key (E1-7). Not part of the session
 *  snapshot — it must outlive the snapshot's removal doLock does. Plain (A16): no secret in it. */
async function readLockNotice(): Promise<Res<"status">["lockNotice"]> {
  try {
    const n = (await plainSession.get(NKEY))[NKEY] as { kind?: unknown; seconds?: unknown } | undefined;
    if (n && n.kind === "idle" && typeof n.seconds === "number") return { kind: "idle", seconds: n.seconds };
    if (n && n.kind === "operator") return { kind: "operator" };
    if (n && n.kind === "not_confirmed") return { kind: "not_confirmed" };
  } catch {
    /* storage.session unavailable — no notice */
  }
  return null;
}

// ---- clipboard auto-clear backstop (spec 01 §8 / E1-4) ----
// The surface schedules a precise local timer at each copy (web-parity), but Chrome closes the
// popup on focus loss so that timer nearly never survives the dominant copy-in-popup flow. This SW
// alarm is the backstop that outlives the popup. The SW has no document, so the actual clipboard
// write is delegated to a context that does: an offscreen document on Chrome, the event page's own
// navigator on Firefox.

/** Arm the single backstop clear alarm. chrome.alarms floors at 0.5 min, so a sub-30 s policy
 *  clears at ~30 s once the copying document is gone (AM7 — honest + deterministic on packed
 *  builds; layer-1 covers sub-30 s while that document survives). Same-name create REPLACES, so the
 *  last copy through us wins (AM2). Answers the effective seconds; locked/absent → default 30. */
async function scheduleClipboardClear(): Promise<Res<"scheduleClipboardClear">> {
  const s = clipboardClearSeconds;
  try {
    await chrome.alarms.create(CLIPBOARD_CLEAR_ALARM, { delayInMinutes: Math.max(s / 60, 0.5) });
  } catch {
    /* alarms unavailable here — the surface's own local timer is the only clear */
  }
  return { ok: true, clearSeconds: s };
}

/** Fire the backstop clear. B1: the write is a SINGLE SPACE (an empty-selection execCommand copy is
 *  a silent no-op) and runs on EVERY alarm fire. Best-effort — every failure is swallowed. */
async function clearClipboardBackstop(): Promise<void> {
  if (typeof chrome.offscreen === "undefined") {
    // Firefox: background.js runs as an EVENT PAGE (a real document) and the clipboardWrite
    // permission lifts the gesture/focus gate — clear directly, execCommand-of-a-space as fallback.
    try {
      await navigator.clipboard.writeText("");
      return;
    } catch {
      /* fall through to the execCommand fallback */
    }
    try {
      const ta = document.createElement("textarea");
      ta.value = " ";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      ta.remove();
    } catch {
      /* nothing more this context can do */
    }
    return;
  }
  // Chrome: the async Clipboard API refuses unfocused documents (offscreen docs are never focused),
  // so offscreen.ts does a textarea + execCommand copy at top level. Close-then-recreate guarantees
  // the clear runs on EVERY fire (never clear-on-load behind a create-if-absent guard — B1).
  try {
    await closeOffscreenIfPresent();
    await chrome.offscreen.createDocument({
      url: "offscreen.html",
      reasons: [chrome.offscreen.Reason.CLIPBOARD],
      justification: "clear a copied secret from the clipboard",
    });
    await closeOffscreenIfPresent(); // the clear ran at document load — tear it back down
  } catch {
    /* offscreen unavailable — the surface's local timer was the only best-effort clear */
  }
}

async function closeOffscreenIfPresent(): Promise<void> {
  try {
    const has = typeof chrome.offscreen.hasDocument === "function" ? await chrome.offscreen.hasDocument() : true;
    if (has) await chrome.offscreen.closeDocument();
  } catch {
    /* none open, or a close race — nothing to do */
  }
}

/** Trusted-store key of this user's item homes (ids only, non-secret: the server sees every (itemId, vaultId)).
 *  A15: moved out of storage.local, where a content script could plant homes that hid items from fill. */
const homesKey = (userId: string): string => nsk(`itemHomes:${userId}`);

/** The item homes, or null when the record cannot be read (design §4.4: unknown, never empty — an empty map here used
 *  to be taken as authoritative and then written back over the real record). */
async function loadHomes(userId: string): Promise<Map<string, string> | null> {
  const k = homesKey(userId);
  let raw: unknown;
  try {
    raw = (await trusted.get(k))[k];
  } catch {
    return null;
  }
  // A10: a strict decode (UUID itemId → UUID vaultId); a cleaned record is re-persisted once.
  const d = decodeItemHomes(raw);
  if (d.rewrite) await trusted.set({ [k]: encodeItemHomes(d.value) }).catch(() => {});
  return d.value;
}

function saveHomes(userId: string, homes: Map<string, string>): Promise<void> {
  return trusted.set({ [homesKey(userId)]: encodeItemHomes(homes) }).catch(() => {});
}

/**
 * Root cause A §5.1 INV-HOME (branch A1b; core applyPull / web store twin): admit a snapshot's rows against this
 * browser's homes, THEN decrypt only the admitted ones. A row under another vault than its item's home (live or
 * tombstone) never reaches session.items, so it is never matched, filled, updated by a capture or given a TOTP. The
 * refusals are counted for the popup's "wrong vault" line. New homes are persisted.
 *
 * A9 (L-1): an UNHOMED row homes its item only if this browser actually APPLIES it — live, blob present, key held, and
 * the envelope opens to a well-formed doc (the open happens once, here; the admitted rows reuse it). A blob-less
 * tombstone or a row under a vault this session holds no key for is skipped: no home, no anomaly. Before A9 such a row
 * served first homed the item to the server's vault and quarantined the genuine row on this browser for good.
 */
async function homeAndDecrypt(
  sync: SyncResponse,
  vaultKeys: Map<string, Uint8Array>,
  userId: string,
  personalVaultId: string,
  held?: { homes: Map<string, string>; known: boolean },
): Promise<{ items: DecryptedItem[]; homes: Map<string, string>; known: boolean; wrongVault: number }> {
  const loaded = held === undefined ? await loadHomes(userId) : null;
  const known = held !== undefined ? held.known : loaded !== null;
  const h = held?.homes ?? loaded ?? new Map<string, string>();
  // §4.4: with the homes record unreadable, only the personal vault's rows are admitted (only this account's own
  // clients can seal under its key, so no other vault's writer can plant one there); no row of another vault is
  // admitted, since nothing can be checked against its home, and the record is not written back.
  const rows = known ? sync.items : sync.items.filter((it) => personalVaultId !== "" && it.vaultId === personalVaultId);
  if (!known) console.warn("andvari: this browser's record of item homes could not be read; shared vaults' items stay hidden this session");
  const opened = new Map<SyncResponse["items"][number], DecryptedItem>();
  const applies = (it: SyncResponse["items"][number]): boolean => {
    if (it.deleted || !it.blob || !vaultKeys.has(it.vaultId)) return false;
    const d = decryptItem(it, vaultKeys);
    if (d) opened.set(it, d);
    return d !== null;
  };
  const { admitted, tally, changed } = admitRows(rows, h, applies);
  if (changed && known) await saveHomes(userId, h);
  const items: DecryptedItem[] = [];
  for (const it of admitted) {
    const d = opened.get(it) ?? decryptItem(it, vaultKeys);
    if (d) items.push(d);
  }
  return { items, homes: h, known, wrongVault: tally.refused };
}

/** One row, decrypted under a held key to a well-formed doc, or null (tombstone, no key, undecryptable, malformed). */
function decryptItem(it: SyncResponse["items"][number], vaultKeys: Map<string, Uint8Array>): DecryptedItem | null {
  if (it.deleted || !it.blob) return null;
  // Fail closed above the read ceiling (web account.ts parity): an fv this client doesn't
  // understand may carry doc semantics an edit would corrupt. Items we CAN read carry their
  // fv onto the session item, and every re-seal AD-binds + rewires that SAME fv (the server
  // refuses per-item fv downgrades) — so nothing we touch can ever downgrade or upgrade.
  if (it.formatVersion > MAX_ITEM_FORMAT_VERSION) return null;
  const vk = vaultKeys.get(it.vaultId);
  if (!vk) return null;
  try {
    const doc: unknown = JSON.parse(
      new TextDecoder().decode(open(vk, fromB64(it.blob), adItem(it.vaultId, it.itemId, it.formatVersion))),
    );
    // spec 02 §3.2 (security review 2026-10): any writer of a shared vault can seal any JSON
    // under its VK — a malformed doc is skipped like an undecryptable one, never admitted.
    if (itemDocProblem(doc) !== null) return null;
    return { itemId: it.itemId, vaultId: it.vaultId, rev: it.rev, formatVersion: it.formatVersion, doc: doc as ItemDoc };
  } catch {
    return null; // undecryptable — skip
  }
}

function decryptItems(sync: SyncResponse, vaultKeys: Map<string, Uint8Array>): DecryptedItem[] {
  const items: DecryptedItem[] = [];
  for (const it of sync.items) {
    const d = decryptItem(it, vaultKeys);
    if (d) items.push(d);
  }
  return items;
}

/** The one rule of the session's list of opened items: it never holds an item of a vault whose key the session does not
 *  hold. Of [items], keeps only those whose vault key is in [vaultKeys] at this moment, the keys of the session the list is
 *  set on. Every place that sets a session's list goes through here (the unlock, the quick unlock, the restore from the
 *  snapshot, a pull's drop of a key and its install, a save that adds an item): a pull that opened rows before a later
 *  pull dropped their vault's key, and installs after it, installs none of them. A source test holds every such place. */
function itemsUnderHeldKeys(items: readonly DecryptedItem[], vaultKeys: ReadonlyMap<string, Uint8Array>): DecryptedItem[] {
  return items.filter((i) => vaultKeys.has(i.vaultId));
}

// ---- matching ----

/** ux-parity--2: ONE list order fleet-wide. Web sorts by name (store.ts localeCompare) and
 *  desktop/Android get core's `sortedBy { it.doc.name.lowercase() }`; the extension listed items in
 *  server change-feed order, so the popup's hoard and the in-page dropdown reshuffled whenever an
 *  item was edited. Transliterates CORE's comparator rather than web's: Kotlin's `sortedBy` on a
 *  String is natural (UTF-16 code-unit) order, which is exactly what `<`/`>` are here — a
 *  locale-aware collator would be a THIRD order. Sorted at the one projection every login surface
 *  reads through (matchesFor, `allItems`, `matches`), on the fresh array `filter` returns. */
const byName = (a: DecryptedItem, b: DecryptedItem): number => {
  const x = a.doc.name.toLowerCase();
  const y = b.doc.name.toLowerCase();
  return x < y ? -1 : x > y ? 1 : 0;
};

function loginItems(): DecryptedItem[] {
  return session ? session.items.filter((i) => i.doc.type === "login").sort(byName) : [];
}

/** Login items whose saved uris match the page — canonical urimatch (spec 02 §3.1) over a
 *  browser FillTarget. [page] is the page's ORIGIN (a browser-set `sender.origin`, the popup's active-tab origin, or
 *  a capture's stored uri), never a bare host: its scheme decides which addresses may match, since a plain-http page
 *  matches only an address saved as http (spec 05 autofill (e) — a login saved for https was
 *  offered on the same host over http, where anyone on the path serves the page). The host is normalized here (an
 *  origin may carry a port); saved androidapp:// entries classify kind:"app" and never match a web target. */
function matchesFor(page: string): DecryptedItem[] {
  if (normalizeHost(page) === null) return [];
  return loginItems().filter((it) => matchLoginsAt(it.doc.login?.uris ?? [], page, pslResolve));
}

/** The page a pending capture was taken on: its stored uri (H124: `http://…` for a plain-http origin, else
 *  `https://<host>`). A pending persisted by an older worker has no uri and matches by its host, as it did then. */
function pendingPage(p: { host: string; uri?: string }): string {
  return p.uri ?? p.host;
}

function toMatchItem(it: DecryptedItem, siteMatch: boolean): MatchItem {
  return {
    itemId: it.itemId,
    name: it.doc.name,
    username: it.doc.login?.username ?? null,
    uris: it.doc.login?.uris ?? [],
    siteMatch,
    hasTotp: Boolean(it.doc.login?.totp),
    // G21: let the page-side surfaces suppress write offers a reader can never complete (popup
    // TOTP paste-add, search-all URI-link) — writableItem() stays the honest SW backstop.
    readOnly: !writableItem(it),
  };
}

// ---- cards (popup copy-only group — the fill/save paths above stay login-only by design) ----

function cardItems(): DecryptedItem[] {
  return session ? session.items.filter((i) => i.doc.type === "card").sort(byName) : []; // ux-parity--2
}

/** Masked, list-safe projection — the number/expiry/CVV never ride a list (messages contract). */
function toCardItem(it: DecryptedItem): CardItem {
  const c = it.doc.card;
  return {
    itemId: it.itemId,
    name: it.doc.name,
    subtitle: cardSubtitle(c?.number),
    hasNumber: digitsOnly(c?.number ?? "") !== "",
    hasExpiry: composeShortExpiry(c?.expMonth ?? "", c?.expYear ?? "") !== null,
    hasCvv: (c?.securityCode ?? "") !== "",
    hasName: (c?.cardholderName ?? "") !== "",
  };
}

// ---- reveal + popup fill (the ZK egress gate) ----

/** [A2] the CALLING frame's own host, from the browser-set `sender.origin` only — the one spelling
 *  of "who is asking" for handlers that would otherwise take a page-supplied `msg.host` at its
 *  word (cardFormInfo states the same rule for the card lane). [A3] fail-closed: an undefined
 *  origin (mid-update SW / an engine that omits it), the empty string, or the opaque "null" of a
 *  sandboxed frame yields null — and null never matches a host. Popup senders have no tab and are
 *  not routed through here: their host comes from `activeTabHost()` under `activeTab`. */
function senderHost(sender: chrome.runtime.MessageSender): string | null {
  if (typeof sender.origin !== "string" || sender.origin === "" || sender.origin === "null") return null;
  return hostOfUrl(sender.origin);
}

/** Contract reveal rules: host-match ∨ one-shot popup grant (consumed) ∨ the popup's explicit pick.
 *  Cut M (v2 #14): failures carry a seam `code` so the fill surfaces render canon copy — the
 *  raw `error` strings here are debug detail and must never reach a user. */
// ---- usage ledger (spec 02 §8.2, design 2026-08-22-login-health) ----
//
// A fill IS the use, so the SW is where the extension's half of the staleness signal comes from.
// Records accumulate in memory and flush on a debounce: spec 03 §3 forbids a PUT per fill, which
// would turn the blob's own updatedAt into a keystroke-grade activity trace.
//
// ACCEPTED LOSS, stated rather than engineered around: an MV3 worker can be evicted mid-debounce,
// and the pending records die with it. The alternative — persisting them to storage.session —
// would add a plaintext BEHAVIORAL buffer to the locked compartment, a new disclosure class
// needing its own justification, to protect advisory ranking data whose worst-case loss is a
// stale cell in one health column. Not worth it. The window is kept short for the same reason.
let pendingUsage: UsageMap = {};
let usageTimer: ReturnType<typeof setTimeout> | null = null;

/** Drop pending records — called wherever vault material is dropped. Behavioral data about the
 *  user's items must not outlive the session that produced it. */
function clearPendingUsage(): void {
  if (usageTimer !== null) clearTimeout(usageTimer);
  usageTimer = null;
  pendingUsage = {};
}

function recordUsage(itemId: string): void {
  if (!session) return;
  pendingUsage = recordUse(pendingUsage, itemId, Date.now());
  if (usageTimer !== null) return;
  usageTimer = setTimeout(() => {
    usageTimer = null;
    void flushUsage();
  }, FLUSH_DEBOUNCE_MS);
}

/**
 * Read the server copy, decide with planFlush (usage.ts — the pure leaf `node --test` pins), then
 * store. The re-read is what stops last-writer-wins from meaning last-writer-DESTROYS — the
 * phone's and the laptop's entries survive our flush even though the endpoint has no merge
 * semantics of its own.
 *
 * With `liveItemIds` (resync's post-full-snapshot point, the ONLY caller allowed to prune) the
 * round runs even with NOTHING buffered (audit H35): the prune is the ledger's growth bound, and
 * a resync almost never lands inside the 15 s debounce window after a fill, so gating it behind a
 * non-empty buffer left it inert on this client. planFlush keeps a quiet resync write-free.
 *
 * The three server outcomes stay DISTINCT (audit H05): a GET that failed or a blob that would not
 * open is NOT an empty ledger to overwrite — no PUT, the buffer is re-armed, the next flush
 * retries. Only a genuinely absent blob (`sealedUsage: null`) is written without a merge.
 *
 * Every failure path is silent: this is a ranking hint and must never surface an error, break a
 * fill, or retry hard enough to be noticed.
 */
async function flushUsage(liveItemIds?: ReadonlySet<string>): Promise<void> {
  if (!session) return;
  if (Object.keys(pendingUsage).length === 0 && !liveItemIds) return;
  // Keyed from the PERSONAL VK, which a snapshot-restored session still holds — the whole reason
  // this client can participate at all (the UVK would be absent here; breaker B1).
  const vk = session.vaultKeys.get(session.personalVaultId);
  if (!vk) return; // no personal vault ⇒ no ledger (spec 02 §8.2), not an error
  const mine = pendingUsage;
  pendingUsage = {};
  await flushUsageRound({ vk, userId: session.userId, mine, liveItemIds });
}

/** H33 (recheck R43): the LOCK-path flush, in the natives' explicit-session shape
 *  (VaultSession.lock → UsageRecorder.flushForSession(live)). Everything the round needs — the
 *  buffer, the personal VK and the userId — is captured SYNCHRONOUSLY here, so doLock can drop
 *  `session` on the very next line and the round still completes: the PUT rides on the TOKEN
 *  pair, not on the session, and the tokens are forgotten only after the bounded await. The
 *  earlier shape awaited flushUsage() BEFORE `session = null`, which kept reveal/fill serviceable
 *  for up to TEARDOWN_FLUSH_TIMEOUT_MS after the user asked to lock — the delay the natives'
 *  lock path deliberately refuses ("the LOCK itself is not delayed"). Never re-arms: the
 *  session-gated re-arm in flushUsageRound sees null, exactly as clearPendingUsage() intends. */
function flushUsageForTeardown(): Promise<void> {
  if (!session) return Promise.resolve();
  const vk = session.vaultKeys.get(session.personalVaultId);
  const mine = pendingUsage;
  pendingUsage = {};
  if (!vk || Object.keys(mine).length === 0) return Promise.resolve();
  return flushUsageRound({ vk, userId: session.userId, mine });
}

/** One GET → planFlush → PUT round over an explicitly-captured context. `mine` has already been
 *  taken off the buffer by the caller; on a skipped or failed round it is re-armed ONLY while a
 *  session still stands (the lock path's clearPendingUsage() must win over a late re-arm). */
async function flushUsageRound(round: { vk: Uint8Array; userId: string; mine: UsageMap; liveItemIds?: ReadonlySet<string> }): Promise<void> {
  const { vk, userId, mine, liveItemIds } = round;
  try {
    const key = usageKey(vk);
    const adu = adUsage(userId);
    let server: ServerLedger;
    try {
      const res = await api.getUsage();
      server = res.sealedUsage
        ? { kind: "present", map: parseUsage(new TextDecoder().decode(open(key, fromB64(res.sealedUsage), adu))) }
        : { kind: "absent" };
    } catch {
      // Offline / HTTP failure on the GET, or a present blob that would not open under our key —
      // the two cases spec 02 §8.2's MUST is about. NOT "no ledger yet": that is the null branch.
      server = { kind: "unreadable" };
    }
    // G04: the prune runs ONLY when handed a provably-complete live set (resync's post-full-
    // snapshot point). The debounce and lock-path flushes pass nothing — pruning against a partial
    // view would drop entries for items this session just hasn't learned yet.
    const put = planFlush(server, mine, liveItemIds);
    if (put === null) {
      // Skipped the write on purpose — keep the fills for the next round (session-gated, see the
      // catch below). A null plan on a READABLE copy means there was nothing to write.
      if (server.kind === "unreadable" && session) pendingUsage = mergeUsage(mine, pendingUsage);
      return;
    }
    await api.putUsage(toB64(seal(key, new TextEncoder().encode(serializeUsage(put)), adu)));
  } catch {
    // Re-arm rather than drop — but ONLY while the session still stands. This catch runs after an
    // await, so on the lock path it can resume AFTER clearPendingUsage() has run; re-arming
    // unconditionally there would resurrect behavioral records into a locked SW, which is exactly
    // what that clear exists to prevent.
    if (session) pendingUsage = mergeUsage(mine, pendingUsage);
  }
}

function reveal(msg: Extract<Req, { type: "reveal" }>, sender: chrome.runtime.MessageSender): Res<"reveal"> {
  if (!session) return { ok: false, code: "locked", error: "locked" };
  const it = session.items.find((i) => i.itemId === msg.itemId && i.doc.type === "login");
  if (!it) return { ok: false, code: "not_allowed", error: "unknown item" };

  // F18 (2026-08-13 audit): the host gate binds to `sender.origin` for TAB senders — every other
  // origin-sensitive handler already does, and `msg.host` (content.ts sends `location.hostname`)
  // can answer differently from the browser's own notion of the frame's origin: a sandboxed frame
  // without allow-same-origin has an opaque origin but a perfectly real `location.hostname`.
  // The popup keeps `msg.host` (no tab; its host comes from `activeTabHost()` under activeTab).
  const webHost = sender.tab !== undefined ? senderHost(sender) : normalizeHost(msg.host);
  // Spec 05 autofill (e): the scheme from the same source as the host — a plain-http page
  // matches only an address saved as http. The popup names the active tab's origin, scheme included.
  const plainHttp = isPlainHttp(sender.tab !== undefined ? sender.origin : msg.host);
  // Security review 2026-10 (root cause B): a TAB sender's `explicit` no longer skips the host
  // match — the in-page click that set it could be steered by the page (revealgate.ts). A page
  // frame gets a host-mismatched item only through the popup's one-shot grant below.
  let allowed =
    revealGate({
      fromTab: sender.tab !== undefined,
      explicit: msg.explicit === true,
      hostMatched: webHost !== null && matchLoginsOnPage(it.doc.login?.uris ?? [], webHost, plainHttp, pslResolve),
    }) === "allow";
  const tabId = sender.tab?.id;
  // A popup fill grant is redeemable ONLY by the tab's TOP frame (fillFromPopup targets frameId 0).
  // Without this, a host-matched top frame leaves the grant armed and a hostile cross-origin
  // sub-frame — which reveal() would otherwise NOT host-match — claims the secret from it.
  const isTopFrame = sender.frameId === undefined || sender.frameId === 0;
  if (!allowed && tabId !== undefined && isTopFrame) {
    // q39: the redeeming document must be the origin the grant was minted for (fail closed on an undefined origin).
    if (loginGrantRedeemable(grants.get(tabId), msg.itemId, sender.origin, Date.now())) {
      grants.delete(tabId); // one-shot
      allowed = true;
    }
  }
  if (!allowed) return { ok: false, code: "not_allowed", error: "not allowed for this site" };

  let totpCode: string | null = null;
  const totp = it.doc.login?.totp;
  if (totp) {
    try {
      totpCode = currentCode(totp, Date.now()).code;
    } catch {
      /* malformed stored totp — the credential fill still proceeds */
    }
  }
  // The credential is being handed out for a fill — that is the use (spec 02 §8.2). Recorded at
  // the single success choke point, AFTER every gate, so a refused reveal never counts as one.
  recordUsage(msg.itemId);
  return {
    ok: true,
    secret: { username: it.doc.login?.username ?? null, password: it.doc.login?.password ?? null, totpCode },
  };
}

// ---- Safari: the andvari app's vault (appvault.ts) ----
// Trust boundary, hop by hop (design 2026-11-09, "Safari extension"):
//   web page → content script: the page can only make the content script report a form or a capture. In the Safari
//     build the content script has no fill menu and asks for no list.
//   content script → worker: a page frame may send `reveal` for one item, and gets a secret only (a) for a login whose
//     saved address matches the frame's BROWSER-SET origin, or (b) by redeeming the popup's one-shot, top-frame,
//     origin-bound grant. It can never list (`allItems`, `matches` answer nothing), unlock, or read a code.
//   popup → worker: the popup (an extension page, by the sender gate) may unlock, list, fill the active tab, copy one
//     login's password or code, and lock.
//   worker → native handler: `vaultOpen` (names, usernames, addresses), `vaultSecret` (one item), `vaultClose`. Only
//     the worker can send native messages; the handler answers whoever in this extension asks, so every gate is here.

/** The Safari build's vault; null in every other build, where the worker has its own session. */
const APP_VAULT: AppVault | null = vaultFromApp(BUILD_TARGET)
  ? new AppVault(nativeSender(globalThis as Parameters<typeof nativeSender>[0], SAFARI_NATIVE_APP) as unknown as ConstructorParameters<typeof AppVault>[0])
  : null;

/** A message of the own-session lanes, answered as the sender gate answers a stranger: that lane does not exist here. */
function noOwnSession(type: Req["type"]): unknown {
  const verdict = senderGate(type, {}, EXTENSION_BASE);
  return verdict.refused ? verdict.answer : { ok: false };
}

/**
 * The Safari build's answers for every message that would otherwise read or change the worker's own session.
 * `undefined` means "not this lane's": the ordinary handler runs (server info, save capture, page reports), and with
 * no session those answer locked or empty.
 */
async function appVaultDispatch(msg: Req, sender: chrome.runtime.MessageSender): Promise<unknown | undefined> {
  const vault = APP_VAULT!;
  switch (msg.type) {
    case "ping":
      // This build never contacts the server: the andvari app does, and the popup shows no connection test.
      return { ok: false, error: "the andvari app talks to the server, not this extension" } satisfies Res<"ping">;
    case "chooseServer":
    case "confirmServer":
      // The server is the andvari app's: only the app's answer (its own ask, or the popup's relay) changes it here, and
      // the page that sent this (Options) is not in this build.
      return { ok: false, code: "not_allowed" } satisfies Res<"chooseServer">;
    case "forgetServer":
      return { ok: false } satisfies Res<"forgetServer">;
    case "forgetEarlierAccount":
      return { ok: false, code: "not_offered" } satisfies Res<"forgetEarlierAccount">; // no own sign-in in this build
    case "followServerChange":
      return { ok: false, code: "not_allowed" } satisfies Res<"followServerChange">;
    case "deferServerChange":
      return { ok: false } satisfies Res<"deferServerChange">;
    case "status":
      return {
        unlocked: vault.unlocked,
        count: vault.items().length,
        email: vault.email,
        cardNotice: null,
        lockNotice: null,
        timerNotice: null, // Safari on iOS: the app's vault, locked by the app
        quickUnlock: { enrolled: false, armed: false, attemptsRemaining: 0, offerDismissed: true, kind: null },
        totpPending: null,
        waitingGrants: 0,
        serverEnded: false,
        wrongVault: 0,
        rememberedEmail: null,
        unsavedCaptures: 0, // Safari on iOS: a capture goes to the andvari app's queue, which the app keeps
        capturesLost: 0, // …so no lock here deletes one
        pageSummoned: Date.now() - pageSummonedPopupAt < PAGE_SUMMON_WINDOW_MS,
      } satisfies Res<"status">;
    case "appUnlock": {
      const r = await vault.open();
      // The Face ID sheet may have dismissed the popup that asked. Bring it back if the engine lets a worker do
      // that (best effort: where it does not, the person taps the toolbar item again and finds the list).
      if (r.state === "open") {
        try {
          void (chrome.action as unknown as { openPopup?: () => Promise<unknown> }).openPopup?.()?.catch(() => {});
        } catch {
          /* openPopup unsupported here */
        }
      }
      return (r.state === "openApp" ? { ok: false, state: r.state, message: r.message } : { ok: r.state === "open", state: r.state }) satisfies Res<"appUnlock">;
    }
    case "lock":
      vault.close();
      // As doLock does: a fill the person picked before the lock is not redeemable after it. (A redemption after close
      // already answered `cancelled`; the grants themselves now go with the lock too.)
      grants.clear();
      cardGrants.clear();
      return { ok: true } satisfies Res<"lock">;
    case "matches": {
      // No in-page menu in this build: a page frame never gets a list. The popup gets the logins saved for the site
      // of the active tab, by the tab's own URL (never the host the message names), so it can lead with them.
      if (sender.tab !== undefined || !vault.unlocked) return { locked: !vault.unlocked, matches: [] } satisfies Res<"matches">;
      const page = await activePageHost();
      const matches = page === null ? [] : appVaultList(undefined).filter((i) => matchLoginsAt(i.uris, page, pslResolve)).map((i) => ({ ...i, siteMatch: true }));
      return { locked: false, matches } satisfies Res<"matches">;
    }
    case "allItems":
      if (sender.tab !== undefined) return { locked: !vault.unlocked, items: [] } satisfies Res<"allItems">;
      return vault.listAnswer(appVaultList(msg.query)) satisfies Res<"allItems">;
    case "cardItems":
      // Answered here, by the vault's own notion of locked: the ordinary handler answers from the worker's session,
      // which this build never has, and its "locked" sent the popup back to the unlock screen after every unlock.
      // Names and masked lines only; a page frame gets none.
      if (sender.tab !== undefined) return vault.listAnswer<CardItem>([]) satisfies Res<"cardItems">;
      return vault.listAnswer<CardItem>(appVaultCards(msg.query)) satisfies Res<"cardItems">;
    case "revealCardField": {
      // The popup's copy of ONE field of one card: only that field is asked of the app.
      if (sender.tab !== undefined) return { ok: false, error: "not allowed from a page" } satisfies Res<"revealCardField">;
      // The card number and the security code are never copied in this build (round-5 C4: the popup has no copy
      // button for them), and the worker does not release them to an extension page either (round-6 review): they
      // are filled into a page, or copied in the app.
      if (msg.field === "number" || msg.field === "cvv") return { ok: false, error: "not in this build" } satisfies Res<"revealCardField">;
      if (!vault.unlocked) return { ok: false, error: "locked" } satisfies Res<"revealCardField">;
      const wanted: CardFieldName[] = msg.field === "expiry" ? ["expMonth", "expYear"] : ["name"];
      const c = await appVaultCard(msg.itemId, wanted);
      return (c === null ? { ok: false, error: "unknown item" } : cardFieldValue(c, msg.field)) satisfies Res<"revealCardField">;
    }
    case "reveal":
      return appVaultReveal(msg, sender);
    case "totp":
      if (sender.tab !== undefined) return { ok: false } satisfies Res<"totp">;
      // One code, when the person copies it. The popup's once-a-second display ticker gets none: a live code for
      // every visible row would be a secret per row per second across the native hop.
      if (msg.forCopy !== true || vault.item(msg.itemId)?.hasTotp !== true) return { ok: false } satisfies Res<"totp">;
      return appVaultCode(msg.itemId);
    // The lanes of a session this build does not have: sign-in, its quick unlock, and every vault write.
    case "unlock":
    case "unlockTotp":
    case "cancelTotp":
    case "unlockWithPin":
    case "unlockWithBio":
    case "enrollQuickUnlock":
    case "enrollQuickUnlockBio":
    case "disableQuickUnlock":
    case "dismissQuickUnlockOffer":
    case "setTotp":
    case "linkUri":
    case "signOut":
      return noOwnSession(msg.type);
    default:
      return undefined;
  }
}

function appVaultCards(query: string | undefined): CardItem[] {
  const q = (query ?? "").trim().toLowerCase();
  return APP_VAULT!.cards().filter((c) => !q || c.name.toLowerCase().includes(q) || c.subtitle.toLowerCase().includes(q));
}

/** The named fields of one of the app's cards, in the shape of a stored card; null when nothing was released. */
async function appVaultCard(itemId: string, fields: readonly CardFieldName[]): Promise<StoredCard | null> {
  const r = await APP_VAULT!.cardFields(itemId, fields);
  if (r.state !== "card") return null;
  const f: AppVaultCardFields = r.fields;
  return { number: f.number, expMonth: f.expMonth, expYear: f.expYear, securityCode: f.cvv, cardholderName: f.name, postalCode: f.postal };
}

/** The app's fields a form's declared kinds need: nothing the form did not declare is asked for. */
function cardFieldsForKinds(kinds: readonly string[]): CardFieldName[] {
  const k = new Set(kinds);
  const out: CardFieldName[] = [];
  if (k.has("cardnumber")) out.push("number");
  if (k.has("cardexpiry") || k.has("cardexpmonth") || k.has("cardexpyear")) out.push("expMonth", "expYear");
  if (k.has("cardname")) out.push("name");
  if (k.has("cardcvv")) out.push("cvv");
  if (k.has("cardpostal")) out.push("postal");
  return out;
}

function appVaultList(query: string | undefined): MatchItem[] {
  const q = (query ?? "").trim().toLowerCase();
  return APP_VAULT!.items()
    .filter((i) => !q || i.name.toLowerCase().includes(q) || i.username.toLowerCase().includes(q) || i.uris.some((u) => u.toLowerCase().includes(q)))
    // readOnly: this build writes nothing to the vault, so every write offer is suppressed.
    .map((i) => ({ itemId: i.itemId, name: i.name, username: i.username === "" ? null : i.username, uris: i.uris, siteMatch: false, hasTotp: i.hasTotp, readOnly: true }));
}

/** `reveal` with the app's vault behind it: the same gates as [reveal], then ONE item's secret from the handler. */
async function appVaultReveal(msg: Extract<Req, { type: "reveal" }>, sender: chrome.runtime.MessageSender): Promise<Res<"reveal">> {
  const vault = APP_VAULT!;
  if (!vault.unlocked) return { ok: false, code: "locked", error: "locked" };
  const it = vault.item(msg.itemId);
  if (!it) return { ok: false, code: "not_allowed", error: "unknown item" };
  let allowed: boolean;
  const tabId = sender.tab?.id;
  if (tabId === undefined) {
    // The popup: an explicit copy of one login's password ([revealGate], as in every build).
    const webHost = normalizeHost(msg.host);
    allowed = revealGate({ fromTab: false, explicit: msg.explicit === true, hostMatched: webHost !== null && matchLoginsOnPage(it.uris, webHost, isPlainHttp(msg.host), pslResolve) }) === "allow";
  } else {
    // A page frame: ONLY by redeeming the popup's one-shot grant, in the top frame, at the origin the grant was
    // minted for. This build has no in-page menu, so a frame has no reason of its own to ask; a host match alone
    // releases nothing here.
    const isTopFrame = sender.frameId === undefined || sender.frameId === 0;
    allowed = isTopFrame && loginGrantRedeemable(grants.get(tabId), msg.itemId, sender.origin, Date.now());
    if (allowed) grants.delete(tabId); // one-shot
  }
  if (!allowed) return { ok: false, code: "not_allowed", error: "not allowed for this site" };
  const r = await vault.secret(msg.itemId, "login");
  if (r.state !== "login") return { ok: false, code: r.state === "refused" ? "not_allowed" : "locked", error: r.state };
  // The one-time code is never part of a fill here: it is released on its own, to the popup, when the person copies it.
  return { ok: true, secret: { username: r.username === "" ? null : r.username, password: r.password, totpCode: null } };
}

async function appVaultCode(itemId: string): Promise<Res<"totp">> {
  const r = await APP_VAULT!.secret(itemId, "code");
  if (r.state !== "code") return { ok: false };
  return { ok: true, code: r.code, secondsLeft: 30 - (Math.floor(Date.now() / 1000) % 30) };
}

/** The active tab's top-level page, from the tab's own URL (readable while the popup is open): its ORIGIN, so the
 *  match sees the scheme (F4: a plain-http page matches only an address saved as http). Null when it has no host. */
async function activePageHost(): Promise<string | null> {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const top = tab?.id === undefined ? null : await topOrigin(tab.id);
    return top === null || normalizeHost(top) === null ? null : top;
  } catch {
    return null;
  }
}

// The list lives for the vault's own lifetime (90 s) or until Lock. Nothing ties it to the popup's page: on iOS the
// system's Face ID sheet dismisses the popup, and a port's disconnect (build 15) then closed the vault that the very
// same unlock was opening, so every reopening asked for Face ID again and never showed a list.
// ---- end of the Safari app-vault lane ----

/**
 * The build that moved to the app's vault retires the session an earlier Safari build signed in with: its tokens,
 * quick-unlock record, cached wraps and item homes, for EVERY server it ever used (every `ns.<originKey>.` prefix in
 * the store, and the origin in effect at start). The local erase is immediate and comes first. The server-side revoke
 * may not be possible yet (offline, or a server awaiting confirmation): the token pair is then kept, alone, in the
 * trusted store, and the revoke is tried again at every worker start until the server confirms it or says the
 * session is already dead. The marker is set only then.
 */
async function retireOwnSession(): Promise<void> {
  const DONE = "safari.ownSessionRetired";
  const OWED = "safari.ownSessionRevokeOwed";
  try {
    const got = await trusted.get(null);
    if (got[DONE] === true) return;
    const originAtStart = serverUrl;
    const keys = new Set<string>([currentOriginKey]);
    for (const k of Object.keys(got)) {
      const m = /^ns\.([0-9a-f]{16})\./.exec(k);
      if (m) keys.add(m[1]!);
    }
    // The erase, now: the lock hands back the pair it saw, which is all the revoke needs.
    const seen: { tokens?: TokenPair } = {};
    await doLock("signout", seen);
    void clearBioCred();
    for (const k of keys) await purgeOriginNamespace(k);
    let owed = got[OWED] as { origin?: unknown; access?: unknown; refresh?: unknown } | undefined;
    if (seen.tokens?.access) {
      owed = { origin: originAtStart, access: seen.tokens.access, refresh: seen.tokens.refresh };
      await trusted.set({ [OWED]: owed });
    }
    if (owed !== undefined && typeof owed.origin === "string" && typeof owed.access === "string") {
      if (dialBlock !== null) return; // A16 review R4: nothing is dialed while a server is pending; the revoke stays owed
      const revoker = new AndvariApi(owed.origin, chrome.runtime.getManifest().version);
      revoker.setTokens(owed.access, typeof owed.refresh === "string" ? owed.refresh : null);
      const revoked = await Promise.race([revoker.logout(), delay(5000).then(() => false)]);
      revoker.setTokens(null, null);
      if (!revoked) return; // not confirmed: the pair stays owed, and the next start tries again
      await trusted.remove(OWED);
    }
    await trusted.set({ [DONE]: true });
  } catch {
    /* the store did not answer: the next worker start tries again */
  }
}
/** Settles once the retirement has run for this worker life (done, or owed again). Resolved at once in other builds. */
const ownSessionRetired: Promise<void> = APP_VAULT !== null ? serverReady.then(() => retireOwnSession()) : Promise.resolve();


/** Card copy egress — POPUP ONLY (a sender with a tab is a content script ⇒ refused): the
 *  in-page path must have NO route to card data until the frame-origin egress contract ships
 *  (cards design 2026-07-09). Cards are deliberately not uri-bound, so there is no host gate —
 *  the gate is the explicit click on a copy button in OUR popup plus the unlocked session.
 *  ONE field per request: the popup receives exactly what lands on the clipboard, no more. */
function revealCardField(
  msg: Extract<Req, { type: "revealCardField" }>,
  sender: chrome.runtime.MessageSender,
): Res<"revealCardField"> {
  if (sender.tab !== undefined) return { ok: false, error: "not allowed from a page" };
  if (!session) return { ok: false, error: "locked" };
  const c = session.items.find((i) => i.itemId === msg.itemId && i.doc.type === "card")?.doc.card;
  if (!c) return { ok: false, error: "unknown item" };
  return cardFieldValue(c, msg.field);
}

/** The stored fields of a card that the copy and fill paths read (a session's card document, or the app's answer). */
type StoredCard = { number?: string | null; expMonth?: string | null; expYear?: string | null; securityCode?: string | null; cardholderName?: string | null; postalCode?: string | null };

/** One copyable field of a card, composed as the popup copies it. */
function cardFieldValue(c: StoredCard, field: Extract<Req, { type: "revealCardField" }>["field"]): Res<"revealCardField"> {
  switch (field) {
    case "number": {
      const d = digitsOnly(c.number ?? "");
      return d !== "" ? { ok: true, value: d } : { ok: false, error: "no number on this card" };
    }
    case "expiry": {
      const e = composeShortExpiry(c.expMonth ?? "", c.expYear ?? "");
      return e !== null ? { ok: true, value: e } : { ok: false, error: "no expiry on this card" };
    }
    case "name": {
      // Tier 2 §6 copy parity: the cardholder name, verbatim (same gates as its siblings).
      const nm = c.cardholderName ?? "";
      return nm !== "" ? { ok: true, value: nm } : { ok: false, error: "no name on this card" };
    }
    case "cvv": {
      const s = c.securityCode ?? "";
      return s !== "" ? { ok: true, value: s } : { ok: false, error: "no security code on this card" };
    }
  }
}

/** Cut M (v2 #14): shape-check the content script's sendResponse before trusting it as an
 *  outcome — an old/orphaned script (or a frame answering nothing) yields undefined, which must
 *  read as "no verdict", never as success. */
function asFillOutcome(v: unknown): FillOutcome | null {
  if (typeof v !== "object" || v === null) return null;
  const f = (v as { filled?: unknown }).filled;
  return f === "both" || f === "username" || f === "password" || f === "nothing" ? (v as FillOutcome) : null;
}

/** Explicit popup pick → mint the tab's one-shot grant, then tell the tab to run its normal
 *  reveal round-trip. Single secret-egress path: the SW never pushes a secret at a tab.
 *  Popup ONLY — the SW refuses tab senders, exactly as its card twin `fillCardFromPopup` does
 *  (F18, 2026-08-13 audit): this handler mints a grant for whatever tab is ACTIVE, which need not
 *  be the sender's tab or origin, so a page-side caller could write a vault password into a
 *  different site's top-frame login form and read it back off `input.value`.
 *  Cut M (v2 #14): `ok` used to mean sendMessage DELIVERY, so the popup closed over a fill
 *  that wrote nothing — now the content script answers its real FillOutcome and ok is true
 *  only when something actually landed in a field. */
async function fillFromPopup(itemId: string, sender: chrome.runtime.MessageSender, confirmedOtherSite: string | null = null, shownPage: string | null = null): Promise<Res<"fillFromPopup">> {
  if (sender.tab !== undefined) return { ok: false, code: "not_allowed", error: "not allowed from a page" };
  // Safari: the open list of the app's vault stands in for the session's items; the secret is fetched at the reveal.
  const unlockedNow = APP_VAULT !== null ? APP_VAULT.unlocked : session !== null;
  if (!unlockedNow) return { ok: false, code: "locked", error: "locked" };
  const known = APP_VAULT !== null ? APP_VAULT.item(itemId) !== null : session!.items.some((i) => i.itemId === itemId && i.doc.type === "login");
  if (!known) {
    return { ok: false, code: "not_allowed", error: "unknown item" };
  }
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.id === undefined) return { ok: false, code: "unreachable", error: "no active tab" };
  // q39: bind the grant to the top-level origin the user is looking at NOW (readable under the popup-open activeTab
  // window); an opaque or unreadable top is never eligible, the card grant's [A1] rule.
  const top = await topOrigin(tab.id);
  if (top === null) return { ok: false, code: "not_allowed", error: "this page cannot be filled" };
  // The tab must still be on the page the popup showed ([shownPage], the origin its "This site" list was
  // for). A tab can move to another site while the popup is open (the page that opened it may navigate it at any
  // moment), and the person's pick was made for the site the popup named: without this the grant below would be minted
  // for the new site, whose own content script then redeems it. Compared at the same read the grant binds to, so a
  // later move cannot get past it either (the redeeming document must then be at [top]).
  if (shownPage === null || shownPage !== top) return { ok: false, code: "not_allowed", error: "the page changed since the popup showed it" };
  // Every build: the popup lists the whole vault, so a login saved for another site is filled here only after the
  // person confirmed it, with both sites named (a look-alike domain is the case). Judged against the tab's top page,
  // where the fill goes, never against a frame inside it.
  {
    const page = normalizeHost(top);
    const saved = APP_VAULT !== null ? (APP_VAULT.item(itemId)?.uris ?? []) : (session!.items.find((i) => i.itemId === itemId)?.doc.login?.uris ?? []);
    // F4 (spec 05 autofill (e)): on a plain-http page only the addresses saved as http can match.
    const uris = offeredUris(saved, isPlainHttp(top));
    // The confirmation is the token of the question asked: it holds for this login, on this top-level origin only.
    const confirmed = confirmedOtherSite !== null && confirmedOtherSite === otherSiteConfirmation(itemId, top);
    if (!confirmed && (page === null || !matchLogins(uris, { webHost: page, packageName: "" }, pslResolve))) {
      return { ok: false, code: "not_allowed", error: "confirm other site", needsConfirm: otherSiteQuestion(itemId, saved, top, pslResolve) };
    }
  }
  grants.set(tab.id, { itemId, origin: top, expiresMs: Date.now() + GRANT_TTL_MS });
  const msg: TabMsg = { type: "fillItem", itemId };
  let raw: unknown;
  try {
    // Top frame ONLY — both the message and the grant (redeemed in reveal()) are frame-0-bound so
    // a cross-origin sub-frame can neither receive the fill request nor consume the grant.
    raw = await chrome.tabs.sendMessage(tab.id, msg, { frameId: 0 });
  } catch {
    grants.delete(tab.id);
    return { ok: false, code: "unreachable", error: "page not reachable — reload the tab and retry" };
  }
  // The fill round-trip is over — void any unconsumed grant (e.g. the content answered no_form
  // before its reveal ran) rather than leaving it armed for the 30 s TTL.
  grants.delete(tab.id);
  const outcome = asFillOutcome(raw);
  if (!outcome) return { ok: false, code: "unreachable", error: "no fill outcome from the page" };
  if (outcome.filled === "nothing") {
    return { ok: false, outcome, code: outcome.code ?? "no_fields", error: `fill wrote nothing (${outcome.code ?? "no_fields"})` };
  }
  return { ok: true, outcome };
}

// ---- S3 in-page card fill (the frame-origin egress contract — design 2026-07-10) ----
// Card data leaves the SW ONLY via revealCardForFill, one field-set per explicit popup click,
// bound to the exact frame that detected the form (frameId + sender.origin + a live top-origin
// recheck), one-shot, in a store SEPARATE from login grants. The popup-only messages refuse tab
// senders; the content path can neither mint a grant nor enumerate offers.

/** The tab's CURRENT top-level origin, read from `tab.url` under the popup-open `activeTab` window
 *  ([A4] — the manifest has NO `tabs` permission; needing `tab.url` outside this window would be a
 *  permission bump + a re-review). Fail-closed ([A3]): null on an unreadable/empty/opaque URL — a
 *  missing URL is NEVER a match, and `null === null` never passes an eligibility check below. */
async function topOrigin(tabId: number): Promise<string | null> {
  try {
    const t = await chrome.tabs.get(tabId);
    if (typeof t.url !== "string" || t.url === "") return null;
    const o = new URL(t.url).origin;
    return o === "null" ? null : o; // opaque/sandboxed top → never eligible ([A1])
  } catch {
    return null;
  }
}

/** Content (per frame): record/clear this frame's card forms. [A2]/[A3]: the frame's identity is the origin the
 *  browser reports for it (cardrelease.ts frameOriginOf: `sender.origin`, else the frame's own `sender.url`), never a
 *  page-controlled host, fail-closed on any undefined. Only a frame whose origin is a payment provider's card-entry
 *  origin ever receives a card; the others' records only let the popup say why it copies instead. */
async function cardFormInfo(
  msg: Extract<Req, { type: "cardFormInfo" }>,
  sender: chrome.runtime.MessageSender,
): Promise<Res<"cardFormInfo">> {
  const tabId = sender.tab?.id;
  const frameId = sender.frameId;
  const origin = frameOriginOf(sender);
  if (tabId === undefined || frameId === undefined) return { ok: false };
  if (frameId !== 0) {
    // Round-13 review: whether the browser named this provider frame's site, for the popup's Details (display only: the
    // frame's own URL is looked at here for that and nothing else).
    const byUrl = webOriginOfUrl(sender.url);
    if (byUrl !== null && isCardProviderOrigin(byUrl)) providerFrameDiag = `${byUrl}: sender.origin ${sender.origin === undefined ? "not set" : sender.origin === byUrl ? "set" : "set, to another origin"}`;
  }
  let heard = cardReports.get(tabId);
  if (heard === undefined) cardReports.set(tabId, (heard = { top: false, origins: new Set(), hints: [] }));
  if (frameId === 0) {
    heard.top = true; // the content script runs in this page, whatever origin the browser reports for it
    // The page's own word about the provider frames it shows: a hint for the popup's line, nothing more (bounded).
    heard.hints = Array.isArray(msg.providerOrigins) ? msg.providerOrigins.filter((o): o is string => typeof o === "string" && isCardProviderOrigin(o) && new URL(o).origin === o).slice(0, 8) : [];
  }
  if (origin === null) {
    // Round-12 review: a sub-frame whose message carries no origin (Firefox before 126) is never a card frame; the popup
    // says that this browser fills no card in a payment frame.
    if (frameId !== 0 && sender.origin === undefined) heard.originless = true;
    return { ok: false };
  }
  heard.origins.add(origin);
  const st = tabs.get(tabId) ?? {};
  const reg = st.cardForms ?? {};
  if (msg.forms.length === 0) {
    // §7: the first-report-always-sends sentinel means every frame of every navigation files an
    // empty report — when it deletes nothing, skip the persistTabs() storage write (a
    // per-frame-per-navigation write for a no-op would dominate the SW's storage traffic).
    if (!(frameId in reg)) return { ok: true };
    delete reg[frameId];
  } else {
    // M2: the form holding the field the person chose, by index. A choice is made only by a report of a new one
    // (`choseNow`, L7: choosing the same field again is one too), stamped when this worker heard of it; a later report
    // keeps a choice this record still holds (its form may have moved), and never brings back one that was let go.
    const a = msg.anchor;
    const index = typeof a === "number" && Number.isInteger(a) && a >= 0 && a < msg.forms.length ? a : null;
    const was = reg[frameId];
    const anchorAt = index === null ? undefined : msg.choseNow === true ? Date.now() : typeof was?.anchor === "number" ? was.anchorAt : undefined;
    const anchor = anchorAt === undefined ? null : index;
    reg[frameId] = {
      origin, forms: msg.forms, anchor, ...(anchorAt !== undefined ? { anchorAt } : {}),
      // Round-12 review: the frame's own report of its ancestor origins (a fill's chain of choices must share them) and
      // whether it is collapsed (then it neither counts nor can be chosen). Round-13 review: on Firefox, its parent's
      // frameId in their place; and the merchant account its URL names. Together with the origin they say which payment
      // form the frame belongs to.
      ancestors: ancestorsOf(msg.ancestors), parent: parentOf(msg.parentFrameId), account: accountOf(msg.account),
      ...(typeof msg.shown === "boolean" ? { shown: msg.shown } : {}),
    };
    // Round-11 review: a new choice of a kind clears the choices of that kind in the other frames of its payment form,
    // which are told. Round-13 review: never in another form; the fill then refuses until the person starts over.
    if (msg.choseNow === true && anchor !== null && anchorAt !== undefined && mayReceiveCard(reg[frameId])) {
      for (const other of supersededChoices(reg, frameId, msg.forms[anchor]!, anchorAt)) letChoiceGo(tabId, reg, other);
    }
  }
  st.cardForms = reg;
  tabs.set(tabId, st);
  persistTabs();
  void refreshTabBadge(tabId); // V4: a card form just appeared/left — repaint (login count still wins)
  return { ok: true };
}

/** [T5]/[T6]: nudge every frame of [tabId] to re-scan + re-report its card form (no frameId =
 *  all frames). The `.catch(() => {})` is LOAD-BEARING [T6]: `tabs.sendMessage` REJECTS whenever
 *  the tab has no receiver at all (chrome://, PDFs, un-injected pages) — a large fraction of
 *  popup opens — and an unhandled rejection here would spam the SW console on every one. */
function broadcastRescanCardForms(tabId: number): void {
  const msg: TabMsg = { type: "rescanCardForms" };
  void chrome.tabs.sendMessage(tabId, msg).catch(() => {});
}

const delay = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** The frames of [tabId] that may receive a card: a payment provider's card-entry document with a card form
 *  (cardrelease.ts). The badge's card dot, the popup's Fill and the chip all read through here. */
function eligibleCardFrames(tabId: number): { frameId: number; origin: string }[] {
  return providerCardFrames(tabs.get(tabId)?.cardForms ?? {});
}

/** How long a recorded frame may take to answer before it counts as gone. */
const FRAME_PROBE_MS = 400;

/**
 * Drop the records of [tabId]'s frames that are gone (removed from the page, or navigated to a document with no content
 * script), so a provider frame an SPA re-mounted does not count twice. Each recorded frame is asked to report afresh;
 * one that cannot be reached is forgotten. The answer is the browser's, so a page cannot keep a record alive.
 */
async function pruneGoneCardFrames(tabId: number): Promise<void> {
  const reg = tabs.get(tabId)?.cardForms;
  if (reg === undefined) return;
  const ids = Object.keys(reg).map(Number);
  const rescan: TabMsg = { type: "rescanCardForms" };
  const answered = await Promise.all(
    ids.map((frameId) => Promise.race([chrome.tabs.sendMessage(tabId, rescan, { frameId }).then(() => true, () => false), delay(FRAME_PROBE_MS).then(() => true)])),
  );
  const now = tabs.get(tabId)?.cardForms;
  if (now === undefined) return;
  let changed = false;
  ids.forEach((frameId, i) => {
    if (!answered[i] && frameId in now) {
      delete now[frameId];
      changed = true;
    }
  });
  if (changed) persistTabs();
}

/** The ancestor origins a frame's content script reported (`location.ancestorOrigins`, nearest first), bounded; null
 *  when it reported none (Firefox has no such list) or anything malformed. */
function ancestorsOf(v: unknown): string[] | null {
  if (!Array.isArray(v) || v.length > 32) return null;
  return v.every((o) => typeof o === "string" && o.length <= 2048) ? (v as string[]) : null;
}

/** Firefox: the parent frameId a frame's content script reported (round-13 review); null for anything else. */
function parentOf(v: unknown): number | null {
  return typeof v === "number" && Number.isInteger(v) && v >= 0 ? v : null;
}

/** The merchant account a provider frame's content script read from its own URL (cardproviders.ts providerAccountOf),
 *  bounded; null for none or anything malformed. */
function accountOf(v: unknown): string | null {
  return typeof v === "string" && v.length <= 300 && /^[a-z]+:[A-Za-z0-9_/-]+$/.test(v) ? v : null;
}

/** The frame [frameId] of [tabId] lets its choice go: its record keeps everything else, and the frame is told. */
function letChoiceGo(tabId: number, reg: Record<string, CardFrameRecord>, frameId: number): void {
  const r = reg[frameId];
  if (r === undefined) return;
  const { anchorAt: _gone, ...kept } = r;
  reg[frameId] = { ...kept, anchor: null };
  const drop: TabMsg = { type: "dropCardChoice" };
  void chrome.tabs.sendMessage(tabId, drop, { frameId }).catch(() => {});
}

/**
 * Popup ONLY: "Start over" (round-13 review). Every frame of the active tab lets its chosen card field go, so the person
 * taps the one payment form they mean before filling.
 */
async function clearCardChoices(sender: chrome.runtime.MessageSender): Promise<Res<"clearCardChoices">> {
  if (sender.tab !== undefined) return { ok: false };
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.id === undefined) return { ok: false };
  const st = tabs.get(tab.id);
  const reg = st?.cardForms;
  if (st === undefined || reg === undefined) return { ok: true };
  for (const frameId of framesWithChoices(reg)) letChoiceGo(tab.id, reg, frameId);
  tabs.set(tab.id, st);
  persistTabs();
  return { ok: true };
}

/**
 * A payment provider's origin that the tab's top frame shows a frame of (by its src) and from which no frame reported to
 * this worker: this extension may not run there (Safari asks per site; Chrome and Firefox may be granted some sites
 * only), so the popup names it to allow. A hint from the page's own DOM: it never decides where a card goes. Null when
 * there is none.
 */
function providerFrameNotAllowed(tabId: number): string | null {
  const heard = cardReports.get(tabId);
  return heard?.hints.find((o) => !heard.origins.has(o)) ?? null;
}

/** V4 (design §V4): the tab's SINGLE badge authority, so the login count and the card discovery dot
 *  never clobber each other. Login precedence — matchesFor(top origin) > 0 paints the count (the
 *  pre-V4 behavior, unchanged); ONLY when there is no login match does a payment provider's card
 *  form (owner decision 2026-11-14) paint CARD_BADGE_TEXT. Both signals are trusted-chrome metadata
 *  (host match; browser-set per-frame origins against the provider list) — zero card data. `topOrigin` reads `tab.url`, which is
 *  visible under the host permission that content injection already required (no new permission).
 *  Locked → early return: doLock clears every tab's badge wholesale, and a late in-flight message
 *  must not repaint a count we can no longer serve. */
function refreshTabBadge(tabId: number): void {
  // Locked → CLEAR (a stale pre-lock count/dot must not outlive the session; review-fold).
  // [A4] review-fold: the top origin comes from the RECORDED top-frame sender.origin (pageInfo) —
  // never a tab-URL read; outside the popup-open activeTab window that read is exactly what the
  // [A4] pin forbids. No record (un-granted page, pre-report) → no badge, fail-quiet.
  // Synchronous now: no await, so no lock/session interleave to re-check.
  const top = session !== null ? (tabs.get(tabId)?.topOrigin ?? null) : null;
  // `host` names the page by its origin (F4: matchesFor reads the scheme from it — a plain-http page counts only the
  // logins saved as http); "" when the recorded origin is not a URL.
  let host = "";
  if (top !== null) {
    try {
      host = new URL(top).origin;
    } catch {
      host = "";
    }
  }
  const loginCount = host !== "" ? matchesFor(host).length : 0;
  const reuse = session !== null && reuseNotices.has(tabId); // outranks the count: it is about what the user just typed
  const text = reuse ? REUSE_BADGE_TEXT : loginCount > 0 ? String(loginCount) : top !== null && eligibleCardFrames(tabId).length > 0 ? CARD_BADGE_TEXT : "";
  chrome.action.setBadgeText({ tabId, text }).catch(() => {});
}

// ---- C1 in-page card chip (design 2026-07-26) ----
// PLACEMENT IS LOAD-BEARING: both handlers sit INSIDE the refreshTabBadge → "Popup ONLY" pin span
// on purpose, so that span's shipped [V4] negatives — no awaited top-origin helper call, no tab-URL
// read — enforce the [A4] discipline on this new gate for free ([S8]). Moving either function out
// of this span silently drops that enforcement; move the pin with it, in the same commit.
// (Both forbidden literals are deliberately UNSPELLED above: the pin is a substring test over this
// very span, so quoting them here would red it.)

/** [S-rate] gate throttle: a page can drive TRUSTED focus at frame rate (`HTMLElement.focus()`),
 *  so an unthrottled gate is a page-driven SW wake loop. One answered offer per tab per 250 ms;
 *  the rest REPLAY the tab's last computed answer (review #3 — a hard refusal here silently lost
 *  the chip when tabbing between the fields of one card form). */
const CHIP_OFFER_MIN_GAP_MS = 250;
/** [S4b] repair throttle — at most ONE repair burst per tab per 2 s. */
const CHIP_REPAIR_MIN_GAP_MS = 2000;
const chipOfferLast = new Map<number, Map<number, { t: number; answer: Res<"cardChipOffer"> }>>();
const chipRepairLast = new Map<number, number>();
/** H02: `passwordReuse` throttle — one answered ask per tab per second. Unlike the chip's replay
 *  this REFUSES (answers count 0): a replayed count would itself be the oracle, and a human never
 *  settles two new passwords inside a second. Cleared with the tab (tabs.onRemoved). */
const REUSE_ASK_MIN_GAP_MS = 1000;
const reuseAskLast = new Map<number, number>();
/** Security review 2026-10: tab → the live signup reuse warning (an exact-match count). SW memory
 *  only, like pendingCardSave: cleared on navigation, lock, tab close, and by the popup's read. */
const reuseNotices = new Map<number, { count: number }>();

/** [S4b] Repair on MISSING RECORD — the post-idle and post-lock states. `rescanCardForms` re-sends a frame's
 *  `cardFormInfo`, so once a frame's card-form entry is gone (MV3 idle-death; doLock's `tabs.clear()` erase) this
 *  nudge is what brings it back; without it the chip would stay dark on that document. Permission-free and carrying no
 *  payload: the frame answers with its own `cardFormInfo` report, i.e. the SAME browser-reported-identity path the
 *  record came from originally. Sent to THAT frame only (review #7: a broadcast would make every frame of the tab
 *  rescan, a CPU amplifier a hostile frame could drive). Fired ONLY on a missing record — never on a refusal, or a
 *  hostile frame could retry a "no" into a "yes". */
function repairCardRecord(tabId: number, frameId: number, now: number): void {
  const last = chipRepairLast.get(tabId);
  if (last !== undefined && now - last < CHIP_REPAIR_MIN_GAP_MS) return;
  chipRepairLast.set(tabId, now);
  const rescan: TabMsg = { type: "rescanCardForms" };
  // The `.catch` is load-bearing [T6]: sendMessage REJECTS when the tab has no receiver at all.
  void chrome.tabs.sendMessage(tabId, rescan, { frameId }).catch(() => {});
}

/** C1 §C2 — may THIS frame render the offer chip? Answers TWO BOOLEANS and nothing else: no item
 *  name, no count, no masked identity, no origin echo, no kinds (the request carries no members
 *  either — [A2]/[S7]). Every input is browser-reported; the page contributes nothing but the fact that
 *  it focused one of its own fields. ALL of the following are required, each fail-closed ([A3]):
 *
 *   1. `sender.frameId` is a number (any frame: a provider's card fields are usually in a sub-frame).
 *   2. The origin the browser reports for this frame (cardrelease.ts frameOriginOf) is a payment provider's card-entry
 *      origin (owner decision 2026-11-14): the only documents that ever receive a card are the only ones that show
 *      the chip. A shop's top frame and its same-origin frames never show it, whatever their page does.
 *   3. the tab is not mid-navigation with a known-stale record ([S2] `topOriginPendingClear`).
 *   4. this frame has a recorded card form, reported from that same origin.
 *
 *  [S3] There is deliberately NO vault condition on `fillable` (the deleted "session holds ≥1 card"
 *  test). `document.elementFromPoint()` retargets to our CLOSED shadow host, so a page can hit-test
 *  the anchor's neighbourhood for the chip's presence and width; with vault state feeding presence,
 *  and page script able to force trusted focus at frame rate, that is not a one-shot disclosure but
 *  a CONTINUOUS vault-state monitor. So chip presence is a function ONLY of facts the page already possesses,
 *  `locked` rides separately as the copy selector, and the surface keeps ONE fixed width in both
 *  states. Everything the chip can do is "open the popup" — the trusted surface it cannot draw. */
async function cardChipOffer(sender: chrome.runtime.MessageSender): Promise<Res<"cardChipOffer">> {
  const locked = APP_VAULT !== null ? !APP_VAULT.unlocked : session === null;
  const no: Res<"cardChipOffer"> = { fillable: false, locked }; // the one refusal shape — never a third state
  const tabId = sender.tab?.id;
  const frameId = sender.frameId;
  if (tabId === undefined || typeof frameId !== "number") return no;
  const origin = frameOriginOf(sender);
  if (!isCardProviderOrigin(origin)) return no; // a shop's own document: never a card, so never an offer of one
  const now = Date.now();
  // [S2] mid-nav: the records are the PREVIOUS document's. Checked BEFORE the [S-rate] replay: an [S2]-marked tab must
  // never be served from the cache, or the new document inherits the old one's verdict.
  if (topOriginPendingClear.has(tabId)) return no;
  let perFrame = chipOfferLast.get(tabId);
  if (perFrame === undefined) chipOfferLast.set(tabId, (perFrame = new Map()));
  const last = perFrame.get(frameId);
  // [S-rate] Review #3: a throttled call REPLAYS the frame's last computed answer instead of refusing (tabbing between
  // the fields of one card form moves faster than the window, and the content script treats a refusal as final).
  if (last !== undefined && now - last.t < CHIP_OFFER_MIN_GAP_MS) return last.answer;
  perFrame.set(frameId, { t: now, answer: no }); // pessimistic until a positive verdict lands
  const rec = tabs.get(tabId)?.cardForms?.[frameId];
  if (rec === undefined) {
    repairCardRecord(tabId, frameId, now); // [S4b] MISSING record (idle-death / post-lock erase) → repair, answer no
    return no;
  }
  if (rec.origin !== origin || !mayReceiveCard(rec)) return no; // a refusal, NOT a repair case
  const yes: Res<"cardChipOffer"> = { fillable: true, locked };
  perFrame.set(frameId, { t: now, answer: yes }); // replayable for the throttle window
  return yes;
}

/** C1 §C4 — the chip was clicked: ATTEMPT `chrome.action.openPopup()` and answer HONESTLY whether
 *  it opened. [A5]: this handler mints nothing, pre-selects nothing and enumerates nothing — the
 *  card grants are still minted only by a click in the popup itself, so it must never reference
 *  `cardGrants`, `session.items` or a `doc`. FORBIDDEN: `tabs.create`/`windows.create` of
 *  popup.html — the popup computes its offers against the ACTIVE tab and would see itself.
 *  [S9]: `openPopup()` targets the FOCUSED window's active tab, so a click delivered from a tab
 *  that is no longer the focused window's active one would open trusted chrome pointed at a
 *  DIFFERENT tab than the one the user clicked in — refuse instead ([A3] fail-closed on an
 *  undefined/absent match). Only from a frame the chip may show in (a provider's card document with a
 *  recorded form, as [cardChipOffer] requires).
 *  [K14]: Chrome 127+ needs no gesture for `openPopup()`; FIREFOX 121+ historically REQUIRES an input handler, so there
 *  this call is expected to REJECT and the content script's "open andvari from the toolbar" toast is the PRIMARY path,
 *  not a fallback. Resolution is the only signal either engine gives — claim nothing more from it. */
async function openPopupForCards(sender: chrome.runtime.MessageSender): Promise<Res<"openPopupForCards">> {
  const tabId = sender.tab?.id;
  if (tabId === undefined || sender.tab?.active !== true) return { opened: false }; // [S9] pages only, and only the active one
  const frameId = sender.frameId;
  const origin = frameOriginOf(sender);
  const rec = typeof frameId === "number" ? tabs.get(tabId)?.cardForms?.[frameId] : undefined;
  // Review #6: the handler with the SIDE EFFECT (opening trusted chrome) must not fail open on frame identity.
  if (rec === undefined || rec.origin !== origin || !mayReceiveCard(rec)) return { opened: false };
  // …and that active tab must be the FOCUSED window's — the exact tab openPopup would land on.
  const [current] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (current?.id === undefined || current.id !== tabId) return { opened: false };
  // Marked only for a request that passed every check above: a hidden tab or another frame cannot mark it.
  pageSummonedPopupAt = Date.now();
  const fn = (chrome.action as unknown as { openPopup?: () => Promise<unknown> }).openPopup;
  if (typeof fn !== "function") return { opened: false }; // absent → honest false
  try {
    await fn.call(chrome.action);
    return { opened: true }; // resolve ⇒ opened
  } catch {
    return { opened: false }; // reject ⇒ not opened (the toast names the toolbar)
  }
}

/** Unlock-prompt (design 2026-08-12): the save banner's Save click answered `locked`, so the
 *  banner asks us to SUMMON the unlock screen — ATTEMPT `chrome.action.openPopup()` and answer
 *  honestly whether it opened, the card chip's contract verbatim ([K14]: on Firefox the
 *  gesture-less call is EXPECTED to reject, and the banner's toolbar sentence is the primary path
 *  there; resolution is the only signal either engine gives). The side effect is bound to a
 *  GENUINE locked offer: nothing opens unless this tab holds a live pending save, resolvable by
 *  this frame (the resolvePendingSave admission rule — capturer or top frame), while the vault is
 *  LOCKED (an unlocked vault means the Save would simply have landed; opening the popup then would
 *  be chrome-out-of-nowhere). [S9]: same focused-window/active-tab rule as the chip — never open
 *  trusted chrome over a tab the user is no longer looking at. [A5]: mints nothing, pre-selects
 *  nothing, enumerates nothing; FORBIDDEN: opening popup.html as a tab or window (the popup
 *  computes its offers against the ACTIVE tab and would see itself — the [C4] pin's ban covers
 *  this function too, its span deliberately swallows us). */
async function openPopupForSave(sender: chrome.runtime.MessageSender): Promise<Res<"openPopupForSave">> {
  const tabId = sender.tab?.id;
  if (tabId === undefined || sender.tab?.active !== true) return { opened: false }; // pages only, and only the active one
  const pending = tabs.get(tabId)?.pending;
  if (!pending || session) return { opened: false }; // only a LOCKED live offer may summon the popup
  if (sender.frameId !== pending.frameId && sender.frameId !== 0) return { opened: false };
  const [current] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (current?.id === undefined || current.id !== tabId) return { opened: false };
  // Marked only for a request that passed every check above: a hidden tab or a sub-frame cannot mark it.
  pageSummonedPopupAt = Date.now();
  const fn = (chrome.action as unknown as { openPopup?: () => Promise<unknown> }).openPopup;
  if (typeof fn !== "function") return { opened: false }; // absent → honest false
  try {
    await fn.call(chrome.action);
    return { opened: true }; // resolve ⇒ opened (the popup renders the locked unlock screen)
  } catch {
    return { opened: false }; // reject ⇒ not opened (the banner line names the toolbar)
  }
}

/** Security review 2026-10 (root cause B): the in-page "Search all logins…" row hands off HERE
 *  instead of revealing anything in the page. Cross-site picks happen in the popup — extension-owned
 *  UI a page can neither draw over nor script — whose Fill mints the one-shot grant reveal() honours.
 *  The chip's contract ([S9] focused-window active tab, frame 0, [A5] mints/selects/enumerates
 *  nothing, honest `opened`); FORBIDDEN, as for the chip: opening popup.html as a tab or window.
 *  Frame 0 only, because the popup fills the top frame only — opening it from a sub-frame's pick
 *  would offer to fill a different form than the one the user clicked in. */
/** When a page-side message last asked for the popup to be opened. The Safari popup then raises no Face ID prompt by
 *  itself (the button does): a page must not be able to put the system's prompt in front of the person. */
let pageSummonedPopupAt = 0;
const PAGE_SUMMON_WINDOW_MS = 10_000;

async function openPopupForSearch(sender: chrome.runtime.MessageSender): Promise<Res<"openPopupForSearch">> {
  const tabId = sender.tab?.id;
  if (tabId === undefined || sender.tab?.active !== true || sender.frameId !== 0) return { opened: false };
  const [current] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (current?.id === undefined || current.id !== tabId) return { opened: false };
  // Marked only for a request that passed every check above: a hidden tab or a sub-frame cannot mark it.
  pageSummonedPopupAt = Date.now();
  const fn = (chrome.action as unknown as { openPopup?: () => Promise<unknown> }).openPopup;
  if (typeof fn !== "function") return { opened: false }; // absent → honest false
  try {
    await fn.call(chrome.action);
    return { opened: true };
  } catch {
    return { opened: false }; // reject ⇒ not opened (the toast names the toolbar)
  }
}

/** Popup ONLY: may the Cards rows offer Fill for the active tab, into which frames? Fillable iff a payment provider's
 *  card document with a card form is in the tab (cardrelease.ts providerCardFrames: the origin the browser reports for
 *  each frame, never the page's word) and no card kind is offered by two provider card frames ([doubled] otherwise).
 *  [frames]: the provider frames where the person chose a card field, with their origins: what a Fill will reach, and
 *  what the popup sends back so the fill goes to exactly those (round-11 review). Otherwise the popup copies instead,
 *  and says why: a provider's frame the page shows, from a site this extension may not run on ([allowOrigin], from the
 *  page's own srcs: a hint only); the page takes the card in its own fields ([pageFormOnly]); or, in Safari, this
 *  extension is not running on the page at all ([allowEverywhere]). Refuses tab senders. [T5]: answers off the
 *  registry once gone frames are dropped; the broadcast makes frames report afresh, and the POPUP owns freshness with
 *  one delayed re-query (~350 ms). */
async function cardFillOffers(sender: chrome.runtime.MessageSender): Promise<Res<"cardFillOffers">> {
  const none: Res<"cardFillOffers"> = { fillable: false, origin: null, frames: [], pageFormOnly: false };
  if (sender.tab !== undefined) return none; // popup-only guard
  if (!(APP_VAULT !== null ? APP_VAULT.unlocked : session !== null)) return none;
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.id === undefined) return none;
  const tabId = tab.id;
  await pruneGoneCardFrames(tabId);
  broadcastRescanCardForms(tabId);
  const records = tabs.get(tabId)?.cardForms ?? {};
  const provider = providerCardFrames(records);
  // Round-12 review: a provider frame the page shows that has not reported refuses every fill (its card kinds cannot
  // be counted); the hint can only refuse, never release. Where the browser names no sub-frame's origin, that is why.
  const originless = cardReports.get(tabId)?.originless === true;
  const allow = providerFrameNotAllowed(tabId);
  if (allow !== null) return originless ? { ...none, noFrameOrigin: true } : { ...none, allowOrigin: allow };
  if (provider.length > 0) {
    if (kindsOfferedTwice(records).length > 0) return { ...none, doubled: true };
    // Round-13 review: card fields tapped in two payment forms fill neither; the popup offers Start over.
    if (choicesSpanForms(records, Date.now())) return { ...none, mixed: true };
    const frames = chosenCardFrames(records, Date.now()).map(({ frameId, origin, kinds, ancestors }) => ({ frameId, origin, kinds, ancestors: ancestors ?? null }));
    return { fillable: true, origin: frames[0]?.origin ?? provider[0]!.origin, frames, pageFormOnly: false };
  }
  if (originless) return { ...none, noFrameOrigin: true };
  if (pageCardFormsOnly(records)) return { ...none, pageFormOnly: true };
  // Safari asks per site, and the popup cannot grant itself one (the app explains it). When nothing of this page has
  // reported, not even after the rescan above has had a moment, andvari is not running there: the line names no site,
  // since none is known, and says to allow andvari on Every Website. A page that is not a web page is left alone.
  if (BUILD_TARGET === "safari" && cardReports.get(tabId)?.top !== true && (tab.url === undefined || /^https?:/.test(tab.url))) {
    await delay(250);
    if (cardReports.get(tabId)?.top !== true) return { ...none, allowEverywhere: true };
  }
  return none;
}

/** Shape-check the granted frame's sendResponse before trusting it (mirrors asFillOutcome).
 *  [T11]: `"partial"` is a FIRST-CLASS verdict here — rejecting it would turn every partial into
 *  `ok:false "unreachable"` AFTER the fields already landed in the page. */
function asCardFillOutcome(v: unknown): CardFillOutcome | null {
  if (typeof v !== "object" || v === null) return null;
  const f = (v as { filled?: unknown }).filled;
  if (!(f === "card" || f === "partial" || f === "nothing")) return null;
  // The kind lists are part of the shape: the popup ITERATES both on "partial" — a verdict
  // without its arrays would dead-end the partial copy after fields already landed.
  const { filledKinds, missedKinds } = v as { filledKinds?: unknown; missedKinds?: unknown };
  return Array.isArray(filledKinds) && Array.isArray(missedKinds) ? (v as CardFillOutcome) : null;
}

/**
 * Popup ONLY: fill the card into the payment provider's card frames where the person chose a field (owner decision
 * 2026-11-14, round-11 review). The fill reaches every provider frame holding a live choice of the person's, each with
 * the form holding its chosen field (cardrelease.ts cardFillPlan): one tap for a provider's single card frame, one in
 * each frame of a split one, then one Fill. Nothing is filled while two provider card frames offer the same kind, and
 * nothing unless the frames are exactly the ones the popup showed ([shown]: their frameIds and origins). One one-shot
 * grant per frame, bound to its frameId and origin; each frame redeems its own through `revealCardForFill` (the value
 * round trip): the worker never pushes card values at a tab. The page's own word (the provider srcs its top frame
 * reports) only picks the words of a refusal. Refuses tab senders.
 */
async function fillCardFromPopup(itemId: string, shown: unknown, sender: chrome.runtime.MessageSender): Promise<Res<"fillCardFromPopup">> {
  if (sender.tab !== undefined) return { ok: false, code: "not_allowed", error: "not allowed from a page" };
  // Safari: the app's open list stands in for the session's items; the card's fields are fetched at each redemption.
  if (!(APP_VAULT !== null ? APP_VAULT.unlocked : session !== null)) return { ok: false, code: "locked", error: "locked" };
  const known = APP_VAULT !== null ? APP_VAULT.card(itemId) !== null : session!.items.some((i) => i.itemId === itemId && i.doc.type === "card");
  if (!known) {
    return { ok: false, code: "not_allowed", error: "unknown item" };
  }
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.id === undefined) return { ok: false, code: "unreachable", error: "no active tab" };
  const tabId = tab.id;
  const records = (): Readonly<Record<string, CardFrameRecord>> => tabs.get(tabId)?.cardForms ?? {};
  await pruneGoneCardFrames(tabId);
  // [T5] a registry miss pays one rescan + a 250 ms re-read.
  let plan = cardFillPlan(records(), Date.now(), providerFrameNotAllowed(tabId));
  if (!plan.ok && plan.reason === "no_choice") {
    broadcastRescanCardForms(tabId);
    await delay(250);
    plan = cardFillPlan(records(), Date.now(), providerFrameNotAllowed(tabId));
  }
  if (!plan.ok) {
    if (plan.reason === "unreported") {
      if (cardReports.get(tabId)?.originless === true) return { ok: false, code: "no_frame_origin", error: "this browser does not say which site a frame comes from" };
      return { ok: false, code: "provider_not_allowed", allowOrigin: plan.origin, error: "a payment provider's frame on the page has not reported" };
    }
    if (plan.reason === "duplicate_kind") return { ok: false, code: "duplicate_fields", error: `more than one provider card frame asks for ${plan.kinds.join(", ")}` };
    if (plan.reason === "mixed_forms") return { ok: false, code: "mixed_forms", error: "card fields tapped in two different payment forms" };
    if (eligibleCardFrames(tabId).length > 0) return { ok: false, code: "no_focus", error: "no card field chosen in a payment provider's card box" };
    if (cardReports.get(tabId)?.originless === true) return { ok: false, code: "no_frame_origin", error: "this browser does not say which site a frame comes from" };
    if (pageCardFormsOnly(records())) return { ok: false, code: "page_form", error: "andvari fills a card only into a payment provider's card box" };
    return { ok: false, code: "no_form", error: "the payment provider's card box is gone" };
  }
  // Round-11 review: exactly the frames, at the origins, the popup showed; anything else is a page that changed since.
  if (!sameFrames(shown, plan.targets)) return { ok: false, code: "changed", error: "the payment form changed since andvari showed it" };
  const targets = plan.targets;
  const expiresMs = Date.now() + GRANT_TTL_MS;
  cardGrants.set(tabId, new Map(targets.map((t): [number, CardGrant] => [t.frameId, { itemId, frameId: t.frameId, origin: t.origin, kinds: t.kinds, sig: t.kinds.join(","), expiresMs }])));
  const filled: CardFieldKind[] = [];
  const missed: CardFieldKind[] = [];
  const unseen: CardFieldKind[] = [];
  let refusal: CardFillOutcome | null | undefined;
  try {
    for (const t of targets) {
      const msg: TabMsg = { type: "fillCard", itemId, sig: t.kinds.join(",") };
      let raw: unknown = null;
      try {
        raw = await chrome.tabs.sendMessage(tabId, msg, { frameId: t.frameId });
      } catch {
        raw = null;
      }
      const outcome = asCardFillOutcome(raw);
      if (outcome === null || outcome.filled === "nothing") {
        // This frame filled nothing; the others still fill their own fields. The first refusal is the one told.
        if (refusal === undefined) refusal = outcome;
        missed.push(...t.kinds);
        continue;
      }
      filled.push(...outcome.filledKinds);
      missed.push(...outcome.missedKinds);
      unseen.push(...(outcome.unseenKinds ?? []));
    }
  } finally {
    // The round trip is over: void every grant not redeemed rather than leaving it armed for the TTL.
    cardGrants.delete(tabId);
  }
  if (filled.length === 0) {
    if (refusal === null || refusal === undefined) return { ok: false, code: "unreachable", error: "frame not reachable — reload the tab and retry" };
    return { ok: false, outcome: refusal, code: refusal.code ?? "no_fields", error: `card fill wrote nothing (${refusal.code ?? "no_fields"})` };
  }
  // Truthful verdict (F9) across the frames: a kind counts filled when ANY frame landed it.
  const filledKinds = [...new Set(filled)];
  const missedKinds = [...new Set(missed)].filter((k) => !filledKinds.includes(k));
  const unseenKinds = [...new Set(unseen)].filter((k) => missedKinds.includes(k));
  const outcome: CardFillOutcome = { filled: missedKinds.length === 0 ? "card" : "partial", filledKinds, missedKinds, ...(unseenKinds.length > 0 ? { unseenKinds } : {}) };
  return { ok: true, outcome };
}

/** Content (S3 redemption): return a frame's declared card fields to that frame ONCE. Every check fails CLOSED on
 *  undefined ([A3]); success consumes the frame's grant, any failure consumes nothing. Each frame redeems its own grant
 *  only: the frame it was minted for, at the payment provider's origin it was minted for, as the browser reports it now
 *  (cardrelease.ts mayRedeem). This is a store SEPARATE from login `grants` — it can ONLY match a card grant, never a
 *  login one ([A5]). PAN/CVV are composed here and never touch `snapshots`/the save path ([A6]). */
async function revealCardForFill(
  msg: Extract<Req, { type: "revealCardForFill" }>,
  sender: chrome.runtime.MessageSender,
): Promise<Res<"revealCardForFill">> {
  if (!(APP_VAULT !== null ? APP_VAULT.unlocked : session !== null)) return { ok: false, error: "locked" };
  const tabId = sender.tab?.id;
  const frameId = sender.frameId;
  if (tabId === undefined || typeof frameId !== "number") return { ok: false, error: "not a page sender" };
  const grant = cardGrants.get(tabId)?.get(frameId);
  if (!mayRedeem(grant, msg.itemId, sender, Date.now())) return { ok: false, error: "no card grant" };
  // [U14] [A3] extension: the kinds/sig bindings are load-bearing egress gates — undefined or
  // malformed at ANY check refuses (a grant shape from a mid-update SW must never fall through
  // to a live-registry read).
  if (!Array.isArray(grant.kinds) || typeof grant.sig !== "string") return { ok: false, error: "no grant kinds" };
  // Safari: only the fields this frame's form declared are asked of the app.
  const c: StoredCard | null | undefined =
    APP_VAULT !== null ? await appVaultCard(msg.itemId, cardFieldsForKinds(grant.kinds)) : session!.items.find((i) => i.itemId === msg.itemId && i.doc.type === "card")?.doc.card;
  if (!c) return { ok: false, error: "unknown item" }; // consumes nothing
  // The grant is looked at again: the app may have taken a moment (a second Face ID), and a navigation or a new
  // fill in between voids this one.
  if (cardGrants.get(tabId)?.get(frameId) !== grant || grant.expiresMs <= Date.now()) return { ok: false, error: "no card grant" };
  // Compose ONLY the kinds THIS frame's form declared ("CVV only if a CVV field was detected").
  // [U15] declared = the GRANT's frozen kinds — never the live registry (Tier 1's live read let
  // a mint→redeem rescan widen egress) and never a frame union (a union could satisfy the [T9]
  // cardnumber+cardtype gate across TWO forms and compose brand for a PAN-less form). Pinned.
  const declared = new Set(grant.kinds);
  const fields: CardFillFields = {};
  if (declared.has("cardnumber")) {
    const n = digitsOnly(c.number ?? "");
    if (n !== "") fields.number = n;
  }
  if (declared.has("cardexpiry") || declared.has("cardexpmonth") || declared.has("cardexpyear")) {
    // v2 (§6): the halves ride INDEPENDENTLY — a parseable month with a junk year still fills
    // month-only targets (and vice versa); only the combined back-compat `expiry` needs both.
    const m = padMonth(c.expMonth ?? "");
    if (m !== null) fields.expMonth = m;
    const y4 = yearTo4(c.expYear ?? "");
    if (y4 !== null) {
      fields.expYear4 = y4;
      fields.expYear2 = y4.slice(2); // ≡ card.ts yearTo2 (same 2/4-ASCII-digit domain); yearTo2 itself is module-private
    }
    const e = composeShortExpiry(c.expMonth ?? "", c.expYear ?? "");
    if (e !== null) fields.expiry = e;
  }
  if (declared.has("cardname")) {
    const nm = c.cardholderName ?? "";
    if (nm !== "") fields.name = nm;
  }
  if (declared.has("cardcvv")) {
    const sc = c.securityCode ?? "";
    if (sc !== "") fields.cvv = sc;
  }
  // G3 [X3-A4d]: postal composed ONLY when THIS frame's form declared cardpostal (the grant's frozen
  // kinds, [U15] — never the live registry). buildCardForm's ambiguity guard already dropped
  // cardpostal from the form's kinds when >1 survived, so a declared cardpostal here is unambiguous.
  if (declared.has("cardpostal")) {
    const pc = c.postalCode ?? "";
    if (pc !== "") fields.postalCode = pc;
  }
  // [T9] brand egress double-gate: composed ONLY when the form declared cardnumber TOO — the
  // zero-new-information argument (this very response already carries the PAN the brand derives
  // from) must never come to depend on a future registry shape. Derived, never the stored field
  // (which is display-only and could be stale); unknown IIN → no brand → the kind files missed.
  if (declared.has("cardnumber") && declared.has("cardtype")) {
    const b = brand(c.number ?? "");
    if (b !== null) fields.brand = b;
  }
  cardGrants.get(tabId)?.delete(frameId); // one-shot: success consumes this frame's grant
  return { ok: true, fields };
}

// ---- capture → pending save → resolve ----

/** Host of a URL (a browser-set origin), normalized like a match target. */
function hostOfUrl(url: string): string | null {
  try {
    return normalizeHost(new URL(url).host);
  } catch {
    return normalizeHost(url);
  }
}

/** The password (and the owning frameId) NEVER ride a pending-save answer — metadata only. */
function publicPending(p: PendingSave & { password: string }): PendingSave {
  return {
    host: p.host, username: p.username, updatesItemId: p.updatesItemId, updatesItemName: p.updatesItemName, updatesItemUsername: p.updatesItemUsername,
    vaultName: p.vaultName ?? null, vaultShared: p.vaultShared ?? (p.updatesItemId !== null),
  };
}

/** A11 (q14): vaultId → meta ciphertext from a full sync's vault rows (only string blobs kept). */
function vaultMetaOf(vaults: readonly { vaultId: string; metaBlob?: string }[] | undefined): Map<string, string> {
  const m = new Map<string, string>();
  for (const v of vaults ?? []) if (typeof v.metaBlob === "string" && v.metaBlob) m.set(v.vaultId, v.metaBlob);
  return m;
}

/** A11 (q14): the destination vault as the banner names it — its name decrypted under a key this session HOLDS (null
 *  otherwise; never a server label), and whether it is anything but the in-force personal vault. */
function destinationOf(vaultId: string): { vaultName: string | null; vaultShared: boolean } {
  if (!session || !vaultId) return { vaultName: null, vaultShared: true };
  return {
    vaultName: vaultNameFromMeta(session.vaultKeys.get(vaultId), vaultId, session.vaultMeta?.get(vaultId)),
    vaultShared: vaultId !== session.personalVaultId,
  };
}

/** [X2-A7] the MASKED public shape — the raw PAN (and expiry/frameId) never leave the SW. The
 *  banner shows `cardSubtitle` ("Visa ••4242"), SW-recomputed from the number, never a stored field. */
function publicPendingCard(p: { host: string; number: string; updatesItemId?: string; updatesItemName?: string }): PendingCardSave {
  return { host: p.host, cardSubtitle: cardSubtitle(p.number), updatesItemId: p.updatesItemId, updatesItemName: p.updatesItemName };
}

/** Content senders carry their tab; the popup asks about the active tab. */
async function contextTabId(sender: chrome.runtime.MessageSender): Promise<number | undefined> {
  if (sender.tab?.id !== undefined) return sender.tab.id;
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab?.id;
}

async function capturedCredential(
  msg: Extract<Req, { type: "capturedCredential" }>,
  sender: chrome.runtime.MessageSender,
): Promise<Res<"capturedCredential">> {
  const tabId = sender.tab?.id;
  if (tabId === undefined) return { ok: false }; // captures come from pages only
  const frameId = sender.frameId ?? 0;
  // Security review 2026-10 (root cause E): the capture is bound to the BROWSER-SET origin. The page
  // URL the content script used to send let an opaque-origin (sandboxed) frame whose URL sits on a
  // site be credited as that site, and mint a pending update of the user's login there.
  const bound = captureBinding(sender.origin);
  if (!bound) return { ok: false };
  // Safari on iOS 26.2 and later: the system offers the save itself, through the andvari app's AutoFill extension.
  // Nothing is captured here, so no prompt of ours can appear beside it. Asked once per worker life, before the first
  // capture is kept.
  if (savesThroughApp(BUILD_TARGET)) {
    if (systemSavesPasswords === null) await syncAppServer();
    if (systemSavesPasswords === true) return { ok: true };
  }
  const host = bound.host;
  const st = tabs.get(tabId) ?? {};

  // A live pending belongs to the frame that captured it. Reject an overwrite from a DIFFERENT
  // frame (a hostile sub-frame firing a synthetic submit to hijack the top frame's Save banner);
  // the owning frame may still update its own capture (user corrects the password).
  // bug-ext-gating--1: …EXCEPT that the top frame OUTRANKS a sub-frame. First-writer-wins with no
  // priority made the slot squattable: a sub-frame (ad/widget — content.js runs allFrames) that
  // captures first owns the tab's ONE pending slot, and every later top-frame login is refused
  // here, so offerPendingSave never fires and the user's real password is silently never offered
  // for saving. The refusal stands for every other pairing (sub-over-top, sub-over-sub).
  if (msg.password && st.pending && st.pending.frameId !== frameId && frameId !== 0) return { ok: true };

  if (!msg.password) {
    // Username-only page (multi-step step 1) — remember it for the password page. Sticky for
    // the tab's life so a wrong-password retry still has it; newer captures overwrite.
    // bug-ext-gating--1: TOP FRAME ONLY. This branch had no frame check at all, and the value is
    // sticky for the tab's life and feeds both the stored username and saveTargetFor below — so a
    // sub-frame could poison it and steer the user's next real save away from the right item,
    // turning an intended update into a duplicate. A multi-step step 1 is a top-frame page.
    if (msg.username && frameId === 0) {
      // H13: stamped WITH the site key so a later capture on another site in this tab cannot
      // inherit it (stepUsernameFor is the one reader; a host that fails the PSL still keys on
      // itself, never on "").
      st.lastUsername = { username: msg.username, site: siteKeyOfHost(host, pslResolve) ?? host };
      tabs.set(tabId, st);
      persistTabs();
    }
    return { ok: true };
  }

  const username = msg.username || stepUsernameFor(st.lastUsername, siteKeyOfHost(host, pslResolve) ?? host);
  // Save-vs-update target (capture-time). A username picks the exact (host ∧ username) match; a
  // password-only submit (username "") falls back to a password-equal item (2a — a re-login) or a
  // lone host login (2b — a password change), else a new item (2c). Locked ⇒ matchesFor() is empty
  // ⇒ records save-new; resolve re-checks post-unlock with a STRICTER rule (no silent 2b clobber).
  // A11 (q14): a personal-vault match outranks a co-member's matching item in another vault.
  // F4: matched as the page it was captured on (bound.uri keeps the http origin of a plain-http page), so a password
  // typed on http://bank.example is never offered as an update of the login saved for https://bank.example.
  const existing = saveTargetFor(matchesFor(bound.uri), username, msg.password, session?.personalVaultId);
  if (existing && (existing.doc.login?.password ?? "") === msg.password) {
    // Unchanged password (a re-login of a known item — 2a) — every successful re-login would banner otherwise.
    if (st.pending) {
      st.pending = undefined;
      tabs.set(tabId, st);
      persistTabs();
    }
    return { ok: true };
  }

  // G21: a reader-vault match still drives the 2a suppress above (a re-login of a shared login is
  // nothing to save), but it can never be the UPDATE target — the server denies a reader's push —
  // so the banner offers Save-new (a fresh personal item) instead of a doomed Update.
  // Design 2026-11-15 §12.2 rule 4: the extension writes only to the personal vault (writableItem). A changed password
  // for a matching login that lives in a shared vault is not updated here: the banner becomes the notice "This login is
  // in *vault*. Update it in the andvari app." (saveoffer.ts), and the resolve step refuses the write (commitPendingSave).
  const shared = existing !== undefined && !writableItem(existing) && session !== null && existing.vaultId !== session.personalVaultId ? existing : undefined;
  const updatable = existing !== undefined && writableItem(existing) ? existing : shared;
  // A11 (q14): the banner names the DESTINATION vault (the update target's, else the personal vault; locked = none
  // known yet), and the vault the user saw named is kept SW-side so the resolve step can hold it to that.
  const dest = destinationOf(updatable?.vaultId ?? session?.personalVaultId ?? "");
  const pending: PendingSave & { password: string; frameId: number; uri: string; updatesVaultId?: string | null; lockedAt?: number; quiet?: boolean; offeredAt?: number } = {
    host,
    username,
    updatesItemId: updatable?.itemId ?? null,
    updatesItemName: updatable?.doc.name ?? null,
    updatesItemUsername: updatable?.doc.login?.username ?? null,
    updatesVaultId: updatable?.vaultId ?? null,
    vaultName: dest.vaultName,
    vaultShared: updatable ? dest.vaultShared : false,
    password: msg.password,
    frameId,
    // H124: the uri a NEW item will store — `http://…` when the origin is plain http (loopback /
    // intranet), else the classic `https://<host>`. From the browser-set origin (captureBinding);
    // SW-side only (publicPending never carries it — the banner shows `host`).
    uri: bound.uri,
  };
  // A first try of this tab's save whose answer was lost keeps its ids only while what was caught is the same (the form
  // submitted again): its second try then sends the same item under the same ids. Anything caught differently (another
  // password typed) is a new item under new ids, never the first request's ids with other content (the server would
  // answer from its record of the first and store nothing new).
  const earlier = st.pending;
  if (earlier?.lost !== undefined && earlier.host === pending.host && earlier.username === pending.username && earlier.password === pending.password && (earlier.uri ?? `https://${earlier.host}`) === pending.uri && pending.updatesItemId === null) {
    (pending as typeof pending & { lost?: LostPut }).lost = earlier.lost;
  }
  // Locked-capture posture (owner decisions 2026-08-18). A pending minted while locked holds a
  // plaintext page password in storage.session, so it carries a TTL stamp (LOCKED_PENDING_TTL_MS,
  // enforced by every re-offer gate + the unlock re-offer). If the known-logins digest recognizes
  // the (site, username) pair — a re-login to something we already hold — the pending is recorded
  // QUIET: no banner now, no re-offers; the unlock-time dedupe drops it (unchanged) or offers
  // Update (changed). An unknown pair keeps today's "unlock to save" banner — that nag is how a
  // genuinely new login survives — with offeredAt stamped so the re-offer throttle counts this
  // first showing.
  if (!session) {
    pending.lockedAt = Date.now();
    if (await isKnownLoginWhileLocked(host, username)) {
      pending.quiet = true;
      st.pending = pending;
      tabs.set(tabId, st);
      persistTabs();
      return { ok: true };
    }
    pending.offeredAt = Date.now();
  }
  st.pending = pending;
  tabs.set(tabId, st);
  persistTabs();
  return { ok: true, pending: publicPending(pending) };
}

/** Safari: hand the tab's pending capture to the andvari app. The pending is dropped only once the app's queue took it. */
async function saveThroughApp(tabId: number, st: TabState, pending: NonNullable<TabState["pending"]>): Promise<Res<"resolvePendingSave">> {
  const send = nativeSender(globalThis as Parameters<typeof nativeSender>[0], SAFARI_NATIVE_APP) as unknown as Parameters<typeof queueSaveToApp>[0];
  // Every attempt is an entry under a new id (queueSaveToApp mints it), and the handler never replaces an entry: a
  // later capture never overwrites one the person was already told is on its way. A retry after a lost answer may
  // queue this login twice; the app keeps the newest capture of a login and drops the older.
  const capture = { site: pending.uri ?? `https://${pending.host}`, username: pending.username, password: pending.password };
  const r = await queueSaveToApp(send, capture, Date.now());
  if (r === "queued") {
    st.pending = undefined;
    tabs.set(tabId, st);
    persistTabs();
    return { ok: true, viaApp: true };
  }
  // The app's own refusal is a code of its own: never the server's `rejected`, whose line speaks of the server.
  return { ok: false, code: r === "no_account" ? "app_no_account" : r === "refused" ? "app_refused" : "app_unavailable" };
}

async function resolvePendingSave(
  action: "save" | "dismiss",
  sender: chrome.runtime.MessageSender,
): Promise<Res<"resolvePendingSave">> {
  const tabId = await contextTabId(sender);
  const st = tabId === undefined ? undefined : tabs.get(tabId);
  const pending = st?.pending;
  if (tabId === undefined || !st || !pending) return { ok: false, error: "nothing pending" };
  // A pending is resolvable ONLY by the frame that captured it, the TOP frame, or the popup (no
  // tab). The capture side already defends the frame (the cross-frame overwrite reject above);
  // without this, ANY frame in the tab could commit or silently dismiss the top frame's offer.
  // Frame 0 is admitted because capture and OFFER live in different frames BY DESIGN: content runs
  // with allFrames, so a sub-frame login records frameId N, but the re-offer surface is top-frame
  // only (offerPendingSave is sent { frameId: 0 } and the post-nav poll renders only when isTop).
  // Capturer-only would answer "nothing pending" forever on every sub-frame login — and worse,
  // capturedCredential refuses a cross-frame overwrite of a live pending while the dismiss branch
  // sits BELOW this guard, so the unresolvable pending would squat the tab's single slot for the
  // tab's life (surviving SW death via storage.session), silently dropping every later capture.
  // No new exposure: the "pendingSave" read case above already lets frame 0 read any frame's
  // pending (publicPending strips the password). The card twin stays capturer-only — a top-level
  // nav deletes pendingCardSave and its banner is only ever rendered by the capturing frame.
  if (sender.tab !== undefined && sender.frameId !== pending.frameId && sender.frameId !== 0) return { ok: false, error: "nothing pending" };

  if (action === "dismiss") {
    st.pending = undefined;
    tabs.set(tabId, st);
    persistTabs();
    return { ok: true };
  }

  // Safari on iOS: this extension has no session to save with. The capture is sealed to the app's account and queued
  // for the app, which saves it at its next unlock under its own rules (a new login, or a newer password for the
  // personal-vault login it matches) and lists what it saved, with undo (appsave.ts; core SaveImporter).
  if (savesThroughApp(BUILD_TARGET)) return saveThroughApp(tabId, st, pending);

  // Pending survives a locked failure so unlock → save can still land it. The surface maps the
  // CODE to copy — the SW's raw "locked" string must never reach the banner (extux-03).
  // Unlock-prompt (2026-08-12): the click itself is REMEMBERED as approval — the banner goes on
  // to summon the unlock screen (openPopupForSave), and the next unlock auto-commits this pending
  // (reofferPendingSaves) instead of re-asking for a second Save click.
  if (!session) {
    pending.approvedAt = Date.now();
    tabs.set(tabId, st);
    persistTabs();
    return { ok: false, code: "locked", error: "locked" };
  }
  // A9 review MEDIUM-1: unlocked but no confirmed personal vault — nothing is sealed under a guessed vault; the click
  // is not kept as approval either (the confirmation, not an unlock, is what is missing).
  if (!session.personalVaultId) return { ok: false, code: "no_personal_vault", error: "no personal vault" };

  // A Save click landing while the approved auto-commit's put is still in flight (post-unlock
  // race) must not start a SECOND put of the same credential — answer retryable; the commit's own
  // toast (or its banner re-offer on failure) tells the user what actually happened.
  if (approvedCommitsInFlight.has(tabId)) return { ok: false, code: "failed", error: "auto-commit in flight" };

  return (await commitPendingSave(tabId, st, pending)).res;
}

/** The unlocked commit half of resolvePendingSave, shared verbatim with the approved-save
 *  auto-commit (unlock-prompt, 2026-08-12) — extracted, not twinned, so the 2b data-loss guard
 *  below can never drift between the two callers. `wrote` distinguishes an actual vault write
 *  from the 2a suppress (both answer ok:true on the seam): the auto-commit path toasts ONLY on
 *  a real write. Re-checks the session itself — the auto-commit runs post-await, where a racing
 *  re-lock would otherwise NPE on session.items. */
async function commitPendingSave(
  tabId: number,
  st: TabState,
  pending: PendingSave & { password: string; frameId: number; uri?: string; updatesVaultId?: string | null; approvedAt?: number; lost?: LostPut },
): Promise<{ res: Res<"resolvePendingSave">; wrote: boolean }> {
  if (!session) return { res: { ok: false, code: "locked", error: "locked" }, wrote: false };
  if (!session.personalVaultId) return { res: { ok: false, code: "no_personal_vault", error: "no personal vault" }, wrote: false }; // A9 review MEDIUM-1
  const owner = session;
  // Re-decide save-vs-update NOW (the capture-time decision is stale if the vault was LOCKED then —
  // matchesFor was empty ⇒ updatesItemId null). resolveSaveAction only auto-updates on UNAMBIGUOUS
  // same-account signals: it NEVER runs the ambiguous "lone host login" (2b) fallback here (a
  // locked-at-capture password-only submit for a DIFFERENT account would otherwise clobber the
  // host's single login — data loss), and it suppresses ONLY a password-only re-login (never drops
  // a username-present new account that reuses a password).
  // A11 (q14): the frozen target counts only while it is still in the vault the banner NAMED (a pending recorded by
  // an older worker named none: only the personal vault then). Anything else is re-decided, personal vault first, and
  // a match in another vault that the banner never named lands as a NEW personal item, never a silent update.
  const frozen = pending.updatesItemId ? session.items.find((i) => i.itemId === pending.updatesItemId) : undefined;
  const namedVault = pending.updatesVaultId ?? session.personalVaultId;
  const frozenTarget = frozen && frozen.vaultId === namedVault ? frozen : undefined;
  let decision = resolveSaveAction(
    frozenTarget,
    matchesFor(pendingPage(pending)),
    pending.username,
    pending.password,
    session.personalVaultId,
  );
  // §12.2 rule 4: the extension writes only to the personal vault. A frozen target in a shared vault (the banner was the
  // "Update it in the andvari app" notice) is never written; a host∧username match outside the personal vault that
  // the banner never named lands as a NEW personal item (resolveSaveAction). The suppress rule is untouched.
  if (decision.kind === "update" && !writableItem(decision.target)) {
    if (frozenTarget !== undefined) return { res: { ok: false, code: "shared_vault", error: "the login is in a shared vault" }, wrote: false };
    decision = { kind: "create" };
  }
  if (decision.kind === "suppress") {
    // 2a re-login of a known item (reachable via the locked-at-capture path, where the :967
    // unchanged-password suppress couldn't run) — nothing to save; don't mint a duplicate.
    st.pending = undefined;
    tabs.set(tabId, st);
    persistTabs();
    return { res: { ok: true }, wrote: false };
  }
  let result: Res<"resolvePendingSave">;
  if (decision.kind === "update") {
    // Update = the same doc with ONLY the password swapped — uris tail, totp, notes, favorite,
    // attachments all ride the spread — put against the rev we decrypted (server 409s a racer).
    const doc: ItemDoc = { ...decision.target.doc, login: { ...decision.target.doc.login, password: pending.password } };
    result = await putExisting(decision.target, doc);
  } else {
    // New login — the frozen/username target vanished, or a locked-2b / 2c ambiguity (recoverable New).
    // H124: a pending persisted by a pre-H124 SW has no `uri` — fall back to the old spelling.
    // A first try whose answer was lost: the same item, under the same ids (BZ).
    const made = await putNewLogin(pending.host, pending.username, pending.password, pending.uri ?? `https://${pending.host}`, pending.lost);
    if (made.lost !== undefined && session === owner) {
      pending.lost = made.lost;
      tabs.set(tabId, st);
      persistTabs();
    }
    const { lost: _ids, ...said } = made;
    result = said;
  }
  // A lock while the write was on the wire already dropped every pending ([S3-lock] allow-list); [st] is
  // the record from before it, so it is not put back (it would bring the dropped fields back with it).
  // The write landed in [owner]'s account. When another account is open by the
  // time it answers, the page must not just say "saved" over a vault that does not hold it: it says where it went.
  if (session !== owner) return { res: result.ok && session !== null && session.userId !== owner.userId ? { ...result, otherAccount: true } : result, wrote: result.ok };
  if (result.ok) {
    st.pending = undefined;
    tabs.set(tabId, st);
    persistTabs();
  }
  return { res: result, wrote: result.ok };
}

// ---- G2 save-card capture → pending card save → resolve (design 2026-07-23 §G2) ----
// The full PAN enters the SW ONLY here (the reverse of reveal), held in the module-scope
// `pendingCardSave` Map (NEVER a persisted TabState — [X2-A1]). Every gate fails closed; the offer
// the content banner receives is the MASKED PendingCardSave (no number — [X2-A7]).

async function captureCard(
  msg: Extract<Req, { type: "captureCard" }>,
  sender: chrome.runtime.MessageSender,
): Promise<Res<"captureCard">> {
  const tabId = sender.tab?.id;
  if (tabId === undefined) return { ok: false }; // captures come from pages only
  const frameId = sender.frameId ?? 0;
  const number = digitsOnly(msg.fields.number ?? "");
  if (!luhnValid(number)) return { ok: false }; // SW-side Luhn re-check (content already gated)
  // [X2-A5] SYNCHRONOUS dedupe BEFORE the first await — a click+submit double-fire of the SAME PAN
  // records one key and the second is dropped (the one-shot trusted gesture is the primary spam
  // guard; this closes the double-pass race the same-origin await below would otherwise open).
  const key = `${frameId}:${number}`;
  const now = Date.now();
  const prev = cardCaptureDedupe.get(tabId);
  if (prev && prev.key === key && now - prev.t < CARD_CAPTURE_DEDUPE_MS) return { ok: true };
  cardCaptureDedupe.set(tabId, { key, t: now });
  // [X2-A2] SW same-origin gate: content runs in ALL frames and cannot know the top origin, so a
  // Stripe/Braintree per-field NUMBER iframe (js.stripe.com) could emit captureCard{number} — a
  // bogus partial-PAN save. Discard unless the sender's browser-set origin equals the tab's CURRENT
  // top-level origin (a cross-origin/PSP frame never drives a save).
  if (typeof sender.origin !== "string" || sender.origin === "" || sender.origin === "null") return { ok: false };
  const top = await topOrigin(tabId);
  if (top === null || sender.origin !== top) return { ok: false };
  // A locked SW holds no vault to match against or seal into — never stash a PAN while locked
  // (doLock clears the Map anyway; this keeps a locked capture from ever recording one).
  if (!session) return { ok: false };
  let host: string;
  try {
    host = new URL(top).hostname;
  } catch {
    return { ok: false };
  }
  // Match an existing card by DIGITS equality only (never expiry/name): an UPDATE refreshes
  // expiry/name/postal on the same card ([X2-A5b]); a mismatch (or no match) is a NEW card.
  // Design §12.2 rule 4: only a card the extension may write (one in the personal vault) is an update target; a card in
  // a shared vault is no target at all, so a page that knows its number cannot get its fields written into that vault.
  const existing = number !== "" ? session.items.find((i) => i.doc.type === "card" && writableItem(i) && digitsOnly(i.doc.card?.number ?? "") === number) : undefined;
  const rec = {
    host,
    number,
    expMonth: padMonth(msg.fields.expMonth ?? "") ?? "",
    expYear: yearTo4(msg.fields.expYear ?? "") ?? "",
    cardholderName: (msg.fields.cardholderName ?? "").trim(),
    postalCode: (msg.fields.postalCode ?? "").trim() || undefined,
    frameId,
    updatesItemId: existing?.itemId,
    updatesItemName: existing?.doc.name,
  };
  // As for a login: a lost first try's ids ride along only while the card caught is the same, field for field.
  const earlier = pendingCardSave.get(tabId);
  const same = earlier !== undefined && earlier.host === rec.host && earlier.number === rec.number && earlier.expMonth === rec.expMonth && earlier.expYear === rec.expYear && earlier.cardholderName === rec.cardholderName && earlier.postalCode === rec.postalCode && rec.updatesItemId === undefined;
  if (same && earlier.lost !== undefined) (rec as typeof rec & { lost?: LostPut }).lost = earlier.lost;
  pendingCardSave.set(tabId, rec); // [X2-A4] single-slot per tab — a new capture REPLACES
  return { ok: true, pending: publicPendingCard(rec) };
}

async function resolvePendingCardSave(
  action: "save" | "dismiss",
  sender: chrome.runtime.MessageSender,
): Promise<Res<"resolvePendingCardSave">> {
  const tabId = await contextTabId(sender);
  const rec = tabId === undefined ? undefined : pendingCardSave.get(tabId);
  if (tabId === undefined || !rec) return { ok: false, error: "nothing pending" };
  // [X2-A2] resolve half: captureCard hard-gates the capture to the tab's top origin and records
  // the capturing frame — honor it here too (the login twin's rule), or any cross-origin ad/PSP
  // iframe could commit the top frame's PAN to the vault (or silently destroy the offer) with no
  // banner click. The popup (no tab) passes.
  if (sender.tab !== undefined && sender.frameId !== rec.frameId) return { ok: false, error: "nothing pending" };
  if (action === "dismiss") {
    pendingCardSave.delete(tabId);
    return { ok: true };
  }
  if (!session) return { ok: false, code: "locked", error: "locked" };
  if (!session.personalVaultId) return { ok: false, code: "no_personal_vault", error: "no personal vault" }; // A9 review MEDIUM-1
  if (!luhnValid(rec.number)) {
    pendingCardSave.delete(tabId);
    return { ok: false, code: "failed", error: "invalid card number" };
  }
  const target = rec.updatesItemId ? session.items.find((i) => i.itemId === rec.updatesItemId && i.doc.type === "card" && writableItem(i)) : undefined;
  let result: { ok: boolean; code?: SaveErrorCode; error?: string };
  if (target && digitsOnly(target.doc.card?.number ?? "") === digitsOnly(rec.number)) {
    // [X2-A5b] UPDATE = spread the existing doc AND card; refresh only expMonth/expYear/cardholderName
    // (+ postal when captured); NEVER touch securityCode or the number (digits already matched). The
    // `|| prev` fallback keeps an empty capture (a checkout that omits a name/expiry field) from
    // CLOBBERING a stored value — the spread already preserves securityCode + any unknown keys.
    const prevCard = target.doc.card ?? {};
    const card: CardData = {
      ...prevCard,
      expMonth: rec.expMonth || prevCard.expMonth,
      expYear: rec.expYear || prevCard.expYear,
      cardholderName: rec.cardholderName || prevCard.cardholderName,
    };
    if (rec.postalCode) card.postalCode = rec.postalCode;
    result = await putCard(target, { ...target.doc, card });
  } else {
    // A NEW card (no match / the matched item vanished); a first try whose answer was lost: the same item, same ids.
    const made = await putNewCard(rec, rec.lost);
    if (made.lost !== undefined) rec.lost = made.lost;
    const { lost: _ids, ...said } = made;
    result = said;
  }
  if (result.ok) pendingCardSave.delete(tabId);
  return result;
}

// ---- writes (seal → push → confirm) ----

/** G21 (2026-08-30 audit): can this item take a put? A "reader" grant is view-only — the server
 *  denies its push (Service.kt: role=="reader" ⇒ Forbidden) — so the save/link/TOTP-add paths must
 *  never OFFER a write against a reader-vault item (the denial used to render as the lying
 *  "Could not save — try again."). Web twin: store.ts roleFor()==="reader".
 *  Security review 2026-10, branch A11 (q13): a vault with NO role entry fails CLOSED. Roles come from this account's
 *  own grant rows, so a key without one is a key the grant table does not account for (a pre-A11 personal-wrap
 *  install, a pre-G21 snapshot until the next sync refills the roles); it is never an update/TOTP-add target. The one
 *  exception is the IN-FORCE personal vault, which the UVK-authenticated wrap decides on its own (§4.3). */
/** Design 2026-11-15 §12.2 rule 4: the extension writes only to the personal vault. The write paths (save, update, a
 *  card's update, TOTP add, link a URI) ask here before they offer or attempt a write, so an item in a shared vault is
 *  read-only in this extension whatever its role; putItem, the one function that sends an item, refuses any other vault
 *  by itself, so a path that forgets to ask still cannot write one. */
function writableItem(it: DecryptedItem): boolean {
  if (!session) return false;
  return session.personalVaultId !== "" && it.vaultId === session.personalVaultId;
}

/** Seal + push one put over the existing envelope path; answers the per-mutation result.
 *  `formatVersion` is computed ONCE by the caller and used for BOTH the AD binding and the
 *  wire field (web ItemUpload pattern) — restating it anywhere would let the two diverge
 *  into an AD mismatch. */
async function putItem(
  itemId: string,
  vaultId: string,
  doc: ItemDoc,
  baseItemRev: number,
  formatVersion: number,
  // A second try of a put whose answer was lost passes the first one's id: the server answers a replayed mutation id
  // from its journal (spec 03 §5), so the item is taken once.
  mutationId: string = crypto.randomUUID(),
): Promise<MutationResult | undefined> {
  // Design §12.2 rule 4, structurally: the one function that sends an item refuses any vault but the personal one.
  if (!session || session.personalVaultId === "" || vaultId !== session.personalVaultId) return undefined;
  // §4.4: under a block (a fork), or while a session the server ended stands, nothing is written; saveFailure says why.
  if (dialBlock !== null || session.serverEnded) return undefined;
  const vk = session.vaultKeys.get(vaultId);
  // A1b: INV-WRITE-KEY (only a key this session holds, i.e. one that opened under the UVK — never a grant seal) and the
  // INV-SEAL home cross-check (the item lives in this vault, or is a fresh id that takes it as its home).
  const gate = sealGate(vk !== undefined, session?.homes.get(itemId), vaultId);
  if (!vk || !session || gate === "no_key" || gate === "refuse") return undefined;
  const owner = session;
  const blob = toB64(seal(vk, new TextEncoder().encode(JSON.stringify(doc)), adItem(vaultId, itemId, formatVersion)));
  writesInFlight++; // hold off resync's wholesale session.items replace until this rev lands
  try {
    const resp = await api.push([
      {
        mutationId,
        op: "put",
        itemId,
        vaultId,
        baseItemRev,
        // attachmentIds mirrors the doc (web putMutation parity) — [] on an update would orphan blobs.
        item: { formatVersion, attachmentIds: doc.attachments?.map((a) => a.id) ?? [], blob },
      },
    ])
      .catch((e: unknown) => {
        // The request may have reached the server and its answer been lost: that is "cannot tell", never "failed".
        throw answerMayBeLost(e) ? new PutAnswerLostError(mutationId) : e;
      });
    const r = resp.results[0];
    if (gate === "new_home" && (r?.status === "applied" || r?.status === "conflict") && !owner.homes.has(itemId)) {
      owner.homes.set(itemId, vaultId);
      if (owner.homesKnown) void saveHomes(owner.userId, owner.homes); // §4.4: an unread record is never written back
    }
    return r;
  } finally {
    writesInFlight--;
  }
}

/**
 * A put that may have reached the server and whose answer did not arrive: no answer at all, an answer that is not the
 * server's (a redirect, a 5xx, a body that does not read), or a refreshed token's retry lost the same way. Nothing was
 * sent only where this browser refused to dial; a 4xx is the server's own refusal of the request.
 */
class PutAnswerLostError extends Error {
  readonly mutationId: string;
  constructor(mutationId: string) {
    super("the save's answer was lost: it may be stored");
    this.mutationId = mutationId;
    this.name = "PutAnswerLostError";
  }
}

function answerMayBeLost(e: unknown): boolean {
  if (!(e instanceof ApiError)) return true;
  if (e.code === "confirm_server") return false;
  return e.status === 0 || e.status >= 500;
}

/**
 * A NEW item whose put's answer was lost: kept with the capture (the tab's pending save, the card's pending save), so
 * that the person's second try sends the same item under the same item id and the same mutation id, and the server
 * takes it once (BZ: never reported as failed, never doubled).
 */
interface LostPut {
  readonly itemId: string;
  readonly mutationId: string;
}

/** What a new item's put answers: [lost] is set where its answer was lost (code `cannot_tell`). */
type NewPutResult = { ok: boolean; code?: SaveErrorCode; error?: string; reason?: string; lost?: LostPut };

/** {@link putItem} of a NEW item under [ids]: its answer, or, where the answer was lost, the `cannot_tell` result. */
async function putNewItem(ids: LostPut, vaultId: string, doc: ItemDoc, fv: number): Promise<{ readonly landed: MutationResult | undefined } | { readonly lostAnswer: NewPutResult }> {
  try {
    return { landed: await putItem(ids.itemId, vaultId, doc, 0, fv, ids.mutationId) };
  } catch (e) {
    if (e instanceof PutAnswerLostError) return { lostAnswer: { ok: false, code: "cannot_tell", error: e.message, lost: ids } };
    throw e;
  }
}

/** Map a non-landed push status to the seam SaveErrorCode (E1-5): denied/duplicate/no-vault-key/
 *  undefined all fold to "failed". `rejected` (H03, recheck R37) is the server's PERMANENT
 *  refusal — the put's attachment refs no longer resolve — and must never fold into the
 *  retryable "failed" rung: the same put fails identically forever, so "try again" would lie.
 *  `conflict` is kept as a distinct code for the union's sake but
 *  no longer reaches here from the four put paths (putExisting/putNewLogin/putNewCard/putCard) — since H20 a conflict is a LANDED write
 *  (putLanded), materialized, and answered ok:true. The `error` string is debug-only detail the
 *  surface never renders (it maps the CODE to copy). */
function saveFailure(status: MutationResult["status"] | undefined, reason?: string): { ok: false; code: SaveErrorCode; error: string; reason?: string } {
  if (dialBlock?.kind === "fork") return { ok: false, code: "server_fork", error: "the server is stopped by a fork; nothing is written" };
  if (session?.serverEnded) return { ok: false, code: "server_ended", error: "the server ended this session; nothing is written" };
  const code: SaveErrorCode = status === "conflict" ? "conflict" : status === "rejected" ? "rejected" : "failed";
  // The server's own reason for a refusal is kept up to the sentence (a full account is said as a full account, not as a
  // missing attachment). Only a wire code's shape is carried; anything else is no reason.
  const why = code === "rejected" && typeof reason === "string" && /^[a-z_]{1,64}$/.test(reason) ? { reason } : {};
  return { ok: false, code, error: `save failed (${status ?? "no vault key"})`, ...why };
}

/** H20 (2026-09-13 audit): did this put LAND? Spec 03 §5 is explicit that `conflict` is a write
 *  the server APPLIED ("write never rejected-and-dropped": blob overwritten, rev bumped, the
 *  displaced version archived and handed back as `serverItem`). The four put paths (putExisting,
 *  putNewLogin, putNewCard, putCard) used to
 *  test `status === "applied"` alone, so a conflicting Update was reported as a failure ("This
 *  login changed elsewhere — open it in the web vault") while the server had already kept OUR
 *  value: the local rev stayed stale (the next Update conflicted again), no copy was made, and the
 *  peer's value survived only in version history — web/core's pull-side fallback then built the
 *  "(conflict)" copy from the winner, a duplicate of our own password. The extension is the ONE
 *  party that receives the losing version, so it is the party that must materialize it. */
function putLanded(r: MutationResult | undefined): r is MutationResult & { status: "applied" | "conflict" } {
  return r?.status === "applied" || r?.status === "conflict";
}

/** H20: the pushing client's duty from spec 03 §5 — materialize the DISPLACED version as
 *  "<name> (conflict YYYY-MM-DD)" (web store.ts materializeConflictFromServerItem / core
 *  SyncEngine twin). Runs only on a landed `conflict` carrying a decryptable serverItem; every
 *  other shape is a silent no-op, and a failure here never un-saves the write that already landed
 *  (the pull side's flag-clearing fallback still runs on the next resync). The copy id is
 *  deterministic over (itemId, winner rev) so a peer, our retry and the pull fallback converge on
 *  one item — its own `conflict`/`duplicate` answer is that convergence, not an error. A reader
 *  vault never materializes (its push would be denied — the web twin's first check). */
async function materializeConflictCopy(r: MutationResult, vaultId: string, owner: Session | null): Promise<void> {
  // Work that outlives a lock: [owner] is the session the landed write was made under. A lock, a sign-out
  // or another account's sign-in while that write was on the wire ends it, and nothing of it may then be decrypted
  // with, or added to, whatever session holds the worker now; the next unlock of that account pulls the copy instead.
  if (r.status !== "conflict" || r.newItemRev === undefined || owner === null || session !== owner) return;
  const losing = r.serverItem;
  if (!losing || losing.deleted || !losing.blob) return;
  // A1b INV-CONFLICT: the displaced value must be the item we wrote, in the vault we wrote it to and its home.
  if (serverItemDecision(vaultId, losing.vaultId, owner.homes.get(losing.itemId)) === "abort") return;
  if (owner.vaultRoles.get(vaultId) === "reader") return;
  // Through decryptItems — the ONE wire-open site (the fv read ceiling, the per-vault key, the AD
  // binding and the undecryptable-skip all live there; a second open here would dodge those pins).
  const [displaced] = decryptItems({ rev: 0, vaults: [], grants: [], items: [losing] }, owner.vaultKeys);
  if (!displaced) return; // above the read ceiling, no key, or not ours to read — nothing safe to copy
  const losingDoc = displaced.doc;
  const copyId = conflictCopyId(losing.itemId, r.newItemRev);
  if (owner.items.some((i) => i.itemId === copyId)) return; // already materialized (peer / retry / pull fallback)
  const copyDoc: ItemDoc = { ...losingDoc, name: conflictCopyName(losingDoc.name, losing.updatedAt ?? Date.now()) };
  // Seal the copy at the fv the displaced version carried (floored by its doc type, the monotonic
  // rule every re-seal here follows) — the copy IS that version, so that is the fv its semantics are.
  const fv = Math.max(losingDoc.type === "card" ? CARD_FORMAT_VERSION : LOGIN_FORMAT_VERSION, losing.formatVersion);
  try {
    const cr = await putItem(copyId, vaultId, copyDoc, 0, fv);
    if (putLanded(cr) && session === owner) {
      owner.items = itemsUnderHeldKeys([...owner.items, { itemId: copyId, vaultId, rev: cr.newItemRev ?? 1, formatVersion: fv, doc: copyDoc }], owner.vaultKeys);
      persistSession();
    }
  } catch {
    /* the landed write above stands; the pull side's fallback preserves at least the winner */
  }
}

async function putExisting(target: DecryptedItem, doc: ItemDoc): Promise<{ ok: boolean; code?: SaveErrorCode; error?: string; reason?: string }> {
  // Monotonic re-seal: never below the fv the item arrived at (web Account.itemFv parity — the
  // server refuses fv downgrades). This is the LOGIN re-seal path only: every putExisting caller
  // filters type==="login", so the floor is LOGIN_FORMAT_VERSION. G2 [X2-A6] lifted the older
  // "the extension never writes card docs" invariant — CARDS re-seal via the card-aware putCard
  // (floor CARD_FORMAT_VERSION), NEVER here (a login floor would down-seal a card).
  const fv = Math.max(LOGIN_FORMAT_VERSION, target.formatVersion);
  const owner = session; // the session this write is made under (materializeConflictCopy)
  const r = await putItem(target.itemId, target.vaultId, doc, target.rev, fv);
  if (!putLanded(r)) return saveFailure(r?.status, r?.reason);
  target.doc = doc;
  target.rev = r.newItemRev ?? target.rev + 1;
  target.formatVersion = fv; // what this write actually sealed at (web store.ts parity)
  if (session === owner) persistSession(); // ended meanwhile: its items are gone, nothing of them is written
  await materializeConflictCopy(r, target.vaultId, owner); // H20: no-op unless status === "conflict"
  return { ok: true };
}

/** `uri` is the stored site uri (H124: `capturedSiteUri` — http stays http); `host` names the item. */
async function putNewLogin(host: string, username: string, password: string, uri: string, lost?: LostPut): Promise<NewPutResult> {
  if (!session) return { ok: false, code: "locked", error: "locked" };
  if (!session.personalVaultId) return { ok: false, code: "no_personal_vault", error: "no personal vault" }; // A9 review MEDIUM-1
  // A second try after a lost answer sends the same item (BZ): the first try's item id and mutation id.
  const ids: LostPut = lost ?? { itemId: crypto.randomUUID(), mutationId: crypto.randomUUID() };
  const itemId = ids.itemId;
  const doc: ItemDoc = { type: "login", name: host, login: { username, password, uris: [uri] } };
  // NEW logins seal at the login doc floor (format.ts). G2 added card creation via a SEPARATE
  // card-aware seal (CARD_FORMAT_VERSION); this path is logins-only.
  const owner = session;
  const p = await putNewItem(ids, owner.personalVaultId, doc, LOGIN_FORMAT_VERSION);
  if ("lostAnswer" in p) return p.lostAnswer;
  const r = p.landed;
  if (!putLanded(r)) return saveFailure(r?.status, r?.reason); // H20: a conflict on a fresh id still LANDED
  // Work that outlives a lock: a lock, a sign-out or another account's sign-in while this write was on the
  // wire ended [owner]. The write landed under its account (the next unlock there pulls it); the new login is never
  // added to the session that holds the worker now, which may be another account's.
  if (session !== owner) return { ok: true };
  const rev = r.newItemRev ?? 1; // matchable immediately:
  owner.items = itemsUnderHeldKeys([...owner.items, { itemId, vaultId: owner.personalVaultId, rev, formatVersion: LOGIN_FORMAT_VERSION, doc }], owner.vaultKeys);
  persistSession();
  await materializeConflictCopy(r, owner.personalVaultId, owner);
  return { ok: true };
}

/** [X2-A6] NEW card (G2 save-card) — sealed at CARD_FORMAT_VERSION, NOT putNewLogin's login floor.
 *  The card-aware create path; the extension now creates cards as well as logins (format.ts). */
async function putNewCard(rec: {
  host: string;
  number: string;
  expMonth: string;
  expYear: string;
  cardholderName: string;
  postalCode?: string;
}, lost?: LostPut): Promise<NewPutResult> {
  if (!session) return { ok: false, code: "locked", error: "locked" };
  if (!session.personalVaultId) return { ok: false, code: "no_personal_vault", error: "no personal vault" }; // A9 review MEDIUM-1
  // A second try after a lost answer sends the same item (BZ), as putNewLogin.
  const ids: LostPut = lost ?? { itemId: crypto.randomUUID(), mutationId: crypto.randomUUID() };
  const itemId = ids.itemId;
  const card: CardData = { number: rec.number };
  if (rec.expMonth) card.expMonth = rec.expMonth;
  if (rec.expYear) card.expYear = rec.expYear;
  if (rec.cardholderName) card.cardholderName = rec.cardholderName;
  if (rec.postalCode) card.postalCode = rec.postalCode;
  const doc: ItemDoc = { type: "card", name: rec.host, card };
  const owner = session;
  const p = await putNewItem(ids, owner.personalVaultId, doc, CARD_FORMAT_VERSION);
  if ("lostAnswer" in p) return p.lostAnswer;
  const r = p.landed;
  if (!putLanded(r)) return saveFailure(r?.status, r?.reason); // H20: a conflict on a fresh id still LANDED
  if (session !== owner) return { ok: true }; // ended while on the wire: as putNewLogin
  const rev = r.newItemRev ?? 1;
  owner.items = itemsUnderHeldKeys([...owner.items, { itemId, vaultId: owner.personalVaultId, rev, formatVersion: CARD_FORMAT_VERSION, doc }], owner.vaultKeys);
  persistSession();
  await materializeConflictCopy(r, owner.personalVaultId, owner);
  return { ok: true };
}

// ---- TOTP add (design 2026-08-12: popup paste-add, ADD-ONLY) ----
// Security review 2026-10 (root cause E): the page otpauth-link offer (totpOffer / addTotpFromPage)
// is retired — a page cannot prove a link is the site's own enrolment, so the popup is the only lane.

/** The ONE add-only TOTP write (the popup's paste-add). Both contract invariants live HERE, not
 *  in any surface: (1) ADD-ONLY — an item already carrying
 *  login.totp is refused (`exists`), so no surface
 *  can ever ROTATE a stored second factor from the extension; replacing/removing stays a
 *  web-vault edit. (2) the SW re-runs the shared normalizeTotp + parse-accept gate — the web
 *  editors' exact save rule (A5 reject-don't-corrupt) — so an unparseable secret is refused,
 *  never stored. Callers guarantee `target` is a LOGIN doc (putExisting is the login re-seal
 *  path; a card doc must never grow a `login` key via this spread). */
async function writeTotp(target: DecryptedItem, rawTotp: string): Promise<{ ok: boolean; code?: TotpAddCode; error?: string }> {
  if ((target.doc.login?.totp ?? "") !== "") return { ok: false, code: "exists", error: "item already has a totp" };
  const totp = normalizeTotp(rawTotp);
  if (!isValidTotp(totp)) return { ok: false, code: "invalid", error: "not a parseable otpauth secret" };
  const doc: ItemDoc = { ...target.doc, login: { ...target.doc.login, totp } };
  const r = await putExisting(target, doc);
  if (r.ok) return { ok: true };
  return { ok: false, code: r.code === "conflict" ? "conflict" : "failed", error: r.error };
}

/** Popup paste-add. Popup-only (tab senders refused — a page must never reach a TOTP write).
 *  Login docs only. */
async function setTotp(
  msg: Extract<Req, { type: "setTotp" }>,
  sender: chrome.runtime.MessageSender,
): Promise<Res<"setTotp">> {
  if (sender.tab !== undefined) return { ok: false, code: "not_allowed", error: "popup only" };
  if (!session) return { ok: false, code: "locked", error: "locked" };
  if (!session.personalVaultId) return { ok: false, code: "no_personal_vault", error: "no personal vault" }; // A9 review MEDIUM-1
  const target = session.items.find((i) => i.itemId === msg.itemId && i.doc.type === "login");
  if (!target) return { ok: false, code: "failed", error: "unknown item" };
  // G21: the honest SW backstop for the suppressed popup offer (MatchItem.readOnly). A reader's
  // push is refused server-side (role=="reader" ⇒ Forbidden) and used to map to the lying
  // "Could not add the code — try again." — refuse here with the honest code instead of a doomed
  // round-trip. Mirrors linkUri's writableItem() guard.
  if (!writableItem(target)) return { ok: false, code: "read_only", error: "read-only vault" };
  return writeTotp(target, msg.totp);
}

/** [X2-A6] card-aware re-seal — floors at max(CARD_FORMAT_VERSION, target.formatVersion), NOT the
 *  login putExisting (LOGIN_FORMAT_VERSION floor). Monotonic; the server refuses fv downgrades. */
async function putCard(target: DecryptedItem, doc: ItemDoc): Promise<{ ok: boolean; code?: SaveErrorCode; error?: string; reason?: string }> {
  const fv = Math.max(CARD_FORMAT_VERSION, target.formatVersion);
  const owner = session; // the session this write is made under (materializeConflictCopy)
  const r = await putItem(target.itemId, target.vaultId, doc, target.rev, fv);
  // H20 (recheck R01): the FOURTH put path — a card UPDATE conflicts exactly like a login update
  // (the server applied our value, the displaced card comes back as serverItem), so it gets the
  // putExisting treatment: a landed conflict is ok:true and the displaced version is materialized.
  if (!putLanded(r)) return saveFailure(r?.status, r?.reason);
  target.doc = doc;
  target.rev = r.newItemRev ?? target.rev + 1;
  target.formatVersion = fv;
  if (session === owner) persistSession(); // ended meanwhile: its items are gone, nothing of them is written
  await materializeConflictCopy(r, target.vaultId, owner); // H20: no-op unless status === "conflict"
  return { ok: true };
}

/** One-tap URI backfill for legacy items: append https://<host>, keep the real tail, shed the
 *  unmatchable "" entries the web editor leaves on untouched items. Idempotent per host.
 *  F18 (2026-08-13 audit): this is a vault WRITE that persists to the server, and it used to take
 *  the caller's word for both the item and the host — so a page-side caller could append its own
 *  host to every login (`allItems` is deliberately not sender-gated) and then collect each
 *  password through a plain host-matched `reveal`, with nothing on screen and no undo. A TAB
 *  sender may now only link ITS OWN host ([A2]: browser-set origin, fail-closed on missing/opaque);
 *  the popup (no tab) keeps the current freedom — its host comes from `activeTabHost()`. */
async function linkUri(msg: Extract<Req, { type: "linkUri" }>, sender: chrome.runtime.MessageSender): Promise<Res<"linkUri">> {
  if (!session) return { ok: false, error: "locked" };
  const it = session.items.find((i) => i.itemId === msg.itemId && i.doc.type === "login");
  if (!it) return { ok: false, error: "unknown item" };
  const webHost = normalizeHost(msg.host);
  if (!webHost) return { ok: false, error: "bad host" };
  if (sender.tab !== undefined && senderHost(sender) !== webHost) return { ok: false, error: "not this frame's host" };
  const kept = (it.doc.login?.uris ?? []).filter((u) => u.trim() !== "");
  // F4 (spec 05 autofill (e)): the page the link is for, scheme included — a tab sender's own browser-set origin, or
  // the origin the popup names. On a plain-http page only an address saved as http counts as linked already, since
  // an https one does not match there; the address stored is then the http origin (capturedSiteUri, H124).
  const page = sender.tab !== undefined ? (typeof sender.origin === "string" ? sender.origin : "") : msg.host;
  const plainHttp = isPlainHttp(page);
  const already = kept.some((u) => {
    const p = parseSavedUri(u);
    return p?.kind === "web" && p.host === webHost && (!plainHttp || isPlainHttp(u));
  });
  if (already) return { ok: true }; // nothing to push
  // G21: a reader grant can't take the append — refuse here instead of pushing a write the server
  // will deny (the offer banner renders its honest "Could not link." line).
  if (!writableItem(it)) return { ok: false, error: "read-only vault" };
  // H124: a link offered on a plain-http page stores the http origin the user is actually on; for a tab sender the
  // browser-set `sender.origin` is the only source (a page-supplied url could not be trusted for the [A2] host check
  // either). The popup names the active tab's origin (F4), so an http page links its http origin there too.
  const uri = capturedSiteUri(page, webHost);
  const doc: ItemDoc = { ...it.doc, login: { ...it.doc.login, uris: [...kept, uri] } };
  return putExisting(it, doc);
}

// Safari Details: this script evaluated to its end (safari-boot.js records when; absent on other builds).
(globalThis as { __andvariBootReady?: () => void }).__andvariBootReady?.();
