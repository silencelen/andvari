import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { ApiClient, type RefreshEnd, type SessionEndKind } from "../api/client";
import { browserStorage } from "../api/devicesecret";
import type { ClientPolicyV2 as ClientPolicy } from "../api/wire";
import { initSodium } from "../crypto/sodium";
import { KdfPolicyError } from "../crypto/keys";
import { Account } from "../vault/account";
import { cardNamesOperator } from "../vault/pinstore";
import { ANOTHER_ACCOUNT_SIGNED_IN, fill, kdfRefusalText, LOCK_INTERRUPTED_WORK, OFFLINE_COPY_OFFER, OPERATOR_NOT_ON_WEB, policyWipeText, REMADE_ACCOUNT_REMEMBERED, SIGN_OUT_KEPT_NOT_REMOVED, SIGN_OUT_NOT_CONFIRMED } from "./copy";
import { dismissRemembered, REMEMBERED_NOTICES_KEY, rememberedNotices } from "../vault/selfidentity";
import { onPolicyWipeMadeLater, type PolicyWipeNotice, retryHeldPolicyWipes, senderForCopy, serverNameOf, takePolicyWipeNotice } from "../vault/policywipe";
import { bakedInstance } from "../vault/publicinstance";
import { VaultStore } from "../vault/store";
import { createWebContext, endedCopyHold, heldWithoutPin, stopSessionTraffic, type WebContext } from "./opensession";
import { endByClientDecision, endedUnconfirmed, endSessionByServer, heldEndNotice, keptChangesLine, lostChangesLine, sessionEndLine } from "./sessionend";
import { Welcome, type LoginMeta } from "./Welcome";
import { BrandSigil } from "./Sigil";
import { Busy } from "./Busy";
import { initTheme } from "./useTheme";
import { Vault } from "./Vault";
import { clearBreachCache } from "./Health";
import { Announcer } from "./Msg";
import { inactivityNotice } from "./format";
import {
  readPersistedAutoLockSeconds,
  resolveAutoLockSeconds,
  useAutoLock,
  writePersistedAutoLockSeconds,
} from "./useAutoLock";
import {
  applyOrgOfflineCachePolicy,
  policyWipeQuestion,
  claimTabTokens,
  clearLockRevoke,
  clearSession,
  clearTabTokens,
  declineCacheNudge,
  defaultBaseUrl,
  loadSession,
  LOCK_REVOKE_UNCONFIRMED,
  lockRevokeUnconfirmed,
  dropKeptAtSignOut,
  finishOwedWipes,
  followSignOuts,
  tellSignedOut,
  unconfirmedRefresh,
  holdAccountOpen,
  makeClient,
  migrateCacheConsentOnce,
  migrateLegacySessionTokens,
  pendingSyncCount,
  recordLockRevoke,
  REVOKE_UNCONFIRMED,
  setOfflineCopyEnabled,
  settleForgettings,
  shouldOfferCacheNudge,
  tokensKeptAcrossLock,
  unsentChangeCount,
  wipeLocalAccountState,
  wipeVaultCache,
  type Session,
} from "./session";
import {
  ACCOUNT_DELETED_NOTICE,
  ACCOUNT_FORGOTTEN_NOTICE,
  DELETION_HOLD_LIMIT_MS,
  DELETION_MOST_LIKELY_DONE,
  type DeletionWatch,
  type DeletionWatchAction,
  type DeletionWatchEvent,
  IDLE_DELETION_WATCH,
  stepDeletionWatch,
} from "./account-delete";
import { DeletionOutcomeUnknownCard, type DeletionEnd, type DeletionTrack } from "./DeleteAccount";
import { adoptSharedPair, dropHeldPair, dropOnSignOutElsewhere, endedInAnotherTabLanding, idleTimerUserId, lockTabTokens, revokeForSignOut, storageVerdict } from "./tabsession";

/** `notice` (F26): one-line reason rendered on the auth card — why the user is looking
 *  at a lock/sign-in screen ("Locked.", "This device's access was revoked.", …). */
type Phase =
  | { kind: "loading" }
  /** [knownEmail]: the account of a session the server ended on this profile, which the first screen offers to sign in to first. */
  | { kind: "welcome"; notice?: string; knownEmail?: string }
  /** [endedHere]: this browser itself ended the sign-in or session and kept the copy over unsent changes (sessionend.ts
   *  endByClientDecision); the card then does not say the server ended it. A new number each time, so the card is
   *  drawn afresh and nothing of the ended sign-in (its kit step) is left on it. */
  | { kind: "unlock"; session: Session; notice?: string; endedHere?: number }
  /** `readOnlyCopy`: the session is the read-only copy of design §4.4 (opened under a forked pin, or frozen when a
   *  refresh found one): its traffic is stopped and the fork warning shows. */
  | { kind: "vault"; account: Account; store: VaultStore; meta: LoginMeta; readOnlyCopy: boolean }
  /** Account deletion: the session ended while the deletion request was in flight and its answer never came — the
   *  vault is closed and the session wiped; the card offers to forget the account here, or to sign in and check. */
  | { kind: "deletionUnknown"; userId: string; email: string; notice?: string };

const UPGRADE_NOTICE = "This tab is running an older version — reload to update.";
// Cut M (v2 #16): pre-lock warning copy — the listed gestures are exactly the activity
// events useAutoLock tracks (pointer/key/touch), so doing any of them keeps the vault open.
const LOCK_WARNING_NOTICE = "Still there? Locking soon — click, tap, or press a key to stay unlocked.";
// B2-11 origin-move nudge copy (design 2026-07-15 §5.4.1). The offer stays up until answered
// (no dismiss-X: an unanswered nudge simply re-fires at the next unlock; a marker is written
// only by an actual answer, so it can never nag a device that has said yes or no).
// H48: qualified to what the web client can actually deliver — see the long note on the
// Offline-copy card in Settings.tsx. Without a service-worker shell (design 2026-07-13 D1) a
// COLD tab cannot load the app at all while the server is unreachable, so the offer promises
// only the thing that is true: a tab you already have open keeps working.
const CACHE_NUDGE_OFFER = OFFLINE_COPY_OFFER;
const CACHE_NUDGE_ACCEPTED = "Offline copy turned on — it will be created at your next unlock or sign-in.";
/** A14 (F5): how long a per-tab lock waits for the Vault's usage flush before revoking (H33 order). */
const LOCK_USAGE_FLUSH_WAIT_MS = 2_000;

export function App() {
  // UI-audit #26: apply the persisted theme preference before first paint, so every
  // phase (including the signed-out cards) honors it. Layout-effect, not effect —
  // an effect would flash the OS scheme for one painted frame on a forced theme.
  useLayoutEffect(() => initTheme(), []);

  const [phase, setPhase] = useState<Phase>({ kind: "loading" });
  const [policy, setPolicy] = useState<ClientPolicy | null>(null);
  // Distinct from `policy === null`: true means the policy fetch FAILED (can't reach the
  // server), false means it succeeded (so an empty recoveryFingerprint genuinely means no
  // recovery key). Without this, a transient fetch failure shows the scary — and now false —
  // "escrow ceremony isn't done" message during enrollment.
  const [policyError, setPolicyError] = useState(false);
  const [policyErrorMessage, setPolicyErrorMessage] = useState<string | undefined>(undefined);
  // 426 min-version pin tripped (api/client.ts onUpgradeRequired): this tab's bundle
  // is older than the server's pin, and every gated API call keeps failing until the
  // tab reloads — sticky once set; only the reload itself clears it.
  const [upgradeStale, setUpgradeStale] = useState(false);
  // A copy a server's policy removed (decided on 2026-11-17): the notice kept apart from the copy, taken once when the
  // app starts (a tab closed before it could say it) and after each such wipe.
  const [policyWipe, setPolicyWipe] = useState<PolicyWipeNotice | null>(() => takePolicyWipeNotice());
  // After "Forget the earlier account on this device" (decided on 2026-11-17): the addresses whose new account this browser
  // now remembers, each said once and kept until dismissed, also across a reload, a lock and a closed tab.
  const [remembered, setRemembered] = useState<string[]>(() => rememberedNotices());
  // A notice raised, or dismissed, in another tab is drawn here at once, not only at this tab's next unlock or reload.
  useEffect(() => {
    const onNoticesChanged = (e: StorageEvent) => {
      if (e.key === null || e.key === REMEMBERED_NOTICES_KEY) setRemembered(rememberedNotices());
    };
    window.addEventListener("storage", onNoticesChanged);
    return () => window.removeEventListener("storage", onNoticesChanged);
  }, []);
  const [baseUrl] = useState(defaultBaseUrl());
  const clientRef = useRef<ApiClient | null>(null);
  const ctxRef = useRef<WebContext | null>(null);
  /** The transport's refused-refresh hook (set at boot) ends the session through the latest onRevoked. */
  const onRefreshRefusedRef = useRef<(why: RefreshEnd) => void>(() => {});
  /** The landing of the `storage` listener for the shared session gone in another tab, set by that listener's effect. */
  const endedInAnotherTabRef = useRef<() => void>(() => {});

  const loadPolicy = useCallback(async () => {
    try {
      const ctx = ctxRef.current!;
      const p = await ctx.wire.clientPolicy();
      setPolicy(p);
      // Design §4.4: every policy probe refreshes the pinned card chain too (the pin store reports a newly verified
      // card, and a card naming the signed-in account as the operator signs it out, §12.2 rule 7).
      if (ctx.pins.state(ctx.origin).kind === "pinned") void ctx.pins.refresh(ctx.origin).catch(() => {});
      setPolicyError(false);
      setPolicyErrorMessage(undefined);
      // §E.4 policy row (design 2026-07-13-web-offline-cache / spec 02 §8): EVERY successful
      // ClientPolicy fetch re-evaluates offlineCacheAllowed. false ⇒ force-wipe this account's
      // cache DB (queue included — server-initiated, cannot be blocked) + pin the last-known bit
      // so an OFFLINE boot keeps honoring it; true ⇒ clear the pin. The pin write inside is
      // synchronous (webCacheEnabled consults it immediately); only the wipe is fire-and-forget
      // (deleteDatabase self-completes via the sibling versionchange, idbcache §D.5.3). This runs
      // at boot and at every unlock (onUnlocked → loadPolicy), the spec's re-evaluation points.
      // Decided on 2026-11-17: before that wipe the changes waiting in the copy are sent once (with a live session of the
      // account only), and how many could not be sent is said once afterwards, here at the top of whatever is on screen.
      if (p && typeof p === "object") {
        const allowed = p.offlineCacheAllowed !== false;
        // The copy of the account this tab has open, else the session this browser keeps: never another tab's account,
        // whose own tab (or next start) sends what waits in its copy with its own session.
        const p0 = phaseRef.current;
        const uid = p0.kind === "vault" ? p0.account.userId : (loadSession()?.userId ?? null);
        // Each change is sent only where this browser may write to its vault at that moment: the open store's question
        // where this tab has the account open and its first pull has run, else the personal vault alone (policyWipeQuestion).
        const open =
          p0.kind === "vault"
            ? { userId: p0.account.userId, personalVaultId: p0.account.personalVaultId, pulled: () => p0.store.pulledInThisSession(), mayWrite: (v: string) => p0.store.mayWrite(v) }
            : null;
        const question = uid === null ? null : policyWipeQuestion(open, uid);
        const sent =
          allowed || uid === null || question === null ? null : { send: senderForCopy(ctx.client, ctx.wire, uid, question), server: serverNameOf(ctx.pins, ctx.origin), mayWrite: question };
        void applyOrgOfflineCachePolicy(allowed, uid, sent).then(async (kept) => {
          // Said only now that the copy is gone; kept here too where storage refused to keep it.
          if (kept !== null) setPolicyWipe(takePolicyWipeNotice() ?? kept);
          // A wipe this policy asked for earlier that could not be made is tried again (nothing is sent again), only
          // after this read found the policy still forbidding the copy; a read that allows it ended those wipes above.
          if (!allowed) {
            await retryHeldPolicyWipes();
            setPolicyWipe((n) => takePolicyWipeNotice() ?? n);
          }
        });
      }
    } catch (e) {
      setPolicy(null);
      setPolicyError(true);
      // H1 (spec 05 T1): a weakened-KDF policy is a security block, NOT a transient "unavailable" —
      // keep the distinct signal so enrollment shows the weak-KDF warning, never "try again".
      setPolicyErrorMessage(e instanceof KdfPolicyError ? kdfRefusalText(e) : undefined);
    }
  }, []);

  useEffect(() => {
    (async () => {
      // A wipe owed from a tab closed while it waited (a sign-out during a policy's run) is made now, with or without a
      // session; it waits for the copy's lock in the background, so the start is not held up by it.
      void finishOwedWipes();
      // A forgetting of an earlier account that was begun and stopped part-way (a tab closed while it ran) is finished
      // now, before any screen reads the address's record. One that fails again keeps its mark for the next start, or
      // for the person's next click on the same confirmation.
      void settleForgettings().catch(() => {});
      await initSodium();
      // A14 (F5): is this tab's sessionStorage pair its own or a duplicated tab's copy? (A copy is
      // dropped: two tabs must never spend one rotating refresh token.)
      await claimTabTokens();
      // §5.4.1 continuity (design 2026-07-15): one-time boot reconciliation of the pre-pivot
      // default-ON cache into an explicit per-user opt-in — BEFORE the policy fetch and any
      // unlock consult the consent-keyed gate, so an existing member's offline copy survives
      // the flip without a beat where the gate reads "no consent".
      await migrateCacheConsentOnce(loadSession()?.userId ?? null);
      // A14 (F5): with the gate settled, a pre-A14 pair on disk for a browser without the offline
      // copy moves into this tab now — nothing secret stays in localStorage past this line.
      migrateLegacySessionTokens();
      const session = loadSession();
      const client = makeClient(session, baseUrl);
      // The one client lives for the whole tab (sign-in/lock reuse it), so registering
      // here covers every phase. Never auto-reload on 426 — an open editor may hold
      // unsaved work; the bar below leaves the reload to the user.
      client.onUpgradeRequired = () => setUpgradeStale(true);
      // Design §4.4: a refused refresh ends the session at once, whatever screen asked (the copy stays).
      client.onRefreshRefused = (why) => onRefreshRefusedRef.current(why);
      client.onEndedElsewhere = () => endedInAnotherTabRef.current();
      clientRef.current = client;
      // The web dials one origin, the one that served it (or the dev override), and pins its card chain (§13). Under a
      // forked or damaged pin of it the transport sends nothing (§4.4): createWebContext wires that gate.
      const origin = baseUrl || window.location.origin;
      // While the copy of a session the server ended is open, nothing leaves either (§4.4): the second stop.
      ctxRef.current = createWebContext(client, origin, browserStorage, bakedInstance(), undefined, () => endedCopyHold(phaseRef.current));
      // Design §4.4: a kept session whose origin holds no pin record dials nothing; its card (Welcome) offers only to
      // forget it, and the first screen after that probes the policy (the effect below).
      if (!heldWithoutPin(session, ctxRef.current)) await loadPolicy();
      // Every held session lands on the unlock card. A14 (F5): on a browser without the offline copy a
      // session with no tokens (after a lock, or a new tab) runs the normal sign-in there. With the offline
      // copy on, a session with no tokens is one the server ended (design §4.4, sessionend.ts endedByServer):
      // the card offers the sign-in that restores it and the copy, read-only.
      setPhase(session !== null ? { kind: "unlock", session } : { kind: "welcome" });
    })();
  }, [baseUrl, loadPolicy]);

  // A policy's wipe that was held up (a connection that did not close) and is made later: said then.
  useEffect(() => onPolicyWipeMadeLater(() => setPolicyWipe((n) => takePolicyWipeNotice() ?? n)), []);

  // The first screen probes the policy when nothing has yet (a boot that held a session with no pin record skipped it).
  const policyUnasked = policy === null && !policyError;
  useEffect(() => {
    if (phase.kind === "welcome" && policyUnasked) void loadPolicy();
  }, [phase.kind, policyUnasked, loadPolicy]);

  // B2-11 (design 2026-07-15 §5.4.1): the one-time offline-copy nudge — armed at unlock for the
  // unlocking user when policy allows and no per-device marker exists (shouldOfferCacheNudge).
  // "offered" renders the question; "accepted" a one-line confirmation (creation happens at the
  // next unlock — the same contract as the settings toggle). Answering writes the marker
  // (opt-in / device opt-out), so the nudge never re-fires once answered; phase-gating below
  // hides it outside the vault, and the next unlock re-evaluates from the markers.
  const [cacheNudge, setCacheNudge] = useState<{ userId: string; state: "offered" | "accepted" } | null>(null);
  const onCacheNudgeKeep = useCallback(() => {
    setCacheNudge((n) => {
      if (!n || n.state !== "offered") return n;
      void setOfflineCopyEnabled(n.userId, true); // clears any opt-out, pins the opt-in, asks persist()
      return { ...n, state: "accepted" };
    });
  }, []);
  const onCacheNudgeDecline = useCallback(() => {
    declineCacheNudge(); // pins the device-wide opt-out — never asked again on this (origin, device)
    setCacheNudge(null);
  }, []);

  const onUnlocked = (account: Account, store: VaultStore, meta: LoginMeta) => {
    deletedAccountRef.current = null; // a new session: a deletion this tab ran earlier owns no later landing
    stepDeletion({ kind: "session_start" }); // ...nor an outcome nothing settled (a request still in flight keeps its watch)
    lockRevokeRef.current = null; // A14 review W1: this tab holds a new pair; an older lock's record is moot
    clearLockRevoke(); // ...and so is the copy of it in the tab's sessionStorage (A14 review 3, W-b)
    // When a lock or a sign-out overtakes this session's work, the screen it lands on says so.
    store.onInterrupted(() =>
      setPhase((p) => (p.kind === "unlock" || p.kind === "welcome" ? { ...p, notice: [p.notice, LOCK_INTERRUPTED_WORK].filter(Boolean).join(" ") } : p)),
    );
    setPhase({ kind: "vault", account, store, meta, readOnlyCopy: store.isReadOnlyCopy() });
    // The session just kept took the address's record afresh where a forgetting left it new: its notice is read now.
    setRemembered(rememberedNotices());
    // §4.4: a copy read under a forked pin asks nothing of the server: no nudge (it would write), no policy probe (the
    // last-known auto-lock window persisted for this user stands).
    if (store.isReadOnlyCopy()) {
      setCacheNudge(null);
      return;
    }
    setCacheNudge(shouldOfferCacheNudge(account.userId) ? { userId: account.userId, state: "offered" } : null);
    // Refresh policy at unlock so the auto-lock/clipboard windows reflect the CURRENT
    // org policy — via loadPolicy so a success also clears a stale policyError from a
    // failed boot-time fetch (otherwise Enroll later shows a false "couldn't reach").
    void loadPolicy();
  };

  // F26: sign-out (and server-side revocation) is the DESTRUCTIVE path — the persisted
  // session is removed and the next visit is a full email+password sign-in. A mere
  // LOCK is not this; see lock() below.
  //
  // §E.4 (design 2026-07-13-web-offline-cache): this is the ONE wipe choke point for the
  // offline cache on a sign-out — the person's own (the Sign-out link), and a session the server
  // ended on a browser WITHOUT the offline copy (endByServer below; there is no copy to keep). Both
  // destroy this account's cache DB (envelopes + queue + cached accountKeys). Design §4.4: a session
  // the server ends with the offline copy on does NOT come here (endByServer keeps the copy), and
  // neither does a LOCK, so the cache is RETAINED on lock.
  // Read the userId BEFORE clearSession removes the session; wipe is fire-and-forget (the
  // deleteDatabase self-completes via the sibling connection's versionchange, idbcache §D.5.3).
  //
  // breaker #9 (§E.4) — the wipe destroys the whole outbound queue, so unsynced offline edits
  // are lost with it. `kind` decides how that loss is handled:
  //  - "user"    (the Sign-out button): the CALLER has already confirmed — see below;
  //  - "expired" (definitive-401 / WS session-end): cannot be blocked (spec 02 §8), but the
  //               count is SURFACED in the notice so the loss is never silent;
  //  - "revoked" (server WS revoked frame): silent-drop (spec 03 §4 accepts it).
  // A14 review W1: the revocation the last per-tab lock made of the pair it dropped (lockTabTokens), so a
  // sign-out with no pair left in the client reports THAT, rather than POSTing a logout with no token.
  const lockRevokeRef = useRef<Promise<boolean> | null>(null);
  // Account deletion (spec 03 §13): the account this tab just deleted, so a sign-out the server's `revoked` frame started
  // concurrently leaves the landing to onAccountDeleted. Cleared by the next unlock.
  const deletedAccountRef = useRef<string | null>(null);
  // Each landing of a sign-in this browser ended by itself (endByClient) draws the card afresh.
  const endedHereSeq = useRef(0);

  // Account deletion (spec 03 §13 client duties; design 2026-11-10 §11): App's side of the deletion request — the hold on
  // a session end that lands while it is in flight, and what each ending does with it — is the pure step function
  // account-delete.ts stepDeletionWatch (tested there); these refs are its state. `deletionWhoRef`: the account the request
  // is for, for the outcome-unknown card's Forget. The timer is the belt to the request's own timeout: no hold outlives
  // DELETION_HOLD_LIMIT_MS, whatever the card reports.
  const deletionWatchRef = useRef<DeletionWatch>(IDLE_DELETION_WATCH);
  const deletionWhoRef = useRef<{ userId: string; email: string } | null>(null);
  const deletionHoldTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const clearDeletionHold = () => {
    if (deletionHoldTimerRef.current !== null) clearTimeout(deletionHoldTimerRef.current);
    deletionHoldTimerRef.current = null;
  };

  // `deletionUnknown` (account deletion): land on DeletionOutcomeUnknownCard for that account instead of the sign-in card.
  const signOut = useCallback(async (notice?: string, kind: "user" | SessionEndKind = "user", deletionUnknown?: { userId: string; email: string }) => {
    const uid = loadSession()?.userId ?? null;
    // A session the server ended: this profile still knows its account, so the first screen offers "Sign in" first.
    const knownEmail = kind === "user" ? undefined : loadSession()?.email || undefined;
    const unsynced = uid ? await pendingSyncCount(uid) : 0;
    // Audit F07 kept the gate this comment describes — a fully-synced device still took the whole
    // destructive path (session cleared, offline copy deleteDatabase'd) off one click of a control
    // that reads like an account switcher — but implemented it as a native window.confirm right
    // here. H135 moved the ASKING, not the gate, out to the control: SignOutLink (the Unlock card
    // and the recovery-capture gate, the only two USER sign-out seams on web — signout-revoke.test
    // pins that Vault has none) arms the house inline two-step confirm, reading the SAME two probes
    // at click time (pendingSyncCount + the non-creating offlineCopyStamp) and carrying the same
    // natives-verbatim sentence. This function is now the unconditional wipe choke point it always
    // was for the other two kinds; anything that grows a new user sign-out control must arm through
    // SignOutLink, or it will wipe without asking. `unsynced` is still read here — the "expired"
    // notice below surfaces the count that could not be blocked.
    // "unconfirmed" (a session this browser could not confirm in time) did not expire: its count has a line of its own.
    const lostCount = lostChangesLine(kind, notice, unsynced);
    // bug-web--0 (spec 03): a USER sign-out revokes the device session server-side BEFORE the
    // local wipe — bounded + best-effort, mirroring the natives; without it the refresh token
    // stays refreshable for ~30 days. "expired"/"revoked" skip it (already dead server-side).
    // Security review 2026-10: it resolves false when the server did not confirm the revocation —
    // the wipe below still happens, but the member is told (REVOKE_UNCONFIRMED). A14 review W1: with
    // no pair left in the client (a per-tab lock dropped it, or this tab never had one) nothing is
    // POSTed; the lock's own revocation result is what is reported.
    // A14 review 3 (W-b): after a reload there is no in-memory lock record; the tab's sessionStorage one answers.
    const revoked = kind === "user" ? await revokeForSignOut(clientRef.current, lockRevokeRef.current, lockRevokeUnconfirmed(uid)) : true;
    lockRevokeRef.current = null;
    // The person's own sign-out: a token kept from a session of that account this browser could not confirm (or that
    // this sign-out found with a refresh unanswered) goes with it, so that nothing that may still be a live credential
    // stays here; the line then says the end was not confirmed, and how to end it. Another account's kept token stays.
    // A sign-out that is not the person's (the server's end, or this browser's) leaves it for the next sign-in's name.
    const keptDropped = kind === "user" && dropKeptAtSignOut(uid);
    // A removal that could not be written (tried twice): the token stays, and the line says so.
    const keptStays = keptDropped && uid !== null && unconfirmedRefresh(uid) !== null;
    // The other tabs drop that account's kept token too (each tab's own, on a browser where each tab holds its session).
    if (kind === "user" && uid !== null) tellSignedOut(uid);
    clearSession();
    clientRef.current?.setTokens(null);
    if (uid) void wipeVaultCache(uid);
    clearBreachCache(); // CR-08: the in-session HIBP breach map is dropped at the wipe choke point
    // Account deletion: the server's `revoked` frame to this tab can start this sign-out just before the deletion's own
    // answer lands; onAccountDeleted then did the wipe and owns the landing (its notice), so don't overwrite it here.
    if (uid !== null && deletedAccountRef.current === uid) return;
    const line = keptStays ? [lostCount, SIGN_OUT_KEPT_NOT_REMOVED].filter(Boolean).join(" ") : keptDropped ? [lostCount, SIGN_OUT_NOT_CONFIRMED].filter(Boolean).join(" ") : revoked ? lostCount : [lostCount, REVOKE_UNCONFIRMED].filter(Boolean).join(" ");
    setPhase(deletionUnknown ? { kind: "deletionUnknown", ...deletionUnknown, notice: line } : { kind: "welcome", notice: line, ...(knownEmail ? { knownEmail } : {}) });
  }, []);

  // Account deletion (spec 03 §13 client duty; design 2026-11-10 §11): the server CONFIRMED it, so this browser forgets
  // the account — wipeLocalAccountState clears the session and the tab's token slot synchronously first (so dropping the
  // pair right after writes nothing back), then every userId-scoped key, the spec 01 §5 self-identity records (so the
  // address can register again here) and the offline copy. Not routed through signOut: there is no session left to
  // revoke and nothing unsynced worth a confirm, and a sign-out deliberately KEEPS the self-identity records. Other tabs
  // follow through the session key's `storage` event. A `revoked` frame the server sends this tab's socket at the same
  // moment may start the ordinary revoked sign-out first: deletedAccountRef tells that sign-out to leave the landing to
  // this handler, whichever of the two finishes last. `end` is how the account went: `confirmed` by the server's answer,
  // or `forgotten` — the member's choice on DeletionOutcomeUnknownCard, after the session ended while the request was in
  // flight. The wipe is the same; only the notice differs (a forgotten account may, rarely, still exist).
  const onAccountDeleted = useCallback((userId: string, email: string, end: DeletionEnd) => {
    deletedAccountRef.current = userId;
    deletionWatchRef.current = IDLE_DELETION_WATCH;
    deletionWhoRef.current = null;
    clearDeletionHold();
    lockRevokeRef.current = null;
    // Its synchronous half (session, tab token slot, userId-scoped keys, self-identity records) has run by the time the
    // call returns, so dropping the pair next writes nothing back; the IndexedDB delete then completes on its own (the
    // live store's handle self-closes on the versionchange — signOut's wipe posture).
    // Only a deletion the server confirmed removes the records of which account the address is and of its key.
    void wipeLocalAccountState(userId, email, end === "confirmed" ? "confirmed" : "unconfirmed");
    clientRef.current?.setTokens(null);
    clearBreachCache();
    setPhase({ kind: "welcome", notice: end === "confirmed" ? ACCOUNT_DELETED_NOTICE : ACCOUNT_FORGOTTEN_NOTICE });
  }, []);

  // F26/F27 lock propagation channel: locking KEEPS the persisted session, so the
  // `storage` event can no longer signal it — locks are announced explicitly.
  const lockChannelRef = useRef<BroadcastChannel | null>(null);

  // A14 (F5): the open Vault registers its usage-ledger flush here, so a lock that revokes can let
  // the session's last uses land first (the H33 flush-before-revoke rule).
  const usageFlushRef = useRef<(() => Promise<void>) | null>(null);
  const perTabLockRef = useRef(false);

  // A14 (F5) — owner decision: a browser NOT opted into the offline copy keeps no token once locked.
  // Lock (manual, idle, or a lock announced by another tab) therefore: lets the Vault's usage flush
  // land (bounded), ends THIS tab's session server-side (best-effort, LOGOUT_TIMEOUT_MS; endSession()
  // reads the pair synchronously, so dropping it on the next line is safe), drops it, and lands
  // on the unlock card, which then runs the normal sign-in (email pre-filled, TOTP when enrolled).
  // [revoke] is false only when another tab took over this pair (it turned the offline copy off):
  // revoking would end THAT tab's session too.
  // 2026-11-16: the lock ends its pair at the server. For a few hours it only forgot the pair,
  // which left a refresh token valid at the server for 30 days where the browser's session-restore files may
  // hold a copy; A14's "keeps no token once locked" has to be true at the server too. It ends exactly this
  // tab's session, by its own refresh token (`end-session`, spec 03 §2), not the logout, which ends every
  // session of the browser's device row and so the account's other tabs in this browser.
  // A14 review W1: the revocation's result is recorded for a later sign-out, and a refusal is said on
  // the unlock card. W7: the phase change runs in a finally — nothing above (a storage write that
  // throws inside setTokens) can leave the vault open.
  const lockPerTab = useCallback(async (notice: string, meta: Session, revoke: boolean) => {
    if (perTabLockRef.current) return;
    perTabLockRef.current = true;
    try {
      const { revoked } = await lockTabTokens(clientRef.current, { flush: usageFlushRef.current, flushWaitMs: LOCK_USAGE_FLUSH_WAIT_MS, revoke });
      if (revoked) {
        lockRevokeRef.current = revoked;
        // A14 review 3 (W-b): the result is also kept in the tab's sessionStorage, so a reload before a sign-out still
        // knows it; until the server answers it is "pending", which a reload reads as unconfirmed.
        recordLockRevoke(meta.userId, "pending");
        void revoked.then((ok) => {
          if (lockRevokeRef.current !== revoked) return;
          recordLockRevoke(meta.userId, ok ? "confirmed" : "unconfirmed");
          if (ok) return;
          setPhase((p) => (p.kind === "unlock" && p.session.userId === meta.userId ? { ...p, notice: [p.notice, LOCK_REVOKE_UNCONFIRMED].filter(Boolean).join(" ") } : p));
        });
      }
    } finally {
      clearTabTokens();
      setPhase((p) => (p.kind === "vault" || p.kind === "unlock" ? { kind: "unlock", session: { ...meta, tokens: null }, notice } : p));
      perTabLockRef.current = false;
    }
  }, []);

  // F26: lock drops this tab's keys (the phase change unmounts Vault, releasing the
  // Account/VaultStore) but KEEPS the persisted session and tokens, so the user lands
  // on the lighter master-password-only Unlock card with a reason line. Same ZK
  // posture as sign-out: unlock re-derives every key from the password; no secret is
  // ever persisted (spec 01 §8). That is the offline-copy-ON browser; without the
  // offline copy the lock is lockPerTab above (A14, F5).
  const lockLocal = useCallback((notice: string) => {
    const meta = loadSession();
    if (meta && !tokensKeptAcrossLock(meta.userId)) {
      // A14: a browser without the offline copy keeps no token once locked, at the server too: the lock ends this tab's
      // session (spec 03 §2 end-session). Forgetting it only would leave its refresh token valid for 30 days.
      void lockPerTab(notice, meta, true);
      return;
    }
    setPhase((p) => {
      if (p.kind !== "vault") return p; // nothing unlocked here — nothing to lock
      const session = loadSession();
      // No persisted session to come back to (shouldn't happen) — fall back to sign-in. A held session without
      // tokens (the copy of one the server ended, §4.4) comes back to its own unlock card.
      return session ? { kind: "unlock", session, notice } : { kind: "welcome", notice };
    });
  }, [lockPerTab]);

  const lock = useCallback(
    (notice: string) => {
      lockLocal(notice);
      lockChannelRef.current?.postMessage("locked"); // F27: bring the other tabs along
    },
    [lockLocal],
  );

  // Stable identities: Vault's WS-subscription effect depends on onRevoked — a fresh
  // closure per render would tear down and re-mint the events socket every render.
  const onManualLock = useCallback(() => lock("Locked."), [lock]);
  // Design §4.4 "A session the server ends does not delete the device's copy": the session ends and its tokens go
  // (sessionend.ts endSessionByServer). With the offline copy on, the copy, its unsent changes and the session record
  // stay, and the tab lands on that session's unlock card: the sign-in there restores it and sends the changes, or
  // the copy opens read-only with the master password. Without the offline copy there is nothing to keep, and the
  // tab signs out as before (F26). The COPY must be truthful either way: only the server's explicit WS `revoked`
  // frame is a revocation; a dead session at ticket mint is ordinary expiry (laptop asleep past the refresh
  // lifetime) and saying "revoked" there would be a false alarm.
  const endByServer = useCallback(
    async (kind: SessionEndKind, notice?: string) => {
      const line = notice ?? sessionEndLine(kind);
      const p = phaseRef.current;
      // The open vault stops now: nothing queued is sent, the socket closes, and the usage ledger halts at unmount.
      if (p.kind === "vault") {
        clientRef.current?.cutLiveTraffic();
        p.store.freezeAsReadOnlyCopy("ended");
      }
      const end = endSessionByServer(clientRef.current, kind);
      if (end.kind === "sign_out") {
        // No offline copy: "revoked" is a silent drop (spec 03 §4 accepts it); expiry surfaces the lost count. A session
        // not confirmed sends nothing either (its token stays kept for the next sign-in).
        await signOut(line, kind);
        return;
      }
      usageFlushRef.current = null;
      lockRevokeRef.current = null;
      clearBreachCache();
      const uid = end.session.userId;
      if (deletedAccountRef.current === uid) return; // the deletion's own landing wins (see signOut)
      const kept = keptChangesLine(await pendingSyncCount(uid));
      // The card says a session not confirmed itself (Welcome, sessionend.ts endedUnconfirmed): not said twice.
      setPhase({ kind: "unlock", session: end.session, notice: heldEndNotice(kind, notice, line, kept) });
    },
    [signOut],
  );
  // `notice` (account deletion) replaces the kind's own line where the deletion's state says more.
  const endSession = useCallback((kind: SessionEndKind, notice?: string) => void endByServer(kind, notice), [endByServer]);
  // Design §4.4 (decided on 2026-11-17): a sign-in, or an open session, that this browser ends by itself (the recovery kit
  // was not confirmed in time; the account is the operator's) says the number of unsent changes before anything is
  // deleted. The sign-in's own session is already ended by its token (Welcome's abandonSignIn); an open one is revoked
  // here as at a sign-out ([kind] "user"). With nothing unsent this is the sign-out it always was. Otherwise the copy,
  // its queue and the session record stay without a pair, and the unlock card says the reason, the number (or that it
  // cannot tell) and what stays; only the person's own "Sign out" there deletes it, after its own count and second click.
  const endByClient = useCallback(
    async (notice: string, kind: "expired" | "user") => {
      const p = phaseRef.current;
      // An open vault stops now, as at a session the server ends: nothing queued goes out while the count is read.
      if (p.kind === "vault") {
        clientRef.current?.cutLiveTraffic();
        p.store.freezeAsReadOnlyCopy("ended");
      }
      const uid = loadSession()?.userId ?? null;
      const unsent = uid === null ? 0 : await unsentChangeCount(uid);
      if (unsent === 0) {
        await signOut(notice, kind);
        return;
      }
      const revoked = kind === "user" ? await revokeForSignOut(clientRef.current, lockRevokeRef.current, lockRevokeUnconfirmed(uid)) : true;
      lockRevokeRef.current = null;
      const end = endByClientDecision(clientRef.current, notice, unsent);
      if (end.kind === "sign_out") {
        await signOut(notice, kind);
        return;
      }
      usageFlushRef.current = null;
      clearBreachCache();
      if (deletedAccountRef.current === end.session.userId) return; // the deletion's own landing wins (see signOut)
      const line = revoked ? end.line : [end.line, REVOKE_UNCONFIRMED].join(" ");
      endedHereSeq.current += 1;
      setPhase({ kind: "unlock", session: end.session, notice: line, endedHere: endedHereSeq.current });
    },
    [signOut],
  );
  // The account whose session this tab holds right now — the vault's, or the unlock card's (the tab may have locked while
  // a deletion request was in flight); null on the sign-in and outcome-unknown cards. Read off the latest render.
  const liveUserId = (): string | null => {
    const p = phaseRef.current;
    return p.kind === "vault" ? p.account.userId : p.kind === "unlock" ? p.session.userId : null;
  };
  // Account deletion: what stepDeletionWatch decided — applied only to the account whose session this tab holds now, so a
  // late settle can neither pull the member off a screen that has no session nor end another account's session.
  const applyDeletionAction = useCallback(
    (a: DeletionWatchAction) => {
      if (a.kind === "none" || a.userId === null || a.userId !== liveUserId()) return;
      if (a.kind === "end_session") {
        endSession(a.end, a.notice);
        return;
      }
      const who = deletionWhoRef.current;
      void signOut(undefined, a.end, { userId: a.userId, email: who?.userId === a.userId ? who.email : (loadSession()?.email ?? "") }); // offer_forget
    },
    [endSession, signOut],
  );
  const stepDeletion = useCallback(
    (e: DeletionWatchEvent) => {
      const { watch, action } = stepDeletionWatch(deletionWatchRef.current, e);
      deletionWatchRef.current = watch;
      if (!watch.inFlight) clearDeletionHold();
      applyDeletionAction(action);
    },
    [applyDeletionAction],
  );
  // Every session end goes through the deletion watch: idle, it is the ordinary sign-out; during a deletion request it is
  // held, and acted on when the request settles (never dropped).
  const onRevoked = useCallback((kind: SessionEndKind) => stepDeletion({ kind: "session_end", end: kind, userId: liveUserId() }), [stepDeletion]);
  // A refresh with no try left ends the session here, unconfirmed: never said as the server's end (sessionEndLine).
  onRefreshRefusedRef.current = (why) => onRevoked(why === "not_confirmed" ? "unconfirmed" : "expired");
  const onDeletionTrack = useCallback(
    (event: DeletionTrack, who: { userId: string; email: string }) => {
      if (event.kind === "started") {
        deletionWhoRef.current = who;
        clearDeletionHold();
        deletionHoldTimerRef.current = setTimeout(() => {
          deletionHoldTimerRef.current = null;
          stepDeletion({ kind: "hold_expired" });
        }, DELETION_HOLD_LIMIT_MS);
      }
      stepDeletion({ ...event, userId: who.userId });
    },
    [stepDeletion],
  );

  // Which account is live in THIS tab (vault/unlock phases) — read by the storage
  // listener below, via a ref so the mount-once listener never sees a stale phase.
  const activeUserIdRef = useRef<string | null>(null);
  useEffect(() => {
    activeUserIdRef.current =
      phase.kind === "vault" ? phase.account.userId : phase.kind === "unlock" ? phase.session.userId : null;
  });

  // F27: one tab locking or signing out must land EVERY tab on the same screen.
  //  - lock → BroadcastChannel message (the session stays, storage can't carry it);
  //  - sign-out/revocation → the session key's REMOVAL arrives as a `storage` event;
  //  - a token pair rotated by another tab → adopt it, so this tab never replays the
  //    spent refresh token (belt to ApiClient.tryRefresh's in-lock re-read braces).
  useEffect(() => {
    const ch = typeof BroadcastChannel !== "undefined" ? new BroadcastChannel("andvari-lock") : null;
    lockChannelRef.current = ch;
    if (ch) ch.onmessage = () => lockLocal("Locked in another tab.");
    // A person's own sign-out in another tab: this tab drops that account's kept token too.
    const stopSignOuts = followSignOuts();
    const onStorage = (e: StorageEvent) => {
      // A14 (F5) + A14 review W4/We: the decision is tabsession.storageVerdict, tested there.
      const v = storageVerdict(e, {
        activeUserId: activeUserIdRef.current,
        have: clientRef.current?.getTokens() ?? null,
        after: loadSession(),
        keptAcrossLock: tokensKeptAcrossLock,
      });
      switch (v.kind) {
        case "signedOutElsewhere":
          // W4: without the offline copy this tab's pair is its own device session — revoked, then dropped.
          void dropOnSignOutElsewhere(clientRef.current, v.revokeOwn);
          clearTabTokens(); // A14 (F5): this tab's own pair goes with the sign-out
          setPhase((p) =>
            p.kind === "vault" || p.kind === "unlock" ? { kind: "welcome", notice: "Signed out in another tab." } : p,
          );
          return;
        case "lockWithoutRevoke":
          // Another tab turned the offline copy OFF and took the shared pair into its own sessionStorage.
          // This tab was riding that same pair, so it stops using it — without revoking, which would end
          // the other tab's session — and locks.
          void lockPerTab("The offline copy was turned off in another tab — sign in again.", v.meta, false);
          return;
        case "endedElsewhere":
          // Design §4.4: the session every tab shares was ended by the server (another tab saw the refused refresh or
          // the revoked frame). This tab's session ends too, through the same path, and keeps the copy.
          if (phaseRef.current.kind === "vault" && !phaseRef.current.readOnlyCopy) onRevoked(endedUnconfirmed(v.meta.userId) ? "unconfirmed" : "expired");
          else {
            // A tab on that session's unlock card drops the pair it still holds in memory: nothing of it may leave from here
            // (a sign-out on the card would otherwise spend its refresh token).
            const p0 = phaseRef.current;
            if (p0.kind === "unlock" && p0.session.userId === v.meta.userId) dropHeldPair(clientRef.current);
            setPhase((p) => (p.kind === "unlock" && p.session.userId === v.meta.userId ? { ...p, session: v.meta } : p));
          }
          return;
        case "adopt":
          // SAME-USER guard inside storageVerdict (shared browser): only this tab's own account. We: a
          // per-tab pair being replaced by the shared one (offline copy turned ON elsewhere) is revoked first.
          void adoptSharedPair(clientRef.current, v.tokens, v.revokeOwnFirst);
          clearTabTokens(); // A14 (F5): the shared pair supersedes this tab's own
          return;
        case "ignore":
          return;
      }
    };
    // The client found the session every tab shares gone from the record before this tab heard of it (it sent nothing,
    // ApiClient.onEndedElsewhere): the landing that event brings, as the record now stands for this tab's account (kept
    // with no pair: the server's end; anything else: a sign-out in another tab).
    endedInAnotherTabRef.current = () => {
      const landing = endedInAnotherTabLanding(loadSession(), activeUserIdRef.current);
      if (landing.kind === "event") return onStorage(landing.event as StorageEvent);
      // Another account is signed in on this browser now: this tab's pair is already dropped (nothing was sent).
      clearTabTokens();
      setPhase((p) => (p.kind === "vault" || p.kind === "unlock" ? { kind: "welcome", notice: ANOTHER_ACCOUNT_SIGNED_IN } : p));
    };
    window.addEventListener("storage", onStorage);
    return () => {
      window.removeEventListener("storage", onStorage);
      lockChannelRef.current = null;
      ch?.close();
      stopSignOuts();
    };
  }, [lockLocal, lockPerTab, onRevoked]);

  // Inactivity auto-lock (spec 01 §8): active only while a vault is open; drives the
  // SAME path as the manual Lock button (F26: session kept → Unlock card + reason).
  // The window comes from the CURRENT policy when one was fetched; when the fetch
  // failed (policy null — e.g. a transient 5xx right after login) the last
  // successfully fetched value persisted for this user takes over, so a fetch failure
  // never silently disables the lock (native SessionStore parity). §2.3 clamp (B1-1,
  // design 2026-07-15): every resolved window lands in (0, AUTO_LOCK_MAX_SECONDS] —
  // a fetched/persisted 0 or oversized value clamps (resolveAutoLockSeconds), so no
  // server can disable the lock; only the vaultUserId===null "nothing unlocked" state
  // passes 0 (timer off).
  const vaultUserId = phase.kind === "vault" ? phase.account.userId : null;
  // A14 review W5: an unlock card that still holds this tab's pair (a reload while unlocked, on a
  // browser without the offline copy) runs the same policy idle timer; when it fires the tab takes the
  // per-tab lock, revoking and dropping the pair.
  const idleUserId = idleTimerUserId(vaultUserId, phase.kind === "unlock" ? phase.session : null, tokensKeptAcrossLock);
  // Design §12.2 rule 7: after each card refresh in an open session, a verified card naming this account as the
  // operator (a handover made this member the operator) signs it out with the operator sentence.
  useEffect(() => {
    const pins = ctxRef.current?.pins;
    if (vaultUserId === null || !pins) return;
    return pins.onPinned((pin) => {
      if (cardNamesOperator(pin, vaultUserId)) void endByClient(OPERATOR_NOT_ON_WEB, "user"); // "user": revoked server-side too
    });
  }, [vaultUserId, endByClient]);
  // Design §4.4: a fork (or a damaged pin) found while the vault is open — by the refresh beside a sync, the policy probe
  // or another tab — stops traffic at once and freezes the store as the read-only copy; the vault then shows the fork
  // warning. The usage flush and the events socket go with it (Vault's effects key on readOnlyCopy).
  useEffect(() => {
    const ctx = ctxRef.current;
    if (vaultUserId === null || !ctx) return;
    const react = () => {
      const p = phaseRef.current;
      if (p.kind !== "vault" || !stopSessionTraffic(ctx, p.store)) return;
      usageFlushRef.current = null; // a lock now must not flush usage to the forked origin
      setPhase((q) => (q.kind === "vault" && q.store === p.store && !q.readOnlyCopy ? { ...q, readOnlyCopy: true } : q));
    };
    react(); // a mark another tab wrote before this effect ran
    return ctx.pins.onStopped((origin) => {
      if (origin === ctx.origin) react();
    });
  }, [vaultUserId]);
  const fetchedAutoLock = policy ? policy.autoLockSeconds ?? 0 : null;
  useEffect(() => {
    if (vaultUserId === null || fetchedAutoLock === null) return;
    const { persist } = resolveAutoLockSeconds(fetchedAutoLock, null);
    if (persist !== null) writePersistedAutoLockSeconds(vaultUserId, persist);
  }, [vaultUserId, fetchedAutoLock]);
  const autoLockSeconds =
    idleUserId === null
      ? 0
      : resolveAutoLockSeconds(fetchedAutoLock, readPersistedAutoLockSeconds(idleUserId)).seconds;
  // Cut M (v2 #16): `lockWarning` is true while ~30 s remain (windows > 60 s only) — an
  // unannounced lock silently destroys open editor work, so the user gets a chance to
  // wiggle first. Rendered as a slim .banner + spoken via the persistent Announcer below.
  const phaseRef = useRef(phase);
  phaseRef.current = phase;
  // The one way a session's work ends. Whatever takes the tab off the open vault (a lock of either kind,
  // a lock announced by another tab, a sign-out, the server ending the session, an account deletion), the store it
  // leaves is closed: its fence refuses every later call of the store, its log layer and the settings flows, so nothing
  // the session started goes out afterwards, under this account's token or the next one's. The vault's own unmount
  // runs first (React tears the child down before this cleanup), so its last usage flush is made before the close.
  const openStore = phase.kind === "vault" ? phase.store : null;
  useEffect(() => {
    if (openStore === null) return;
    return () => openStore.close();
  }, [openStore]);
  // While this tab has an account open it holds that account's lock (a Web Lock, which the browser lets go when the tab
  // ends), so a forgetting of the account in another tab is refused, also where this tab's session record never got written.
  const openAccountId = phase.kind === "vault" ? phase.account.userId : null;
  useEffect(() => {
    if (openStore === null || openAccountId === null) return;
    return holdAccountOpen(openAccountId);
  }, [openStore, openAccountId]);
  const onIdle = useCallback(() => {
    const p = phaseRef.current;
    const notice = inactivityNotice(autoLockSeconds);
    if (p.kind === "vault") lock(notice);
    else if (p.kind === "unlock" && p.session.tokens) void lockPerTab(notice, p.session, true);
  }, [autoLockSeconds, lock, lockPerTab]);
  const lockWarning = useAutoLock(autoLockSeconds, onIdle);

  // 426 nudge: a persistent, non-dismissable slim bar (the Vault mustChange-banner
  // idiom) above whichever phase shell is showing. App itself never unmounts, so the
  // bar survives lock/unlock/sign-out and every in-vault navigation; it blocks
  // nothing — the server serves the web bundle, so the one Reload click IS the update.
  // BL-1: the current lock/sign-out/enroll reason line (welcome + unlock phases carry it).
  const phaseNotice =
    phase.kind === "welcome" || phase.kind === "unlock" ? phase.notice : phase.kind === "deletionUnknown" ? DELETION_MOST_LIKELY_DONE : undefined;
  // B2-11: the nudge shows only in the vault phase, and a belt against the org forbidding
  // caching between the unlock-time check and a fresh policy landing (§E.4 pin wins anyway).
  const cacheNudgeVisible = phase.kind === "vault" && cacheNudge !== null && policy?.offlineCacheAllowed !== false;
  const cacheNudgeText = cacheNudgeVisible ? (cacheNudge.state === "offered" ? CACHE_NUDGE_OFFER : CACHE_NUDGE_ACCEPTED) : "";
  const withUpgradeBar = (content: JSX.Element): JSX.Element => (
    <>
      {/* BL-1: PERSISTENT polite announcers — always mounted (present + empty at first
          paint), so the 426 pin and the lock/sign-out reason are SPOKEN when their text
          mutates in. The visible .banner below (and Welcome's .msg info notice) stay
          conditional for sighted users; the announcement never rides a conditionally-
          mounted node, which for a polite region would enter the tree already-populated
          and go silent. App itself never unmounts, so these survive every phase change. */}
      <Announcer text={upgradeStale ? UPGRADE_NOTICE : ""} />
      <Announcer text={phaseNotice ?? ""} />
      <Announcer text={lockWarning ? LOCK_WARNING_NOTICE : ""} />
      <Announcer text={cacheNudgeText} />
      <Announcer text={policyWipe ? policyWipeText(policyWipe) : ""} />
      <Announcer text={remembered.map((e) => fill(REMADE_ACCOUNT_REMEMBERED, e)).join(" ")} />
      {/* H137: print-only line (display:none on screen) — it explains the blanks a printed page
          carries where a revealed password, one-time code, card number or health table was. */}
      <p className="print-note">Secrets are hidden when printing — passwords, one-time codes, card numbers and the health tables do not appear on paper.</p>
      {upgradeStale && (
        <div className="banner">
          <span>{UPGRADE_NOTICE}</span>
          <button className="link" onClick={() => window.location.reload()}>Reload</button>
        </div>
      )}
      {policyWipe && (
        <div className="banner">
          <span>{policyWipeText(policyWipe)}</span>
          <button className="link" onClick={() => setPolicyWipe(null)}>OK</button>
        </div>
      )}
      {remembered.map((e) => (
        <div className="banner" key={e}>
          <span>{fill(REMADE_ACCOUNT_REMEMBERED, e)}</span>
          <button
            className="link"
            onClick={() => {
              dismissRemembered(e);
              setRemembered(rememberedNotices());
            }}
          >
            OK
          </button>
        </div>
      ))}
      {/* Cut M (v2 #16): pre-lock countdown notice. No dismiss button — ANY tracked
          activity (including tapping the banner) clears it via the hook; a dedicated
          button would just be a slower way to move the pointer. */}
      {lockWarning && (
        <div className="banner">
          <span>{LOCK_WARNING_NOTICE}</span>
        </div>
      )}
      {/* B2-11 one-time offline-copy nudge (design 2026-07-15 §5.4.1): answered with a marker
          either way, so it fires at most once per (origin, device) — one tap re-gains offline
          access after an origin move instead of it silently vanishing. */}
      {cacheNudgeVisible && cacheNudge.state === "offered" && (
        <div className="banner">
          <span>{CACHE_NUDGE_OFFER}</span>
          <button className="link" onClick={onCacheNudgeKeep}>Keep a copy</button>
          <button className="link" onClick={onCacheNudgeDecline}>Not on this device</button>
        </div>
      )}
      {cacheNudgeVisible && cacheNudge.state === "accepted" && (
        <div className="banner">
          <span>{CACHE_NUDGE_ACCEPTED}</span>
          <button className="link" onClick={() => setCacheNudge(null)}>OK</button>
        </div>
      )}
      {content}
    </>
  );

  if (phase.kind === "loading") {
    return withUpgradeBar(
      <div className="auth-shell">
        <div className="card">
          <div className="card-hero" style={{ marginBottom: 0 }}>
            <div className="sigil"><BrandSigil /></div>
            {/* UI-audit #24: the boot wait (sodium + policy fetch) visibly moves. */}
            <p className="muted"><Busy>Unsealing…</Busy></p>
          </div>
        </div>
      </div>
    );
  }

  if (phase.kind === "vault") {
    // Read once per render: the deletion hand-off below must still know the address if a racing `revoked` frame has
    // already cleared the session by the time the deletion's answer arrives.
    const vaultEmail = loadSession()?.email ?? "";
    const deletingUserId = phase.account.userId;
    return withUpgradeBar(
      <Vault
        account={phase.account}
        store={phase.store}
        client={phase.meta.client}
        usageWire={phase.meta.usageWire}
        settings={phase.meta.settings}
        email={vaultEmail}
        policy={policy}
        readOnlyCopy={phase.readOnlyCopy}
        openedFromCopy={phase.meta.openedFrom === "offline"}
        copySealedElsewhere={phase.meta.copySealedElsewhere === true}
        isAdmin={false}
        mustChangePassword={false}
        offlineRecoveryReminder={false}
        onLock={onManualLock}
        onRevoked={onRevoked}
        registerUsageFlush={(fn) => {
          usageFlushRef.current = fn;
        }}
        onAccountDeleted={(end) => onAccountDeleted(deletingUserId, vaultEmail, end)}
        onDeletionTrack={(event) => onDeletionTrack(event, { userId: deletingUserId, email: vaultEmail })}
      />
    );
  }

  if (phase.kind === "deletionUnknown") {
    const p = phase;
    return withUpgradeBar(
      <DeletionOutcomeUnknownCard
        notice={p.notice}
        onForget={() => onAccountDeleted(p.userId, p.email, "forgotten")}
        onSignIn={() => setPhase({ kind: "welcome" })}
      />,
    );
  }

  return withUpgradeBar(
    <Welcome
      key={phase.kind === "unlock" && phase.endedHere !== undefined ? `ended-here-${phase.endedHere}` : "welcome"}
      ctx={ctxRef.current!}
      policy={policy}
      policyError={policyError}
      policyErrorMessage={policyErrorMessage}
      onRetryPolicy={loadPolicy}
      mode={phase.kind === "unlock" ? { unlock: phase.session } : { fresh: true }}
      notice={phase.notice}
      knownEmail={phase.kind === "welcome" ? phase.knownEmail : undefined}
      onReady={onUnlocked}
      // §E.4: the Unlock card's "Sign out / use a different account" calls onForget() with NO
      // notice → a USER sign-out (SignOutLink asked first, with the count). With a notice it is a
      // sign-in this browser ended by itself (the kit timed out; the operator account), whose own
      // session Welcome already ended: endByClient says the unsent count before anything is deleted.
      onForget={(notice?: string) => void (notice ? endByClient(notice, "expired") : signOut(undefined, "user"))}
      endedByBrowser={phase.kind === "unlock" && phase.endedHere !== undefined}
      // Design §4.4: the unlock card found the session gone server-side (a definitive 401). It ends as every session the
      // server ends does, through the deletion watch: the copy stays when the offline copy is on.
      onSessionEnded={() => onRevoked("expired")}
    />
  );
}
