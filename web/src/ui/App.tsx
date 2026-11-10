import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { ApiClient, type SessionEndKind } from "../api/client";
import type { ClientPolicy } from "../api/types";
import { initSodium } from "../crypto/sodium";
import { KdfPolicyError, WEAK_KDF_MESSAGE } from "../crypto/keys";
import { Account } from "../vault/account";
import { VaultStore } from "../vault/store";
import { Welcome, type LoginMeta } from "./Welcome";
import { peekPendingEnroll } from "../enroll/enrolllink";
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
  claimTabTokens,
  clearLockRevoke,
  clearSession,
  clearTabTokens,
  declineCacheNudge,
  defaultBaseUrl,
  loadSession,
  LOCK_REVOKE_UNCONFIRMED,
  lockRevokeUnconfirmed,
  makeClient,
  migrateCacheConsentOnce,
  migrateLegacySessionTokens,
  pendingSyncCount,
  recordLockRevoke,
  REVOKE_UNCONFIRMED,
  setOfflineCopyEnabled,
  shouldOfferCacheNudge,
  tokensKeptAcrossLock,
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
  IDLE_DELETION_WATCH,
  stepDeletionWatch,
} from "./account-delete";
import { DeletionOutcomeUnknownCard, type DeletionEnd, type DeletionTrack } from "./DeleteAccount";
import { adoptSharedPair, dropOnSignOutElsewhere, idleTimerUserId, lockTabTokens, revokeForSignOut, storageVerdict } from "./tabsession";

/** `notice` (F26): one-line reason rendered on the auth card — why the user is looking
 *  at a lock/sign-in screen ("Locked.", "This device's access was revoked.", …). */
type Phase =
  | { kind: "loading" }
  | { kind: "welcome"; notice?: string }
  | { kind: "unlock"; session: Session; notice?: string }
  | { kind: "vault"; account: Account; store: VaultStore; meta: LoginMeta }
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
const CACHE_NUDGE_OFFER =
  "Keep an encrypted offline copy of your vault on this device? A tab you already have open could then unlock even when the server can't be reached.";
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
  const [baseUrl] = useState(defaultBaseUrl());
  const clientRef = useRef<ApiClient | null>(null);

  const loadPolicy = useCallback(async () => {
    try {
      const p = await clientRef.current!.clientPolicy();
      setPolicy(p);
      setPolicyError(false);
      setPolicyErrorMessage(undefined);
      // §E.4 policy row (design 2026-07-13-web-offline-cache / spec 02 §8): EVERY successful
      // ClientPolicy fetch re-evaluates offlineCacheAllowed. false ⇒ force-wipe this account's
      // cache DB (queue included — server-initiated, cannot be blocked) + pin the last-known bit
      // so an OFFLINE boot keeps honoring it; true ⇒ clear the pin. The pin write inside is
      // synchronous (webCacheEnabled consults it immediately); only the wipe is fire-and-forget
      // (deleteDatabase self-completes via the sibling versionchange, idbcache §D.5.3). This runs
      // at boot and at every unlock (onUnlocked → loadPolicy), the spec's re-evaluation points.
      if (p && typeof p === "object") {
        void applyOrgOfflineCachePolicy(p.offlineCacheAllowed !== false, loadSession()?.userId ?? null);
      }
    } catch (e) {
      setPolicy(null);
      setPolicyError(true);
      // H1 (spec 05 T1): a weakened-KDF policy is a security block, NOT a transient "unavailable" —
      // keep the distinct signal so enrollment shows the weak-KDF warning, never "try again".
      setPolicyErrorMessage(e instanceof KdfPolicyError ? WEAK_KDF_MESSAGE : undefined);
    }
  }, []);

  useEffect(() => {
    (async () => {
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
      clientRef.current = client;
      await loadPolicy();
      // One-scan onboarding: a captured enroll link is consumed on the signed-OUT Welcome
      // (FreshStart prefills the Enroll tab). If a session already exists we boot to Unlock —
      // surface a notice instead of silently swallowing the scanned link (never repoint the
      // session's server from a link).
      const pendingEnroll = peekPendingEnroll();
      // A14 (F5): on a browser without the offline copy a session with no tokens (after a lock, or a
      // new tab) still lands on the unlock card, which then runs the normal sign-in. With the offline
      // copy on, today's rule stands: no tokens, no unlock card.
      const unlockable = session !== null && (session.tokens !== null || !tokensKeptAcrossLock(session.userId));
      setPhase(
        unlockable ? { kind: "unlock", session, notice: pendingEnroll ? "You're signed in on this browser. To set up a NEW account from that invite link, sign out first." : undefined }
          : { kind: "welcome" },
      );
    })();
  }, [baseUrl, loadPolicy]);

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
    lockRevokeRef.current = null; // A14 review W1: this tab holds a new pair; an older lock's record is moot
    clearLockRevoke(); // ...and so is the copy of it in the tab's sessionStorage (A14 review 3, W-b)
    setPhase({ kind: "vault", account, store, meta });
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
  // offline cache — user sign-out, `onRevoked` (WS revoked/expired), and the definitive-401
  // routed here from Welcome's Unlock card all destroy this account's cache DB (envelopes +
  // queue + cached accountKeys). A LOCK does NOT come here, so the cache is RETAINED on lock.
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
  const signOut = useCallback(async (notice?: string, kind: "user" | "expired" | "revoked" = "user", deletionUnknown?: { userId: string; email: string }) => {
    const uid = loadSession()?.userId ?? null;
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
    const lostCount =
      kind === "expired" && unsynced > 0
        ? `${notice ? notice + " " : ""}${unsynced} offline ${unsynced === 1 ? "change" : "changes"} could not be synced — this session expired before reconnecting.`
        : notice;
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
    clearSession();
    clientRef.current?.setTokens(null);
    if (uid) void wipeVaultCache(uid);
    clearBreachCache(); // CR-08: the in-session HIBP breach map is dropped at the wipe choke point
    // Account deletion: the server's `revoked` frame to this tab can start this sign-out just before the deletion's own
    // answer lands; onAccountDeleted then did the wipe and owns the landing (its notice), so don't overwrite it here.
    if (uid !== null && deletedAccountRef.current === uid) return;
    const line = revoked ? lostCount : [lostCount, REVOKE_UNCONFIRMED].filter(Boolean).join(" ");
    setPhase(deletionUnknown ? { kind: "deletionUnknown", ...deletionUnknown, notice: line } : { kind: "welcome", notice: line });
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
    void wipeLocalAccountState(userId, email);
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
  // land (bounded), revokes THIS tab's pair server-side (best-effort, LOGOUT_TIMEOUT_MS; logout()
  // captures the pair synchronously, so dropping it on the next line is safe), drops it, and lands
  // on the unlock card, which then runs the normal sign-in (email pre-filled, TOTP when enrolled).
  // [revoke] is false only when another tab took over this pair (it turned the offline copy off):
  // revoking would end THAT tab's session too.
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
      void lockPerTab(notice, meta, true);
      return;
    }
    setPhase((p) => {
      if (p.kind !== "vault") return p; // nothing unlocked here — nothing to lock
      const session = loadSession();
      // No persisted session to come back to (shouldn't happen) — fall back to sign-in.
      return session?.tokens ? { kind: "unlock", session, notice } : { kind: "welcome", notice };
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
  // The session died server-side, so a mere unlock could never succeed — both kinds
  // are a full sign-out (F26) — but the COPY must be truthful: only the server's
  // explicit WS `revoked` frame is a revocation; a dead session at ticket mint is
  // ordinary expiry (laptop asleep past the refresh lifetime) and saying "revoked"
  // there would be a false alarm.
  // `notice` (account deletion) replaces the kind's own line where the deletion's state says more.
  const endSession = useCallback(
    (kind: SessionEndKind, notice?: string) =>
      kind === "revoked"
        ? void signOut(notice ?? "This device's access was revoked.", "revoked") // server-initiated: silent-drop
        : void signOut(notice ?? "Your session ended — sign in again.", "expired"), // expiry: surface the lost count
    [signOut],
  );
  // Account deletion: what stepDeletionWatch decided. Only the vault and unlock phases still hold a session to end (the
  // tab may have locked while the request was in flight); once the session is gone — the outcome-unknown card, or the
  // sign-in card after the deletion's own wipe — a late settle must not pull the member off that screen.
  const applyDeletionAction = useCallback(
    (a: DeletionWatchAction) => {
      const phaseKind = phaseRef.current.kind;
      if (a.kind === "none" || (phaseKind !== "vault" && phaseKind !== "unlock")) return;
      if (a.kind === "end_session") endSession(a.end, a.notice);
      else void signOut(undefined, a.end, deletionWhoRef.current ?? undefined); // offer_forget
    },
    [endSession, signOut],
  );
  const stepDeletion = useCallback(
    (e: DeletionTrack) => {
      const { watch, action } = stepDeletionWatch(deletionWatchRef.current, e);
      deletionWatchRef.current = watch;
      if (!watch.inFlight) clearDeletionHold();
      applyDeletionAction(action);
    },
    [applyDeletionAction],
  );
  // Every session end goes through the deletion watch: idle, it is the ordinary sign-out; during a deletion request it is
  // held, and acted on when the request settles (never dropped).
  const onRevoked = useCallback((kind: SessionEndKind) => stepDeletion({ kind: "session_end", end: kind }), [stepDeletion]);
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
      stepDeletion(event);
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
    window.addEventListener("storage", onStorage);
    return () => {
      window.removeEventListener("storage", onStorage);
      lockChannelRef.current = null;
      ch?.close();
    };
  }, [lockLocal, lockPerTab]);

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
      {/* H137: print-only line (display:none on screen) — it explains the blanks a printed page
          carries where a revealed password, one-time code, card number or health table was. */}
      <p className="print-note">Secrets are hidden when printing — passwords, one-time codes, card numbers and the health tables do not appear on paper.</p>
      {upgradeStale && (
        <div className="banner">
          <span>{UPGRADE_NOTICE}</span>
          <button className="link" onClick={() => window.location.reload()}>Reload</button>
        </div>
      )}
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
        client={clientRef.current!}
        email={vaultEmail}
        policy={policy}
        isAdmin={phase.meta.isAdmin}
        mustChangePassword={phase.meta.mustChangePassword}
        escrowStale={phase.meta.escrowStale}
        escrowNeedsV2={phase.meta.escrowNeedsV2 ?? false}
        escrowFingerprint={phase.meta.escrowFingerprint}
        offlineRecoveryReminder={phase.meta.offlineRecoveryReminder ?? false}
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
      client={clientRef.current!}
      policy={policy}
      policyError={policyError}
      policyErrorMessage={policyErrorMessage}
      onRetryPolicy={loadPolicy}
      mode={phase.kind === "unlock" ? { unlock: phase.session } : { fresh: true }}
      notice={phase.notice}
      onReady={onUnlocked}
      // §E.4: the Unlock card's "Sign out / use a different account" calls onForget() with NO
      // notice → a USER sign-out (blocking confirm if the queue is non-empty, breaker #9); a
      // definitive-401 calls onForget("Session expired…") → an EXPIRED wipe (surfaces the count,
      // cannot block). Both route through signOut, the one wipe choke point.
      onForget={(notice?: string) => void signOut(notice, notice ? "expired" : "user")}
    />
  );
}
