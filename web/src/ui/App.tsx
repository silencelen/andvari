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
  clearSession,
  defaultBaseUrl,
  loadSession,
  makeClient,
  pendingSyncCount,
  SESSION_STORAGE_KEY,
  wipeVaultCache,
  type Session,
} from "./session";

/** `notice` (F26): one-line reason rendered on the auth card — why the user is looking
 *  at a lock/sign-in screen ("Locked.", "This device's access was revoked.", …). */
type Phase =
  | { kind: "loading" }
  | { kind: "welcome"; notice?: string }
  | { kind: "unlock"; session: Session; notice?: string }
  | { kind: "vault"; account: Account; store: VaultStore; meta: LoginMeta };

const UPGRADE_NOTICE = "This tab is running an older version — reload to update.";
// Cut M (v2 #16): pre-lock warning copy — the listed gestures are exactly the activity
// events useAutoLock tracks (pointer/key/touch), so doing any of them keeps the vault open.
const LOCK_WARNING_NOTICE = "Still there? Locking soon — click, tap, or press a key to stay unlocked.";

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
      setPhase(
        session?.tokens
          ? { kind: "unlock", session, notice: pendingEnroll ? "You're signed in on this browser. To set up a NEW account from that invite link, sign out first." : undefined }
          : { kind: "welcome" },
      );
    })();
  }, [baseUrl, loadPolicy]);

  const onUnlocked = (account: Account, store: VaultStore, meta: LoginMeta) => {
    setPhase({ kind: "vault", account, store, meta });
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
  //  - "user"    (the Sign-out button): BLOCK on an explicit confirm carrying the count;
  //  - "expired" (definitive-401 / WS session-end): cannot be blocked (spec 02 §8), but the
  //               count is SURFACED in the notice so the loss is never silent;
  //  - "revoked" (server WS revoked frame): silent-drop (spec 03 §4 accepts it).
  const signOut = useCallback(async (notice?: string, kind: "user" | "expired" | "revoked" = "user") => {
    const uid = loadSession()?.userId ?? null;
    const unsynced = uid ? await pendingSyncCount(uid) : 0;
    if (kind === "user" && unsynced > 0) {
      const ok =
        typeof window !== "undefined" && typeof window.confirm === "function"
          ? window.confirm(`${unsynced} unsynced ${unsynced === 1 ? "change" : "changes"} will be permanently lost if you sign out on this device. Sign out anyway?`)
          : true;
      if (!ok) return; // aborted — session, tokens, and cache are untouched
    }
    const lostCount =
      kind === "expired" && unsynced > 0
        ? `${notice ? notice + " " : ""}${unsynced} offline ${unsynced === 1 ? "change" : "changes"} could not be synced — this session expired before reconnecting.`
        : notice;
    clearSession();
    clientRef.current?.setTokens(null);
    if (uid) void wipeVaultCache(uid);
    clearBreachCache(); // CR-08: the in-session HIBP breach map is dropped at the wipe choke point
    setPhase({ kind: "welcome", notice: lostCount });
  }, []);

  // F26/F27 lock propagation channel: locking KEEPS the persisted session, so the
  // `storage` event can no longer signal it — locks are announced explicitly.
  const lockChannelRef = useRef<BroadcastChannel | null>(null);

  // F26: lock drops this tab's keys (the phase change unmounts Vault, releasing the
  // Account/VaultStore) but KEEPS the persisted session and tokens, so the user lands
  // on the lighter master-password-only Unlock card with a reason line. Same ZK
  // posture as sign-out: unlock re-derives every key from the password; no secret is
  // ever persisted (spec 01 §8).
  const lockLocal = useCallback((notice: string) => {
    setPhase((p) => {
      if (p.kind !== "vault") return p; // nothing unlocked here — nothing to lock
      const session = loadSession();
      // No persisted session to come back to (shouldn't happen) — fall back to sign-in.
      return session?.tokens ? { kind: "unlock", session, notice } : { kind: "welcome", notice };
    });
  }, []);

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
  const onRevoked = useCallback(
    (kind: SessionEndKind) =>
      kind === "revoked"
        ? void signOut("This device's access was revoked.", "revoked") // server-initiated: silent-drop
        : void signOut("Your session ended — sign in again.", "expired"), // expiry: surface the lost count
    [signOut],
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
      if (e.key !== SESSION_STORAGE_KEY) return;
      if (e.newValue === null) {
        clientRef.current?.setTokens(null);
        setPhase((p) =>
          p.kind === "vault" || p.kind === "unlock" ? { kind: "welcome", notice: "Signed out in another tab." } : p,
        );
      } else {
        // SAME-USER guard (shared browser): the persisted session may now belong to a
        // DIFFERENT account (someone signed in as Y while X's tab was frozen) — never
        // graft Y's pair into X's live client.
        const cur = loadSession();
        const t = cur?.tokens;
        const have = clientRef.current?.getTokens();
        if (
          cur &&
          t &&
          clientRef.current &&
          cur.userId === activeUserIdRef.current &&
          (!have || have.refreshToken !== t.refreshToken)
        ) {
          clientRef.current.setTokens(t);
        }
      }
    };
    window.addEventListener("storage", onStorage);
    return () => {
      window.removeEventListener("storage", onStorage);
      lockChannelRef.current = null;
      ch?.close();
    };
  }, [lockLocal]);

  // Inactivity auto-lock (spec 01 §8): active only while a vault is open; drives the
  // SAME path as the manual Lock button (F26: session kept → Unlock card + reason).
  // The window comes from the CURRENT policy when one was fetched; when the fetch
  // failed (policy null — e.g. a transient 5xx right after login) the last
  // successfully fetched value persisted for this user takes over, so a fetch failure
  // never silently disables the lock (native SessionStore parity). A fetched 0 is
  // authoritative: it disables the lock AND overwrites any stale non-zero fallback.
  const vaultUserId = phase.kind === "vault" ? phase.account.userId : null;
  const fetchedAutoLock = policy ? policy.autoLockSeconds ?? 0 : null;
  useEffect(() => {
    if (vaultUserId === null || fetchedAutoLock === null) return;
    const { persist } = resolveAutoLockSeconds(fetchedAutoLock, null);
    if (persist !== null) writePersistedAutoLockSeconds(vaultUserId, persist);
  }, [vaultUserId, fetchedAutoLock]);
  const autoLockSeconds =
    vaultUserId === null
      ? 0
      : resolveAutoLockSeconds(fetchedAutoLock, readPersistedAutoLockSeconds(vaultUserId)).seconds;
  // Cut M (v2 #16): `lockWarning` is true while ~30 s remain (windows > 60 s only) — an
  // unannounced lock silently destroys open editor work, so the user gets a chance to
  // wiggle first. Rendered as a slim .banner + spoken via the persistent Announcer below.
  const lockWarning = useAutoLock(autoLockSeconds, () => lock(inactivityNotice(autoLockSeconds)));

  // 426 nudge: a persistent, non-dismissable slim bar (the Vault mustChange-banner
  // idiom) above whichever phase shell is showing. App itself never unmounts, so the
  // bar survives lock/unlock/sign-out and every in-vault navigation; it blocks
  // nothing — the server serves the web bundle, so the one Reload click IS the update.
  // BL-1: the current lock/sign-out/enroll reason line (welcome + unlock phases carry it).
  const phaseNotice = phase.kind === "welcome" || phase.kind === "unlock" ? phase.notice : undefined;
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
            <p className="muted"><Busy>unsealing…</Busy></p>
          </div>
        </div>
      </div>
    );
  }

  if (phase.kind === "vault") {
    return withUpgradeBar(
      <Vault
        account={phase.account}
        store={phase.store}
        client={clientRef.current!}
        email={loadSession()?.email ?? ""}
        policy={policy}
        isAdmin={phase.meta.isAdmin}
        mustChangePassword={phase.meta.mustChangePassword}
        escrowStale={phase.meta.escrowStale}
        escrowFingerprint={phase.meta.escrowFingerprint}
        offlineRecoveryReminder={phase.meta.offlineRecoveryReminder ?? false}
        onLock={onManualLock}
        onRevoked={onRevoked}
      />
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
