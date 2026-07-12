import { useCallback, useEffect, useRef, useState } from "react";
import { ApiClient, type SessionEndKind } from "../api/client";
import type { ClientPolicy } from "../api/types";
import { initSodium } from "../crypto/sodium";
import { Account } from "../vault/account";
import { VaultStore } from "../vault/store";
import { Welcome, type LoginMeta } from "./Welcome";
import { peekPendingEnroll } from "../enroll/enrolllink";
import { BrandSigil } from "./Sigil";
import { Vault } from "./Vault";
import { Announcer } from "./Msg";
import { inactivityNotice } from "./format";
import {
  readPersistedAutoLockSeconds,
  resolveAutoLockSeconds,
  useAutoLock,
  writePersistedAutoLockSeconds,
} from "./useAutoLock";
import {
  clearSession,
  defaultBaseUrl,
  loadSession,
  makeClient,
  SESSION_STORAGE_KEY,
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

export function App() {
  const [phase, setPhase] = useState<Phase>({ kind: "loading" });
  const [policy, setPolicy] = useState<ClientPolicy | null>(null);
  // Distinct from `policy === null`: true means the policy fetch FAILED (can't reach the
  // server), false means it succeeded (so an empty recoveryFingerprint genuinely means no
  // recovery key). Without this, a transient fetch failure shows the scary — and now false —
  // "escrow ceremony isn't done" message during enrollment.
  const [policyError, setPolicyError] = useState(false);
  // 426 min-version pin tripped (api/client.ts onUpgradeRequired): this tab's bundle
  // is older than the server's pin, and every gated API call keeps failing until the
  // tab reloads — sticky once set; only the reload itself clears it.
  const [upgradeStale, setUpgradeStale] = useState(false);
  const [baseUrl] = useState(defaultBaseUrl());
  const clientRef = useRef<ApiClient | null>(null);

  const loadPolicy = useCallback(async () => {
    try {
      setPolicy(await clientRef.current!.clientPolicy());
      setPolicyError(false);
    } catch {
      setPolicy(null);
      setPolicyError(true);
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
  const signOut = useCallback((notice?: string) => {
    clearSession();
    clientRef.current?.setTokens(null);
    setPhase({ kind: "welcome", notice });
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
      signOut(kind === "revoked" ? "This device's access was revoked." : "Your session ended — sign in again."),
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
  useAutoLock(autoLockSeconds, () => lock(inactivityNotice(autoLockSeconds)));

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
      {upgradeStale && (
        <div className="banner">
          <span>{UPGRADE_NOTICE}</span>
          <button className="link" onClick={() => window.location.reload()}>Reload</button>
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
            <p className="muted">unsealing…</p>
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
      onRetryPolicy={loadPolicy}
      mode={phase.kind === "unlock" ? { unlock: phase.session } : { fresh: true }}
      notice={phase.notice}
      onReady={onUnlocked}
      onForget={() => signOut()}
    />
  );
}
