import { useCallback, useEffect, useRef, useState } from "react";
import { ApiClient } from "../api/client";
import type { ClientPolicy } from "../api/types";
import { initSodium } from "../crypto/sodium";
import { Account } from "../vault/account";
import { VaultStore } from "../vault/store";
import { Welcome, type LoginMeta } from "./Welcome";
import { Vault } from "./Vault";
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
  type Session,
} from "./session";

type Phase =
  | { kind: "loading" }
  | { kind: "welcome" }
  | { kind: "unlock"; session: Session }
  | { kind: "vault"; account: Account; store: VaultStore; meta: LoginMeta };

export function App() {
  const [phase, setPhase] = useState<Phase>({ kind: "loading" });
  const [policy, setPolicy] = useState<ClientPolicy | null>(null);
  // Distinct from `policy === null`: true means the policy fetch FAILED (can't reach the
  // server), false means it succeeded (so an empty recoveryFingerprint genuinely means no
  // recovery key). Without this, a transient fetch failure shows the scary — and now false —
  // "escrow ceremony isn't done" message during enrollment.
  const [policyError, setPolicyError] = useState(false);
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
      clientRef.current = client;
      await loadPolicy();
      setPhase(session?.tokens ? { kind: "unlock", session } : { kind: "welcome" });
    })();
  }, [baseUrl, loadPolicy]);

  const onUnlocked = (account: Account, store: VaultStore, meta: LoginMeta) => {
    setPhase({ kind: "vault", account, store, meta });
    // Refresh policy at unlock so the auto-lock/clipboard windows reflect the CURRENT
    // org policy — via loadPolicy so a success also clears a stale policyError from a
    // failed boot-time fetch (otherwise Enroll later shows a false "couldn't reach").
    void loadPolicy();
  };

  // Stable identity: Vault's WS-subscription effect depends on this — a fresh closure per
  // render would tear down and re-mint the events socket on every App re-render.
  const onLoggedOut = useCallback(() => {
    clearSession();
    clientRef.current?.setTokens(null);
    setPhase({ kind: "welcome" });
  }, []);

  // Inactivity auto-lock (spec 01 §8): active only while a vault is open; drives the
  // SAME path as the manual Lock button (session cleared, keys dropped with the phase).
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
  useAutoLock(
    vaultUserId === null
      ? 0
      : resolveAutoLockSeconds(fetchedAutoLock, readPersistedAutoLockSeconds(vaultUserId)).seconds,
    onLoggedOut,
  );

  if (phase.kind === "loading") {
    return (
      <div className="auth-shell">
        <div className="card-hero">
          <div className="sigil">ᛅ</div>
          <p className="muted">unsealing…</p>
        </div>
      </div>
    );
  }

  if (phase.kind === "vault") {
    return (
      <Vault
        account={phase.account}
        store={phase.store}
        client={clientRef.current!}
        policy={policy}
        isAdmin={phase.meta.isAdmin}
        mustChangePassword={phase.meta.mustChangePassword}
        onLock={onLoggedOut}
      />
    );
  }

  return (
    <Welcome
      client={clientRef.current!}
      policy={policy}
      policyError={policyError}
      onRetryPolicy={loadPolicy}
      mode={phase.kind === "unlock" ? { unlock: phase.session } : { fresh: true }}
      onReady={onUnlocked}
      onForget={onLoggedOut}
    />
  );
}
