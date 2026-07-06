import { useEffect, useRef, useState } from "react";
import { ApiClient } from "../api/client";
import type { ClientPolicy } from "../api/types";
import { initSodium } from "../crypto/sodium";
import { Account } from "../vault/account";
import { VaultStore } from "../vault/store";
import { Welcome, type LoginMeta } from "./Welcome";
import { Vault } from "./Vault";
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
  const [baseUrl] = useState(defaultBaseUrl());
  const clientRef = useRef<ApiClient | null>(null);

  useEffect(() => {
    (async () => {
      await initSodium();
      const session = loadSession();
      const client = makeClient(session, baseUrl);
      clientRef.current = client;
      try {
        setPolicy(await client.clientPolicy());
      } catch {
        setPolicy(null);
      }
      setPhase(session?.tokens ? { kind: "unlock", session } : { kind: "welcome" });
    })();
  }, [baseUrl]);

  const onUnlocked = (account: Account, store: VaultStore, meta: LoginMeta) =>
    setPhase({ kind: "vault", account, store, meta });

  const onLoggedOut = () => {
    clearSession();
    clientRef.current?.setTokens(null);
    setPhase({ kind: "welcome" });
  };

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
      mode={phase.kind === "unlock" ? { unlock: phase.session } : { fresh: true }}
      onReady={onUnlocked}
      onForget={onLoggedOut}
    />
  );
}
