import { useMemo, useState } from "react";
import type { ApiClient } from "../api/client";
import type { AccountDeletePreview } from "../api/types";
import type { Account } from "../vault/account";
import type { VaultStore } from "../vault/store";
import {
  BLOCKED_UNEXPLAINED,
  blockerLines,
  type BlockerLine,
  type BlockerLink,
  deletionSummary,
  emailConfirmed,
  OUTCOME_UNKNOWN,
  previewErrorText,
  runAccountDeletion,
  totpDigits,
} from "./account-delete";
import { Busy } from "./Busy";
import { Field } from "./Field";
import { Announcer, Msg } from "./Msg";

/**
 * Settings → Delete account (spec 03 §13; design docs/design/2026-11-10-account-deletion.md §11). Closed, the card is one
 * paragraph and a button. Opened, it fetches the preview and says what goes for good and which vaults the member leaves;
 * blockers, when there are any, are listed with a link to where each is resolved and the form is not offered; otherwise
 * the member types their address, the master password and (when enrolled) the code. A confirmed deletion hands off to
 * App, which wipes this browser's state for the account and lands on the sign-in card.
 */

export interface DeleteAccountView {
  open: boolean;
  loading: boolean;
  previewError: string;
  summary: { deletes: string[]; leaves: string[] } | null;
  /** null: none known. An empty array: the server refused without naming anything (still blocked). */
  blockers: BlockerLine[] | null;
  totpRequired: boolean;
  typedEmail: string;
  password: string;
  totp: string;
  canSubmit: boolean;
  busy: boolean;
  err: string;
  unknownOutcome: boolean;
}

/** The card body — a pure function of the view (the node-env static-render posture; see account-delete.test.ts). */
export function DeleteAccountBody({
  view,
  onOpen,
  onCancel,
  onTypedEmail,
  onPassword,
  onTotp,
  onSubmit,
  onLink,
  onBackup,
}: {
  view: DeleteAccountView;
  onOpen: () => void;
  onCancel: () => void;
  onTypedEmail: (v: string) => void;
  onPassword: (v: string) => void;
  onTotp: (v: string) => void;
  onSubmit: () => void;
  onLink: (link: BlockerLink) => void;
  onBackup?: () => void;
}) {
  const v = view;
  const blocked = v.blockers !== null;
  return (
    <div className="sheet">
      <h2>Delete account</h2>
      <p className="muted" style={{ marginTop: 0 }}>
        Permanently delete your andvari account and everything only you hold on this server. Vaults you share with other
        people stay with them.
      </p>
      <Announcer text={v.err || (v.unknownOutcome ? OUTCOME_UNKNOWN : "")} />
      {!v.open ? (
        <div className="actions">
          <button type="button" className="ghost" style={{ color: "var(--danger)" }} onClick={onOpen}>Delete my account…</button>
        </div>
      ) : v.loading ? (
        <p className="muted"><Busy>Checking what would be deleted…</Busy></p>
      ) : v.previewError ? (
        <>
          <Msg kind="err">{v.previewError}</Msg>
          <div className="actions">
            <button type="button" className="ghost" onClick={onCancel}>Close</button>
          </div>
        </>
      ) : (
        <>
          {v.summary && (
            <>
              <p style={{ marginBottom: 4 }}><strong>Deleting your account removes, for good:</strong></p>
              <ul>{v.summary.deletes.map((line) => <li key={line}>{line}</li>)}</ul>
              {v.summary.leaves.map((line) => <p key={line}>{line}</p>)}
              <p>
                This can't be undone.
                {onBackup && (
                  <>
                    {" "}
                    <button type="button" className="link" onClick={onBackup}>Back up your vault first</button>
                  </>
                )}
              </p>
            </>
          )}
          {blocked ? (
            <>
              <Msg kind="err">Your account can't be deleted yet:</Msg>
              <ul>
                {(v.blockers!.length > 0 ? v.blockers! : [{ text: BLOCKED_UNEXPLAINED, link: null, linkLabel: "" }]).map((b) => (
                  <li key={b.text}>
                    {b.text}
                    {b.link && (
                      <>
                        {" "}
                        <button type="button" className="link" onClick={() => onLink(b.link!)}>{b.linkLabel}</button>
                      </>
                    )}
                  </li>
                ))}
              </ul>
              <div className="actions">
                <button type="button" className="ghost" onClick={onCancel}>Close</button>
              </div>
            </>
          ) : (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                if (v.canSubmit && !v.busy) onSubmit();
              }}
            >
              <Field label="Type your email address to confirm" prompt>
                <input type="email" autoComplete="off" spellCheck={false} value={v.typedEmail} disabled={v.busy} onChange={(e) => onTypedEmail(e.target.value)} />
              </Field>
              <Field label="Master password">
                <input type="password" autoComplete="current-password" value={v.password} disabled={v.busy} onChange={(e) => onPassword(e.target.value)} />
              </Field>
              {v.totpRequired && (
                <Field label="Code from your authenticator app">
                  <input className="mono" inputMode="numeric" autoComplete="one-time-code" placeholder="123 456" value={v.totp} disabled={v.busy} onChange={(e) => onTotp(e.target.value)} />
                </Field>
              )}
              {v.err && <Msg kind="err">{v.err}</Msg>}
              {v.unknownOutcome && <Msg kind="err">{OUTCOME_UNKNOWN}</Msg>}
              <div className="actions">
                <button type="submit" className="ghost" style={{ color: "var(--danger)" }} disabled={!v.canSubmit || v.busy}>
                  {v.busy ? <Busy>Deleting…</Busy> : "Delete my account permanently"}
                </button>
                <button type="button" className="ghost" disabled={v.busy} onClick={onCancel}>Keep my account</button>
              </div>
            </form>
          )}
        </>
      )}
    </div>
  );
}

/** Whether the form may be submitted: the address matches, a password is typed, and the code has its six digits. */
export function deleteFormReady(f: { typedEmail: string; accountEmail: string; password: string; totp: string; totpRequired: boolean }): boolean {
  return emailConfirmed(f.typedEmail, f.accountEmail) && f.password.length > 0 && (!f.totpRequired || totpDigits(f.totp).length >= 6);
}

export function DeleteAccountCard({
  client,
  account,
  store,
  email,
  onDeleted,
  onOpenVaultSettings,
  onOpenAdmin,
  onBackup,
}: {
  client: ApiClient;
  account: Account;
  store: Pick<VaultStore, "vaults">;
  /** The signed-in address the typed confirmation must match ("" when the session predates it: the server decides). */
  email: string;
  /** The server confirmed the deletion: App wipes this browser's state for the account and lands signed out. */
  onDeleted: () => void;
  onOpenVaultSettings: (vaultId: string) => void;
  onOpenAdmin?: () => void;
  onBackup?: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [preview, setPreview] = useState<AccountDeletePreview | null>(null);
  const [previewError, setPreviewError] = useState("");
  // A refusal of the request itself overrides the preview's (the state moved between the two).
  const [refused, setRefused] = useState<AccountDeletePreview["blockers"] | null>(null);
  const [typedEmail, setTypedEmail] = useState("");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [unknownOutcome, setUnknownOutcome] = useState(false);

  // Names decrypt locally (the server knows vaults only as ids); once per preview, not per keystroke.
  const names = useMemo(() => new Map(store.vaults().map((v) => [v.vaultId, v.name] as const)), [store, preview]);
  const vaultName = (id: string): string | null => names.get(id) ?? null;

  const reset = () => {
    setOpen(false);
    setPreview(null);
    setPreviewError("");
    setRefused(null);
    setTypedEmail("");
    setPassword("");
    setTotp("");
    setErr("");
    setUnknownOutcome(false);
  };

  const openCard = async () => {
    setOpen(true);
    setLoading(true);
    setPreviewError("");
    setRefused(null);
    try {
      setPreview(await client.accountDeletePreview());
    } catch (e) {
      setPreviewError(previewErrorText(e));
    } finally {
      setLoading(false);
    }
  };

  const submit = async () => {
    if (!preview) return;
    setBusy(true);
    setErr("");
    setUnknownOutcome(false);
    try {
      const outcome = await runAccountDeletion(client, account, { email: typedEmail, password, totp, totpRequired: preview.totpRequired });
      switch (outcome.kind) {
        case "deleted":
          onDeleted();
          return;
        case "blocked":
          setRefused(outcome.blockers);
          break;
        case "error":
          setErr(outcome.message);
          break;
        case "unknown":
          setUnknownOutcome(true);
          break;
      }
    } finally {
      setPassword("");
      setTotp("");
      setBusy(false);
    }
  };

  const blockers = refused ?? (preview && preview.blockers.length > 0 ? preview.blockers : null);
  const view: DeleteAccountView = {
    open,
    loading,
    previewError,
    summary: preview ? deletionSummary(preview, vaultName, account.personalVaultId || null) : null, // "" = no personal vault
    blockers: blockers === null ? null : blockerLines(blockers, vaultName),
    totpRequired: preview?.totpRequired ?? false,
    typedEmail,
    password,
    totp,
    canSubmit: preview !== null && deleteFormReady({ typedEmail, accountEmail: email, password, totp, totpRequired: preview.totpRequired }),
    busy,
    err,
    unknownOutcome,
  };

  return (
    <DeleteAccountBody
      view={view}
      onOpen={() => void openCard()}
      onCancel={reset}
      onTypedEmail={setTypedEmail}
      onPassword={setPassword}
      onTotp={setTotp}
      onSubmit={() => void submit()}
      onLink={(link) => (link.kind === "vault" ? onOpenVaultSettings(link.vaultId) : onOpenAdmin?.())}
      onBackup={onBackup}
    />
  );
}
