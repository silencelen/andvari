import { BrandSigil } from "./Sigil";

/**
 * Audit F06 — the boot precondition nothing in the client ever checked.
 *
 * Every key this app derives routes through WebCrypto (keys.ts authKey/wrapKey → hkdfSha256 →
 * hmacSha256 → provider.ts `crypto.subtle.importKey`), and `SubtleCrypto` is `[SecureContext]`:
 * on an `http://<private-ip>` origin `crypto.subtle` is undefined and that call throws. So does
 * `crypto.randomUUID` (account.ts). docs/self-hosting.md lists plain http on a private address as
 * a supported bring-up story, and on such an instance the web vault is 100% non-functional at
 * first contact — Argon2id (pure WASM) runs fine, then the very next step throws. What the
 * operator saw instead was "Enrollment failed." or "Sign-in failed. Please try again." — advice
 * that can never work, while the native clients keep working against the same server, so nothing
 * pointed at the origin's scheme.
 *
 * This is a terminal card, not a warning: there is no degraded mode to offer.
 */
export const INSECURE_CONTEXT_HEADING = "andvari can't run on this address";
export const INSECURE_CONTEXT_MESSAGE =
  "This browser will not run andvari's cryptography over plain http. Open this vault over https (or http://localhost), or use the desktop or mobile app for this server.";
export const INSECURE_CONTEXT_DETAIL =
  "Nothing is wrong with your account, your password, or your server — browsers only expose the encryption andvari needs on a secure address. Your other devices can keep using this server in the meantime.";

/**
 * True when this document cannot do the crypto. Deliberately NOT `!isSecureContext`: it fires
 * only on an explicit non-secure context or a genuinely absent `crypto.subtle`, so a browser
 * that simply doesn't expose `isSecureContext` is never locked out of a working vault.
 * Takes its globals as a parameter so the decision is testable off a browser.
 */
export function webCryptoUnavailable(
  ctx: { isSecureContext?: boolean; crypto?: { subtle?: unknown } } = globalThis as {
    isSecureContext?: boolean;
    crypto?: { subtle?: unknown };
  },
): boolean {
  return ctx.isSecureContext === false || typeof ctx.crypto?.subtle === "undefined";
}

/** The whole app, replaced. Uses the signed-out auth shell so it reads as andvari, not a crash. */
export function InsecureContextCard() {
  return (
    <div className="auth-shell">
      <div className="card">
        <div className="card-hero">
          <div className="sigil"><BrandSigil /></div>
          <h1>{INSECURE_CONTEXT_HEADING}</h1>
          <p>this address is not a secure context</p>
        </div>
        <div className="msg err" role="alert" style={{ display: "block" }}>{INSECURE_CONTEXT_MESSAGE}</div>
        <p className="muted">{INSECURE_CONTEXT_DETAIL}</p>
      </div>
    </div>
  );
}
