import { Component, type ErrorInfo, type ReactNode } from "react";
import { BrandSigil } from "./Sigil";

export const RENDER_FAILED_HEADING = "Something here could not be shown";
export const RENDER_FAILED_MESSAGE =
  "andvari hit an item or setting it could not display, and stopped rather than show you a broken vault. Reloading locks the vault; unlock again to continue.";

/**
 * Security review 2026-10 (root cause D): the app had NO error boundary, so any render-time throw —
 * the documented one was a shared-vault co-member's malformed item reaching a string method —
 * unmounted the whole React root and left a blank page on every unlock, with no way to reach the
 * controls that would fix it. Decrypted documents are now shape-checked at the decrypt boundary
 * (vault/itemdoc-shape.ts), so this is the belt: whatever slips past fails CLOSED onto a card that
 * says so. It never renders the error itself — a message can quote the value that threw — and its
 * one action is a reload, which drops the in-memory keys exactly like a lock.
 */
export class ErrorBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };

  static getDerivedStateFromError(): { failed: boolean } {
    return { failed: true };
  }

  componentDidCatch(_error: unknown, _info: ErrorInfo): void {
    // Deliberately silent: the error text may carry decrypted vault content.
  }

  render(): ReactNode {
    if (!this.state.failed) return this.props.children;
    return (
      <div className="auth-shell">
        <div className="card">
          <div className="card-hero">
            <div className="sigil"><BrandSigil /></div>
            <h1>{RENDER_FAILED_HEADING}</h1>
          </div>
          <div className="msg err" role="alert" style={{ display: "block" }}>{RENDER_FAILED_MESSAGE}</div>
          <button onClick={() => window.location.reload()}>Reload</button>
        </div>
      </div>
    );
  }
}
