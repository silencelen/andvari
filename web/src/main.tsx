import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./ui/App";
import { ErrorBoundary } from "./ui/ErrorBoundary";
import { InsecureContextCard, webCryptoUnavailable } from "./ui/securecontext";
import "./ui/styles.css";

const root = createRoot(document.getElementById("root")!);

// Audit F06: the crypto precondition, checked BEFORE anything else. Every key derivation goes
// through crypto.subtle, which browsers expose only on a secure context — so on a plain-http
// self-host (a documented bring-up story) enrollment and sign-in could only ever fail, with copy
// that blamed the password or the network. A terminal card instead: there is no degraded mode.
if (webCryptoUnavailable()) {
  root.render(
    <StrictMode>
      <InsecureContextCard />
    </StrictMode>,
  );
} else {
  root.render(
    <StrictMode>
      <ErrorBoundary>
        <App />
      </ErrorBoundary>
    </StrictMode>,
  );
}
