import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./ui/App";
import { captureEnrollFromLocation } from "./enroll/enrolllink";
import { InsecureContextCard, webCryptoUnavailable } from "./ui/securecontext";
import "./ui/styles.css";

const root = createRoot(document.getElementById("root")!);

// Audit F06: the crypto precondition, checked BEFORE anything else. Every key derivation goes
// through crypto.subtle, which browsers expose only on a secure context — so on a plain-http
// self-host (a documented bring-up story) enrollment and sign-in could only ever fail, with copy
// that blamed the password or the network. A terminal card instead: there is no degraded mode.
// This runs before captureEnrollFromLocation ON PURPOSE — that call STRIPS the invite fragment
// from the URL, and burning an invite link on an origin that cannot use it would be the one
// unrecoverable thing this screen could do.
if (webCryptoUnavailable()) {
  root.render(
    <StrictMode>
      <InsecureContextCard />
    </StrictMode>,
  );
} else {
  // One-scan onboarding: capture an /enroll#a1.<payload> link at MODULE LOAD — before React
  // renders — so a StrictMode double-mounted effect can never re-read an already-stripped hash
  // and lose the prefill. Strips the fragment (the invite token must not linger in history).
  captureEnrollFromLocation();

  root.render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
}
