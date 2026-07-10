import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./ui/App";
import { captureEnrollFromLocation } from "./enroll/enrolllink";
import "./ui/styles.css";

// One-scan onboarding: capture an /enroll#a1.<payload> link at MODULE LOAD — before React
// renders — so a StrictMode double-mounted effect can never re-read an already-stripped hash
// and lose the prefill. Strips the fragment (the invite token must not linger in history).
captureEnrollFromLocation();

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
