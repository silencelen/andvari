# Android autofill — Fold debugging protocol (owner)

The autofill service is fill-only. v5 (batch B2) fixed four reasons it produced **zero
suggestions on every browser**: missing package-visibility (`<queries>`), a Chrome cert pin
truncated by one character, no `supportsInlineSuggestions`, and total silence on every
failure. What we **cannot** verify without your Fold: which browser you use, its real
signing-cert digest, and whether inline chips render. This protocol turns your phone into
the instrument that answers those — every step ends in a screenshot you send over Telegram.

Install the new APK first (devstore → andvari, or `bash scripts/ship.sh release` output).

## The screen: Settings → Autofill → **Autofill status**

Three sections:
- **1 · Service & vault** — is andvari the autofill service (red/green), signed-in, vault
  locked/unlocked, how many items carry web vs app URIs, the auto-lock window + idle time.
  A **"Set as autofill service"** button is here if it's red.
- **2 · Last request** — the most recent fill request: which app asked, the **trust verdict**
  (and, on a mismatch, the browser's **observed cert digest** — this is the value we pin),
  each field we saw (kind, site host, why we classified it), how many items matched, and the
  **terminal reason** (a plain-English "why nothing filled" line).
- **3 · Debug** — a **"Debug autofill (24h)"** toggle (self-expires) that records the last 50
  requests, and **Copy log**. No passwords, usernames, item names, or full web addresses are
  ever logged — only field types, counts, host names, and the reason codes.

## Ordered steps (screenshot after each ⇒)

1. Open **Autofill status**. ⇒ **Screenshot Section 1.**
   - If "andvari is your autofill service" is **red**, tap **Set as autofill service**, pick
     andvari, come back. If item count is 0, that's expected pre-migration — the fallback
     "Open andvari" row will still prove the service is being called.
2. Turn on **Debug autofill (24h)** (Section 3).
3. **Chrome must be told to use us.** Chrome → ⋮ → Settings → **Autofill services** (or
   "Passwords & autofill") → turn **"Autofill using other services"** ON → fully close and
   reopen Chrome. (By default Chrome routes everything to Google Password Manager and never
   calls a third-party service — this is the single most common "nothing pops up" cause.)
4. In Chrome open any login page (e.g. github.com/login) and **tap the username field**.
   - If nothing appears, **long-press** the field → **Autofill**.
5. Switch back to andvari → **Autofill status** → **Section 2**. ⇒ **Screenshot Section 2.**
   - "No autofill request seen yet" ⇒ Chrome still isn't dispatching → recheck step 3 / try
     the long-press.
   - Trust verdict **CERT_MISMATCH** or **NO_PIN_DIGEST** with an **observed digest** shown ⇒
     that's the value we pin for your browser. ⇒ **Screenshot it** (the digest is selectable).
   - Terminal reason **NO_URI_MATCH / NO_ITEMS** ⇒ the service works; there's just no saved
     login for that site yet (expected with an empty vault — the "Open andvari" row appears).
6. Repeat 4–5 in **Samsung Internet** (likely your default browser on the Fold — its cert
   digest is not published, so its Section 2 verdict + observed digest is the only way we can
   pin it). ⇒ **Screenshot.**
7. Optional: repeat 4–5 in one **native app** login screen. ⇒ **Screenshot.**
8. Section 3 → **Copy log** and paste it into Telegram (safe to paste — no secrets).

## What each result tells us

| Section 2 says | Meaning | Next |
|---|---|---|
| "No request seen yet" | The browser never called us | Chrome toggle (step 3) / compat mode |
| Trust **TRUSTED**, reason **NO_URI_MATCH** | Working — just no matching saved login | Nothing; add an item and retry |
| Trust **CERT_MISMATCH** + digest | Our pin ≠ your browser's real cert | We pin the observed digest, ship again |
| Trust **NO_PIN_DIGEST** + digest | Known browser we never pinned (e.g. Samsung) | Same — pin the observed digest |
| Reason **EXCEPTION** | The fill path threw | Send the screenshot; we fix the code |
| Fields list empty | We didn't recognize the form's fields | Send it — classifier tuning |

Send the batch of screenshots + the copied log; pinning your browser's real digest and
confirming inline chips render are the two things that close this out.
