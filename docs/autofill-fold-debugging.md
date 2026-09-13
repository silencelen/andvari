# Android autofill — diagnosing "nothing filled" with the Autofill status screen

**Status: current-facing, last verified against the shipped app 2026-09-13.** This started life in
2026-07 as a one-off protocol for bringing autofill up on a single Fold (batch B2: package
visibility, a truncated Chrome cert pin, missing inline suggestions, and total silence on failure).
The screen it drives is now a permanent part of the app, so the file is kept as a general guide —
what it says about the *product* is checked at each audit rather than frozen at the bring-up. Two
claims that had rotted are corrected below and called out, because a stale sentence in a debugging
guide sends the reader looking for the wrong bug (audit H118).

**Autofill both fills and saves.** An earlier version of this page opened "the autofill service is
fill-only," which was true during the B2 bring-up and false since **0.25.0**: andvari offers to save
a new login from the sign-in screen you just used (`SaveConfirmActivity`), including — this was the
0.25.0 fix — screens whose username box you leave empty, which andvari would previously offer to
*fill* and never offer to *save*. If saving does not work for you, that is a bug worth reporting,
not the documented behaviour.

**Getting the app.** Install the current APK from your instance's *Settings → Your devices →
Android* (or however the person who runs your instance distributes it). There is no `scripts/ship.sh`
in this repository — the old instruction to run one was a leftover from a private bring-up script and
never worked for anybody else.

## The screen: Settings → Autofill → **Autofill status**

Three sections:

- **1 · Service & vault** — is andvari the autofill service (red/green), signed-in, vault
  locked/unlocked, how many items carry web vs app URIs, the auto-lock window + idle time.
  A **"Set as autofill service"** button is here if it's red.
- **2 · Last request** — the most recent fill request: which app asked, the **trust verdict**
  (and, on a mismatch, the browser's **observed cert digest**), each field we saw (kind, site host,
  why we classified it), how many items matched, and the **terminal reason** (a plain-English
  "why nothing filled" line).
- **3 · Debug** — a **"Debug autofill (24h)"** toggle (self-expires) that records the last 50
  requests, and **Copy log**. No passwords, usernames, item names, or full web addresses are
  ever logged — only field types, counts, host names, and the reason codes.

## Ordered steps

Take a screenshot after each step marked ⇒; the sequence is what makes an unhelpful "autofill
doesn't work" into something diagnosable.

1. Open **Autofill status**. ⇒ **Screenshot Section 1.**
   - If "andvari is your autofill service" is **red**, tap **Set as autofill service**, pick
     andvari, come back. If the item count is 0, the fallback "Open andvari" row will still prove
     the service is being called.
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
     that is your browser's real signing digest. Use **"Trust this browser"** on that same screen
     to approve it on this device (see below). ⇒ **Screenshot it** (the digest is selectable).
   - Terminal reason **NO_URI_MATCH / NO_ITEMS** ⇒ the service works; there is just no saved
     login for that site yet (expected with an empty vault — the "Open andvari" row appears).
6. Repeat 4–5 in your **default browser** if it is not Chrome — Samsung Internet, Brave and
   Firefox do not publish a digest andvari can ship a pin for, so Section 2's observed digest is
   the only way to establish trust for them.
7. Optional: repeat 4–5 on one **native app** login screen.
8. Section 3 → **Copy log** and attach it to your report (safe to paste — no secrets).

## "Trust this browser" — the self-service digest path

You do not have to wait for a new release to pin a browser. A browser's real signing-cert digest is
**install-source specific** (Play App Signing, a pre-install from the phone vendor, and a direct APK
all differ), so a digest shipped blind in the app would silently never match on many phones. Instead,
**Autofill status → "Trust this browser"** records the digest that is actually on *your* device.

Two properties worth knowing, because they are the reason this is safe:

- The stored digest is re-read from the **live** installed browser on **every** fill request. If
  that browser is re-signed — or a hostile app takes over the package name — trust drops
  immediately and you are asked again.
- It is **per-device and never synced**, and it is not a secret (a public certificate hash). Revoking
  is one tap.

## What each result tells us

| Section 2 says | Meaning | Next |
|---|---|---|
| "No request seen yet" | The browser never called us | Chrome toggle (step 3) / compat mode |
| Trust **TRUSTED**, reason **NO_URI_MATCH** | Working — just no matching saved login | Nothing; add an item and retry |
| Trust **CERT_MISMATCH** + digest | The shipped pin ≠ your browser's real cert | "Trust this browser" to approve the observed digest |
| Trust **NO_PIN_DIGEST** + digest | A browser with no shippable pin (e.g. Samsung) | Same — approve the observed digest |
| Reason **EXCEPTION** | The fill path threw | Report it with the screenshot; that is a code bug |
| Fields list empty | The form's fields were not recognised | Report it — classifier tuning |

## Reporting

Send the screenshots and the copied log to whoever maintains your instance, the same way you would
report anything else (`docs/user-test-guide-0.6.0.md` § "Found something? Tell us"). The Section 2
verdict plus the copied log is almost always enough to tell "the browser never called us" apart from
"we were called and could not match", which are completely different bugs.
