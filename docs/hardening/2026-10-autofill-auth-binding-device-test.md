# Device test — autofill authentication binding (security review 2026-10, root cause G)

**Status:** not yet run. The unit tests on this branch pin the decision (`AutofillAuthGate`) and the
wiring (`AutofillAuthBindingTest`), but the attack itself was reasoned from AOSP source and has never
been demonstrated on a device. Run this on a real phone with andvari selected as the autofill service,
once against the last release (expected: **leaks**) and once against this branch (expected: **refused**).

## What is being tested

The "Unlock andvari" row and the "Trust {browser} to fill here" row are backed by mutable
PendingIntents. When the user taps one, the framework hands the IntentSender and a fill-in intent to
the **requesting app's own process**, which then calls `startIntentSenderForResult`. A hostile app can
substitute its own fill-in carrying an `EXTRA_ASSIST_STRUCTURE` that claims to be Chrome on any domain.
Before this branch the authentication activities parsed that structure and returned the matching
logins (and every card) to the hostile app's `onActivityResult`. After it, they fill only the form the
service parsed in `onFillRequest` and baked into the PendingIntent's base intent, and refuse when the
delivered structure names another package.

## The hostile test app (minimal, debug-signed, never published)

One activity, package e.g. `com.example.autofillprobe`:

1. A layout with a username `EditText` and a password `EditText` (`autofillHints` username / password)
   so andvari's service offers the locked "Unlock andvari" row.
2. Override `onActivityResult` and log/display the `EXTRA_AUTHENTICATION_RESULT` `FillResponse`: count
   the datasets and, for each, the field values (the test only needs to show whether any credential
   for a *web* login arrived).
3. Intercept the authentication launch. The standard route is the activity's
   `startIntentSenderForResult(IntentSender, requestCode, fillInIntent, …)` override: when the
   autofill framework calls it with andvari's IntentSender, call `super` with the **same** IntentSender
   but a **replaced** `fillInIntent` whose `AutofillManager.EXTRA_ASSIST_STRUCTURE` is a forged
   `AssistStructure`:
   - take the structure the framework passed in, write it to a `Parcel`, replace the leading
     `ComponentName` with `com.android.chrome/…` (any activity name), and read it back through
     `AssistStructure.CREATOR`;
   - set `webDomain` on the username/password nodes to a domain the test vault has a login for
     (e.g. a throwaway `https://example.org` item created for this test).
   If rewriting the parcel proves fiddly, a second variant is enough to prove the binding: forward
   the original IntentSender with a fill-in whose structure is simply taken from a *different* app's
   fill request (any second test app), so the package differs.
4. Keep a reference to the IntentSender and add a button that re-fires it later (replay variant).

Preconditions on the phone: real Chrome installed (its signing cert matches the shipped pins), the
test vault holds one web login for the chosen domain and one card, andvari is the autofill service.

## Steps and expected results

| # | Step | Last release | This branch |
|---|---|---|---|
| 1 | Lock andvari. Open the probe app, focus the username field, tap "Unlock andvari", unlock | the probe's `onActivityResult` receives the web login's username + password and the card dataset | the unlock overlay closes without prompting (`BINDING_REFUSED` in Settings → Autofill status), result is `RESULT_CANCELED`, no dataset |
| 2 | Same, but forward the **original** fill-in unchanged (control) | probe gets only logins saved for `androidapp://com.example.autofillprobe` (normally none → "no match" toast) | identical — the honest path is unchanged |
| 3 | With andvari unlocked (open the main app first), re-fire the captured IntentSender with the forged fill-in | silent fill of the forged domain, no prompt | refused, no prompt, `BINDING_REFUSED` |
| 4 | Real Chrome, real site with a saved login: lock, tap "Unlock andvari", unlock | fills | fills (regression check) |
| 5 | A browser andvari does not trust yet: tap "Trust {browser} to fill here", confirm | dropdown refreshes with matches | dropdown refreshes with matches (the refill uses the baked form) |
| 6 | Checkout page in a trusted browser with a saved card, vault locked: unlock from the row | card dataset offered | card dataset offered (regression check) |

Record the Android version, device model, Chrome version and andvari build for each run. If step 1 on
the last release does **not** leak, note how the framework behaved (did the probe's
`startIntentSenderForResult` override see the call at all?) — that would mean the platform route is
narrower than the source reading suggested, which changes the severity but not the fix.

## Not covered here

The PendingIntent is still `FLAG_MUTABLE` (the platform must add the inline-suggestions request) and
not `FLAG_ONE_SHOT`; a captured IntentSender can be replayed, but after this branch a replay only ever
fills the form the service originally parsed for the original requesting app. Making it one-shot was
left out because a cancelled unlock followed by a second tap on the same row would then fail, and that
needs its own device check first.
