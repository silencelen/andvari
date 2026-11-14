# iOS UI tests in the simulator

The workflow `.github/workflows/ios-uitest.yml` builds the app for the iOS Simulator on a GitHub macOS runner,
starts an unmodified andvari server and a small test site on the runner's loopback, and runs the XCUITest
target `AndvariUITests` against them. It needs no secret and no signing identity.

Read a run without a Mac:

```sh
app-ios/scripts/uitest-report.sh <run id> [directory]
```

That downloads the run's artifact and prints one line per test. The directory then holds
`uitest-summary.json` (test, status, failure or skip message, screenshot names),
`screenshots/<Class>.<test>__NN_<step>.png` (one per step, plus the screen at the end of each test),
`server.log`, the `xcodebuild` logs and the `.xcresult` bundle.

## What runs where

| Piece | Where | Notes |
|---|---|---|
| andvari server | `http://127.0.0.1:8087` | `:server:shadowJar` from the checkout, throwaway data directory. `127.0.0.1` because it is the only host the app dials over plain http. |
| Account and items | made by `tools/uitest-seed` | An ordinary client: it enrolls with the server's bootstrap invite (which designates its personal vault, as any registering device does), confirms the recovery phrase and saves five logins, a note and a card through the sync engine. The server has no test-only door. The simulator is a second device of that account, so it is asked once to confirm the personal vault. |
| Test site | `https://site.andvari-uitest.test:8443` | Static pages with a sign-in form, a sign-up form and a one-time-code field. A hosts-file name for loopback; its certificate comes from a CA made in the job, trusted only by the job's simulator. |
| Test site, another site | `https://other-uitest.test:8443` | The same pages under another registrable domain and the same certificate, for a fill that crosses sites. |
| Test site, plain http | `http://plainhttp-uitest.test:8081` | The same pages under another registrable domain, for the rule that an http page is only offered a login saved as http. |
| Simulator | newest installed iOS, a new device per run | `boot-simulator.sh` |
| Another device, a second account | `POST /control/…` on the test site | `vault-create`, `vault-delete` and `vault-restore` (`?name=`) sign in as another device of the account and change one of its shared vaults (`tools/uitest-seed vault`). `share-read-only` (`?name=&item=`) has a second account, enrolled with an invite the test account mints as the server's admin, share a vault holding one login read-only with the account, and another device of the account accept it by typing the sharer's identity code (`tools/uitest-seed share`). The app learns of either at its next sync. |
| Page event log | `<page>.html?uitest-events` | The test site adds a passive log after the page's content: presses, focus moves with the page's user activation and focus, and window focus. The card tests read it to say what the page saw. |

The account's email and master password are in `env.sh`. They are fixtures for a server that lives for one job.

A card is filled only into a payment provider's card form (owner decision 2026-11-14), so the test site has a
stand-in provider: `https://pay.andvari-uitest.test:8443` (`UITEST_PROVIDER_ORIGIN` in `env.sh`), the same server
under its own name, which the certificate carries too. Only the Safari extension's UI-test build lists it as a
provider (`UITEST=1` in `prepare.sh`, which this workflow sets; `extension/build.mjs`), and `ios-unsigned.yml` fails
when a release bundle names the test domain. `checkout.html` is a shop page that embeds the provider's card form:
`pay/card.html` in one frame (`?layout=card`, the default), one `pay/field.html` frame per field (`?layout=split`), or
a security code alone (`?layout=code`). The shop's own name-on-card field there is never filled.

## Adding a test

Subclass `UITestCase`, write the test as `step("name") { … }` blocks (each ends with a screenshot), find
elements by accessibility identifier (`AccessID` in `Andvari/Support/Theme.swift` and the literal identifiers
in the views). A test that cannot run in the simulator stays in the suite and calls `try skip("why")`, so the
summary carries the reason.

## What the simulator can and cannot show

Measured on the iOS 26.5 simulator of the `macos-26` runner. Every test is green or skipped with its reason in
the summary; a red test is a regression or a new finding, never a known gap.

| Checklist item | In the simulator | Test |
|---|---|---|
| First launch, server, Trust Gate, sign in, vault list with every seeded item | Works | `T1…test01` |
| The personal-vault notice on a device that signed in: one "Use Personal", gone after it, not asked again after a lock | Works (wording, below) | `T1…test01` |
| Wrong password, background lock, Lock button, item detail, search, sign out | Works | `T1…test02`–`07` |
| Add a login on a device that signed in, after confirming the personal vault | Works | `T1…test08` |
| Turn Face ID on, unlock by face, non-matching face, background then face, turn it off | Works, with a software key in place of the Secure Enclave key (below) | `T2…` |
| Turn andvari on under Settings > General > AutoFill & Passwords | Works by driving the Settings app. No `simctl` or `defaults` route is documented. | `T3…test01` |
| Safari offers the login for the https site and fills it after Face ID | Works. iOS 26 shows a sheet ("Sign in to … with your password for … saved in andvari") in place of a QuickType suggestion. | `T3…test02` |
| The provider's list sheet (Passwords key, choose andvari, Face ID, pick a login) | Works | `T3…test03` |
| One-time code offered above the keyboard and filled | Works; the code the site receives is checked against RFC 6238 for the seeded secret | `T3…test04` |
| A plain-http page gets only the login saved as http | Skipped: Safari offers nothing from a provider on a plain-http page, so the rule is not observable | `T3…test05` |
| The system's save offer (iOS 26.2+), saved by the app at its next unlock, listed, in Personal, Done dismisses the list | Works | `T3…test06` |
| Turn the Safari web extension on in Settings | Works | `T3…test07` |
| Extension popup: Face ID once it has painted, the site's logins listed under "This site", fill, and opened again at once it lists without Face ID | Works | `T3…test08` |
| Fill a field in an app with no website (andvari's own unlock field) | Works: the list opens with every login and the chosen password is put in the field | `T3…test09` |
| A changed password saved from Safari: applied at the next unlock and listed, kept across a lock, the new password and the previous one in the login, Undo, everything as it was | Works | `T3…test10` |
| The popup lists cards (masked number); the popup's root fills its sheet and a row is centred in it (within 3 points) | Works | `T3…test11` |
| A login for another site chosen in the popup: nothing filled until a confirmation that names both sites | Works | `T3…test12` |
| Two logins saved before the app is next unlocked both arrive and are listed; Undo all takes both back | Works since the save-id fix (below); the test checks the queue and skips with the reason if two saves ever share an entry again | `T3…test13` |
| Delete a login, restore it from the trash; delete it again and delete it forever | Works | `T4…test01` |
| Change a login's password, then restore the earlier version from its history | Works | `T4…test02` |
| Create a shared vault; copy a login into it (both stay) and move another (it leaves Personal) | Works | `T4…test03` |
| A shared vault deleted, then restored, on another device: a notice for each after a sync, gone when dismissed | Works | `T4…test04` |
| A login in a vault the account only reads: no Edit, "Copy to another vault…" and no Move; the copy in Personal can be edited | Works. A second account shares the vault read-only and another device of this account accepts it; the app takes it at a sync, through the account's own wrap of the vault key, with no invitation screen of its own | `T4…test05` |
| card-skimmer.html: Fill refuses with nothing tapped and with only the email tapped; the hidden form receives nothing | Works | `T4…test06` |
| A card filled from the popup in the default (Compact) tab layout, the popup reached with the keyboard still up: a tap on the address Safari's bar shrank to above it brings the page menu back | Worked with ios-ui up to 034b9684; refused since 3ef56e8b (regression, below) | `T4…test07` |
| The same with the keyboard closed first by its Done | Skipped: app defect (below) | `T4…test08` |
| card-two-forms.html: the new card's number fills only its own form; the saved card's security code alone fills only that code | The first worked with ios-ui up to 034b9684 and is refused since 3ef56e8b (regression, below); the second is skipped with a finding (below) | `T4…test09` |
| card-inner-scroll.html: filled once scrolled into view; scrolled away again, nothing is written and the popup says the field can't be seen | Worked with ios-ui up to 034b9684; refused since 3ef56e8b (regression, below) | `T4…test10` |
| The third-party keyboard switch | Present and off by default. Whether such a keyboard is kept out is skipped: the simulator has none, and the suite would need an app of its own to add one | `T4…test11` |
| Two-step setup survives a trip to the Settings app (the same key at the confirm step after the unlock); the authenticator's code turns it on, a later one off | Works | `T4…test12` |

The Safari tests have helpers for what Safari does on a cold start: it can come up on its start page and drop
the address it was opened with, show first-run tips over what the tests tap, and offer a fill before the system's
store of suggestions has caught up. The simulator also has spells of several minutes in which every TLS connection
from Safari to the test site fails ("bad certificate format" in the simulator's log after a stall of about 20
seconds, "certificate unknown" alerts in the site's log) and then passes again, so a page is tried for up to nine
minutes. Each helper retries a bounded number of times and then fails with a tree dump; none of them loosens an
assertion.

### Findings the tests show

- **Saves made before the app is next opened overwrote each other** (found 2026-11-12, fixed on ios-ui by
  6e90fc5 and 4b8c7c0). The AutoFill
  extension queues a save under `ASSavePasswordRequest.sessionID`, which is "1" for every save on the iOS 26.5
  simulator (each save runs in a fresh extension process), and the queue's `put` replaces an entry with the same
  id. After three saves the App Group's `saves/` held only `q-s-1.json`, and the app listed only the last one.
  The same id also makes a later save replace an earlier save's record in the "Saved … from AutoFill" list
  even when the app was unlocked in between, so the earlier save can no longer be undone from the list.

- **Since 3ef56e8b no card is filled into a page without frames** (found 2026-11-13, a regression). On
  card-two-forms.html, which has no frame, object or embed, the popup answers Fill with "Something else sits
  over or under the card field you tapped, such as a form embedded from another page. andvari doesn't fill a
  card there, so nothing was filled." The same test filled the card on ios-ui 034b9684 and is refused on
  094c92ae; the field was pressed, chosen and still had the focus (the page's event log and Safari's tree show
  it). With no frame on the page, the likely source is the Safari branch of `cardFillAgainst`
  (`extension/src/content.ts`), which refuses for any element overlapping the field other than the field, its
  ancestors and its wrapper.

- **A card cannot be filled from the popup once the keyboard is closed with its Done** (found 2026-11-13). In
  the Compact and Bottom tab layouts Safari's page menu, the way to the popup, is behind the keyboard while a
  page field has it. Done blurs the field while the page keeps its focus (the page's event log:
  `focusout #cc-number hasFocus=true now=body`), and the content script lets the chosen field go when focus
  moves elsewhere in the page (`noteFocusLeft`, `extension/src/content.ts`), so Fill then says "Tap the card
  number field on the page first, then fill again." and fills nothing. Reaching the menu by a tap on the
  shrunk address keeps the field (T4 test07), but Done is the keyboard's own way to close it.

- **A form holding only a security code is never filled** (found 2026-11-13). card-two-forms.html expects a
  tap on the saved card's security code, then Fill, to fill only that code. `buildCardForm`
  (`extension/src/detect.ts`) makes a card form only where there is a card-number field, so that field is
  never chosen, and Fill says "Tap the card number field on the page first, then fill again." The extension
  or the page needs to change. On the same page the saved card's code has the focus about a second after the
  page loads, without a press (the event log shows `activation=false`); the extension rightly does not take
  that as a choice.

- **The personal-vault notice on a device's first sign-in** (found 2026-11-12, fixed on ios-ui by d6ff8074;
  the test still accepts both sentences) opened with "The server says your personal vault
  is Personal." even when the account's own record names the same vault, where a device that had read the
  record says "Confirm your personal vault on this device: Personal." Reproduced on the JVM with the core's
  own classes: a new device that runs `hydrate()` before its first `sync()` holds the proposal against "no
  designation" (its copy of the account state is still empty), and a held proposal is not re-judged once the
  refresh has brought the designation. Without the `hydrate()` first, the same account gets the same-vault
  sentence. Both offer the one "Use Personal"; the first wording says less than it could.

### The quick-unlock key

The simulator has no Secure Enclave: `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave` returns no
key there, and the app said "This device can't hold a quick-unlock key." So a simulator build falls back to a
software P-256 key under the same tag and access group (`core/src/iosSimulatorArm64Main`). That source set
is compiled only for the simulator target; the device target's counterpart is one line that returns null, and on
a device a quick-unlock key that is not the Secure Enclave's is refused at run time, when it is made and when it
is used. `ios-core.yml` requires the device framework's header to declare `QuickUnlockSecureEnclaveOnly` and not
`SimulatorSoftwareQuickUnlockKey`; `ios-uitest.yml` requires the simulator build's header to declare the
latter. The cost: in these tests the key is not hardware-bound, needs no passcode, and survives a change of
enrolled faces.

### What this can never tell us

- Anything about the real Secure Enclave key: `biometryCurrentSet` invalidation, the passcode requirement,
  the key being readable from the extensions on a signed device build.
- Real Face ID: the simulator's is a switch that says "match" or "no match".
- The extensions' memory limits and iOS ending their processes under pressure.
- The signed build: entitlements, provisioning profiles, the App Group and Keychain group as TestFlight
  ships them. The tests run an ad hoc signed Debug build.
- Hardware and OS behaviours the simulator lacks or fakes: a device passcode, lock and unlock of the phone,
  the clipboard's Universal Clipboard exclusion, timing on a real CPU.
