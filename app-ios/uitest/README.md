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

The account's email and master password are in `env.sh`. They are fixtures for a server that lives for one job.

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
| Two logins saved before the app is next unlocked both arrive and are listed; Undo all takes both back | Skipped while the defect below is present (the test checks the queue and says so) | `T3…test13` |

The Safari tests have helpers for what Safari does on a cold start: it can come up on its start page and drop
the address it was opened with, show first-run tips over what the tests tap, and offer a fill before the system's
store of suggestions has caught up. Each helper retries a bounded number of times and then fails with a tree
dump; none of them loosens an assertion.

### Findings the tests show

- **Saves made before the app is next opened overwrite each other** (reported 2026-11-12). The AutoFill
  extension queues a save under `ASSavePasswordRequest.sessionID`, which is "1" for every save on the iOS 26.5
  simulator (each save runs in a fresh extension process), and the queue's `put` replaces an entry with the same
  id. After three saves the App Group's `saves/` held only `q-s-1.json`, and the app listed only the last one.
  The same id also makes a later save replace an earlier save's record in the "Saved … from AutoFill" list
  even when the app was unlocked in between, so the earlier save can no longer be undone from the list.

- **The personal-vault notice on a device's first sign-in** opens with "The server says your personal vault
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
is compiled only for the simulator target; the device target's counterpart is one line that returns null, and
`ios-core.yml` fails if the simulator's code is found in the device framework. The cost: in these tests the
key is not hardware-bound, needs no passcode, and survives a change of enrolled faces.

### What this can never tell us

- Anything about the real Secure Enclave key: `biometryCurrentSet` invalidation, the passcode requirement,
  the key being readable from the extensions on a signed device build.
- Real Face ID: the simulator's is a switch that says "match" or "no match".
- The extensions' memory limits and iOS ending their processes under pressure.
- The signed build: entitlements, provisioning profiles, the App Group and Keychain group as TestFlight
  ships them. The tests run an ad hoc signed Debug build.
- Hardware and OS behaviours the simulator lacks or fakes: a device passcode, lock and unlock of the phone,
  the clipboard's Universal Clipboard exclusion, timing on a real CPU.
