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
| Account and logins | made by `tools/uitest-seed` | An ordinary client: it enrolls with the server's bootstrap invite, confirms the recovery phrase and saves items through the sync engine. The server has no test-only door. |
| Test site | `https://site.andvari-uitest.test:8443` | Static pages with a sign-in form, a sign-up form and a one-time-code field. A hosts-file name for loopback; its certificate comes from a CA made in the job, trusted only by the job's simulator. |
| Test site, plain http | `http://plainhttp-uitest.test:8081` | The same pages under another registrable domain, for the rule that an http page is only offered a login saved as http. |
| Simulator | newest installed iOS, a new device per run | `boot-simulator.sh` |

The account's email and master password are in `env.sh`. They are fixtures for a server that lives for one job.

## Adding a test

Subclass `UITestCase`, write the test as `step("name") { … }` blocks (each ends with a screenshot), find
elements by accessibility identifier (`AccessID` in `Andvari/Support/Theme.swift` and the literal identifiers
in the views). A test that cannot run in the simulator stays in the suite and calls `try skip("why")`, so the
summary carries the reason.

## What the simulator can and cannot show

Measured on the iOS 26.5 simulator of the `macos-26` runner, last in run 43137187027. Two things in that
table are the app's, not the simulator's: adding or auto-saving a login fails on a device that signed in to
an account made elsewhere, because the personal vault is only a proposal there and the iOS app has no place
to confirm it.

The Safari tests are the least steady. A Safari that has just started sometimes drops the address it was
opened with, and its first-run tips cover what the tests tap; the helpers work around both, and a run can
still lose one test to it. Run again before reading a single Safari failure as a regression.

| Checklist item | In the simulator | Test |
|---|---|---|
| First launch, server, Trust Gate, sign in, vault list | Works | `T1…test01` |
| Wrong password, background lock, Lock button, item detail, search, sign out | Works | `T1…test02`–`07` |
| Add a login on a device that signed in (did not enroll) | Runs, and fails in the app: "Choose a vault for this item." | `T1…test08` |
| Turn Face ID on, unlock by face, non-matching face, background then face, turn it off | Works, with a software key in place of the Secure Enclave key (below) | `T2…` |
| Turn andvari on under Settings > General > AutoFill & Passwords | Works by driving the Settings app. No `simctl` or `defaults` route is documented. | `T3…test01` |
| Safari offers the login for the https site and fills it after Face ID | Works. iOS 26 shows a sheet ("Sign in to … with your password for … saved in andvari") in place of a QuickType suggestion. | `T3…test02` |
| The provider's list sheet (Passwords key, choose andvari, Face ID, pick a login) | Works | `T3…test03` |
| One-time code offered above the keyboard and filled | Works; the code the site receives is checked against RFC 6238 for the seeded secret | `T3…test04` |
| A plain-http page gets only the login saved as http | Skipped: Safari offers nothing from a provider on a plain-http page, so the rule is not observable | `T3…test05` |
| The system's save offer (iOS 26.2+) and the login arriving in the app | The offer works and names andvari; the capture reaches the app. It is not saved by itself for an account that signed in: same "Choose a vault" refusal. | `T3…test06` |
| Turn the Safari web extension on in Settings | Works | `T3…test07` |
| Extension popup: Face ID, list, fill | Fails. The popup opens from Safari's page menu after Safari asks to let the extension see `127.0.0.1` and the site; Face ID runs; the popup then shows its headings with no logins and "Session locked — unlock to continue." Not yet known whether that is the simulator or the extension. | `T3…test08` |
| Fill a field in an app with no website (andvari's own unlock field) | Works: the list opens with every login and the chosen password is put in the field | `T3…test09` |

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
