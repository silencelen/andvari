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
