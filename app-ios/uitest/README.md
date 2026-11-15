# iOS UI tests in the simulator

The workflow `.github/workflows/ios-uitest.yml` builds the app for the iOS Simulator on a GitHub macOS runner,
starts an unmodified andvari server and a small test site on the runner's loopback, and runs the XCUITest
target `AndvariUITests` against them. It needs no secret and no signing identity.

Read a run without a Mac:

```sh
app-ios/scripts/uitest-report.sh <run id> [directory]
app-ios/scripts/uitest-report.sh --text <run id> [directory]
```

That downloads the run's artifact and prints one line per test, with what the test noted on the way (`note:`
lines: something a reader should know whether it passed or not, such as a prompt iOS put over the app). The
directory then holds `uitest-summary.json` (test, status, failure or skip message, notes, screenshot names),
`screenshots/<Class>.<test>__NN_<step>.png` (one per step, plus the screen at the end of each test),
`trees/<Class>.<test>__<name>.txt` (the UI tree where a test dumped it, at a failure mostly), `server.log`, the
`xcodebuild` logs and the `.xcresult` bundle. The whole artifact is hundreds of megabytes; `--text` fetches the
run's second, small artifact: the summary, the logs and the trees. The job's own log prints the summary too.

A branch other than `ios-ui` is run by hand: `gh workflow run ios-uitest.yml --ref <branch>`.

## What runs where

| Piece | Where | Notes |
|---|---|---|
| andvari server | `http://127.0.0.1:8087` | `:server:shadowJar` from the checkout, throwaway data directory. `127.0.0.1` because it is the only host the app dials over plain http. |
| Account and items | made by `tools/uitest-seed` | An ordinary client: it enrolls with the server's bootstrap invite (which designates its personal vault, as any registering device does), confirms the recovery phrase and saves five logins, a note and a card through the sync engine. The server has no test-only door. The simulator is a second device of that account, so it is asked once to confirm the personal vault. That account, an admin, then invites a second, empty one the same way, for the account-deletion test to delete (`T5`). |
| Test site | `https://site.andvari-uitest.test:8443` | Static pages with a sign-in form, a sign-up form and a one-time-code field. A hosts-file name for loopback; its certificate comes from a CA made in the job, trusted only by the job's simulator. |
| Test site, another site | `https://other-uitest.test:8443` | The same pages under another registrable domain and the same certificate, for a fill that crosses sites. |
| Test site, plain http | `http://plainhttp-uitest.test:8081` | The same pages under another registrable domain, for the rule that an http page is only offered a login saved as http. |
| Simulator | newest installed iOS, a new device per run | `boot-simulator.sh` |
| Another device, a second account | `POST /control/…` on the test site | `vault-create`, `vault-delete` and `vault-restore` (`?name=`) sign in as another device of the account and change one of its shared vaults (`tools/uitest-seed vault`). `share-read-only` (`?name=&item=`) has a second account, enrolled with an invite the test account mints as the server's admin, share a vault holding one login read-only with the account, and another device of the account accept it by typing the sharer's identity code (`tools/uitest-seed share`); with `&email=&password=` that second account has that address and master password, so a test can sign in as the owner of a vault someone else uses. The app learns of either at its next sync. `server-stall` (`?seconds=`, 20 at most) stops the vault server for that long and lets it go on: a network that stalls. |
| Files and Photos | the simulator's own | The runner is a simulator process and the simulator's containers are folders on its disk: a test writes its files into the Files app's On My iPhone (`FilesApp` in `Support/Backend.swift`), where the system's file picker offers them, and reads back what the app saved or exported there. `boot-simulator.sh` puts one picture into Photos (`simctl addmedia`) for the photo picker. The same way a test reads what andvari keeps on disk: its files, its preferences and the rows of its access groups in the simulator's Keychain (`LocalState`, `SimulatorKeychain`). |
| Page event log | `<page>.html?uitest-events` | The test site adds a passive log after the page's content: presses, focus moves with the page's user activation and focus, and window focus. The card tests read it to say what the page saw. |

The account's email and master password are in `env.sh`. They are fixtures for a server that lives for one job.

A card is filled only into a payment provider's card form (owner decision 2026-11-14), so the test site has a
stand-in provider: `https://pay.andvari-uitest.test:8443` (`UITEST_PROVIDER_ORIGIN` in `env.sh`), the same server
under its own name, which the certificate carries too. Only the Safari extension's UI-test build lists it as a
provider (`UITEST=1` in `prepare.sh`, which this workflow sets; `extension/build.mjs`), and `ios-unsigned.yml` fails
when a release bundle names the test domain or any payment provider's test host (`app-ios/scripts/check-no-test-hosts.sh`). The App Store build has no in-page card fill at all (owner decision
2026-11-14), so this workflow also sets `CARDFILL=1`, the switch the card-preview build uses. `checkout.html` is a shop page that embeds the provider's card form:
`pay/card.html` in one frame (`?layout=card`, the default), one `pay/field.html` frame per field (`?layout=split`), or
a security code alone (`?layout=code`). The shop's own name-on-card field there is never filled. `?layout=lure` adds a
rewards widget of another site with provider frames of its own (`rewards.html`): a field tapped there and the shop's
code are two payment forms, in either order, so the popup fills neither and offers Start over; `?layout=clipped` clips the card frame to its postal code, so a fill from a tap there writes nothing else.

## Adding a test

Subclass `UITestCase`, write the test as `step("name") { … }` blocks (each ends with a screenshot), find
elements by accessibility identifier (`AccessID` in `Andvari/Support/Theme.swift` and the literal identifiers
in the views). A test that cannot run in the simulator stays in the suite and calls `try skip("why")`, so the
summary carries the reason. `note("…")` records something the test saw for the summary without failing it.

A class makes the state it needs and relies on nothing the class before left: the account deletion tests end with
no account in the app, so a test starts with `freshVault()` (the app started again, the seeded account signed in
and unlocked) and one that needs the extensions with `requireAutoFillProvider()`, which also turns Face ID on.

The vault list builds only the rows near what it shows. A new item's row is where its name sorts, which in a long
list is below the fold and not in the tree at all: find it with `requireInVault` or open it with `openItem` /
`openAnyItem`, which scroll to it, never by waiting for the row to exist.

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
| Change a login's password twice (the editor's generator), then restore the earlier version that held a password | Works | `T4…test02` |
| Create a shared vault; copy a login into it (both stay) and move another (it leaves Personal) | Works | `T4…test03` |
| A shared vault deleted, then restored, on another device: a notice for each after a sync, gone when dismissed | Works | `T4…test04` |
| A login in a vault the account only reads: no Edit, "Copy to another vault…" and no Move; the copy in Personal can be edited | Works. A second account shares the vault read-only and another device of this account accepts it; the app takes it at a sync, through the account's own wrap of the vault key, with no invitation screen of its own | `T4…test05` |
| The third-party keyboard switch | Present and off by default. Whether such a keyboard is kept out is skipped: the simulator has none, and the suite would need an app of its own to add one | `T4…test06` |
| Two-step setup survives a trip to the Settings app (the same key at the confirm step after the unlock); the authenticator's code turns it on, a later one off | Works | `T4…test07` |
| A password typed into the login editor a key at a time keeps the keyboard and is saved as typed | Works since the fix of 2026-11-14 (below) | `T4…test08` |
| Every card test page (extension/test-pages/card-*.html: the review rounds' attacks and first-party card forms): no Fill, and the popup's line says to copy from the app; the skimmer's hidden form receives nothing | Works | `T5…test01` |
| checkout.html with the provider's frame Safari keeps the extension out of (Other Websites: Ask): no Fill, and the popup names the provider's site to allow; with every website allowed in Safari's settings, a Fill into the provider's origin | Works | `T5…test02` |
| `?layout=card`: a tap on the number in the provider's frame, then Fill: number, expiry and code in the provider's form, the shop's own name-on-card field empty | Works | `T5…test03` |
| `?layout=split`: one provider frame per field. A fill reaches only the frames tapped in (round 11): the number alone fills the number alone; a tap in each frame, then one Fill, fills all three | Works | `T5…test04` |
| `?layout=code`: a security code alone in the provider's frame | Works | `T5…test05` |
| The choice survives the keyboard's Done | Works | `T5…test06` |
| `?layout=twice`: a second card-number frame beside the first: no Fill, the popup says the page shows more than one payment form asking for the same card detail and to copy from the app; nothing is filled | Works | `T5…test07` |
| `?layout=lure` (rounds 12 and 13): the shop asks for the security code alone beside another site's rewards widget with provider frames of its own; after typing into the widget, a tap on the code: two payment forms, no Fill, the popup says so and offers Start over; after Start over, a tap on the code and Fill: the Fill names the security code alone, the code is filled, the widget's fields keep what was typed | Works | `T5…test08` |
| `?layout=clipped` (round 12): the card frame clipped to its postal-code row; a fill from a tap there writes none of the number, expiry or security code | Works | `T5…test09` |
| A shared vault made here: Members offers adding someone and this account is its owner; an address the server does not know is said so and nothing is recorded under People you verified | Works | `T4Sharing…test01` |
| Vault health counts the logins and records a check ("It worked") against the login checked | Works | `T4Sharing…test02` |
| Delete an empty account from Settings: the preview, the address and the master password, the confirmation, then the server screen | Works | `T5AccountDeletion…test01` |
| The login editor's password and one-time code key, hidden while typed a key at a time and read back with Show; its notes; saved, and read again from the item (the code is the authenticator's for the key typed) | Works | `T6…test01` |
| The card editor's number and security code on the number pad, read back with Show; its notes; saved, and read again from the item | Works | `T6…test02` |
| A note's text, two lines of it, read back from the field and from the saved note | Works | `T6…test03` |
| The recovery phrase field of "Forgot your master password?": hidden while typed, the same characters once shown | Works | `T6…test04` |
| The unlock screen's master password typed a key at a time: one dot a character, and it opens the vault | Works | `T6…test05` |
| A note with a text file, a PDF and an image chosen in Files: each listed in the item, opened as what it is, and saved back to Files byte for byte | Works | `T7…test01` |
| A note with a picture chosen in the photo picker: listed under the name Photos gives it, opened as an image | Works | `T7…test02` |
| The document scanner | Skipped: the simulator has no camera, so the Add a file menu offers no Scan a document (checked) and no scan can be made | `T7…test03` |
| A note saved with three 20 MB files while the server stalls and the app leaves the screen: the note is in the vault once with its three files, nothing is left set aside on the device, and one saved back to Files is the file added | Works | `T7…test04` |
| A Chrome CSV export chosen in Files: the screen says where it is from and what it would add, the import adds its three logins (one with a comma and quotes in its password reads as in the file), and the same file again adds nothing | Works | `T8…test01` |
| Vault health counts two more logins, two more weak and two more reused after two imported logins that share a weak password, and says of each that it is reused in one other login | Works | `T8…test02` |
| The vault exported as a CSV into On My iPhone: the screen names the file, the file has the header and as many logins as the screen counted, and an imported login is in it as it went in | Works | `T8…test03` |
| A backup under a passphrase typed a key at a time, twice: the file saved is an andvari backup (`ANDVBK01`) and holds no seeded password, name or card number in plain text | Works | `T8…test04` |
| An account that owns a vault someone else reads: the deletion preview names the vault and takes no confirmation; with the vault deleted in Shared vaults the account is deleted, and the app is as a fresh install is, in a new process too: the server screen, and no file, preference or Keychain row of the account or its server on the simulator's disk | Works since the deletion forgets the server too (below) | `T9…test01` |

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

- **The login editor's password field let go of the keyboard while it was typed into** (found 2026-11-14,
  fixed the same day). Typed a key at a time, 0.4 s apart, it kept the keyboard for a key or two; typed fast, the
  rest of the keys were lost (a password saved as "Fi" for "First-Passw0rd"). `LoginEditorView` and
  `CardEditorView` make their `SecretTextField` without `focused`, which defaults to false, and every update of the
  field (each key changes the draft) ran `updateUIView`, which resigned the first responder of a field that was not
  `focused` (`Support/SecretFields.swift`, since bfd0b412). The field now follows a change of its focus request
  only, and `T4…test08` fails if it lets go again.

- **iOS offers to save a password typed in andvari's own fields** (seen 2026-11-15). After a login whose password
  was typed into the editor's hidden field is saved, iOS puts its own "Save Password? Securely store your password
  so it's filled automatically the next time you need it." (Not Now, Save) over the vault; it does the same for the
  master password after a sign-in or an unlock by typing. A person sees it too, on an iPhone where AutoFill
  Passwords is on with Apple's Passwords as a provider: the simulator shows it until the AutoFill tests have made
  andvari the provider, and a run of the whole suite, where they have, showed none after the editor. A password
  shown with the editor's eye before Save is not offered. The tests answer Not Now and note each time in the
  summary. Whether andvari should keep iOS from offering to store its master password and its items' passwords
  elsewhere is a product question, not the tests'.

- **Deleting the account left the server on the device** (found 2026-11-15). After Delete account the app stood
  on the server screen, but the server's address was still stored: a new process started on the sign-in screen of
  that server, and what the device kept for other accounts of that server stayed. The owner's rule since: a
  deletion leaves the app as a fresh install is. `T9…test01` starts the app again after the deletion and lists
  what is left on the simulator's disk.

- **Card fill into merchant pages, before 2026-11-14** (overtaken by the owner's redesign: a card goes only into a
  payment provider's card form). Under the earlier design the tests found that closing the keyboard with its Done
  dropped the tapped field, that a form holding only a security code was never filled, and that since 3ef56e8b a
  page with no frame was refused as having something over or under the field. The new design keeps the choice
  across Done and fills a provider frame holding only a security code (T5 test05, test06).

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
  the clipboard's Universal Clipboard exclusion, timing on a real CPU, a camera (the document scanner).
- What a Keychain item holds. The simulator's Keychain is a database on its disk, and a test counts the rows of
  andvari's access groups there; the items' secrets, and their names, are sealed.
