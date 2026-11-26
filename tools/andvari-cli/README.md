# andvari-cli

The headless andvari client (design `docs/design/2026-11-15-onboarding-trust.md` §9.5, §12, §14.1, §18, the CLI): one device per
home directory (`--home`, `$ANDVARI_CLI_HOME` or `~/.andvari-cli`), the engine of `:core` over the JVM's HTTP client.
`andvari-cli --help` lists every command.

## Secrets

A secret is never a command-line argument: the master password (`--password-file` / `$ANDVARI_PASSWORD`), a new one
(`--new-password-file` / `$ANDVARI_NEW_PASSWORD`), a two-step code (`--totp-file` / `$ANDVARI_TOTP`), an emailed code,
a kit (`--kit-file`), a link (`--link-file`, or `-` for standard input). Without a file or the environment the tool asks
at the terminal, or reads one line of standard input when there is none. Something that must be captured (a new
recovery kit) or confirmed (the Trust Gate, an account deletion) is refused without a terminal unless its own
non-interactive form is given: `--kit-out FILE`, `--trust-card <card0Hash>`, `--confirm-email <address>`.

## What a server sends is shown, never obeyed

Every line the tool prints goes through one function (`Shown.text` in `Term.kt`): control characters (escape sequences,
line feeds, carriage returns, tabs), line separators, direction overrides and isolates, zero-width and other format
characters are shown escaped (`\n`, `\r`, `\t`, `\u{202E}` ...), so a server's text can never move the cursor, retitle the
terminal or forge a line of the tool's own. `--json` documents get the same characters as JSON `\uXXXX` escapes, so a
script reads the values the server sent. A value printed for pasting into a command (an address, an id, an origin) is one
shell word: quoted when it holds anything but plain characters, since an address may contain `` ` ``, `$`, `|` or `&`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | done |
| 1 | refused; the message on standard error says why and whether anything was sent |
| 2 | usage: the command was not understood; nothing was sent |
| 3 | the server's answer was larger than this device accepts for it (`[server_answer_too_large]`), or held a row this device will not show (`[server_row_refused]`) |
| 4 | the account is short of space, so a copy did not start (`[account_short_of_space]`; `restore --json` prints `{error, short: [{quota, used, limit, adds, by}]}` on standard output, after the preview) |
| 8 | another andvari-cli command was running in this home for the whole wait (`[home_busy]`): nothing was sent or changed; run it again |

One command at a time changes a home. Every command holds the home's lock (the file `andvari-cli.lock` in it) from
before it reads anything there until it ends; a second command waits up to 10 seconds (`ANDVARI_CLI_LOCK_WAIT_MS`
names another wait, from 0 to 60000) and then stops with exit 8. The system drops the lock when the process that holds
it ends in any way, so a lock left by a process that died does not block. A command that waits for a person (a device
link, a password typed at a prompt) holds the home meanwhile.

A message key in brackets after `andvari-cli` names a fault a script may tell apart, for example
`[deletion_outcome_unknown]` (an account deletion whose outcome cannot be told yet: run `account delete --check`).

## Machine-readable output (`--json`)

With `--json`, a command that prints a list or a state prints **one JSON document on standard output and nothing else
there**. Everything else (prompts, notes, warnings, refusals) goes to standard error, and the exit codes are as without
`--json`. When the command fails, standard output is empty. A list is an array, a state an object. Fields the tool
builds are always present, `null` when there is no value; rows that are the server's own JSON may leave out a field at its
default (marked `?`).

No secret appears in this output unless printing it is the command's purpose: `item list --json` prints the items,
secrets included, because that is what it is for. A link is never printed by `link list` (it is a capability), and no
request code by any recovery list.

| Command | Document |
|---|---|
| `whoami` | `{origin, account, server: {name, kind, cardSeq, pinnedThrough} \| null, state}`; `state` is `open`, `blocked`, or the stop's code (`forked`, `moving`, ...) |
| `card show` | `{origin, name, kind, instanceId, card0Hash, cardSeq, cardHash, operator, operatorKey, recoveryFp, pinnedVia}`; `operatorKey` grouped as the Trust Gate shows it |
| `sync` | `{vaults}`: how many vaults the server lists for the account |
| `contacts` | `[{userId, label, compared, code}]`; `code` is the comparison code, `null` when the contact is not current here |
| `vault list` | `[{vaultId, name, kind, log, owner, members, headSeq}]`; `kind` is `personal` or `shared`; `log` is the shared vault's log status (`verified`, ...), `null` for the personal vault; `owner`, `members` (a count) and `headSeq` only from a verified log |
| `item list V` | `[{itemId, doc}]`, `doc` the decrypted item |
| `link list` | `[{linkId, kind, shares}]`, `shares` a count |
| `recovery-requests` | `{offered, requests: [{requestId, state, createdAt, verifiedAt, holdEndsAt, platform}]}`; `platform` is self-reported |
| `recovery show` | `{posture, recorded, fp, operatorOffered}`; `posture` is `private` when none is recorded |
| `account quota` | `{quota: {accountBytes, items, ownedSharedVaults, openLinks: {used, limit}} \| null}` from a fresh sync; `null` when the server gave no figures |
| `account signing-key` | `{userId, signingKey, shortForm}` from this device's own copy of the account: what `operator hand-over` names |
| `account devices`, `operator devices E` | `[{deviceId, platform, name, clientVersion, createdAt, lastSeenAt, live, how, linkedFrom?, current}]` |
| `operator accounts` | `[{userId, email, displayName, role, status, createdAt, lastSeenAt, disabledAt?, recovery, ..., quota?}]`, the server's rows; without `--json` each line ends with the meters as `used/limit`, or `quota unknown` |
| `operator status` | the server's `AdminStatus` object |
| `operator audit` | `[{id, at, type, userId?, deviceId?, ip?, meta?}]` |
| `operator recovery-requests` | `[{requestId, userId, email, rPub, platform, createdAt, verifiedAt, holdEndsAt}]`: never the request code, and never the server's account ID (what the operator checks comes from the person: the code they read out and the account ID on their kit). Every field is checked first; when a row fails, nothing is printed and the command exits 3 with `[server_row_refused]` |
| `operator policy` | the policy object, always JSON, with or without `--json`; `operator policy set --file` takes the same |

Times are milliseconds since the epoch.
