# Self-hosting andvari

andvari is a zero-knowledge household password manager you can run yourself. Your
master password never leaves your devices, and the server keeps the contents of every
vault only as ciphertext it cannot read, so hosting it is mostly a matter of keeping one
small container alive (two with the caddy overlay), together with its data folder and its
two settings files, and backing them up.

The andvari apps and the browser extension connect to your server as to any andvari
server: by its address, or through a link your server made. The web app is served by
your server itself, at its address. Clients apply your instance's declared policy under one
hard rule — **a server can make a client safer, never laxer** (spec 03 §1.1) — so you
configure the *server's* stance here and the clients follow to the extent that's safe.

This page is bundled with every server at `<your-origin>/selfhost`, together with
downloadable copies of `docker-compose.yml`, `docker-compose.caddy.yml` and `andvari.env.template`.

## What you need

- A Linux host (amd64 or arm64) with **Docker Engine + the compose v2 plugin**
  (`docker compose version` must work). Docker's documentation says that on a host where
  SELinux is enforcing, a host folder mounted into a container needs the `:z` or `:Z`
  option of the mount before the container may use it. The lines of this guide and
  `docker-compose.yml` do not add it.
- **Docker's ordinary daemon**, the one that runs as root: the lines of this guide are
  written for it. Rootless Docker is not covered by this guide; there the `mv` of the
  setup line (step 4 of **Install**) already fails, with `mv: cannot stat
  'data/andvari.env': Permission denied`.
- **A file system for `./data` that keeps owners and modes and allows a second name for a
  file.** FAT, the format of many USB sticks, keeps none of these, and neither does exFAT,
  the format of most larger sticks and memory cards. With FAT it looks like this. On a disk
  mounted with no options (every file then belongs to root), setup prints only
  `chown: changing ownership of '/data': Operation not permitted` and writes nothing.
  Mounted for the server's user, with uid and gid 10001 and an owner-only mask in the
  mount's options (`uid=10001,gid=10001,umask=077`), setup works and the server runs and
  reports healthy, but every snapshot run ends with status 1 (in the trial, each with a
  line that begins `andvari: backup stopped at the dated name:`), and no snapshot is kept:
  the server looks healthy while no night's snapshot is kept.
- **Memory and disk**, each measured once on one machine, which is no promise: the
  server's container, holding two accounts and 200 items, used about 0.3 GB of memory by
  `docker stats`. Holding 108 items, its peak (the container's `memory.peak`, which counts
  cached files too) was about 0.4 GB a minute after a start, and about 0.5 GB once a
  snapshot run had run in it; the run is a second process in the same container. Building
  the image from its source with an empty Docker cache, on that machine (4 cores, 8 GB of
  memory), took 4 min 21 s, with about 4 GB of the machine's memory in use at the highest
  of the samples taken, and the disk in use grew by about 3 GB.
- A **domain name** for the server (e.g. `vault.example.org`) and an **https front**
  that answers for it. The server's address is `https://` and that name: a name of at
  least two parts, in lowercase, with no path and no IP address, and a port only when it
  is not 443 (`https://vault.example.org:8443`). Setup refuses any other address, and so
  does the server's start. With an https address the server
  sends HSTS on every answer (`max-age=31536000; includeSubDomains`): browsers that have
  seen it reach that name, and every name under it, only over https for a year. Plain
  http is accepted only for `http://localhost` and `http://127.0.0.1`, to try andvari out
  on the host itself, and the server then warns that a plain-http address is for
  development only. There is no plain-http setup for other machines on your network, and
  never expose plain http to the internet. The front is one of:
  1. **The caddy overlay** (`docker-compose.caddy.yml`): Caddy gets the certificate
     itself (Let's Encrypt or ZeroSSL). Needs ports 80+443 reachable from the internet
     and DNS pointing at the host. Step 3 of **Install** switches it on.
  2. **Your own front**: any reverse proxy, `cloudflared`, or `tailscale serve`
     pointed at `127.0.0.1:8080` (the app publishes on loopback only by default).
     **Read the client-IP note below before you finish this one** — the default
     topology works, but every caller shares one rate-limit bucket and one audit
     IP until you tell the server which peer is your proxy.
- **Paper and a safe place** for what brings an account back without its master
  password: every member gets a recovery kit when they register and must keep it before
  their vault opens, and if you choose operator recovery (step 4 of **Install**) you
  print its recovery sheet. Neither is kept on the server.

### Client IPs behind your own front (option 2)

Rate-limit keys and audit rows want the *caller's* IP, not your proxy's. The server
will only believe a forwarded header (`X-Forwarded-For` and friends) when the
request's **direct TCP peer** is one you have declared trustworthy — otherwise any
LAN client could simply set the header and pick its own rate-limit bucket.

Two variables, and they work together:

- `ANDVARI_TRUSTED_PROXY_CIDRS` — **which peers may be believed.** Default
  `127.0.0.0/8,::1/128` (loopback only). An entry may be an address block such as
  `10.0.0.0/8` or a single address such as `172.18.0.1` (taken as `/32`); any other entry,
  a host name for example, stops the server's start, naming it.
- `ANDVARI_TRUSTED_IP_HEADERS` — **which headers to read** from such a peer, in
  priority order. **Default `X-Forwarded-For`** (spec 03 §8's sole default trusted
  header); set it to override the list, or to an *empty* value to trust no forwarded
  header at all. Only a peer inside `ANDVARI_TRUSTED_PROXY_CIDRS` is ever asked for one,
  so the default is inert until you widen the CIDRs.

The catch that makes this a real setting rather than paperwork: **inside the shipped
container your host-side proxy is not loopback.** `docker-compose.yml` *publishes*
`127.0.0.1:8080`, and a published port is a NAT hop — the peer address the app sees
is the compose bridge gateway, never `127.0.0.1`. So with the defaults,
a `cloudflared` / `tailscale serve` / nginx front on the host gets its forwarded
headers ignored, every request keys the same bucket, and every audit row records the
gateway. Nothing leaks in that state, but it is coarse, and silently so: every sign-in
from every caller counts against one budget (5 a minute by default), so one stranger's
wrong passwords keep every member from signing in.

Pick one:

| Topology | What to set | Result |
|---|---|---|
| **caddy overlay** (`docker-compose.caddy.yml`) | nothing | caddy shares the app's network namespace, so its hop really *is* loopback, and `X-Forwarded-For` is already the default header. |
| **your own front on the host** | `ANDVARI_TRUSTED_PROXY_CIDRS=<the bridge gateway>/32` | per-caller keys and audit rows. The header list already defaults to `X-Forwarded-For`; name it explicitly only to read a different one. |
| **`network_mode: host`** on the app service (in `docker-compose.yml`, in place of its `ports:` lines; keep the edited file with your backups) | `ANDVARI_HOST=127.0.0.1` in `andvari.env` | the proxy's hop is genuinely loopback; no CIDR needed, and the default header applies. Without that line the server listens on every address of the host (the image sets `ANDVARI_HOST=0.0.0.0`), in plain http, beside your proxy. |

Whichever front you run, it must either overwrite the client's `X-Forwarded-For`, merge
into it (one line, the real client appended last — cloudflared, tailscale serve and Caddy
do this by default; nginx only with `proxy_set_header X-Forwarded-For
$proxy_add_x_forwarded_for`, stock nginx adds nothing), or append its own header *line*
(HAProxy's `option forwardfor`).
The server reads the rightmost entry of the **last** line, which is the one your proxy
wrote in every one of those shapes. A front that leaves the client's header untouched
and adds nothing is not a trusted proxy and must not be named in the CIDR list.

`docker network inspect andvari_default -f '{{(index .IPAM.Config 0).Gateway}}'`
prints the address to put there (for a server you gave another `COMPOSE_PROJECT_NAME`,
the network is `<that name>_default`). Name **only** the peer(s) that are actually your
proxy: widening the CIDR to a range real clients can reach from hands those clients
their own header, and with it their own rate-limit key and their own audit row. The
trust boundary is "this exact peer address is my proxy", nothing weaker — a `/32` is
the right shape. `/metrics` is unaffected: it stays gated on the **raw** loopback peer
and never consults this setting.

## Install

These steps set up one server in a folder of its own. They are written for Docker run as
root: type them in a root shell (`sudo -i`). The server's settings file, `andvari.env`,
belongs to the container's own user, uid 10001, with mode 600, because it holds the
server's secrets; Docker Compose reads it as root, and the commands below read it as the
container's user. On the host, only root, whatever account has uid 10001 and every member
of the `docker` group (which can run any container as root) can read it and the data
folder: if `getent passwd 10001` prints a line, that account can, unless the server's
folder lies under a folder it cannot enter, such as `/root` with mode 700 (`ls -ld /root`
shows it; that account's `cat` of `andvari.env` then answers `Permission denied`). So use
a host where no account has uid 10001, and put in the `docker` group only accounts you
would give root.

**The server's address.** andvari needs an https address with a domain name, such as
`https://vault.example.org`: a name of at least two parts, with no path and no IP address,
and a port only when it is not 443. Plain http is accepted only for `http://localhost` and
`http://127.0.0.1`, for trying andvari out on the machine itself. Choose the address
before you start: setup writes it into the server's settings, and every link the server
makes carries it.

**The image.** The server, the web app and the offline recovery tool are one container
image, `ghcr.io/silencelen/andvari-server`, with one tag per version (`1.0.0`). Instead of
pulling it, you can build it from the source; you can read every line of it at
<https://github.com/silencelen/andvari> (AGPLv3 server, GPLv3 clients, see
`LICENSING.md`). The build downloads the tools it uses, so it needs internet access too.
Run these two lines in the folder where you will make the server's folder in step 1:

```sh
git clone --branch v1.0.0 https://github.com/silencelen/andvari andvari-src
docker build -t ghcr.io/silencelen/andvari-server:1.0.0 andvari-src
```

The first line fetches the source of version 1.0.0 into `andvari-src`; the second builds
the image from its `Dockerfile` and gives it the name the steps below use, so Docker
never needs to pull it.

**1. The folder and the compose files.**

```sh
mkdir andvari && cd andvari
curl -fsSLO https://raw.githubusercontent.com/silencelen/andvari/v1.0.0/deploy/docker-compose.yml
curl -fsSLO https://raw.githubusercontent.com/silencelen/andvari/v1.0.0/deploy/docker-compose.caddy.yml
```

This makes the folder that holds everything of this server and downloads the compose
file of version 1.0.0 and the caddy overlay, which you need only for option 1 under
**What you need**. Every running andvari server also offers the compose files and the
settings template of its own version at `<its address>/selfhost`.

**2. The data folder.**

```sh
mkdir -m 700 data
```

`data` holds the database and the attachments. Only its owner (and root) may open it: the
container makes it its own user's at every start (owner uid 10001, mode 700) and every
database file mode 600.

**3. The compose settings.**

```sh
printf 'ANDVARI_VERSION=1.0.0\n' > .env
```

`.env` holds the settings of Docker Compose itself, beside `docker-compose.yml`; this line
names the version to run. With the caddy overlay, add the two lines that switch it on and
name the server's domain (the address without `https://`):

```sh
printf 'COMPOSE_FILE=docker-compose.yml:docker-compose.caddy.yml\nANDVARI_DOMAIN=vault.example.org\n' >> .env
```

Only when this host already runs another andvari server, give this one a name and a host
port of its own (the defaults are `andvari` and `8080`):

```sh
printf 'COMPOSE_PROJECT_NAME=andvari2\nANDVARI_HOST_PORT=8081\n' >> .env
```

Each server then keeps its own folder, and at most one of them can use the caddy overlay,
because it takes the host's ports 80 and 443.

Until the `mv` of step 4 has put `andvari.env` beside `docker-compose.yml`, Compose stops
at that file: `docker compose config` and `docker compose up -d` print `env file
…/andvari.env not found: stat …/andvari.env: no such file or directory`, end with a status
other than 0 and make no container and no `andvari.env`.

**4. Setup.** Setup runs once: it makes the server's database and its settings file, and
refuses to run again over them (see the end of this step). So decide first what it is to
write: its options, the mail settings and operator recovery.

Setup takes these options (`--help` lists them):

- `--kind private` (the default) or `--kind public`. A public server asks everyone who
  registers to confirm their age, lets only the operator make invitations, and has no
  operator recovery.
- `--mode links` (the default), `--mode open` or `--mode closed`: how people join, see
  **Invites & email**.
- `--name TEXT`: the server's name, 1 to 64 bytes (default `andvari`).
- `--cap N`: how many active member accounts the server takes (default 200);
  `--age-confirm` asks everyone who registers to confirm their age.
- `--register-links members` or `--register-links operator`: who may make invitations on a
  private server (default `members`).
- The mail settings. Without them the server sends no mail, and `--mode open` and
  operator recovery need mail. For mail, read **Mail** under **Invites & email** now and
  run the setup line given there instead of the one below.
- `--recovery-pubkey KEY`: operator recovery, next.

**Operator recovery (optional, private servers with mail only).** With it you can help a
member who has lost both their master password and their recovery kit. Decide before
setup: the setup link and the server's signed identity record whether it has operator
recovery. Make the key first:

```sh
docker run --rm --network none --log-driver none ghcr.io/silencelen/andvari-server:1.0.0 recovery-cli keygen
```

This prints the recovery sheet. Its seed can open every recovery copy the server will
keep, and `--log-driver none` keeps it out of Docker's logs. Run it on a computer with no
network if you can (`--network none` keeps the container itself off it), print the sheet
twice, keep the copies in separate safe places, and clear your terminal's scrollback.
Then give setup the sheet's public key with `--recovery-pubkey`, together with the mail
settings: the code of a request for help is sent by mail. The sheet's own closing lines, a
"Config snippet for /etc/andvari/andvari.env" and a "Next" list with `canary`, are not
steps of this guide: setup writes the key into `andvari.env` itself.

**The setup line.** Put your server's address after `--origin`, and the options you chose
after it:

```sh
docker run --rm --log-driver none -v "$PWD/data:/data" ghcr.io/silencelen/andvari-server:1.0.0 \
    setup --env-file /data/andvari.env --origin https://vault.example.org
mv data/andvari.env andvari.env
```

Setup checks the address, creates the database `data/andvari.db` with your server's
instance in it, writes the settings file (the address, the kind of server, how people
join, its name, two random secrets and where the data lives), and prints a **setup link**.
It writes as the container's user, mode 600, and never over an existing server: it
refuses when the database already holds anything or the settings file exists. `mv` puts
the settings file beside `docker-compose.yml`, where Compose reads it; it keeps its owner
and mode. Beside `data`, the server's two settings files are now in this folder:
`andvari.env` and `.env`. **Backup** says what to keep of the folder.

The setup link is a secret: whoever opens it first becomes the operator of this server. It
works once and for 24 hours. `--log-driver none` keeps it, and everything else setup
prints, out of Docker's logs; it stays only in your terminal.

**If setup went wrong.** A second run of setup refuses and changes nothing. Before the
`mv` it answers `andvari: /data/andvari.env already exists; setup never overwrites it (use
--status or --reset-setup)`, after it `andvari: /data/andvari.db already exists; setup
never writes over an existing instance`. To start over with another address or other
options while no account exists on this server: if you have started the server, stop it
with `docker compose down`; then move the data folder and the settings file aside and make
a new, empty data folder:

```sh
mv data data.old
mv andvari.env andvari.env.old
mkdir -m 700 data
```

If you had not run the `mv` of the setup line yet, the settings file is inside `data.old`
and the second line only reports that there is nothing to move. With the caddy overlay,
change `ANDVARI_DOMAIN` in `.env` to the new name too. Then run the setup line again.
`data.old` and `andvari.env.old` hold the old setup's secrets: delete them once the new
server runs.

**5. Start.**

```sh
docker compose up -d
docker compose ps
```

The first line starts the server in the background; Docker starts it again after a
reboot. The second shows it as `healthy` once it answers on `/healthz`, within about a
minute. `docker compose logs andvari` shows its start line, for example
`[andvari] private instance at https://vault.example.org, listening on 0.0.0.0:8080`. Your
https front (option 1 or 2 under **What you need**) must answer at the server's address
before any app can reach it.

**6. The operator account.** Open the setup link in the andvari desktop app on the
computer that will hold this server's operator account. Use an app you do not use for your
everyday account: an app holds one account per server. Then check, but only after the
`mv` of step 4: this line and the ones after it mount `andvari.env` from this folder, and
when it is not there, Docker makes an empty folder of that name in its
place; the `mv` would then put the settings file inside that folder, where Compose does not
read it.

```sh
docker run --rm -v "$PWD/data:/data" -v "$PWD/andvari.env:/andvari.env:ro" \
    ghcr.io/silencelen/andvari-server:1.0.0 setup --status --env-file /andvari.env
```

It prints one line. `ready: card 0 is signed`: the operator account exists and has signed
the server's identity card. `waiting for the operator to open the setup link`: no
operator account yet (the line stays after the link has run out at 24 hours, until the
running server marks it so; then make a new link as below). `waiting for card 0: the
operator account exists; resume from the operator's app`: the account was made but has
not signed the card yet; finish in that app.
``no live setup link: run `andvari setup --reset-setup` ``: no operator account, and no
setup link is left open. If the link was lost or has run out, and while no operator
account exists, this prints a new setup link and ends the old one:

```sh
docker run --rm --log-driver none -v "$PWD/data:/data" -v "$PWD/andvari.env:/andvari.env:ro" \
    ghcr.io/silencelen/andvari-server:1.0.0 setup --reset-setup --env-file /andvari.env
```

Once an operator account exists it refuses with `andvari: an operator account exists; a
new setup link is minted only while none does`.

**7. Your everyday account.**

```sh
docker run --rm --log-driver none -v "$PWD/data:/data" -v "$PWD/andvari.env:/andvari.env:ro" \
    ghcr.io/silencelen/andvari-server:1.0.0 admin enrol-link --email you@example.org --env-file /andvari.env
```

This prints an enrol link that registers one account for that address, valid for 7 days.
Before the link it prints a line that begins `{"audit":true` (this action's entry for the
audit log); the link is the last line.
`--expires 30d` (or `30`) makes it 1 to 90 days; any other value, a mistyped one too,
gives 7 days without saying so. Open it in the app you use every day. The link is a
secret like the setup link, so this line keeps it out of Docker's logs too. The command is
refused until card 0 is signed.

Keep `--log-driver none` on every line that prints a link or a secret: Docker copies what
a container prints to its log driver (a file on disk, the journal, or a log shipper) even
while you watch it in your terminal, and `docker compose run` cannot turn that off for one
run.

**Changing `andvari.env` later.** Edit it as root, then give it back to the container's
user and apply it:

```sh
chown 10001:10001 andvari.env && chmod 600 andvari.env
docker compose up -d
```

Compose reads `andvari.env` when it makes the server's container: `docker compose up -d`
makes the container anew when a setting in the file has changed, and so applies it,
while `docker compose restart` keeps the container and the old settings. With the caddy
overlay, check
afterwards that your server's address still answers; if it does not, run `docker compose
up -d` once more, as the overlay's own note asks after the server's container was made
anew, so that caddy attaches to the new one.

When `andvari.env` is missing while the server's container is started again (`docker
compose start`, `docker start`, or a restart of Docker's service), the container does not
start: `docker compose ps -a` shows it as `Exited (127)`, the first two print a line that
begins `Error response from daemon: failed to create task for container:` and names
`/etc/andvari.env`, and Docker has made a folder, owned by root, named `andvari.env` in
the file's place. Stop the server, move that folder aside, put the settings file back as
`andvari.env` with owner 10001 and mode 600 (the first of the two lines under
**Changing `andvari.env` later** above does that), and run `docker compose up -d`.

A wrong value of a number, an on/off or a choice setting stops the server's start with a
line that names it. A mistyped name stops it too, because setup writes the line
`ANDVARI_STRICT_ENV=1` into `andvari.env`: `ANDVARI_TOTP_REQURED=1`, for example, prints
`[andvari] env WARNING: unknown env var ANDVARI_TOTP_REQURED (typo? renamed?)` and then
`[andvari] ANDVARI_STRICT_ENV=1: refusing to start with 1 env problem(s)`, and the server
does not start. With that line, a number, on/off or choice setting left blank also stops
the start. In a settings file without that line (one written by hand that leaves it out,
or one whose line was taken out), a mistyped name only prints the warning and the server
starts without that setting, and a blank setting takes its default; the two lines under
**A wrong value stops the start** below add the line.

## The policy variables — what your instance declares

Clients fetch `GET /api/v1/client-policy` before login and render/behave
accordingly. These are **operator** settings in `andvari.env`, not in the operator
account's app: what the operator account sets there can only make the server stricter,
so a compromised operator session cannot open your front door. `andvari.env.template`
lists every variable the server reads, apart from the three of its test mode. The host
commands also read `ANDVARI_ENV_FILE`, the settings file to read when `--env-file` is not
given, and setup's test mode `ANDVARI_CLI`.

| Variable | Declares |
|---|---|
| `ANDVARI_CANONICAL_ORIGIN` | The instance's one true address, written by setup. Clients receive it in the policy, the server's signed identity card names it, and every link the server makes carries it. Form: `https://` and a lowercase domain name, a port only when it is not 443, no path, no trailing slash; plain http only for `http://localhost` and `http://127.0.0.1` (development). |
| `ANDVARI_SIGNUP_MODE` | How people join: `links` (the default), `open` or `closed`, written by setup. See **Invites & email**. |
| `ANDVARI_TOTP_REQUIRED` | `1` ⇒ every account must enroll an authenticator: an account without one gets a **restricted session** at login, which can only set up two-step sign-in or sign out, until it enrolls. `0` (default) ⇒ password-only login is allowed — but an account that **has** enrolled TOTP is asked for it at every sign-in. |
| `ANDVARI_OFFLINE_CACHE_ALLOWED` | Operator **floor** for client durable offline caches, ANDed with the admin-settable policy knob. **Monotonicity note:** clients treat the resulting field as *forbid-only* — `false` forbids and wipes their local copy for your origin; `true` alone never forces caching onto a device (web and desktop still require an explicit per-device opt-in; Android defaults on, by recorded design — spec 05 T3/R11). |
| `ANDVARI_INSTANCE_NAME` | A display label, written by setup. Decorative only — clients never render it as a verified identity; the raw origin is what users are asked to trust. |
| `ANDVARI_SELFHOST_DOCS_URL` | Where clients link "run your own server". Defaults to `<canonical-origin>/selfhost` — this very page, served by your own instance. |
| `ANDVARI_FORCE_HSTS` | `1` ⇒ every answer carries `Strict-Transport-Security: max-age=31536000; includeSubDomains`. Required for an https address: setup writes `1`, and the server refuses to start with an https address without it. |
| `ANDVARI_LOGIN_RATE_PER_MIN` | Per-IP login attempts/min (default 5; an IPv6 caller counts by its /64). An email-keyed exponential backoff after repeated failures is always on. |
| `ANDVARI_STRICT_ENV` | `1` ⇒ the start also stops on an `ANDVARI_*` name the server does not know, and on a number, switch or choice left blank, instead of printing a warning and going on. Setup writes `1`. In a settings file without this line, the start only warns about them. |

**A wrong value stops the start, and under `ANDVARI_STRICT_ENV=1` a wrong name does
too.** A switch takes `1` or `true`, `0` or `false`; a number must be a whole number in
its range; a setting with a list of values (such as `ANDVARI_SIGNUP_MODE`) must name one
of them. Anything else stops the server's start with a line that names the setting: with
`ANDVARI_STRICT_ENV=1`, as setup writes it, `docker compose logs andvari` shows
`[andvari] env WARNING: invalid …`, followed by `[andvari] ANDVARI_STRICT_ENV=1: refusing
to start with 1 env problem(s)` for one wrong value; without that line, `[andvari]
refusing to start: …`. A mistyped *name*, such as `ANDVARI_TOTP_REQURED=1`, is a variable
the server does not know: it prints `[andvari] env WARNING: unknown env var
ANDVARI_TOTP_REQURED (typo? renamed?)`; with `ANDVARI_STRICT_ENV=1` the start then stops,
and without it the server starts with the setting meant at its default, here with required
two-step sign-in off. A settings file without an `ANDVARI_STRICT_ENV` line (one written by
hand that leaves it out, or one whose line was taken out) gets it from these two lines:

```sh
printf 'ANDVARI_STRICT_ENV=1\n' >> andvari.env
docker compose up -d
```

The first line adds the switch at the end of the settings file, which keeps its owner and
mode; the second starts the server again with it.

Timer-ish policy values the operator account can set in its app (auto-lock, clipboard clear) are
**clamped on the client side** (auto-lock ≤ 15 min, clipboard ≤ 5 min) — a server,
including a hostile one, cannot disable a device's auto-lock. That is the trust
boundary working as intended.

## Backup

A backup that can bring your server back holds these files of the server's folder (the
one that holds `docker-compose.yml`):

- `data/` — the SQLite database `andvari.db` (accounts, ciphertext items, audit log),
  `blobs/` with the encrypted attachments, and `backup/` with the snapshots below. Also
  `downloads/` when `ANDVARI_DOWNLOADS_DIR` points there, and the file that
  `ANDVARI_SIGNUP_BLOCKLIST` names when you set it: it must lie in `data/`, the only folder
  of the host the container sees, and the server does not start while it is missing.
- `andvari.env` — the server's settings. Setup wrote it once and never writes it again
  for an existing database. It holds the address, the kind of server and the recovery key
  that the server's signed identity card names, the two random secrets, and the mail
  settings.
- `.env` — Compose's own settings: `ANDVARI_VERSION`, without which Compose does not
  start the server, and the lines you added in step 3 of **Install**.
- `docker-compose.yml`, if you changed it (for `network_mode: host`, for example).

Keep `andvari.env` as it is. The server starts with other secrets, but it no longer
matches what it stored with the old ones: a new `ANDVARI_ENUM_SECRET` changes every address
hash the database keeps (an enrol link made for one address, a sign-up waiting for its code
and a request for your help no longer match their address), and it changes the stand-in
answers the server gives for addresses that have no account, so that anyone who asked about
an address before can tell whether it has one; a new `ANDVARI_SIGNUP_SECRET` makes every
sign-up code and request code in flight fail; and with a recovery key other than the one
the server's signed identity card names, the server no longer hands the key to the apps, so
operator recovery stops.

The vault contents in the database and the blobs are ciphertext the server cannot read
(spec 05 T7), but a copy of the database is not harmless to a thief: it also holds every
member's sign-in TOTP seed in plaintext and the login verifiers a guess at a master password
can be checked against offline (the master password's Argon2id cost is what slows that down),
and `andvari.env` holds the server's secrets and the mail password. Keep backups as private
as the live folder, and remember they are the only copy your server can be rebuilt from.

**The snapshot.** The server takes it with a command of its own, in a container of the
server's service. From the server's folder, as root:

```sh
docker compose exec -T -u andvari andvari /usr/local/bin/docker-entrypoint.sh admin backup --env-file /etc/andvari.env
```

This runs `andvari admin backup` in a running container of the server's service (the
server's own, unless a one-off container of the service is up: see below), through the image's
own start script, as the server's own user (`andvari`, uid 10001), without a terminal
(`-T`); the host needs no program of its own for the snapshot. Started as that user, the
start script changes the owner of no file. It can print two kinds of `WARN:` line of its
own before the command runs, and neither stops the command. `WARN: could not restrict
/data/andvari.db… to its owner (chmod 600)` names a file in `./data` whose name begins
with `andvari.db` that it cannot make owner-only (one that root put there: move it out of
`./data`). `WARN: could not restrict /data to its owner (chmod 700) …` says the same of
`./data` itself: as root on the host, give `./data` to uid 10001 with mode 700. The
command reads its settings from the file that `docker-compose.yml` mounts read-only at
`/etc/andvari.env` in that container (`andvari.env`), as the container sees that file when
the command runs: an edit in place shows there at once, but after the file was replaced by
a new one under its name (as a `mv` of a new file onto that name does), the container and
this command read the old file until the container is made anew, as `docker compose up -d`
does when a setting in the file has changed; the server holds the settings it was started with.
A snapshot is taken of a running server only. `docker compose exec` picks a container of
the service, and while a one-off container made by `docker compose run` exists, it can pick
that one, also while the server is stopped; so the command itself looks first whether a
running server holds the database (the first point below). While no container of the
service runs, the line prints an error of Compose's own instead, such as `service
"andvari" is not running`, and takes no snapshot.

What a run does:

- It first looks whether a running server holds the database: the server takes a lock on
  the file `server.lock` in `./data` at its start and keeps it for as long as it runs (it
  writes into that file one line that names its database file; leave the file as it is:
  without it, no run takes a snapshot until the server is started again). Where no
  running server holds that lock for the database file the command would open, or where
  the command cannot tell, the command stops with one line that begins `andvari: backup
  stopped at the server:`, ends with status 1, and has not opened the database and has
  made and changed nothing. A server that could
  not take the lock at its start says so in one line of its log, which begins
  `[andvari] WARNING: the server could not take the lock on` and names the reason, and
  runs without it; the command does not take such a server for a running one.

  The lock cannot see a backup that is copied into the database file while its server
  still runs: the line in `server.lock` names the file, not what it holds, and that file
  stays the same file (a restore, below, begins with stopping the server). Nor can it see
  a database file that is moved away and back within one file system while its server
  runs: the file keeps its identity, and the line still names it. Moved to another file
  system and back, it is a new file under that name, and the next run stops at the
  server's lock with a line that says the line in `server.lock` names another database
  file than the one at the database's path. Whoever can write in
  `./data` can replace the database itself, and the lock is no defence against that.
- It adds no row and no table to the database, and leaves the database's journal mode as
  it is.
- Then it looks at the database, and the first of these that applies ends the run. A
  database whose file does not say write-ahead mode, the mode a running server keeps it
  in, is refused with one line, and nothing is changed. A rollback journal
  (`andvari.db-journal`) beside the database is refused before the database is opened: no
  snapshot is taken. A database whose marker makes the server's start refuse it is refused
  with the sentence the server's start gives. Then nothing in `data/backup/` changes.
- Then the backup folder, `data/backup/`: where it is missing, the command makes it,
  owner-only. A link or anything other than a folder in its place is refused and left as
  it is, with a line that begins `andvari: backup stopped at the backup folder:` and ends
  `Nothing was written.`
- One run at a time: a run that starts while another one works stops and does nothing.
  The file `data/backup/backup.lock` stays after a run (it holds nothing; leave it).
- Then the names in `data/backup/`: `andvari-nightly.db` and the temporary names of the
  last point below must be ordinary files where they exist. A link or anything other than
  an ordinary file in their place is refused and left as it is, with a line that begins
  `andvari: backup stopped at the names in the backup folder:` and ends `No snapshot was
  changed.` Then the command removes what a killed run left under the temporary names.
- Before it writes, it needs free room on the file system that holds `data/backup/` of at
  least twice the size of the database and its write-ahead file together; with less it
  stops and prints both numbers.
- It writes one consistent state of the database into a new file,
  `data/backup/andvari-nightly.db.tmp`, and checks it: the file is not empty, SQLite's
  integrity check answers `ok`, and it holds this version's marker. Where the snapshot
  itself fails, the database cannot be closed after it, or the snapshot cannot be read for
  its check or does not pass one of these checks, the command looks at the server's lock
  once more before it prints its line, and the line can then say more (see after this
  list). The stops whose lines hold `could not make the temporary file` or `could not be
  written to the disk` take no such look; neither is about the database.
- Then it looks at the server's lock again, as it did first. Where the lock is no longer
  held as it was when the run began (as when the server stopped, or stopped and started
  again, while the run worked), or where the command cannot tell, the run keeps no
  snapshot of that night and changes no earlier one: it prints one line that begins
  `andvari: backup stopped at the server, looked at again: the snapshot was made and
  checked, but`, and ends with status 1.
- Only then does the file get its two names, and the temporary name goes:
  - The same file under the date and time it was taken, in UTC, such as
    `andvari-nightly-2026-01-31-111700.db`. A dated name is never written over.
  - `andvari-nightly.db`: the newest snapshot that passed its check, unless the line of a
    failed run says otherwise.
- The newest 14 dated snapshots stay; `--keep N` at the end of the line keeps N instead (1
  to 999). Older ones are removed only after tonight's snapshot has its two names, and only
  files whose names have exactly that form. Tonight's snapshot stays whatever its date, even
  when the host's clock went back.
- A run that works prints nothing and ends with status 0. A run that fails prints one line,
  `andvari: backup stopped at <the step>: …`, which says what went wrong, and ends with
  status 1. A run that stops at the snapshot, its check, its second look at the server or
  its dated name changes no earlier snapshot, and its line says so unless it names an error
  nobody foresaw; one that stops later says which names tonight's snapshot has. It removes
  its own temporary file. A killed run can leave it, and `andvari-nightly.db.tmp-journal`,
  `andvari-nightly.db.tmp-wal` or `andvari-nightly.db.tmp-shm` beside it; the next run
  that gets past "one run at a time" removes them, also when that run then stops for want
  of room. Where one of them, or `andvari-nightly.db`, is a link or anything other than an
  ordinary file, that run is refused at the names, as said above, and removes none.

**Reading a failed night's line.** Where the snapshot failed or did not pass its check,
the line can carry a clause about the server's lock just before `no earlier snapshot was
changed`: `the lock on <the lock file> is no longer held as it was when this run began
(…), so the database's files may have been moved or replaced while this run read them,
and this failure says nothing certain about the database that is there now`, or the same
clause beginning `this command cannot tell whether the lock on <the lock file> is still
held as it was when this run began (…)`. It comes, for example, when the server was
stopped, or stopped and started again, while the run worked, as on a night on which the
database was put back. Such a line is no finding about the database that is there now: do
not restore because of it. Type the line under **The snapshot** above by hand once the
server runs: the line of that run, taken beside a server that holds its lock throughout,
is the finding. Where nobody types it, the next night's run answers. A line without that clause, from a run
beside a server that held its lock throughout, says what went wrong with the database or
its snapshot.

**Who owns the snapshots.** `data/backup/` and every snapshot in it belong to the server's
user, like the database, and only that user can read them (the command makes the folder
with mode 700 and each snapshot with mode 600). The server's own user can therefore change or remove them: a server that breaks,
or one that an attacker takes over, can take its snapshots with it. Only the copy off the
host, with its history, protects you against that.

**The room they need.** Each snapshot is a file of its own, at most about as large as the
database and its write-ahead file together; `andvari-nightly.db` is the newest dated
snapshot under a second name, not a copy. So `data/backup/` holds 14 snapshots (N with
`--keep N`), one more while a run works, and a run starts only with twice the size of the
database and its write-ahead file free.
Plan room for the database, its snapshots and twice the database again, on the same file
system as the database: the server's own saves need room there too.

`./data` is owner-only: the container makes it mode 700, owned by its `andvari` user
(uid 10001), and the database files 0600, because the database also holds the members'
sign-in TOTP seeds and login verifiers. Run the copy off the host as root (or that uid).

**Every night.** Add this line to root's crontab (`crontab -e` as root), with the path of
your server's folder in place of `/root/andvari`:

```
17 3 * * * cd /root/andvari && docker compose exec -T -u andvari andvari /usr/local/bin/docker-entrypoint.sh admin backup --env-file /etc/andvari.env
```

It takes the snapshot at 03:17 every night by the host's clock (the dated names give the
time in UTC); `-T` runs the command without a terminal, which cron does not have. A night
on which the server is not running gets no snapshot: the line prints an error of Compose's
own, or, while a one-off container of the service exists, the command's own line that
begins `andvari: backup stopped at the server:`. cron tells you of a failed night only by
mailing what the line printed to root, and only on a host that can send mail; where root's
mail lands depends on the host's mail program (on a Debian host whose exim4 has no alias
for root, for example, in `/var/mail/mail`). So look now and then, from a root
shell on the host:

```sh
find /root/andvari/data/backup -name andvari-nightly.db -mmin -1560
```

It prints the snapshot's name when a run in the last 26 hours put its snapshot in place,
and nothing when none did: the file's time is the time its snapshot was written, and giving
it its names does not change it.

**The copy off the host.** Copy the whole server folder to another machine every night,
after the snapshot, with a tool that keeps a history of the copies and encrypts them:
`restic` and `borg` do both. A plain `rsync` encrypts nothing, and with `--delete` it makes
the copy whatever the host holds that night. The copy holds the server's secrets and the
members' sign-in TOTP seeds and login verifiers, as said above: keep it encrypted, or where
only you can read it. Take the snapshot before the copy: the copy of `blobs/` then holds
every attachment the snapshot names, unless one was deleted in between.

**Checking a copy.** Where the copy is, in its server folder (taken out of `restic` or
`borg` first), check its snapshot with the `sqlite3` program, which only that machine
needs:

```sh
sqlite3 data/backup/andvari-nightly.db "PRAGMA integrity_check;"
```

It must print `ok`. The check stops at the file: a server started on a copy of the data is
a restore as soon as a device reaches it, with everything **Before you restore a backup**
says. Look at the snapshot's age and check the copy now and then: a backup you never notice
breaking is not a backup. Restore = stop the server, move `andvari.db-wal` and
`andvari.db-shm` out of `./data` if they are there, copy the nightly snapshot into place
as `andvari.db` (copy it, never move it, and keep it until the restore has worked) and
`blobs/` back under `./data`, run `andvari admin restored` once, and
`docker compose up -d`, but read **Before you restore a backup** below first: a
restore is not a neutral act for the people who use your server.

A nightly run that is still working while you stop the server and put the database back
can leave a new `andvari.db-shm` beside the put-back database, and in one case an empty
`andvari.db-wal` as well. `andvari admin restored` then refuses once, with a line that
begins `andvari: Left over beside the database:`, names those files and says what to do.
It cannot tell who made them, and it removes nothing. Do what its line says; no save is
lost.

Not in the server's backup, and kept apart from it: the printed recovery sheet if you
chose operator recovery, each member's recovery kit, and the `.andvari` export files
members make of their own vaults.

**Durability, and what it costs you.** The server runs SQLite in WAL mode with
`PRAGMA synchronous=FULL`: every committed write is fsynced before the client is told
`applied` (spec 02 §7.1). That is deliberate, and it is the setting a password manager
needs — a client drops a saved item from its outbox as soon as the server acknowledges
it, so an acknowledgement that a power cut can undo would lose the newest saves with
nothing left to re-send them. The price is one fsync per write. Household write rates
make that invisible (reads and idle sync take no fsync at all), but on slow storage — an
SD card, a cheap USB stick — a bulk import will feel it (and such a card or stick must
first carry a file system that **What you need** allows). If you hit that, the answer is
faster storage for `./data`, not a laxer setting: `synchronous=NORMAL` buys throughput by
making "saved" mean "probably saved". None of this replaces the backup above; fsync
protects you from a power cut, not from a dead disk.

## Before you restore a backup

A restore is not a neutral act. Your members' devices remember what the server told them
after the snapshot was taken; the restored server knows none of it. This is what a
restore does to the people who use your server:

- **Saves made after the snapshot are gone from the server.** They are left only on the
  devices that hold them. The server had acknowledged them, so no device keeps them to
  send again; a device sends such an item again only when someone edits it there (the
  server then stores it as it would a new item).
- **Devices that synced after the snapshot refuse the older state.** At its next sync
  each such device says that the server sent an older copy of the vault than it has
  already seen, keeps everything it has, and takes nothing from the server.
- **Then those devices can miss other people's saves without a word.** The server numbers
  every change with one counter, and the restore takes that counter back, so the numbers
  a device has already seen are handed out again for new changes. Once new changes carry
  the counter past the number a device had reached, that device syncs normally again, but
  it never receives the changes made under the numbers it had already seen. Nothing tells
  it so. A device that holds nothing of the account (a fresh sign-in) receives everything
  the server holds.
- **Devices revoked after the snapshot are back.** The server knows them again, and its
  devices list shows them as signed out once `andvari admin restored` has run. Such a
  device can no longer sync or renew its session with what it holds, but the server knows
  its device secret again: with the account's master password it signs in as a known
  device, with no link even where the account requires one for new devices, and no
  new-device mail goes out. Nothing tells the account's owner, and the revocation is not
  in the audit log any more.
- **Every session ends.** `andvari admin restored` ends every session of every account,
  yours included: at its next contact each device is signed out, keeps everything it
  holds, unsent saves included, and its person signs in again. A browser that keeps no
  offline copy loses the changes it could not send before the restart.
- **What was changed or removed after the snapshot is back as it was.** An account you
  disabled is active again, an account that was deleted is back, and a member removed
  from a shared vault is a member again and can read it. A recovery kit or a two-step
  (authenticator) setup replaced after the snapshot is undone: the former one is in force.
- **Mail that was waiting to be sent at the time of the snapshot is sent again**, code
  mails for requests for your help included.
- **A master password changed after the snapshot is undone.** The former password signs
  in; the new one is refused as a wrong password.
- **A shared vault whose history changed after the snapshot can stop on some devices.**
  A device that saw a change to the vault's members after the snapshot shows the vault
  read-only, because the server now shows an older history than it has checked. As soon
  as a member whose device never saw that change makes another change to the members (or
  leaves), the first device finds two different histories and freezes the vault for good:
  it stays readable there, and nothing more can be written to it from that device.
  Devices that never saw the lost change go on normally.

**When to restore, and when not.** Restore when the data is gone or damaged: a lost
disk, a database that fails its integrity check. Do not restore to undo a mistake in one
account (a deleted item, a removed member): every member pays for it, and a deleted item
can be brought back from the trash. Do not restore to go back after an update that runs:
it has already taken saves that a restore throws away. Restore after an update only when
the new version does not start on your data, from the snapshot you took just before you
pulled it. Restore the **newest** snapshot that passes `PRAGMA integrity_check`:
everything above grows with the time between the snapshot and the restore.

**Run `andvari admin restored` once, before you start the server again.** Stop the server
first, and run the command on the host that runs it: the command refuses, and changes
nothing, while the server has the database open on that host, but on a network volume
whose locks do not reach across hosts (NFS mounted `nolock`, CIFS `nobrl`, a volume shared
by two hosts) only the server's write-ahead file beside the database gives it away. Copy
the nightly snapshot (`backup/andvari-nightly.db`) into place as `andvari.db`, never move
it, and keep it until the restore has worked; copy it, not the live `andvari.db` that an
off-host copy of `./data` also carries, and before that move `andvari.db-wal` and
`andvari.db-shm` out of `./data`, keeping them until the restore has worked: they belong
to the database you replace, and opening the put-back file beside them applies them to it
and can damage it. Put back only the nightly snapshot, never a copy of the live
`andvari.db` (a copy of `./data` taken while the server was running is one). Such a copy
looks to andvari exactly like the server's own database after an unclean stop, so the
server's start and the other commands of `andvari` that open the database open it with
whatever write-ahead file lies beside it, the one of the database you replaced
included, and that can damage it.
Only `andvari admin restored` refuses every leftover file beside the database, whatever
kind of copy you put back. That is one more reason to run it before anything else touches
the put-back file. The command refuses while a write-ahead file (`andvari.db-wal`), its
companion (`andvari.db-shm`) or a rollback journal (`andvari.db-journal`) lies beside the
database, and says what to do. After that, and before it changes anything, the command
runs SQLite's integrity check on the put-back file, the check the snapshot takes, and
refuses a file that is empty or fails it, with nothing changed and the way back in its
line: copy the newest snapshot that passes `PRAGMA integrity_check` into place again (a
snapshot the command refuses is not that one: take the next older) and run the command
again. A run of the command that was stopped part-way leaves a
rollback journal, and the next run refuses: then, as for any file it finds there, move the
files it names out of `./data` and keep them, copy the nightly snapshot into place as
`andvari.db` again, and run the command again. A rollback journal (`andvari.db-journal`)
carries nothing that ties it to one database file: neither andvari nor SQLite can tell
whether the journal beside your `andvari.db` was left by that file or by another one.
Opening the database (the server's start, or any command of `andvari` that opens it)
applies whatever journal lies beside it, and a journal of another file damages the
database for good. So
never put a journal beside a database yourself, and never let one travel with a backup's
file. If `andvari admin restored` names a journal, do what it says: move the journal out
of `./data` and keep it, copy the backup's `andvari.db` into place again, and run the
command again. Open the database with the journal still beside it (for example with
`andvari admin status`) only when you no longer have the backup's file AND the journal is
the one that a stopped run of `andvari admin restored` left beside that same file. Check
the host's clock: the times the command writes are the host's. Then put `blobs/` back and
run the server's own command on the put-back database (`docker compose run --rm -v
"$PWD/andvari.env:/andvari.env:ro" andvari admin restored --env-file /andvari.env`). In
one step it ends every session of every account, yours included, so every member signs in
again (with the master password in force at the time of the snapshot); it marks every
device as signed out, keeping each one in its account's devices list; and it closes the
invites, links and device links that were in progress. It ends the requests for your help
that were in progress, those you had already answered included, so that nobody can finish
one. It removes no data, changes no password, key or setting, leaves the server's change
counter where the snapshot left it, tells the devices nothing about the restore, prints
what it did and keeps that record in the server's own settings, where `andvari admin
status` shows it. Run it once per restore: a later run signs everyone out again.
Run it before the first start: once the server has run on the put-back database, the
command refuses while the server's write-ahead file lies beside the database, and the way
out its line gives is to copy the backup into place again, which loses what the server
took since that start.

**After a restore:**

- **At once, before you tell members to sign in again, look at every account's devices
  list and revoke again** every device that was revoked after the snapshot: until then
  such a device signs in with the master password as a known device. Ask each member to
  check their own devices list too: neither you nor the server can tell which devices
  those were.
- Tell every member that the server was restored to the time of the snapshot, that they
  must sign in again on every device, and that if they changed their master password after
  that time, **the former one** is in force again (they can change it again afterwards).
- Disable again the accounts you disabled after the snapshot. Ask members to make a new
  recovery kit or two-step setup if they replaced one after the snapshot, at once if they
  replaced it because of a leak.
- **Send new invites** for those not yet used, and tell members to make device links and
  connection links again. The device of each person who had asked for your help says, at
  its next look, that the request is over and offers to ask again; the reason it gives
  today may be another one (that the account's side ended it, that it ran out of time or
  was used, or that the account's password or recovery setting changed): tell those people
  it was the restore. They ask again, and you look at who is asking before you answer, as
  for any request.
- Tell members that items saved after the snapshot exist only on the devices that hold
  them: to put one back on the server, edit it and save it on such a device.
- Tell members that a device which synced after the snapshot may later miss other
  people's saves without saying so. Once they have saved again what only that device
  holds, signing in afresh on that device (forget the server there, then sign in) gives
  it everything the server holds; forgetting the server drops what only that device held.
- A member whose device shows a shared vault as read-only or frozen after the restore:
  the vault's items are still readable there. The device leaves that state only by
  forgetting the server and signing in again, which also drops what only that device held.

Keep snapshots frequent (nightly at least, and before every update): the shorter the time
between the newest snapshot and a failure, the less of all this there is.

## Invites & email

**How people join.** `ANDVARI_SIGNUP_MODE` in `andvari.env` (setup's `--mode`) decides:

- `links`, the default: people join only through a link. A member makes an invitation in
  their app and hands it over, and registering with it connects the two of them. On a
  private server every member may make invitations; `ANDVARI_REGISTER_LINKS=operator`
  keeps that to the operator. On a public server only the operator can. You can also make
  an enrol link on the host, as in step 7 of **Install**: it registers one account and
  connects it to nobody.
- `open`: anyone may sign up with an email address, which the server confirms with a
  six-digit code it mails; invitations work too. The server does not start in this mode
  without mail.
- `closed`: only enrol links made on the host register anyone.

`ANDVARI_SIGNUP_CAP` (default 200) is the most active member accounts the server takes,
and `ANDVARI_SIGNUP_DAILY_MAX` (default 25) the most accounts that sign-ups and
invitations make in one day (UTC); enrol links count toward the cap only. What the
operator account sets for the mode and the cap can make them stricter, never looser. To
loosen them, change `andvari.env` with the host command and start the server again:

```sh
docker run --rm -v "$PWD/data:/data" -v "$PWD/andvari.env:/andvari.env" \
    ghcr.io/silencelen/andvari-server:1.0.0 admin signup links --env-file /andvari.env
docker compose up -d
```

The first line sets the mode (`open`, `links` or `close`; `cap N` sets the cap) in
`andvari.env` and clears the stricter value the operator account stored, and ends with
`Restart the server to apply it.`; the second line does that. Use `docker compose up -d`
for it, not `docker compose restart`, which keeps the old settings (see **Changing
`andvari.env` later** under **Install**). The settings file is mounted without `:ro` here
because the command writes it.

**Mail.** The server sends mail through Microsoft Graph or through SMTP, and through
neither until you give it one of them. Each needs all four of its settings:

- SMTP: `ANDVARI_SMTP_HOST`, `ANDVARI_SMTP_USER`, `ANDVARI_SMTP_PASS`, `ANDVARI_SMTP_FROM`,
  and `ANDVARI_SMTP_PORT` when it is not 587. The server requires STARTTLS and checks the
  mail server's certificate, so the mail server must offer STARTTLS on that port: port
  465, where TLS starts with the first byte, does not work.
- Microsoft Graph (app-only): `ANDVARI_GRAPH_TENANT`, `ANDVARI_GRAPH_CLIENT_ID`,
  `ANDVARI_GRAPH_CLIENT_SECRET`, `ANDVARI_GRAPH_SENDER`. When both are complete, Graph is
  used.

Give them to setup, which writes them into `andvari.env`. Keep the password off the
command line, where every user of the host can see it:

```sh
read -rs ANDVARI_SMTP_PASS && export ANDVARI_SMTP_PASS
docker run --rm --log-driver none -e ANDVARI_SMTP_PASS -v "$PWD/data:/data" ghcr.io/silencelen/andvari-server:1.0.0 \
    setup --env-file /data/andvari.env --origin https://vault.example.org \
    --smtp-host smtp.example.org --smtp-user vault@example.org --smtp-from vault@example.org
mv data/andvari.env andvari.env
unset ANDVARI_SMTP_PASS
```

The first line asks for the password without showing it and keeps it in your shell; `-e`
hands it to setup from there, and `unset` takes it out of your shell again once setup has
written it. The rest is step 4 of **Install**: add the other options you chose there, and
`--recovery-pubkey` for operator recovery. For Graph, the flags are
`--graph-tenant`, `--graph-client-id` and `--graph-sender`, and the secret goes in
`ANDVARI_GRAPH_CLIENT_SECRET` the same way. Compose later reads these values from
`andvari.env` with its own rules for `$`, ` #` and quotes, so a password or secret that
holds one of them may reach the server changed, and mail then fails: choose one without
them. On a server that is already set up, add the lines to `andvari.env` with an editor
instead, then give the file back to the container's user and start the server again with
it (`docker compose restart` would keep the old settings):

```sh
chown 10001:10001 andvari.env && chmod 600 andvari.env
docker compose up -d
```

Operator recovery, though, is chosen at setup, and it needs mail then.

Without mail the server still does everything else: the notices are not sent, and the
server's log says so. Sign-up in `open` mode and operator recovery need mail.

**What the server sends.**

- The six-digit code of a sign-up in `open` mode, and a notice to an address that tries to
  sign up again although it already has an account.
- Notices to the person of an account when something happens to it: a new device, a
  device removed, the master password changed, two-step sign-in turned off, the recovery
  setting changed, a recovery applied, the account disabled, enabled or deleted (by its
  person or by you), and a cleared setting that required a link for new devices; and a
  notice when someone asks you for help with an account that has no operator recovery.
- With operator recovery: the code of a request for your help and the notices about that
  request, and a notice when you read a member's recovery copy.

No mail carries a password, a key, a link that signs anyone in or acts, or the name of a
vault or an item. The only codes are the six-digit sign-up and request codes, and, in the
code mail of a request for help, a mailbox value that opens nothing but one more request
for the same address. The only link is to a help page on `andvaripass.com`. Each mail
names your server by its name and address. A notice about a device names the kind of app
in the server's own words, from what the device reported (the server cannot check that the
device really is that kind), and, for a device that was already on the account, the day
the server added it (UTC); it never shows the name the device gave itself, which stays in
the devices list in the app. Before the server's name or any other value goes into a mail,
every run of blanks becomes one space, invisible and formatting characters are removed,
and no more than four accent marks stay on a letter: choose a server name that reads well
that way and that cannot be read as an instruction or an address.

**The contact the mails name.** A mail that tells the person whom to ask (you read their
recovery copy, a recovery was applied, you disabled, enabled or deleted their account)
names the address the mails are sent from: `ANDVARI_GRAPH_SENDER`, else
`ANDVARI_SMTP_FROM`, and replies go there too. So send from an address that someone reads:
a `noreply` address is named as it is. When that setting is not an email address, the
mails name the operator without an address.

A mail that cannot be sent is tried again for up to 24 hours, a code mail only while its
code is valid, and a mail the mail server refuses (an address it rejects, or an answer in
the 500s) is not tried again. While mail has been stuck for 10 minutes, the server refuses
new sign-ups and new requests for your help, and says that mail is not available. A mail
that fails leaves no line in the server's log: a mail given up shows as `email_failed` in
the server's audit log, which this line prints:

```sh
docker run --rm -v "$PWD/data:/data" -v "$PWD/andvari.env:/andvari.env:ro" \
    ghcr.io/silencelen/andvari-server:1.0.0 admin audit --type email_failed --env-file /andvari.env
```

## Updates

An update is a version you choose. The image has one tag per version and no tag that
moves by itself, so `docker compose pull` brings only the version `.env` names.

**1. Take a snapshot, copy it aside, and stop the server.**

```sh
docker compose exec -T -u andvari andvari /usr/local/bin/docker-entrypoint.sh admin backup --env-file /etc/andvari.env
```

This is the snapshot of **Backup**, taken while the server still runs. If it printed
anything, stop here and do not go on to step 2. Otherwise copy the snapshot out of
`data/backup/` under a name of your own, here with the version you are about to start;
the server stops only after a copy that worked (if `cp` prints an error, the server runs
on: stop here):

```sh
cp -p data/backup/andvari-nightly.db andvari-before-1.0.1.db && \
    docker compose stop
```

`cp -p` keeps the snapshot's owner and mode 600. From now on, `andvari-before-1.0.1.db`
in the server's folder is the snapshot of step 1: the server's container sees only
`./data` and `andvari.env`, so no later run of the snapshot can remove, rename or replace
it, whatever `--keep` says and however many nights pass. Where **Before you restore a
backup** copies `andvari-nightly.db` into place, copy this file instead when you restore
the snapshot of step 1. The stop comes last, so that nothing more is saved before the
update; what is saved between the snapshot and the stop is not in it. So type this step's
three commands, in its two blocks, one after the other, at a time when nobody is saving.
Keep the snapshot of step 1 until the new version has run well
for a while: there is no way back to an older version on the same database.

**2. Name the new version.**

```sh
sed -i 's/^ANDVARI_VERSION=.*/ANDVARI_VERSION=1.0.1/' .env
```

This changes the version line in `.env` (here to 1.0.1).

**3. Fetch it and start it.**

```sh
docker compose pull
docker compose up -d
```

The first line downloads the image of that version; the second replaces the running
server with it. With the caddy overlay, check then that your server's address answers,
as **Changing `andvari.env` later** under **Install** says. If you build the image
yourself, build the new version instead of the pull, then run the second line. Install put
the source in `andvari-src` beside this folder, so from this folder:

```sh
git -C ../andvari-src fetch --tags
git -C ../andvari-src checkout v1.0.1
docker build -t ghcr.io/silencelen/andvari-server:1.0.1 ../andvari-src
```

**4. Check its start.**

```sh
docker compose logs --tail 20 andvari
```

A server that started prints its start line (`[andvari] private instance at …, listening
on 0.0.0.0:8080`).

**What the server does with the database it finds.** At every start the server reads a
marker it keeps in the database. If the database is empty, the server creates a new one.
If the marker is this server's own, the server opens the database. Where an earlier build
of this server made it differently in a way this version knows how to mend (a table, a
column or an index missing or defined differently, or one of two columns that are no
longer kept), the server adds, rebuilds or drops that at the start and says so in one log
line that begins `[andvari] database brought up to baseline`; you never run a migration
tool. Vault contents are ciphertext the server cannot read, so nothing it does at the
start rewrites them. Any other database stops the server with a line that begins
`[andvari] refusing to start:`. For a database of another version or build, the line ends
with one of these sentences:

- `This database is from andvari 0.x; restore its export into a new account instead (see the cut-over guide).`
  Most often a 0.x server (0.30.0 included) made it: the server says this of every database
  that has tables but no marker.
- `This database was created by a different andvari build (baseline '…', this build expects '…').`
- `This database was made by an older development build of andvari, and this build cannot bring it up to its baseline (…). Start this build on a new, empty database file (keep the old file aside), or run the build that made it.`

In each of those cases nothing is converted. Docker then starts the server again and
again, and each start prints the same line. Keep that file as it is, and do not point the
new version at it again. If the new version does not start on your data, stop it
(`docker compose down`), name the old version in `.env` again, and restore the snapshot
from step 1, not the database the new version refused; read **Before you restore a
backup** first. What was saved between the snapshot of step 1 and the stop of the server
is lost by that restore. Once a new version has started and members have used it, do not
restore to go back: the saves it has taken would be lost.

**From a 0.30.0 server.** andvari 1.0.0 is a new image, `ghcr.io/silencelen/andvari-server`,
and starts only on a new database: it refuses a 0.x database with the first sentence above.
The old image name, `ghcr.io/silencelen/andvari`, stays at 0.30.0: versions from 1.0.0 on
are published only under the new name, so updating a 0.30.0 server never brings it 1.0.0.
The cut-over guide that the refusal names, for moving a 0.30.0 server's accounts across,
is not part of this guide yet; until it is, keep a 0.30.0 server on 0.30.0.

**The apps' own updates.** The web app is part of the server image and is updated with
it. The desktop app looks for a newer version of itself: first in the update list at your
server's `/downloads/manifest.json`, then in the andvari releases on GitHub. It accepts a
list only when it is signed with the key the app was built with, so a server can hold an
update back but cannot make one up. Your server answers under `/downloads/` only when you
set `ANDVARI_DOWNLOADS_DIR` to a folder of files you put there, for example
`/data/downloads`. The other apps are updated the way they were installed.

## Day-2 notes

- **Health:** `GET /healthz` (the compose healthcheck uses it). **Metrics:**
  `GET /metrics` is Prometheus-format, loopback-trust only — scrape from inside the
  network namespace or drop a sidecar; never expose it.
- **Helping a member who lost both the master password and the recovery kit** (operator
  recovery: private servers only, and only for accounts that chose it). The member asks
  for help in their app and confirms the request with a code the server mails to their
  address. The request then waits seven days, during which every signed-in device of the
  account is told and can stop it; nobody can refuse it at the server, and one left alone
  ends by itself. The operator account's desktop app lists the requests; from there you
  download the member's recovery copy (the member is mailed when you do) and carry it to
  an **offline** computer with your recovery sheet. There `recovery-cli assist` takes the
  request's id and key from the desktop app, the member's user id (`--user`: the UUID that
  `andvari admin accounts` prints first on the member's line, not the account ID, the
  32-character identity fingerprint, which goes to `--identity-fp`), the
  server's instance id (`--instance`, which `andvari admin status` prints), the downloaded
  recovery copy (`--identity-file`), the request code from the member, the member's address
  as you know it, and their identity fingerprint from outside the server
  (`--no-identity-anchor` instead cannot detect an identity the server forged); it checks
  the copy, asks you to type `RECOVER <first 8 characters of their id>` and prints the
  answer as its last line (`andvari-answer:…`). Once the seven days are over, upload that
  line in the desktop app; the member's device opens it and the member sets a new master
  password there. There is no temporary password at any point. The normative steps are
  spec 04 §7. The recovery-cli in the image is the same tool:
  `docker run --rm -it --network none --log-driver none ghcr.io/silencelen/andvari-server:<ver> recovery-cli`
  (the tool asks for the recovery seed at its prompt and prints the answer, so the log
  driver stays off here too). It runs as the container's user (uid 10001), so mount the
  recovery copy into the container with `-v` where that user can read it.
- **Members' self-service recovery** works out of the box (`/recovery/self/*`): a member
  who still has their recovery kit sets a new master password with it. The two that take
  the kit, `/recovery/self/verify` and `/recovery/self/commit`, are reachable by anyone who
  can reach your server — they are rate-limited **per-IP only (5/min fixed window),
  deliberately with NO per-account backoff** (the third, `/recovery/self/confirm`, needs a
  signed-in device and is limited per device), because a per-account throttle on the
  last-resort recovery path is an easy way for an attacker to lock a victim out of their
  own account with a handful of wrong guesses (spec 05 T11, design 2026-07-12 §F.8). What
  makes per-IP sufficient is the kit itself: its secret is a full-entropy 256-bit key, not
  a password (spec 05 R9), so guessing it is not a rate problem. Note the contrast
  with **login**, which does carry an email-keyed exponential backoff — a master password is
  guessable and a recovery key is not. A considered default, not an oversight.
- **Moving to another host:** stop the server (`docker compose stop`), copy the whole server
  folder (with `data/`, `andvari.env`, `.env` and the compose files) to the new
  host as root, keeping owners and modes (the host commands read `andvari.env` as uid
  10001), then run
  `docker compose up -d` there, point DNS and your front at it, and move the cron line of
  **Backup** to the new host. Do not start the server on the old host
  again: from then on the two copies would differ. Change nothing in `andvari.env` on the
  way, except an `ANDVARI_TRUSTED_PROXY_CIDRS` that names the bridge gateway: check that
  address on the new host as **Client IPs behind your own front** shows. The address is
  the identity members' devices trust (the server's signed identity card names it), and a
  new `ANDVARI_ENUM_SECRET` changes every address hash the database keeps. Giving the server a
  new address is a step of its own, which the operator account signs in its desktop app;
  devices then follow after a one-tap prompt. This guide does not describe that step yet.
