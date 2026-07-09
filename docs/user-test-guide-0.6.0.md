# andvari — user test guide (0.6.0)

Thanks for helping test **andvari**, our private password manager. This round adds two
"safety net" features, and the goal is simple: use it for real and try to break it. Here's
what's new, how to get it on each device, and what we'd love you to poke at.

---

## Before you start — get on the network

andvari is **private to our network** — there is no public website. To reach it on any
device, you must be connected to our **Tailscale** network first.

- Don't have Tailscale on a device yet? Ask Jacob to add you — it's a quick app install and a
  login.
- No andvari account yet? Ask Jacob for an invite (sign-up is invite-only).
- Everything below assumes Tailscale is connected.

---

## What's new in 0.6.0

### 1. Version history — undo a bad password change
Every time you save a login, andvari quietly keeps its **last 10 versions**. So if a password
gets overwritten by mistake, you can get the old one back:

- Open any login → **Version history**.
- Each past version shows its date. Tap **Show** to reveal an old password, **Restore** to
  bring it back.
- Honest limit: it keeps **up to the last 10 saves** — not forever.

### 2. Trash — recover a deleted item
Deleted something you still needed? It's no longer gone for good:

- Open **Trash** (a tab on the web; the trash-can icon on phone and desktop).
- Find the item and tap **Restore** — it comes back on **all** your devices.
- Note: file *attachments* on a deleted item are not recovered — the login, password, and
  notes come back, but not attached files.

---

## How to get it, per device

You don't need to type a server address — every app is already pointed at our server. Just
sign in.

**Web (any computer)**
Open **https://andvari.taila2dff2.ts.net** in your browser and sign in. Nothing to install —
the web version already has 0.6.0.

**Android phone/tablet**
1. Open **https://devserv.taila2dff2.ts.net** (our private app store) in your phone's browser.
2. Find **andvari** and tap install/update. (Android may ask you to allow installing from this
   source once — that's expected.)
3. Open the app and sign in. Already have andvari? The store shows the new version — just
   update.

**Windows PC**
Download and run **https://andvari.taila2dff2.ts.net/downloads/andvari-0.6.0.msi**. If andvari
is already installed, it upgrades in place.
*(Being published shortly — Jacob is building the Windows installer. Until then, use the web
version on Windows.)*

**Linux PC**
Download **https://andvari.taila2dff2.ts.net/downloads/andvari-0.6.0.deb** and install it
(`sudo apt install ./andvari-0.6.0.deb`), then launch andvari and sign in.

---

## What we especially want you to try to break

This is the whole point — please find the holes:

- **Version history:** change a login's password 2–3 times, then open Version history, reveal
  the old values, and Restore one. Does the right value come back? Does it update on your other
  devices?
- **Trash:** delete a login, open Trash, Restore it. Does it reappear everywhere? Try it with a
  login you also have open on another device at the same time.
- **Sync:** make a change on your phone and watch it appear on the web (or the reverse).
  Anything slow, stuck, duplicated, or out of order?
- **Everyday use:** create logins, edit them, and actually use andvari for a few days. Anything
  confusing, ugly, or plain wrong is worth telling us.

### Autofill — fill & save logins in your browser and apps (Android)

andvari can fill your saved logins and offer to save new ones as you sign in. **Two one-time setup
steps, then it just works:**

1. **Turn andvari on as your autofill service.** Android **Settings → search "autofill service" →
   pick andvari** (some phones: Settings → Passwords/Passkeys & accounts → Autofill service).
2. **The first time you use a login page in a given browser,** tap the username field. Instead of
   filling, you'll see a **"Trust {your browser} to fill here"** row in the suggestion bar — tap it,
   confirm, and reopen the page. **You do this once per browser** (a security step, so andvari only
   trusts browsers you picked). **Chrome** additionally needs its own switch: Chrome → Settings →
   **"Autofill using other services" → ON**.

Once a browser is trusted:
- **Fill:** tap a username or password field → andvari suggests your saved login → tap to fill.
- **Save:** sign in somewhere new → andvari asks **"Save to andvari?"** → confirm → it's saved, and
  fills next time.

**Please try to break it:** lots of different sites (a good sandbox is **https://fill.dev**), your
real logins, and apps as well as browsers. Tell us anything that won't fill, won't offer to save,
fills the wrong field, or is confusing. (Windows/Mac/Linux: no autofill yet — use the web app +
copy/paste; a browser extension is coming.)

---

## Found something? Tell us

No bug is too small — "this was confusing" counts. When you report, please include:

- **Which device/app** (web / Android / Windows / Linux) and roughly when.
- **What you did** (the steps) and **what happened** vs. what you expected.
- A screenshot if you can grab one.

Send it to **_[Jacob / the test group chat — fill in your preferred channel]_**.

Thanks — using it for real and telling us what's rough is exactly how we find the problems
before they matter.
