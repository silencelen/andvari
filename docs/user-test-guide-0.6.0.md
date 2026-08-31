# andvari — user test guide

Thanks for helping test **andvari**. The goal is simple: use it for real, on the devices you
actually use, and try to break it. This guide is deliberately version-neutral and
instance-neutral — for what changed in the release you are testing, read
[`CHANGELOG.md`](../CHANGELOG.md); for anything that needs a server address, use *your*
instance's.

---

## Before you start

- **You need your instance's address.** andvari is self-hosted, and every client works with
  any andvari server — so the address is whatever the person who runs your instance gave
  you (`https://<your-origin>`). Open it in a browser and you have the full vault; nothing
  to install. There is no single "the andvari service": the shipped builds default to a
  reference instance, but it is not privileged in the protocol, and pointing a client at
  your own is a supported first-class path (*Settings → Server*, or opening an invite link
  from that instance).
- **Sign-up is invite-only.** No account yet? Ask whoever runs your instance for an invite.
  The link points at that instance's address and expires, so redeem it on a device that can
  reach that address.
- **Save your recovery phrase when it is shown.** Registration shows it once. If your
  instance was set up without an admin backstop, that phrase plus your master password are
  the *only* things that can restore the account — nobody, including the server operator,
  can read or reset your vault for you. That is the point of the design, and it is worth
  testing that the reveal screen actually made you save it.

---

## Getting andvari on each device

Everything an instance publishes for its users is listed in the web vault under
**Settings → Your devices**. That page renders exactly what *your* server publishes, so if a
row says a platform isn't published yet, that instance genuinely has no build for it — not a
broken link.

**Web (any computer or phone browser)**
Open your instance's address and sign in. The web vault is served by every andvari server at
its own origin and is always current with that server.

**Browser extension (Chrome / Edge / Brave / Firefox)**
*Settings → Your devices → Browser extension.* Chrome-family browsers install from the Chrome
Web Store listing and update themselves; Firefox installs a Mozilla-signed add-on and updates
itself too. If your instance offers only the plain `.zip` fallback instead, unzip it to a
folder you'll keep and follow the `INSTALL.txt` inside (about two minutes; the steps differ
per browser) — and note that a copy loaded that way **cannot update itself**, so check that
page again for newer versions.

**Windows / Linux desktop**
*Settings → Your devices* lists the Windows installer and the Linux `.deb` when your instance
publishes them. Installing over an existing copy upgrades in place.

**Android**
*Settings → Your devices → Android* lists the app (`.apk`) when your instance publishes one.
If the row says it isn't published yet, that instance builds and hands out the app itself —
ask whoever runs it.

The first unlock on a freshly installed client takes a few seconds on purpose: your keys are
derived from your master password on the device, and that work is deliberately slow.

---

## What we especially want you to try to break

This is the whole point — please find the holes.

**Everyday use.** Create logins, edit them, and actually live in andvari for a few days.
Anything confusing, ugly, or plain wrong is worth telling us.

**Sync.** Make a change on one device and watch it appear on another. Anything slow, stuck,
duplicated, or out of order? Bonus points for editing the same item on two devices at once —
you should get a visible "(conflict copy)" rather than a silent overwrite.

**Version history.** Change a login's password two or three times, then open the item and use
**Version history** to reveal an old value and restore it. Does the right value come back? Does
it reach your other devices? Honest limit: **up to the last 10 saves**, not forever.

**Trash.** Delete a login, open **Trash** (the trash-can icon on the vault), and restore it. It
should reappear everywhere. Try it while the same item is open on another device. Two limits to
check we state honestly: deleted items are kept **30 days** and then removed automatically, and
**file attachments on a deleted item are not recovered** — the login, password, and notes come
back, but not attached files.

**Vault health** (web vault and the Android app). Open **Vault health** and look at what it
says about weak and reused passwords, then run the breach scan — it is on demand, and only a
truncated hash prefix of each password ever leaves the device. The duplicate-entry finding is
worth pushing on hardest: identical copies offer a guided merge (the extras go to Deleted
items, restorable for 30 days), while clusters whose passwords differ ask *you* to pick the
copy to keep (**Keep this one**) — only you know which password the site still accepts — and
retire the others the same recoverable way. Does it find your real duplicates? Does it ever
claim two genuinely different accounts are the same one?

**Autofill in a computer browser (the extension).** Click into a username or password field —
a small andvari dropdown should list your matching logins. Submit a login andvari doesn't know
and a *"Save this login for … to andvari?"* bar should appear. Open the popup from the
toolbar icon to see whether the vault is unlocked; its **Lock** button wipes it from memory
straight away. (The toolbar icon itself does not signal lock state — only a small badge
marking a page where a card can be filled.) Known-rough edge worth probing: multi-step
logins (email first, password on the next screen) may only half-work — telling us *where* is
exactly the feedback we want.

**Autofill on Android.** Turn andvari on as your phone's autofill service, then the first time
you use a login page in a given browser you'll be offered a row to **trust that browser on this
device** — a deliberate one-time step per browser, so andvari only fills into browsers you
picked. The app's Autofill screen names the exact steps for your phone and browser (some
browsers need one extra switch of their own); follow it there rather than guessing, and tell us
if what it says doesn't match what you see. Then try lots of sites (**https://fill.dev** is a
good sandbox), your real logins, and apps as well as browsers. Anything that won't fill, won't
offer to save, fills the wrong field, or is confusing is a bug.

**Payment cards.** Save a card and try a real checkout. The extension shows a chip at the card
field; the actual values only leave the extension when *you* pick the card in the popup. Report
any checkout where the expiry, card type, or security code is left empty or lands in the wrong
box — and any page where andvari offers a *login* on card fields, which it must never do.

**One-time codes.** Attach a 2FA secret to a login (paste the `otpauth://` link or the "can't
scan?" setup key) and check the code it generates is accepted. The extension can only *add* a
code to a login that has none — replacing or removing one is a web-vault edit on purpose, so
tell us if any surface lets you rotate a stored second factor without going there.

---

## Found something? Tell us

No bug is too small — "this was confusing" counts. When you report, please include:

- **Which device/app** (web / Android / Windows / Linux / extension) and roughly when.
- **What you did** (the steps) and **what happened** vs. what you expected.
- A screenshot if you can grab one — but check it first: screenshots of the vault contain real
  secrets, and a recovery phrase or master password must never end up in a bug report.

Send it back through whatever channel your test round is using; whoever invited you will have
told you where.

Thanks — using it for real and telling us what's rough is exactly how we find the problems
before they matter.
