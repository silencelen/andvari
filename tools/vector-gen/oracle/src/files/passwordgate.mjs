// passwordgate.json: the decisions of the password rule (design §4.4) and of the entry rule
// (§8.2 step 0, §10, §12.1).

import { passwordGate, PURPOSES, ENTRIES, PAYLOADS, ROOTS } from '../passwordgate.mjs';
import { isOrigin, emailNorm } from '../grammar.mjs';

export const file = 'passwordgate.json';

const PUBLIC = 'https://vault.andvaripass.com';
const X = 'https://vault.example.org';
const ALICE = 'alice@example.com';
const BOB = 'bob@example.com';
const OPERATOR = 'operator@example.org';

const pin = (origin, root, account) => (account ? { origin, root, account } : { origin, root });

function buildRows() {
  const rows = [];
  const names = new Set();
  /** `decision` is what §4.4 says; the builder checks the oracle agrees before writing the row. */
  const add = (name, decision, why, input) => {
    const row = { purpose: input.purpose, entry: input.entry ?? null, payload: input.payload ?? null, origin: input.origin, account: input.account ?? null, pins: input.pins ?? [], session: input.session ?? null };
    const got = passwordGate(row);
    if (got !== decision) throw new Error(`passwordgate "${name}": the design says ${decision}, the oracle says ${got}`);
    if (names.has(name)) throw new Error('passwordgate: duplicate name ' + name);
    names.add(name);
    rows.push({ name, why, ...row, expect: { decision } });
  };
  const link = { purpose: 'device_link', entry: 'link_device_screen', payload: 'd' };
  const signIn = { purpose: 'sign_in', entry: 'server_choice', account: ALICE };
  const kit = { purpose: 'kit_recovery', entry: 'kit_recovery_screen', payload: 'kit', account: ALICE };

  // ---- the entry rule: a payload starts something only on the screen that takes it ----
  for (const entry of ['scan_invite', 'paste_invite', 'app_link']) {
    add(`d-link-on-${entry}`, 'refuse_entry', `A /d link ${entry === 'app_link' ? 'that arrives as a tapped link' : entry === 'scan_invite' ? 'scanned on "Scan an invite"' : 'pasted on "Scan an invite" or "Paste an invite link"'}: it starts no device link, even to the baked origin. The app shows "To add this device to your account, open Sign in → Link from your other device and scan the code there."`,
      { ...link, entry, origin: PUBLIC, pins: [pin(PUBLIC, 'baked')] });
  }
  add('d-link-on-kit-recovery-screen', 'refuse_entry', 'The kit-recovery scanner takes only andvari-kit: payloads.', { ...link, entry: 'kit_recovery_screen', origin: PUBLIC, pins: [pin(PUBLIC, 'baked')] });
  for (const entry of ['scan_invite', 'paste_invite', 'app_link', 'link_device_screen', 'cli_link_device']) {
    add(`kit-on-${entry}`, 'refuse_entry', 'A kit payload anywhere but Sign in → Forgot your master password? → Scan your recovery kit starts nothing (FS-B1), even with a kit pin for that account.',
      { ...kit, entry, origin: X, pins: [pin(X, 'kit', ALICE)] });
  }
  add('l-link-on-link-device-screen', 'refuse_entry', 'The scanner and paste field on "Link from your other device" take only /d.', { purpose: 'register', entry: 'link_device_screen', payload: 'l', origin: X, account: ALICE, pins: [pin(X, 'link_offer')] });
  add('l-link-on-kit-recovery-screen', 'refuse_entry', 'The kit-recovery scanner takes only andvari-kit: payloads.', { purpose: 'register', entry: 'kit_recovery_screen', payload: 'l', origin: X, account: ALICE, pins: [pin(X, 'link_offer')] });
  add('l-link-on-cli-link-device', 'refuse_entry', '`andvari-cli link-device` takes a /d link.', { purpose: 'register', entry: 'cli_link_device', payload: 'l', origin: X, account: ALICE, pins: [pin(X, 'link_offer')] });

  // ---- device_link (§8.2 step 0): the account is not known before the claim ----
  add('device-link-baked', 'proceed', 'device_link to the baked origin, from "Link from your other device".', { ...link, origin: PUBLIC, pins: [pin(PUBLIC, 'baked')] });
  add('device-link-baked-cli', 'proceed', 'The same from `andvari-cli link-device`.', { ...link, entry: 'cli_link_device', origin: PUBLIC, pins: [pin(PUBLIC, 'baked')] });
  add('device-link-trust-gate-pin', 'proceed', 'A pin this device made earlier through the Trust Gate is a password pin for any account.', { ...link, origin: X, pins: [pin(X, 'trust_gate')] });
  add('device-link-no-pin', 'trust_gate', 'device_link to an origin with no pin: the Trust Gate, in its device-link wording, before any claim is sent.', { ...link, origin: X, pins: [] });
  add('device-link-no-pin-cli', 'trust_gate', 'The CLI asks the person to confirm the printed origin and operator key (its Trust Gate).', { ...link, entry: 'cli_link_device', origin: X, pins: [] });
  add('device-link-pin-for-another-origin', 'trust_gate', 'A baked pin for the public instance says nothing about another origin.', { ...link, origin: X, pins: [pin(PUBLIC, 'baked')] });
  add('device-link-link-offer-pin', 'trust_gate', 'device_link with only a link-offer pin.', { ...link, origin: X, pins: [pin(X, 'link_offer')] });
  add('device-link-enrol-pin', 'trust_gate', 'device_link with only an enrol pin.', { ...link, origin: X, pins: [pin(X, 'enrol')] });
  add('device-link-kit-pin', 'trust_gate', 'A kit pin used to link a device (FS-B1).', { ...link, origin: X, pins: [pin(X, 'kit', ALICE)] });
  add('device-link-setup-pin', 'trust_gate', 'A setup pin used to link a device (FS-B1).', { ...link, origin: X, pins: [pin(X, 'setup', OPERATOR)] });

  // ---- sign_in ----
  add('sign-in-baked', 'proceed', 'Signing in on the public instance in a store build.', { ...signIn, origin: PUBLIC, pins: [pin(PUBLIC, 'baked')] });
  add('sign-in-trust-gate-pin', 'proceed', 'Signing in on a server whose address the person confirmed at the Trust Gate.', { ...signIn, origin: X, pins: [pin(X, 'trust_gate')] });
  add('sign-in-no-pin', 'trust_gate', 'A hand-typed address with no pin yet.', { ...signIn, origin: X, pins: [] });
  add('sign-in-link-offer-pin', 'trust_gate', 'sign_in through a link-offer pin: enough to create an account, never to sign in to an existing one.', { ...signIn, origin: X, pins: [pin(X, 'link_offer')] });
  add('sign-in-link-offer-pin-from-the-link', 'trust_gate', 'The same decision when the sign-in starts from the opened invite ("Switch to …"): the Trust Gate first.', { ...signIn, entry: 'scan_invite', payload: 'l', origin: X, pins: [pin(X, 'link_offer')] });
  add('sign-in-enrol-pin', 'trust_gate', 'sign_in through an enrol pin (FI-B8): root enrol is not a password pin.', { ...signIn, origin: X, pins: [pin(X, 'enrol')] });
  add('sign-in-kit-pin-own-account', 'trust_gate', 'A kit pin is for the recovery alone: a later sign-in through it shows the Trust Gate even for the kit\'s own account. The kit vouches for one thing, that this is the instance the kit was made on, and for one act; entering the master password at a server is a separate decision, which the person makes at the gate (§4.4).', { ...signIn, origin: X, pins: [pin(X, 'kit', ALICE)] });
  add('sign-in-kit-pin-another-account', 'trust_gate', 'A kit pin used to sign in to another account (FS-B1).', { ...signIn, account: BOB, origin: X, pins: [pin(X, 'kit', ALICE)] });
  add('sign-in-setup-pin-operator-account', 'proceed', 'A setup pin (this device signed card 0) allows signing in to the operator account it enrolled.', { ...signIn, account: OPERATOR, origin: X, pins: [pin(X, 'setup', OPERATOR)] });
  add('sign-in-setup-pin-another-account', 'trust_gate', 'A setup pin used to sign in to another account (FS-B1).', { ...signIn, origin: X, pins: [pin(X, 'setup', OPERATOR)] });
  add('sign-in-baked-from-an-app-link', 'proceed', 'A tapped invite for the public instance, then signing in to an existing account there: the baked pin is a password pin.', { ...signIn, entry: 'app_link', payload: 'l', origin: PUBLIC, pins: [pin(PUBLIC, 'baked')] });

  // ---- register: any pin is enough to create an account ----
  add('register-link-offer-pin-scan', 'proceed', 'register through a link-offer pin, from a scanned invite.', { purpose: 'register', entry: 'scan_invite', payload: 'l', origin: X, account: ALICE, pins: [pin(X, 'link_offer')] });
  add('register-link-offer-pin-app-link', 'proceed', 'The same from a tapped invite.', { purpose: 'register', entry: 'app_link', payload: 'l', origin: X, account: ALICE, pins: [pin(X, 'link_offer')] });
  add('register-enrol-pin-paste', 'proceed', 'register through an enrol pin, from a pasted link.', { purpose: 'register', entry: 'paste_invite', payload: 'l', origin: X, account: ALICE, pins: [pin(X, 'enrol')] });
  add('register-baked', 'proceed', '"Create an account on andvari".', { purpose: 'register', entry: 'server_choice', origin: PUBLIC, account: ALICE, pins: [pin(PUBLIC, 'baked')] });
  add('register-trust-gate-pin', 'proceed', '"Use your own server", after the Trust Gate.', { purpose: 'register', entry: 'server_choice', origin: X, account: ALICE, pins: [pin(X, 'trust_gate')] });
  add('register-kit-pin', 'proceed', 'Creating an account proceeds with ANY pin for the origin, a kit pin included: nothing derived from an existing account\'s secrets is sent.', { purpose: 'register', entry: 'server_choice', origin: X, account: BOB, pins: [pin(X, 'kit', ALICE)] });
  add('register-setup-pin', 'proceed', 'The same through a setup pin.', { purpose: 'register', entry: 'server_choice', origin: X, account: ALICE, pins: [pin(X, 'setup', OPERATOR)] });
  add('register-no-pin', 'trust_gate', '"Use your own server" with a hand-typed address and no pin: the Trust Gate first.', { purpose: 'register', entry: 'server_choice', origin: X, account: ALICE, pins: [] });

  // ---- kit_recovery ----
  add('kit-recovery-kit-pin', 'proceed', 'kit_recovery from the kit-recovery screen with a kit pin for that account (card 0 hashed to the kit\'s card0Hash).', { ...kit, origin: X, pins: [pin(X, 'kit', ALICE)] });
  add('kit-recovery-kit-pin-another-account', 'trust_gate', 'A kit pin counts only for the kit\'s own account: a pin left by another account\'s kit does not cover this recovery.', { ...kit, origin: X, pins: [pin(X, 'kit', BOB)] });
  add('kit-recovery-no-pin', 'trust_gate', 'No pin for the origin, for example a kit made before an operator reset whose card0Hash no longer matches (§4.4): the Trust Gate, with its warning.', { ...kit, origin: X, pins: [] });
  add('kit-recovery-baked', 'proceed', 'Recovering on the public instance in a store build.', { ...kit, origin: PUBLIC, pins: [pin(PUBLIC, 'baked')] });
  add('kit-recovery-trust-gate-pin', 'proceed', 'A Trust Gate pin counts for any account and purpose.', { ...kit, origin: X, pins: [pin(X, 'trust_gate')] });
  add('kit-recovery-link-offer-pin', 'trust_gate', 'A link-offer pin is not a password pin.', { ...kit, origin: X, pins: [pin(X, 'link_offer')] });
  add('kit-recovery-enrol-pin', 'trust_gate', 'An enrol pin is not a password pin.', { ...kit, origin: X, pins: [pin(X, 'enrol')] });
  add('kit-recovery-setup-pin-another-account', 'trust_gate', 'A setup pin counts only for the operator account it enrolled.', { ...kit, origin: X, pins: [pin(X, 'setup', OPERATOR)] });
  add('kit-recovery-setup-pin-operator-account', 'proceed', 'A setup pin also allows recovering the operator account it enrolled with that account\'s kit.', { ...kit, account: OPERATOR, origin: X, pins: [pin(X, 'setup', OPERATOR)] });

  // ---- assisted_recovery ----
  const assisted = { purpose: 'assisted_recovery', entry: 'server_choice', account: ALICE };
  add('assisted-recovery-trust-gate-pin', 'proceed', 'Asking the operator for help on a server confirmed at the Trust Gate.', { ...assisted, origin: X, pins: [pin(X, 'trust_gate')] });
  add('assisted-recovery-no-pin', 'trust_gate', 'A hand-typed address with no pin yet.', { ...assisted, origin: X, pins: [] });
  add('assisted-recovery-link-offer-pin', 'trust_gate', 'A link-offer pin is not a password pin.', { ...assisted, origin: X, pins: [pin(X, 'link_offer')] });
  add('assisted-recovery-enrol-pin', 'trust_gate', 'Nor is an enrol pin.', { ...assisted, origin: X, pins: [pin(X, 'enrol')] });
  add('assisted-recovery-kit-pin', 'trust_gate', 'Assisted recovery through a kit pin, even for the kit\'s own account: the kit pin is for the kit recovery alone.', { ...assisted, origin: X, pins: [pin(X, 'kit', ALICE)] });
  add('assisted-recovery-setup-pin', 'trust_gate', 'Assisted recovery through a setup pin.', { ...assisted, origin: X, pins: [pin(X, 'setup', OPERATOR)] });

  // ---- reauth: a session this device already holds for that account, at that origin ----
  const reauth = { purpose: 'reauth', account: ALICE, origin: X, session: { origin: X, account: ALICE } };
  add('reauth-session-link-offer-pin', 'proceed', 'reauth with a session for that account: the account was created through a link-offer pin, and its own session is what allows the password proof.', { ...reauth, pins: [pin(X, 'link_offer')] });
  add('reauth-session-enrol-pin', 'proceed', 'The same for an account created through an enrol link.', { ...reauth, pins: [pin(X, 'enrol')] });
  add('reauth-session-kit-pin', 'proceed', 'The same after a kit recovery: the session it left allows re-authentication, though the kit pin would not allow a new sign-in.', { ...reauth, pins: [pin(X, 'kit', ALICE)] });
  add('reauth-session-baked', 'proceed', 'On the public instance.', { purpose: 'reauth', account: ALICE, origin: PUBLIC, session: { origin: PUBLIC, account: ALICE }, pins: [pin(PUBLIC, 'baked')] });
  add('reauth-no-session', 'refuse_entry', 'A re-authentication with no session at all is refused at the entry: there is nothing to re-authenticate, whatever the pin.', { purpose: 'reauth', account: ALICE, origin: PUBLIC, pins: [pin(PUBLIC, 'baked')] });
  add('reauth-session-for-another-account', 'refuse_entry', 'The device holds a session at that origin, but for another account.', { purpose: 'reauth', account: ALICE, origin: X, session: { origin: X, account: BOB }, pins: [pin(X, 'trust_gate')] });
  add('reauth-session-at-another-origin', 'refuse_entry', 'The device holds a session for that account, but at another origin.', { purpose: 'reauth', account: ALICE, origin: X, session: { origin: PUBLIC, account: ALICE }, pins: [pin(X, 'trust_gate'), pin(PUBLIC, 'baked')] });
  return rows;
}

/** The rows the web twin grades (design §17): its four purposes, baked or Trust Gate pins, an entry a browser has. */
const WEB_PURPOSES = ['sign_in', 'register', 'reauth', 'kit_recovery'];
const BROWSER_PINS = (row) => row.pins.every((p) => p.root === 'baked' || p.root === 'trust_gate');
const NOT_A_BROWSER_ENTRY = ['app_link', 'scan_invite'];
export const webTwinGrades = (row) => WEB_PURPOSES.includes(row.purpose) && BROWSER_PINS(row) && !NOT_A_BROWSER_ENTRY.includes(row.entry);

export function build() {
  const rows = buildRows();
  const webTwinRows = rows.filter(webTwinGrades).length;
  const entries = [...new Set(rows.filter(webTwinGrades).map((row) => (row.entry === null ? 'null' : row.entry)))];
  if (entries.some((e) => !['server_choice', 'kit_recovery_screen', 'null'].includes(e))) throw new Error('passwordgate: a web twin row has an entry a browser may not have');
  const webTwinEntries = entries.slice(0, -1).join(', ') + ' and ' + entries[entries.length - 1];
  const leftOut = rows.filter((row) => WEB_PURPOSES.includes(row.purpose) && BROWSER_PINS(row) && NOT_A_BROWSER_ENTRY.includes(row.entry)).map((row) => row.name);
  const webTwinLeftOut = leftOut.length === 1 ? 'one row, ' + leftOut[0] : leftOut.length + ' rows, ' + leftOut.join(', ');
  return {
    _about: [
      'The password rule of design 2026-11-15-onboarding-trust §4.4 and the entry rule of §8.2 step 0, §10 and §12.1: the decisions of the pure core function PasswordGate (T2-B1, FS-B1, FI-B8).',
      'Hand-authored from the independent oracle in tools/vector-gen/oracle (no andvari code). Regenerate with `npm run generate` there; `npm run check` fails on any difference.',
      'Each row: {purpose, entry, payload, origin, account, pins, session} -> expect.decision. `proceed` is the ONLY decision after which a client may send prelogin, a claim, authKey, recoveryAuthKey or a TOTP code to `origin`. `trust_gate`: show the Trust Gate for that origin first; once confirmed, the pin is a password pin. `refuse_entry`: this screen does not take this payload, and nothing starts.',
      'purpose: sign_in, device_link, kit_recovery, assisted_recovery, register, reauth. entry: link_device_screen, kit_recovery_screen, scan_invite, paste_invite, app_link, cli_link_device, server_choice, or null where the flow has no entry screen (reauth). payload: l, d, kit, or null where nothing was scanned or pasted. account: the account the secret belongs to, by its email; null for a device link, whose account is not known before the claim.',
      'pins: this device\'s pin records, at most one per origin: {origin, root, account?}. root: baked, kit, setup, trust_gate, link_offer, enrol; a kit or setup pin names the one account it counts for. session: {origin, account} if the device holds a session, else null.',
      'The rule. (1) A payload starts a flow only on the screen that takes it: d on link_device_screen and cli_link_device, kit on kit_recovery_screen, l on scan_invite, paste_invite and app_link; anything else is refuse_entry. (2) A session for that account at that origin: proceed; a reauth with no such session is refuse_entry. (3) Otherwise the pin for that origin decides. None: trust_gate. register: proceed with any pin. baked or trust_gate: proceed, for any account and purpose. link_offer or enrol: nothing but register. kit: kit_recovery of the kit\'s own account only (a later sign_in through it is trust_gate even for that account). setup: sign_in to, and kit_recovery of, the operator account it enrolled, and nothing else. device_link and assisted_recovery never count a link_offer, enrol, kit or setup pin.',
      'Graded by core on every target and by the CLI, which uses the same core function (§17). The web twin of the password rule has the purposes a browser can start (§13): sign_in, register, reauth and kit_recovery (the kit typed or pasted on "Forgot your master password?"). It grades the rows of those four purposes whose pins a browser can hold (baked and Trust Gate pins) and whose entry a browser has (no app link and no scan), design §17: that is, the rows whose `purpose` is one of the four, in whose `pins` every root is baked or trust_gate (a row with no pin among them), and whose `entry` is neither app_link nor scan_invite. That is ' + webTwinRows + ' rows, whose entries are ' + webTwinEntries + '; the entry rule leaves out ' + webTwinLeftOut + '. A browser holds no other pin: the web client pins only the card chain of the origin that serves it (§13: the baked root for the public instance, otherwise the Trust Gate once per browser, in its typed-address wording). The extension signs in only through a baked or Trust Gate pin.',
    ],
    enums: { purpose: PURPOSES, entry: ENTRIES, payload: PAYLOADS, root: ROOTS, decision: ['proceed', 'trust_gate', 'refuse_entry'] },
    rows,
  };
}

export function grade(doc) {
  const failures = [];
  let rows = 0;
  const expect = (cond, what) => {
    rows++;
    if (!cond) failures.push(what);
  };
  const names = new Set();
  for (const row of doc.rows) {
    expect(!names.has(row.name), `row ${row.name}: duplicate name`);
    names.add(row.name);
    let got;
    try {
      got = passwordGate(row);
    } catch (e) {
      got = 'oracle refuses: ' + e.message;
    }
    expect(got === row.expect.decision, `row ${row.name}: oracle says ${got}`);
    expect(isOrigin(row.origin) && row.pins.every((p) => isOrigin(p.origin)), `row ${row.name}: origins are in the §2.2 grammar`);
    expect(row.account === null || emailNorm(row.account) === row.account, `row ${row.name}: account is an emailNorm`);
    expect(doc.enums.decision.includes(row.expect.decision), `row ${row.name}: decision`);
  }
  return { rows, failures };
}
