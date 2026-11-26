// The password rule of design §4.4 and the entry rule of §8.2 step 0, §10 and §12.1, as one pure
// decision: may this client send a value derived from an account's secrets (prelogin, a claim,
// authKey, recoveryAuthKey, a TOTP code) to this origin, for this purpose, from this entry?
//
//   proceed       yes
//   trust_gate    only after the person confirms the Trust Gate for the origin
//   refuse_entry  this screen does not take this payload; nothing starts

export const PURPOSES = ['sign_in', 'device_link', 'kit_recovery', 'assisted_recovery', 'register', 'reauth'];
export const ENTRIES = ['link_device_screen', 'kit_recovery_screen', 'scan_invite', 'paste_invite', 'app_link', 'cli_link_device', 'server_choice'];
export const PAYLOADS = ['l', 'd', 'kit'];
export const ROOTS = ['baked', 'kit', 'setup', 'trust_gate', 'link_offer', 'enrol'];

/** Which payload each scanner, paste field or handler takes (§12.1 "three scanners, three jobs"). */
const TAKES = {
  link_device_screen: 'd', // "accept only /d"
  cli_link_device: 'd', // andvari-cli link-device <link>
  kit_recovery_screen: 'kit', // "accept only andvari-kit:"
  scan_invite: 'l', // "accept /l only"
  paste_invite: 'l',
  app_link: 'l', // only /l is an app link; /d never is
};

export function passwordGate({ purpose, entry, payload, origin, account, pins, session }) {
  if (!PURPOSES.includes(purpose)) throw new Error('unknown purpose ' + purpose);
  if (entry !== null && !ENTRIES.includes(entry)) throw new Error('unknown entry ' + entry);
  if (payload !== null && !PAYLOADS.includes(payload)) throw new Error('unknown payload ' + payload);
  for (const p of pins) if (!ROOTS.includes(p.root)) throw new Error('unknown root ' + p.root);

  // The entry rule: a payload starts something only on the screen that takes it.
  if (payload !== null) {
    if (entry === null || !Object.hasOwn(TAKES, entry)) throw new Error('not a valid input: a payload with no entry that scans or pastes');
    if (TAKES[entry] !== payload) return 'refuse_entry';
  }

  // A session this device already holds for that account, at that origin (re-authentication).
  if (session && session.origin === origin && session.account === account) return 'proceed';
  // A re-authentication with no such session is refused at the entry: there is nothing to re-authenticate.
  if (purpose === 'reauth') return 'refuse_entry';

  const here = pins.filter((p) => p.origin === origin);
  if (here.length > 1) throw new Error('not a valid input: a device keeps at most one pin record per origin');
  const pin = here[0];
  if (!pin) return 'trust_gate'; // no pin at all: the typed-address root is the only way to make one

  // Creating an account proceeds with ANY pin for the origin: nothing derived from an existing
  // account's secrets is sent.
  if (purpose === 'register') return 'proceed';

  // A baked pin and a pin made through the Trust Gate are password pins for any account.
  if (pin.root === 'baked' || pin.root === 'trust_gate') return 'proceed';

  switch (purpose) {
    case 'sign_in':
      // A setup pin allows signing in to the operator account it enrolled, and nothing else.
      // A kit pin is for the recovery alone, even for the kit's own account.
      return pin.root === 'setup' && pin.account === account ? 'proceed' : 'trust_gate';
    case 'device_link':
      // A pin from a link offer, an enrol link, a kit or setup does not count for a device link.
      return 'trust_gate';
    case 'kit_recovery':
      // A kit pin for the kit's own account, or the setup pin of the operator account being recovered.
      return (pin.root === 'kit' || pin.root === 'setup') && pin.account === account ? 'proceed' : 'trust_gate';
    case 'assisted_recovery':
      // Through a kit or a setup pin, as through a link-offer or enrol pin: the Trust Gate.
      return 'trust_gate';
    default:
      throw new Error('unreachable purpose ' + purpose);
  }
}
