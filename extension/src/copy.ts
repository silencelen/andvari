/**
 * The extension's sentences that are not refusal lines (those are errors.ts's): the popup, the options page, the quick
 * unlock window, the in-page menus, banners and toasts. Each is an exported, named constant with its own doc comment,
 * marked as the web marks its copy: `PLACEHOLDER` (the words await the owner's) or `Approved wording` (the owner's
 * words, or the design's own). The wording tool places the owner's words by the constant's name; copy-walk.test.ts
 * fails on a sentence a person reads that is not one of these. `{0}`, `{1}`, … are filled by errors.ts fillApproved.
 *
 * DOM-free and dependency-free: the content script, the popup and the pages all import it.
 */

// ---- the popup: device unlock and the server line

/** Approved wording (the released extension's own words): the device-unlock button's name for the device, where the platform has no name of its own. */
export const YOUR_DEVICE = "your device";
/** Approved wording (the released extension's own words): the device-unlock button, where the platform has no name of its own. */
export const UNLOCK_WITH_YOUR_DEVICE = "Unlock with your device";
/** Approved wording (the released extension's own words): the device-unlock button; {0} the platform's name (Touch ID, Windows Hello). */
export const UNLOCK_WITH = "Unlock with {0}";
/** Approved wording (the released extension's own words): the server dot's tooltip, the server answered. */
export const SERVER_DOT_REACHABLE = "server reachable";
/** Approved wording (the released extension's own words): the server dot's tooltip, no server is confirmed yet. */
export const SERVER_DOT_NONE = "no server confirmed";
/** Approved wording (the released extension's own words): the server dot's tooltip, the server did not answer. */
export const SERVER_DOT_UNREACHABLE = "server unreachable";
/** Approved wording (the released extension's own words): the server line for screen readers, the server answered. */
export const SERVER_REACHABLE = "Server reachable";
/** Approved wording (the released extension's own words): the server line for screen readers, no server is confirmed yet. */
export const SERVER_NONE_CONFIRMED = "No server confirmed";
/** Approved wording (the released extension's own words): the server line for screen readers, the server did not answer. */
export const SERVER_UNREACHABLE = "Server unreachable";
/** Approved wording (the released extension's own words): the popup's background worker did not answer. */
export const BACKEND_NOT_RESPONDING = "Extension backend not responding — try reloading the extension.";
/** Approved wording (the released extension's own words): the password field's label while no server is known. */
export const MASTER_PASSWORD_LABEL = "Master password";
/** Approved wording (the released extension's own words): the update banner; {0} the newer version. Its button follows. */
export const UPDATE_AVAILABLE = "Update available — andvari {0}. ";
/** Approved wording (the released extension's own words): the update banner's button. */
export const UPDATE_DOWNLOAD_RELOAD = "Download & reload";
/** Approved wording (the released extension's own words): the update line when the server's update listing is signed too long ago. */
export const UPDATE_LISTING_STALE = "Updates: the server’s update listing hasn’t been re-signed in a while — if you’re expecting an update, mention it to your admin.";
/** Approved wording (the released extension's own words): the update line when the server's update listing does not verify. */
export const UPDATE_LISTING_UNVERIFIED = "Updates: the server’s update listing couldn’t be verified, so no update will be offered from it. Your vault and sync are unaffected.";

// ---- the popup: the server choice and its stops

/** Approved wording (the released extension's own words): the server choice's heading while no server is chosen (Safari: the app's). */
export const NO_SERVER_YET = "No server yet";
/** Approved wording (the released extension's own words): the stop's heading while andvari's settings could not be loaded. */
export const SETTINGS_NOT_LOADED_TITLE = "andvari couldn’t load its settings";
/** Approved wording (the released extension's own words): the stop's body while andvari's settings could not be loaded. */
export const SETTINGS_NOT_LOADED = "It can’t tell which server you use right now, so it won’t sign in anywhere. Close this window and open it again in a minute.";
/** Approved wording (decided on 2026-11-17): the stop's heading where the browser gives andvari no storage of its own. */
export const NO_STORE_TITLE = "andvari can't keep a server in this browser";
/** Approved wording (decided on 2026-11-17): the stop's body where the browser gives andvari no storage of its own. */
export const NO_STORE = "This browser gives andvari no storage of its own (Firefox does this when it's set never to remember history), so andvari can't keep which server is yours and signs in nowhere. Turn that setting off, then restart the browser.";
/** Approved wording (decided on 2026-11-17): the stop's heading under a fork. */
export const FORK_TITLE = "Don't continue";
/** Approved wording (the design's own words, §4.4): the button that forgets this server (the web's FORGET_THIS_SERVER). */
export const FORGET_THIS_SERVER = "Forget this server";
/** Approved wording (decided on 2026-11-17): the server choice's heading. */
export const CHOOSE_YOUR_SERVER = "Choose your server";
/** Approved wording (decided on 2026-11-17): the public server's line in the server choice. */
export const PUBLIC_SERVER_LEAD = "Free · best effort · US only · 13+";
/** Approved wording (decided on 2026-11-17): the line under the public server, about choosing one's own. */
export const OWN_SERVER_BODY = "Or use your own andvari server: andvari checks its identity card before you connect.";
/** Approved wording (decided on 2026-11-17): the button that opens the options page to choose one's own server. */
export const YOUR_OWN_SERVER = "Your own server";
/** Approved wording (decided on 2026-11-17): a signed move of the server; {0} its name, {1} the old address, {2} the new one. */
export const SERVER_MOVED_NOTICE = "{0} ({1}) has moved to {2}. Its operator signed the move.";
/** Approved wording (decided on 2026-11-17): the button that follows a signed move; {0} the new address. */
export const MOVE_TO = "Move to {0}";
/** Approved wording (the design's own words, §12.3): the kind-change gate's body; {0} the server's name, {1} its address,
 *  {2} the kind it now says it is. */
export const KIND_CHANGE_NOTICE = "{0} ({1}) now says it is a {2} server. This changes who can be offered operator recovery. Continue only if you expected this.";
/** Approved wording (the released extension's own words): the kind-change gate's button that goes on. */
export const CONTINUE = "Continue";
/** Approved wording (the released extension's own words): the button that puts a question off. */
export const NOT_NOW = "Not now";
/** Approved wording (decided on 2026-11-17): forgetting the server failed. */
export const FORGET_FAILED = "andvari couldn't forget the server. Close this window and try again.";
/** Approved wording (decided on 2026-11-17): the line while the server's identity card is checked. */
export const CHECKING_CARD = "Checking the server's identity card…";
/** Approved wording (the released extension's own words): the line when the session locked while the popup was open. */
export const SESSION_LOCKED = "Session locked — unlock to continue.";

// ---- the popup: the list and an item

/** Approved wording (the released extension's own words): the heading of the logins for the open site; {0} the site's host. */
export const THIS_SITE_FOR = "This site — {0}";
/** Approved wording (the released extension's own words): no login saved for the open site; {0} the site's host. */
export const NO_LOGIN_FOR = "No login saved for {0}.";
/** Approved wording (decided on 2026-11-17): the count of logins, one. */
export const LOGINS_IN_HOARD_ONE = "{0} login in your vault";
/** Approved wording (decided on 2026-11-17): the count of logins, {0} of them. */
export const LOGINS_IN_HOARD = "{0} logins in your vault";
/** Approved wording (the released extension's own words): the list when the vault holds no login. */
export const HOARD_EMPTY = "The hoard is empty.";
/** Approved wording (the released extension's own words): a search that matched nothing; {0} what was typed. */
export const NOTHING_MATCHES = "Nothing in the hoard matches “{0}”.";
/** Approved wording (the released extension's own words): a row's tooltip that opens the item. */
export const VIEW_DETAILS = "View details";
/** Approved wording (the released extension's own words): a row's second line when the login has no username. */
export const NO_USERNAME = "no username";
/** Approved wording (the released extension's own words): a row's terse button text, copy the username (its tooltip says it in full). */
export const BTN_USER = "user";
/** Approved wording (the released extension's own words): a row's terse button text, copy the password. */
export const BTN_PASS = "pass";
/** Approved wording (the released extension's own words): the detail's terse button text, copy. */
export const BTN_COPY = "copy";
/** Approved wording (the released extension's own words): the detail's terse button text, show the password. */
export const BTN_SHOW = "show";
/** Approved wording (the released extension's own words): the detail's terse button text, hide the password. */
export const BTN_HIDE = "hide";
/** Approved wording (the released extension's own words): the detail's terse button text, add a one-time code. */
export const BTN_ADD = "add";
/** Approved wording (the released extension's own words): a card row's terse button text, fill the card into the page. */
export const BTN_FILL = "fill";
/** Approved wording (the released extension's own words): a card detail's short name in a partial fill's line: the number. */
export const CARD_KIND_NUMBER = "number";
/** Approved wording (the released extension's own words): a card detail's short name in a partial fill's line: the expiry. */
export const CARD_KIND_EXPIRY = "expiry";
/** Approved wording (the released extension's own words): a card row's terse button text, copy the number. */
export const BTN_NUM = "num";
/** Approved wording (the released extension's own words): a card row's terse button text, copy the expiry. */
export const BTN_EXP = "exp";
/** Approved wording (the released extension's own words): a card row's terse button text, copy the name on the card. */
export const BTN_NAME = "name";
/** Approved wording (the released extension's own words): a card row's terse button text, copy the security code. */
export const BTN_CVV = "cvv";
/** Approved wording (the released extension's own words): the one-time-code chip's text for a moment after a copy. */
export const COPIED_FLASH = "copied";
/** Approved wording (the released extension's own words): the button that copies the username. */
export const COPY_USERNAME = "Copy username";
/** Approved wording (the released extension's own words): the button that copies the password. */
export const COPY_PASSWORD = "Copy password";
/** Approved wording (the released extension's own words): the button that shows the password. */
export const REVEAL_PASSWORD = "Reveal password";
/** Approved wording (the released extension's own words): the item has no password to copy or show. */
export const NO_PASSWORD_ON_ITEM = "No password on this item.";
/** Approved wording (the released extension's own words): an item's title when it has no name. */
export const LOGIN_UNNAMED = "Login";
/** Approved wording (the released extension's own words): the item's username field. */
export const USERNAME_LABEL = "Username";
/** Approved wording (the released extension's own words): the item's password field. */
export const PASSWORD_LABEL = "Password";
/** Approved wording (the released extension's own words): the item's one-time-code field. */
export const ONE_TIME_CODE_LABEL = "One-time code";
/** Approved wording (the released extension's own words): the item's sites, more than one. */
export const SITES_LABEL = "Sites";
/** Approved wording (the released extension's own words): the item's site, one. */
export const SITE_LABEL = "Site";
/** Approved wording (the released extension's own words): the item has no site saved. */
export const NO_SITE_SAVED = "no site saved";
/** Approved wording (the released extension's own words): the button that fills the open page with this login. */
export const FILL_THIS_PAGE = "Fill this page";
/** Approved wording (the released extension's own words): that button's tooltip. */
export const FILL_THIS_PAGE_TITLE = "Type this login into the current tab";
/** Approved wording (decided on 2026-11-17): the button that adds a one-time code to the login (the wording page's NW1 names it). */
export const ADD_TOTP_LABEL = "Add a one-time code to this login";
/** Approved wording (the released extension's own words): the one-time-code secret field's hint. */
export const TOTP_SECRET_HINT = "otpauth:// link or setup key";
/** Approved wording (the released extension's own words): the one-time-code secret field's name for screen readers. */
export const TOTP_SECRET_LABEL = "One-time code secret — paste the otpauth:// link or the setup key";
/** Approved wording (the released extension's own words): the one-time-code field's value while the login has none. */
export const TOTP_NONE = "none";
/** Approved wording (the released extension's own words): the button that saves a pasted one-time-code secret. */
export const TOTP_SAVE_BUTTON = "save";
/** Approved wording (the released extension's own words): the tooltip of the button that adds it. */
export const TOTP_ADD_TITLE = "Add this one-time code";
/** Approved wording (the released extension's own words): said to screen readers after a copy. */
export const COPIED_CLEARS_SOON = "Copied — it clears from your clipboard soon";
/** Approved wording (the released extension's own words): the question before filling a login saved for another site; {0} the site it is saved for, {1} this page. */
export const FILL_OTHER_SITE = "This login is saved for {0}. You are on {1}. Fill it here only if you trust this page.";
/** Approved wording (the released extension's own words): the site a login is saved for, in that question, when none of its addresses has a host. */
export const ANOTHER_SITE = "another site";
/**
 * PLACEHOLDER: in that question and on its button, a page served over plain http, named with its scheme; {0} the page
 * (`http://` and its host). Must say that the page is not secure, after the address, in a word or two.
 */
export const FILL_PAGE_NOT_SECURE = "⟦{0} (not secure)⟧";
/**
 * PLACEHOLDER: a second line of that question, where the page's host is longer than its site's registrable domain;
 * {0} that domain. Must say which site the page belongs to, so that a long address whose end is out of view cannot hide it.
 */
export const FILL_OTHER_SITE_DOMAIN = "⟦This page belongs to {0}.⟧";
/** Approved wording (the released extension's own words): the button that fills it there anyway; {0} this page. */
export const FILL_ON = "Fill on {0}";
/** Approved wording (the released extension's own words): the button that cancels a question. */
export const CANCEL = "Cancel";
/** Approved wording (the released extension's own words): the one-time-code chip's tooltip and name. */
export const COPY_TOTP = "Copy one-time code";
/** Approved wording (the released extension's own words): the Safari chip's text in place of the code. */
export const COPY_CODE_CHIP = "copy code";
/** Approved wording (the released extension's own words): said to screen readers after the code was copied. */
export const TOTP_COPIED = "One-time code copied";
/** Approved wording (the released extension's own words): how long the code shown holds; {0} the seconds. */
export const SECONDS_LEFT = "{0} seconds left";
/** Approved wording (the released extension's own words): the button that starts a card fill over. */
export const START_OVER = "Start over";

// ---- the popup: cards

/** Approved wording (the released extension's own words): the heading of the cards. */
export const CARDS_LABEL = "Cards";
/** Approved wording (the released extension's own words): the remedy after a card refusal where the popup copies card details. */
export const CARD_USE_COPY_BUTTONS = "Use the copy buttons instead.";
/** Approved wording (the released extension's own words): the remedy after a card refusal in Safari, where the app copies them. */
export const CARD_COPY_IN_APP = "Copy what you need from the andvari app.";
/** Approved wording (the released extension's own words): a card row's tooltip. */
export const COPY_CARD_DETAILS = "Copy card details";
/** Approved wording (the released extension's own words): the card fill button's tooltip; {0} the details the form asks for, {1} the page or provider. */
export const FILL_CARD_DETAILS_INTO = "Fill this card's {0} into {1}";
/** Approved wording (the released extension's own words): the card fill button's tooltip; {0} the page or provider. */
export const FILL_CARD_INTO = "Fill this card into {0}";
/** Approved wording (the released extension's own words): where a card fill goes, under the card; {0} the provider's documents, {1} the details it writes. */
export const FILL_DESTINATION_DETAILS = "Fill → {0}: {1}";
/** Approved wording (the released extension's own words): where a card fill goes, under the card; {0} the page's address. */
export const FILL_DESTINATION = "Fill → {0}";
/** Approved wording (the released extension's own words): the place a card goes when no provider is known. */
export const THE_PAGE = "the page";
/** Approved wording (the released extension's own words): the button that copies the card number. */
export const COPY_CARD_NUMBER = "Copy card number";
/** Approved wording (the released extension's own words): the button that copies the expiry. */
export const COPY_CARD_EXPIRY = "Copy expiry (MM/YY)";
/** Approved wording (the released extension's own words): the button that copies the name on the card. */
export const COPY_CARD_NAME = "Copy name on card";
/** Approved wording (the released extension's own words): the button that copies the security code. */
export const COPY_CARD_CVV = "Copy security code";
/** Approved wording (the released extension's own words): a card detail's name inside a line: the number. */
export const CARD_DETAIL_NUMBER = "card number";
/** Approved wording (the released extension's own words): a card detail's name inside a line: the expiry. */
export const CARD_DETAIL_EXPIRY = "expiry date";
/** Approved wording (the released extension's own words): a card detail's name inside a line: the security code. */
export const CARD_DETAIL_CVV = "security code";
/** Approved wording (the released extension's own words): a card detail's name inside a line: the name on the card. */
export const CARD_DETAIL_NAME = "name on card";
/** Approved wording (the released extension's own words): a card detail's name inside a line: the card type. */
export const CARD_DETAIL_TYPE = "card type";
/** Approved wording (the released extension's own words): a card detail's name inside a line: the postal code. */
export const CARD_DETAIL_POSTAL = "postal code";
/** Approved wording (the released extension's own words): the remedy lead after a partial card fill where the popup copies card details. */
export const CARD_COPY_INSTEAD = "Copy instead:";
/** Approved wording (the released extension's own words): the remedy after a partial card fill in Safari. */
export const CARD_COPY_MISSING_IN_APP = "Copy what's missing from the andvari app.";
/** PLACEHOLDER: a partial card fill, the fields that could not be seen; {0} their names. The remedy follows it. */
export const CARD_FIELDS_UNSEEN = "The {0} field can't be seen on the page: scroll so it shows and fill again, or";
/** Approved wording (decided on 2026-11-17): a partial card fill; {0} what was filled, {1} what was not. */
export const CARD_FILLED_SOME = "Filled {0}. Couldn't fill {1}.";
/** Approved wording (decided on 2026-11-17): a card fill that filled none of the details asked for; {0} what was not filled. */
export const CARD_FILLED_NONE = "Couldn't fill {0}.";
/** Approved wording (the released extension's own words): the generated password's lead for screen readers. */
export const GENERATED_PASSWORD = "Generated password: ";
/** Approved wording (the released extension's own words): said to screen readers after Regenerate. */
export const NEW_PASSWORD_GENERATED = "New password generated";
/** Approved wording (the released extension's own words): said to screen readers after the password was copied. */
export const PASSWORD_COPIED = "Password copied";

// ---- the popup: sign-in, quick unlock, sign out

/** Approved wording (the released extension's own words): the unlock button while the password is worked on. */
export const UNSEALING = "Unsealing…";
/** Approved wording (the released extension's own words): the unlock button. */
export const UNLOCK = "Unlock";
/** Approved wording (the released extension's own words): the code button while the code is checked. */
export const VERIFYING = "Verifying…";
/** Approved wording (the released extension's own words): the code button. */
export const VERIFY = "Verify";
/** Approved wording (the released extension's own words): the code had fewer than 6 digits. */
export const ENTER_ALL_DIGITS = "Enter all 6 digits of the code.";
/** Approved wording (the released extension's own words): too many wrong one-time codes in this sign-in. */
export const TOO_MANY_WRONG_CODES = "Too many wrong codes — sign in again.";
/** Approved wording (the released extension's own words): the quick-unlock setting, on. */
export const QUICK_UNLOCK_IS_ON = "Quick unlock is on";
/** Approved wording (the released extension's own words): the quick-unlock setting, off. */
export const QUICK_UNLOCK_IS_OFF = "Quick unlock is off";
/** Approved wording (the released extension's own words): the button that turns quick unlock off. */
export const TURN_OFF = "Turn off";
/** Approved wording (the released extension's own words): the button that sets quick unlock up. */
export const SET_UP = "Set up";
/** Approved wording (the released extension's own words): the line while the device's unlock prompt opens. */
export const OPENING_UNLOCK_PROMPT = "Opening your device’s unlock prompt…";
/** Approved wording (the released extension's own words): the line while the device's setup prompt opens. */
export const OPENING_SETUP_PROMPT = "Opening your device’s setup prompt…";
/** Approved wording (the released extension's own words): device quick unlock was set up. */
export const DEVICE_QUICK_UNLOCK_ON = "Device quick unlock is on for this browser.";
/** Approved wording (the released extension's own words): PIN quick unlock was set up. */
export const QUICK_UNLOCK_ON_HERE = "Quick unlock is on for this browser.";
/** Approved wording (the released extension's own words): quick unlock was turned off. */
export const QUICK_UNLOCK_TURNED_OFF = "Quick unlock turned off.";
/** Approved wording (the released extension's own words): the sign-out button. */
export const SIGN_OUT = "Sign out";
/** Approved wording (the released extension's own words): the sign-out button after its first click. */
export const SIGN_OUT_CONFIRM = "Sign out? Click again to confirm";
/** Approved wording (the released extension's own words): what signing out removes, shown at its first click. */
export const SIGN_OUT_EXPLAINED = "Signing out removes this browser's quick unlock (PIN or biometric) and its saved session. Your vault on the server is untouched.";
/** Approved wording (decided on 2026-11-17): at the sign-out's first click, when one login or card this browser captured on a page was not saved to the vault. */
export const SIGN_OUT_UNSAVED_ONE = "1 login or card this browser captured on a page hasn't been saved to your vault yet. Signing out deletes it.";
/** Approved wording (decided on 2026-11-17): as above, more than one. {0} the count. */
export const SIGN_OUT_UNSAVED_MANY = "{0} logins or cards this browser captured on pages haven't been saved to your vault yet. Signing out deletes them.";
/** Approved wording (decided on 2026-11-17): at the lock's first click, when one capture was not saved (a page's password is not kept past a lock). */
export const LOCK_UNSAVED_ONE = "1 login or card this browser captured on a page hasn't been saved to your vault yet. Locking deletes it.";
/** Approved wording (decided on 2026-11-17): as above, more than one. {0} the count. */
export const LOCK_UNSAVED_MANY = "{0} logins or cards this browser captured on pages haven't been saved to your vault yet. Locking deletes them.";
/**
 * Approved wording (decided on 2026-11-17): above the unlock form, the next time the popup opens (once), when a lock or sign-out nobody was asked
 * about (the idle lock; the full sign-out after the server ended the session for good) deleted one capture unsaved.
 */
export const CAPTURES_LOST_ONE = "1 login or card this browser captured on a page wasn't saved to your vault before andvari locked or was signed out, so it was deleted.";
/** Approved wording (decided on 2026-11-17): as above, more than one. {0} the count. */
export const CAPTURES_LOST_MANY = "{0} logins or cards this browser captured on pages weren't saved to your vault before andvari locked or was signed out, so they were deleted.";
/** Approved wording (decided on 2026-11-17): at the first click of "Forget this server" on the options page, when one capture was not saved. */
export const FORGET_UNSAVED_ONE = "1 login or card this browser captured on a page hasn't been saved to your vault yet. Forgetting this server deletes it.";
/** Approved wording (decided on 2026-11-17): as above, more than one. {0} the count. */
export const FORGET_UNSAVED_MANY = "{0} logins or cards this browser captured on pages haven't been saved to your vault yet. Forgetting this server deletes them.";
/** Approved wording (decided on 2026-11-17): as above, when andvari could not tell (the worker did not answer the count). Never said as none. */
export const FORGET_UNSAVED_UNKNOWN = "andvari can't tell whether logins or cards this browser captured on pages are still waiting to be saved. Forgetting this server deletes any that are.";
/** Approved wording (decided on 2026-11-17): the "Forget this server" button after its first click, over captures or when andvari cannot tell. */
export const FORGET_CONFIRM = "Forget and lose them";
/** PLACEHOLDER: the popup's "Forget this server" was chosen again too soon after its first click (two clicks in one
 *  turn, a double click, a held key), so it was not taken; shown above the line the first click said, which stays. Must
 *  say: read the line below first, then choose the button again to forget this server. */
export const FORGET_SERVER_READ_FIRST = "⟦Read the line below first, then choose the button again to forget this server.⟧";
/** Approved wording (decided on 2026-11-17): under those lines while the vault is open and its session live: how to save them first. */
export const UNSAVED_SAVE_FIRST = "To keep them, choose Save on the page where each one was captured.";
/** Approved wording (the released extension's own words): the lock button (popup.html carries the same word until the page's words are filled at load). */
export const LOCK = "Lock";
/** Approved wording (decided on 2026-11-17): the lock button after its first click, when captures would be lost. */
export const LOCK_CONFIRM = "Lock and lose them";
/** Approved wording (the released extension's own words): the options page could not be opened because no server is known right now. */
export const CANT_TELL_SERVER = "andvari can’t tell which server to open right now — close this window and try again.";
/** Approved wording (the released extension's own words): the connection test answered. */
export const SERVER_REACHABLE_DONE = "Server reachable.";
/** Approved wording (decided on 2026-11-17): the server line while the server is stopped (fork or damaged record). */
export const SERVER_STOPPED = "Server stopped";
/** Approved wording (the released extension's own words): the server line while the worker did not say which server. */
export const SERVER_UNKNOWN = "Server unknown";
/** Approved wording (the released extension's own words): the server line's name for screen readers; {0} the server's address. */
export const CONNECTED_SERVER = "Connected server: {0}";
/** Approved wording (the released extension's own words): the Safari server line's details toggle. */
export const DETAILS = "Details";
/** Approved wording (the released extension's own words): the Face ID button while the app asks. */
export const WAITING_FOR_FACE_ID = "Waiting for Face ID…";
/** Approved wording (the released extension's own words): the Face ID button. */
export const UNLOCK_WITH_FACE_ID = "Unlock with Face ID";
/** Approved wording (the released extension's own words): Safari, the andvari app is locked. */
export const OPEN_APP_AND_UNLOCK = "Open andvari and unlock it, then try again.";
/** Approved wording (the released extension's own words): Safari, the andvari app could not be reached. */
export const APP_NOT_REACHED = "Couldn’t reach the andvari app. Open it once, then try again.";
/** Approved wording (the released extension's own words): an error the popup did not expect; {0} what it was. */
export const UNEXPECTED_PROBLEM = "andvari hit a problem: {0}";
/** Approved wording (the released extension's own words): Safari, the andvari app has no server chosen. */
export const APP_SERVER_NONE = "Choose your server in the andvari app. This extension uses the same one.";
/** Approved wording (the released extension's own words): Safari, the andvari app could not be asked which server. */
export const APP_SERVER_UNKNOWN = "andvari couldn’t ask the andvari app which server you use. Open the app once, then open this again.";

// ---- the options page

/** Approved wording (the released extension's own words): the options page's server line while andvari does not answer. */
export const OPTIONS_SERVER_NOT_ANSWERING = "unknown — andvari isn't answering. Close this page and open it again.";
/** Approved wording (the released extension's own words): the options page's server line while andvari's settings could not be loaded. */
export const OPTIONS_SERVER_UNSETTLED = "unknown — andvari couldn't load its settings, so it signs in nowhere. Close this page and open it again in a minute.";
/** PLACEHOLDER: the options page's server line while no server is chosen. */
export const OPTIONS_NO_SERVER_YET = "no server yet — choose “andvari” in the toolbar popup, or enter your own server below.";
/** Approved wording (decided on 2026-11-17): the options page's heading over a stopped server. */
export const SERVER_CANT_BE_USED = "This server can't be used";
/** Approved wording (decided on 2026-11-17): the options page's autofill line, on. */
export const AUTOFILL_INJECTION_ON = "Autofill on other sites: on";
/** Approved wording (decided on 2026-11-17): the options page's autofill line, off. */
export const AUTOFILL_INJECTION_OFF = "Autofill on other sites: off";
/** Approved wording (decided on 2026-11-17): the browser declined access to the server's address. */
export const ACCESS_DECLINED = "The browser didn't allow andvari to reach that server. Nothing changed.";
/** Approved wording (the released extension's own words): a server was chosen; {0} its address. */
export const CONNECTED_TO = "Connected to {0}. Sign in from the toolbar popup.";
/** Approved wording (decided on 2026-11-17): a server was chosen, but autofill on other sites waits for the permission; {0} its address. */
export const CONNECTED_TO_AUTOFILL_OFF = "Connected to {0}. Autofill on other sites stays off until you allow andvari to read and change web pages: choose Continue again to allow it. Sign in from the toolbar popup.";
/** Approved wording (the released extension's own words): removing the data failed because andvari does not answer. */
export const PURGE_NOT_ANSWERING = "andvari isn't answering, so nothing was removed. Close this page and open it again.";
/** Approved wording (decided on 2026-11-17): the remove button after its first click; {0} the server's address. */
export const PURGE_CONFIRM = "Remove this browser's data for {0} now";
/** Approved wording (decided on 2026-11-17): what removing the data does (the wording page's A7 names it). */
export const PURGE_NOTE = "This removes this browser's PIN and quick unlock, and what it keeps for that server. andvari's record of the server's identity stays: Forget this server removes that too. Your vault on the server is not affected.";
/** Approved wording (the released extension's own words): the remove button. */
export const PURGE_BUTTON = "Remove data for this server…";
/** Approved wording (the released extension's own words): the data was removed; {0} the server's address. */
export const PURGE_DONE = "Removed this browser's stored data for {0}.";
/** Approved wording (the released extension's own words): removing the data failed. */
export const PURGE_FAILED = "Couldn't remove the stored data.";

// ---- the quick-unlock window (connector)

/** Approved wording (the released extension's own words): the window was opened with nothing to do. */
export const CONNECTOR_NOTHING_TO_DO = "Nothing to do here — you can close this window.";
/** Approved wording (the released extension's own words): the window's heading, setting up. */
export const CONNECTOR_SET_UP_TITLE = "Set up quick unlock";
/** Approved wording (the released extension's own words): the window's heading, unlocking. */
export const CONNECTOR_UNLOCK_TITLE = "Unlock andvari";
/** Approved wording (the released extension's own words): the window's line, setting up. */
export const CONNECTOR_SET_UP = "Set up unlocking with your device’s biometrics or PIN.";
/** Approved wording (the released extension's own words): the window's line, unlocking. */
export const CONNECTOR_UNLOCK = "Confirm it’s you to unlock andvari.";
/** Approved wording (the released extension's own words): the line while the device's prompt is up. */
export const CONNECTOR_FOLLOW_PROMPT = "Follow your device’s prompt…";
/** Approved wording (the released extension's own words): the prompt was cancelled. */
export const CONNECTOR_CANCELLED = "Cancelled — you can close this window and try again.";
/** Approved wording (the released extension's own words): the device has no biometric quick unlock. */
export const CONNECTOR_NO_BIO = "This device can’t do biometric quick unlock. Use a PIN instead.";
/** Approved wording (the released extension's own words): the line while setup finishes. */
export const CONNECTOR_FINISHING = "Finishing setup…";
/** Approved wording (the released extension's own words): the line while it unlocks. */
export const CONNECTOR_UNLOCKING = "Unlocking…";
/** Approved wording (the released extension's own words): setup is done. */
export const CONNECTOR_SET_UP_DONE = "Quick unlock is on ✓";
/** Approved wording (the released extension's own words): the unlock is done. */
export const CONNECTOR_UNLOCK_DONE = "Unlocked ✓ — reopen andvari.";
/** Approved wording (the released extension's own words): the window's last line. */
export const CONNECTOR_DONE = "Done — you can close this window and reopen andvari.";

// ---- in the page: toasts, the menu, the banners

/** Approved wording (decided on 2026-11-17): the toast after a login was filled whose site asks for a one-time code (the wording page's NW1 names it). */
export const TOTP_COPIED_TOAST = "One-time code copied. Paste it when the site asks for it.";
/** Approved wording (decided on 2026-11-17): the same toast's lead when the code could not be copied; the code follows (the wording page's NW1 names
 *  it). */
export const TOTP_SHOWN_TOAST = "One-time code:";
/** Approved wording (the released extension's own words): a card saved from the page. */
export const CARD_SAVED = "Card saved to the hoard.";
/** Approved wording (the released extension's own words): a card fill from the page needs the toolbar. */
export const OPEN_FROM_TOOLBAR_TO_FILL_CARD = "Open andvari from the toolbar to fill this card";
/** Approved wording (the released extension's own words): a fill wrote both the username and the password. */
export const LOGIN_FILLED = "Login filled";
/** Approved wording (the released extension's own words): a fill wrote the username only. */
export const USERNAME_FILLED = "Username filled";
/** Approved wording (the released extension's own words): a fill wrote the password only. */
export const PASSWORD_FILLED = "Password filled";
/** Approved wording (the released extension's own words): searching all logins needs the toolbar. */
export const SEARCH_FROM_TOOLBAR = "Click the andvari toolbar icon to search all your logins";
/** Approved wording (the released extension's own words): a generated password was filled. */
export const STRONG_PASSWORD_FILLED = "Strong password filled";
/** Approved wording (decided on 2026-11-17): the banner's Not now, nothing was saved. */
export const NOTHING_CHANGED = "Nothing was changed.";
/** Approved wording (the released extension's own words): a login saved from the page. */
export const SAVED_TO_HOARD = "Saved to the hoard.";
/** Approved wording (the released extension's own words): the in-page menu cannot be shown where it can't be confirmed unobstructed. */
export const MENU_UNCONFIRMED = "This browser can't confirm andvari's menu is unobstructed — use the andvari toolbar icon instead";
/** Approved wording (the released extension's own words): the in-page menu is covered by something on the page. */
export const MENU_COVERED = "Something on this page is covering andvari — use the andvari toolbar icon instead";
/** Approved wording (the released extension's own words): the card chip's name while locked. */
export const CARD_CHIP_LOCKED = "andvari is locked — click the andvari toolbar icon";
/** Approved wording (the released extension's own words): the card chip's name. */
export const CARD_CHIP = "Fill card with andvari";
/** Approved wording (the released extension's own words): the card chip's name for screen readers while locked. */
export const CARD_CHIP_LOCKED_LABEL = "andvari is locked — click the andvari toolbar icon. Press Alt plus Down Arrow to open andvari.";
/** Approved wording (the released extension's own words): the card chip's name for screen readers. */
export const CARD_CHIP_LABEL = "Fill card with andvari. Press Alt plus Down Arrow to open andvari.";
/** Approved wording (the released extension's own words): the in-page menu while locked. */
export const MENU_LOCKED = "Locked — click the andvari toolbar icon to unlock";
/** Approved wording (the released extension's own words): the in-page menu's name for screen readers; {0} the site's host. */
export const MENU_LABEL = "andvari — saved logins for {0}";
/** Approved wording (the released extension's own words): the in-page menu when no login is saved for the site; {0} its host. */
export const MENU_NO_LOGIN = "No saved login for {0}";
/** Approved wording (the released extension's own words): the in-page menu's row that fills a generated password. */
export const MENU_STRONG_PASSWORD = "Use a strong password";
/** Approved wording (the released extension's own words): the in-page menu's row that opens the search. */
export const MENU_SEARCH_ALL = "Search all logins…";
/** Approved wording (the released extension's own words): said to screen readers while the menu is locked. */
export const MENU_LOCKED_ANNOUNCE = "andvari is locked — click the andvari toolbar icon to unlock";
/** Approved wording (the released extension's own words): said to screen readers when no login is saved; {0} the site's host. */
export const MENU_NO_LOGIN_ANNOUNCE = "No saved login for {0}, arrows to browse";
/** Approved wording (decided on 2026-11-17): said to screen readers, one login. */
export const MENU_LOGINS_ANNOUNCE_ONE = "{0} login. Use the arrow keys to choose.";
/** Approved wording (decided on 2026-11-17): said to screen readers, {0} logins. */
export const MENU_LOGINS_ANNOUNCE = "{0} logins. Use the arrow keys to choose.";
/** Approved wording (decided on 2026-11-17): the card banner, an update; {0} the card's name, {1} its masked line. */
export const UPDATE_CARD_OFFER = "Update the card {0} ({1})?";
/** Approved wording (decided on 2026-11-17): the card banner, a new card; {0} the card's line. */
export const SAVE_CARD_OFFER = "Save the card {0} to andvari?";
/** Approved wording (the released extension's own words): the banner's button that updates. */
export const UPDATE = "Update";
/** Approved wording (the released extension's own words): the banner's button that saves. */
export const SAVE = "Save";
/** Approved wording (decided on 2026-11-17): the shared-login notice's one button. */
export const OK = "OK";
/** Approved wording (decided on 2026-11-17): the login banner for a login in a shared vault; {0} the vault's name, or "a shared vault". */
export const SHARED_LOGIN_NOTICE = "This login is in {0}. Update it in the andvari app.";
/** Approved wording (decided on 2026-11-17): the login banner's name for a shared vault with no name known. */
export const A_SHARED_VAULT = "a shared vault";
/** Approved wording (decided on 2026-11-17): the login banner, an update; {0} the login's name. */
export const UPDATE_PASSWORD_OFFER = "Update the password for {0}?";
/** Approved wording (decided on 2026-11-17): the login banner, an update; {0} the login's name, {1} its username. */
export const UPDATE_PASSWORD_OFFER_USER = "Update the password for {0} ({1})?";
/** Approved wording (decided on 2026-11-17): the login banner, an update; {0} the login's name, {1} the vault's name. */
export const UPDATE_PASSWORD_OFFER_IN = "Update the password for {0} in “{1}”?";
/** Approved wording (decided on 2026-11-17): the login banner, an update; {0} the login's name, {1} its username, {2} the vault's name. */
export const UPDATE_PASSWORD_OFFER_USER_IN = "Update the password for {0} ({1}) in “{2}”?";
/** Approved wording (the released extension's own words): the login banner's name for a login with none. */
export const THIS_LOGIN = "this login";
/** Approved wording (decided on 2026-11-17): the login banner, a new login; {0} the site's host. */
export const SAVE_LOGIN_OFFER = "Save this login for {0} to andvari?";
/** Approved wording (decided on 2026-11-17): the login banner, a new login; {0} the site's host, {1} the vault's name. */
export const SAVE_LOGIN_OFFER_IN = "Save this login for {0} in “{1}”?";
/** Approved wording (the released extension's own words): a typed password used for one other login. */
export const REUSED_ONE = "The password you just typed on this page is already used for another login — a unique one is safer.";
/** Approved wording (the released extension's own words): a typed password used for {0} other logins. */
export const REUSED_MANY = "The password you just typed on this page is already used for {0} other logins — a unique one is safer.";
/** Approved wording (the released extension's own words): a card's name when its brand is not known; its last four digits follow. */
export const CARD_FALLBACK_NAME = "Card";
/** Approved wording (the released extension's own words): a card's line when it holds no number. */
export const CARD_SUBTITLE_NO_NUMBER = "card";
