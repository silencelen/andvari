package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.client.pin.TrustGateWording

/**
 * The signed-out journey (§12.1): the first screen, an invite, sign-up, registration, sign-in, linking this device,
 * and recovery. Core owns where the journey is ([AppSnapshot.entry]); a UI renders that screen and calls the
 * intents that take it.
 *
 * Every screen is made by core alone, and an intent acts only on the screen that is on show (anything else answers
 * [Trouble.STALE]). That is what makes the order of the journey a fact of the types: a screen that asks for a
 * secret exists only after the steps that must come before it.
 *
 * The engine's flows have the same shape one layer down (`core.client.onboard`, `link`, `devicelink`, `recovery`,
 * `pin`): a step that sends something has an internal constructor there too. Each screen below says which engine
 * state it shows, so the two cannot drift apart unnoticed.
 *
 * **A screen acts on the server it names, and on no other.** Every screen that belongs to a server is given its
 * [EntryFlow] when core makes it and keeps it for good; an intent reads the flow of the screen it was handed and
 * nothing else. Core holds no "current server" beside the screens, so whatever was opened in between (a tapped
 * invite, another scan, Back) a password typed on the sign-in screen of one server can never go to another.
 */
sealed class EntryScreen private constructor(internal val flow: EntryFlow?) {
    /**
     * §12.1: the first screen. Three buttons of equal size and style, none preselected or focused
     * ([CopyKey.FIRST_SCAN_INVITE] or, on desktop, [CopyKey.FIRST_PASTE_INVITE_LINK]; [CopyKey.FIRST_CREATE_ACCOUNT]
     * with [CopyKey.FIRST_CREATE_ACCOUNT_LINE]; [CopyKey.FIRST_OWN_SERVER]), and below them, as text,
     * [CopyKey.FIRST_SIGN_IN].
     */
    class FirstRun internal constructor(
        /**
         * What the public instance says about new accounts. When [SignupStatus.full], the second button reads
         * [CopyKey.FIRST_SIGNUP_FULL] and is disabled.
         *
         * **While the mode is [JoinMode.NOT_KNOWN]** (the server has not answered yet, or cannot be reached) the
         * screen shows its three choices as usual and never presents sign-up as closed:
         * [EntryApi.createAccountOnAndvari] asks the server and answers with what it says.
         *
         * GAP (§12.1): the design gives the second button's label only for `full`. For `links` and `closed` this
         * carries the mode and no wording.
         */
        val signup: SignupStatus,
        /** This build takes a server's setup link under "Use your own server" (the desktop app; never a phone, §9.5). */
        val takesSetupLinks: Boolean,
        /**
         * This device asked an operator for help earlier and still holds the request (§9.3: it must survive the
         * 7-day hold on an install that has no account). [EntryApi.resumeOperatorHelp] shows it.
         */
        val operatorHelpWaiting: Boolean,
        /**
         * This build has a baked public instance (§0.3). False in a build without one: the second button is not
         * shown, [signup] says nothing, and [EntryApi.createAccountOnAndvari] does nothing.
         */
        val offersPublicInstance: Boolean,
        /** Something this screen says once, after a journey that ended by itself; null otherwise. [EntryApi.dismissNotice] takes it away. */
        val notice: FirstRunNotice?,
        /**
         * The account this device just deleted ([AccountSettingsApi.deleteAccount] answered DONE): said once on this
         * screen, beside [notice] (a field of its own, so an exhaustive `when` over [FirstRunNotice] is unchanged), until
         * [EntryApi.dismissNotice] takes it away with [notice]. Null otherwise. Additive.
         */
        val accountDeleted: AccountDeletedNotice? = null,
        /**
         * The account whose deletion was sent from this device with no answer, and whose session the server has since
         * ended ([LockedScreen.deletionOutcomeUnknown], then [AppApi.signInAgain]): we cannot tell yet whether it was
         * deleted. Said on this screen in the same way as [accountDeleted], until [EntryApi.dismissNotice] takes it away
         * with [notice]. Null otherwise. Additive: the apps can drop their own flag for it.
         */
        val deletionOutcomeUnknown: DeletionOutcomeUnknownNotice? = null,
        /**
         * The account on this device that a verified card names as its server's operator, on a phone (the owner's decision
         * of 2026-11-16): stopped and locked here, its copy kept until the person removes it
         * ([EntryApi.removeHeldOperatorAccount]). Shown as long as it stands, through restarts; [EntryApi.dismissNotice]
         * does not take it away. While it stands no other account can be added on this device (one account is kept at a
         * time): the entry answers ANOTHER_ACCOUNT_KEPT. Null otherwise. Additive.
         */
        val heldAsOperator: HeldOperatorAccount? = null,
        /**
         * A recovery (with the kit or the operator's help) the person left after its new password was sent, whose answer
         * arrived later: what it came to, said on this screen until [EntryApi.dismissNotice] takes it away with [notice].
         * Null otherwise. Additive.
         */
        val lateRecovery: LateRecoveryNotice? = null,
        /**
         * After [AppApi.signInAgain] from a lock screen with [LockedScreen.sessionNotConfirmed]: this device could not
         * confirm its session with its server in time. Said once as [CopyKey.SESSION_NOT_CONFIRMED], in place of
         * [notice] (which is null then, never [FirstRunNotice.SIGNED_OUT_BY_SERVER]), until [EntryApi.dismissNotice] takes
         * it away. Additive.
         */
        val sessionNotConfirmed: Boolean = false,
    ) : EntryScreen(null) {
        /**
         * [CopyKey.SESSION_NOT_CONFIRMED_SIGN_OUT_FIRST] where [sessionNotConfirmed]; null otherwise. Drawn in place of
         * [CopyKey.SESSION_NOT_CONFIRMED] (which ends "sign in again") while a way out that signs the kept account OUT
         * stands on this screen ([AppSnapshot.kitWiped] with [KitWipedNotice.wayOut] [KeptWayOut.SIGN_OUT_KEPT_ACCOUNT]).
         * Additive.
         */
        val sessionNotConfirmedBesideSignOut: CopyKey? get() = if (sessionNotConfirmed) CopyKey.SESSION_NOT_CONFIRMED_SIGN_OUT_FIRST else null
    }

    /**
     * "Scan an invite", with "Paste a link" beside it (desktop: "Paste an invite link"). It takes invites (`/l`)
     * only: a device link or a kit handed in here is refused and starts nothing (§12.1 "Three scanners, three jobs").
     */
    class InviteEntry internal constructor() : EntryScreen(null)

    /** "Use your own server": the address field (§4.4, typed-address root). */
    class OwnServer internal constructor(
        /** The field also takes a setup link (desktop, §12.1). */
        val takesSetupLinks: Boolean,
    ) : EntryScreen(null)

    /**
     * The Trust Gate (§4.4, §12.3), in the wording [TrustGatePrompt.wording] names. Nothing derived from an
     * account's secrets has been sent to this origin, and nothing is until [EntryApi.confirmTrustGate].
     */
    class TrustGate internal constructor(flow: EntryFlow, val prompt: TrustGatePrompt) : EntryScreen(flow)

    /**
     * A flow found that a server this device holds a pin for cannot be used as that pin stands (§2.4: handled
     * first, and the flow is opened again afterwards). [instance] names the server as pinned, and its
     * [InstanceSnapshot.card] says what was found:
     *
     * - [InstanceCardState.Moved], [InstanceCardState.KindChanged] or [InstanceCardState.UpdateAndvari]: the chain
     *   moved it or changed its `kind` (the engine's `FirstPin.PinChanged`). [InstanceApi.followMove] and
     *   [InstanceApi.acceptKindChange] take that card as they take the connected server's. When they are done the
     *   journey returns to the screen before this one, where the flow starts again and every check runs from the
     *   beginning.
     * - [InstanceCardState.Withheld]: the server serves less of its chain than this device pinned (`withheld` under
     *   an existing pin). Nothing was sent and nothing can be opened there now; [EntryApi.back], and try later.
     * - [InstanceCardState.Stopped] or [InstanceCardState.Damaged]: the server is blocked on this device (the
     *   engine's `FirstPin.Blocked`). The only way on is [InstanceApi.forgetServer] with [instance].
     *
     * Intents answered [ServerResult.SERVER_CHANGED] or [ServerResult.IDENTITY_CONFLICT] (or the same values of
     * their own result) to get here. While this screen is on show, [AppSnapshot.instance] is [instance].
     */
    class ServerChanged internal constructor(flow: EntryFlow, val instance: InstanceSnapshot) : EntryScreen(flow)

    /**
     * §2.4 pinning, `origin_mismatch`: the server at [dialed] served a genuine identity card made for another
     * address, [cardNames] (the engine's `FirstPin.OriginMismatch`). Cards are public, so any server can serve
     * another server's chain; an address that does so is not that server. Nothing was pinned and nothing of the
     * person's was sent. Intents answered [ServerResult.OTHER_ADDRESS] (or the same value of their own result) to get
     * here; [EntryApi.back] returns to where the address came from.
     *
     * GAP (§2.4): the design gives the verdict and no wording. Show both addresses, whole.
     */
    class AddressMismatch internal constructor(
        flow: EntryFlow?,
        /** The address this app dialed: the one typed, or the one the invite, the device link or the kit names. */
        val dialed: String,
        /** The address the served card names. */
        val cardNames: String,
        val opening: AddressMismatchFor,
        /** [dialed] is this build's public instance: only an app update helps, and [sentence] says so. */
        val publicInstance: Boolean,
    ) : EntryScreen(flow) {
        /**
         * A recovery kit made before its server moved names the old address. [EntryApi.recoverAtNamedAddress] starts
         * the recovery again at [cardNames], where every check runs again (a scanned kit's own card hash still
         * anchors it; a typed kit passes the Trust Gate for that address). An address typed for anything else is
         * simply typed again; a device link is never redirected: its QR names the address, and the person starts
         * again from the other device.
         */
        val canRecoverThere: Boolean
            get() = (opening == AddressMismatchFor.KIT || opening == AddressMismatchFor.TYPED_KIT) && !publicInstance

        /** [CopyKey.CARD_MOVED_UPDATE] for the baked public instance; null otherwise. */
        val sentence: CopyKey? get() = if (publicInstance) CopyKey.CARD_MOVED_UPDATE else null
    }

    /**
     * Connected to a typed server, signed out: create an account there when its mode allows, or sign in. This
     * device vouches for the origin: it passed the Trust Gate for it, now or earlier, or it signed its card 0.
     *
     * The heading is [instance], name and origin, marked [CopyKey.AS_THE_SERVER_NAMES_ITSELF] when
     * [InstanceLabel.selfNamed]. The design gives this screen no wording (§12.1); the keys below are reserved for it
     * ([CopyKey.reserved]).
     */
    class Server internal constructor(flow: EntryFlow, val instance: InstanceLabel, val signup: SignupStatus) : EntryScreen(flow) {
        /** The first button, [EntryApi.createAccountHere]: offered while [notTaking] is null. */
        val createAccountLabel: CopyKey get() = CopyKey.SERVER_CREATE_ACCOUNT

        /** The second button, [EntryApi.signInHere]: always offered. */
        val signInLabel: CopyKey get() = CopyKey.SERVER_SIGN_IN

        /**
         * What stands where the first button would be when the server takes no new account by email: closed first,
         * then full, then invitation-only. Null when it takes them, and while the mode is [JoinMode.NOT_KNOWN]
         * (the button stays, and [EntryApi.createAccountHere] asks the server).
         */
        val notTaking: CopyKey?
            get() = when {
                signup.mode == JoinMode.NOT_KNOWN || signup.takingAccounts -> null
                signup.mode == JoinMode.CLOSED || signup.full -> CopyKey.SERVER_NOT_TAKING_ACCOUNTS
                else -> CopyKey.SERVER_INVITATION_ONLY
            }

        /** After [CopyKey.SERVER_NOT_TAKING_ACCOUNTS]: [CopyKey.NOT_TAKING_CLOSED] or [CopyKey.NOT_TAKING_FULL]; null otherwise. */
        val notTakingWhy: CopyKey?
            get() = when {
                notTaking != CopyKey.SERVER_NOT_TAKING_ACCOUNTS -> null
                signup.mode == JoinMode.CLOSED -> CopyKey.NOT_TAKING_CLOSED
                else -> CopyKey.NOT_TAKING_FULL
            }
    }

    /**
     * A connect link opened without an account, on an instance that takes new accounts (§6.7): "Create an account on
     * … to connect with …". The link checked out in the order of §6.8: the offer is signed by the key the link's
     * fingerprint names, and the card chain contains the card the offer names. (The engine's
     * `RecipientStep.Confirm` with `needsAccount`, for a connect link.)
     */
    class JoinInvite internal constructor(
        flow: EntryFlow,
        /** The link's instance, from the card chain the offer anchors. */
        val instance: InstanceLabel,
        /** The creator's name as they chose it: "as they call themselves". Plain text. */
        val from: String,
    ) : EntryScreen(flow) {
        val headline: CopyLine get() = CopyLine.of(CopyKey.JOIN_TO_CONNECT, instance.name, from)
    }

    /**
     * The dead end of §6.7: a connect link opened without an account, on an instance that is not taking sign-ups.
     * (The engine's `RecipientStep.NotTakingAccounts`.)
     */
    class NotTakingAccounts internal constructor(
        flow: EntryFlow,
        val instance: InstanceLabel,
        /** The creator's name as they chose it. */
        val from: String,
        /** Why: invitation-only, closed or full. */
        val signup: SignupStatus,
    ) : EntryScreen(flow) {
        val headline: CopyLine get() = CopyLine.of(CopyKey.NOT_TAKING_ACCOUNTS, from, instance.name)

        /** The explanation that follows [headline]; null only while the mode is not known. */
        val whyNot: CopyLine?
            get() = when {
                signup.full -> CopyLine.of(CopyKey.NOT_TAKING_FULL)
                signup.mode == JoinMode.INVITATION_ONLY -> CopyLine.of(CopyKey.NOT_TAKING_INVITATION_ONLY, from)
                signup.mode == JoinMode.CLOSED -> CopyLine.of(CopyKey.NOT_TAKING_CLOSED)
                else -> null
            }
    }

    /** §7.2: the address a code is sent to, and "I am 13 or older" when [ageConfirmRequired]. */
    class SignUpEmail internal constructor(
        flow: EntryFlow,
        val instance: InstanceLabel,
        val ageConfirmRequired: Boolean,
        /** The person this account will connect with once it exists (a connect link); null otherwise. */
        val connectWith: String?,
        /** The proof of work is being computed (§7.5): show the progress note. */
        val provingWork: Boolean,
        /** While [provingWork]: how far it is, 0 to 100 (the engine's `signupStart` progress). 0 otherwise. */
        val workPercent: Int,
    ) : EntryScreen(flow)

    /**
     * §7.2: the six-digit code. The answer that led here is the same whether or not the address has an account
     * (G6), so this screen never says a code was sent to an account: show [CopyKey.EMAIL_CHECK_SPAM].
     */
    class SignUpCode internal constructor(
        flow: EntryFlow,
        val instance: InstanceLabel,
        /** The address as the person typed it. */
        val email: String,
        val connectWith: String?,
    ) : EntryScreen(flow) {
        /** The line above the code field (a placeholder key, [CopyKey.awaitingOwner]): true also for an address that already has an account. */
        val codeLine: CopyLine get() = CopyLine.of(CopyKey.SIGN_UP_CODE_LINE, email)
    }

    /**
     * §7.3: the form of a new account. It exists only once something authorises a registration on [instance]: a
     * verified address (the ticket stays inside core), or a register, enrol or setup link that checked out. The
     * password gate answers `proceed` for a registration through any pin (§4.4), so this is one of the screens a
     * password may be typed on.
     */
    class CreateAccount internal constructor(
        flow: EntryFlow,
        val via: RegistrationVia,
        val instance: InstanceLabel,
        /** The account's address when it is not the person's to choose (a verified address, or a bound enrol link). */
        val fixedEmail: String?,
        /** The person who sent the link, as they call themselves; this account and theirs are pinned to each other by it. */
        val invitedBy: String?,
        val ageConfirmRequired: Boolean,
        /**
         * The recovery choice (§7.7), or null when none is offered: the card names no recovery key, the instance
         * is public (variant R), or this is the operator account. Then only [CopyKey.RECOVERY_KIT_ONLY] is shown.
         */
        val recovery: RecoveryQuestion?,
        /**
         * What the form will register. It starts as [WhoCanRecover.ONLY_ME] and becomes
         * [WhoCanRecover.ME_OR_OPERATOR] only through [EntryApi.acceptOperatorRecovery].
         */
        val whoCanRecover: WhoCanRecover,
    ) : EntryScreen(flow)

    /** §7.7: the warning shown before operator recovery is chosen at sign-up. */
    class RecoveryWarning internal constructor(flow: EntryFlow, val warning: OperatorRecoveryWarning) : EntryScreen(flow)

    /**
     * The recovery kit, before the vault opens (§10): after a registration, after either recovery replaced the old
     * kit (FS-B1), at a sign-in that found the kit was never saved, and at an unlock that finds the same. There is
     * no way past it but [KitApi].
     */
    class Kit internal constructor(flow: EntryFlow, val kit: KitScreen) : EntryScreen(flow)

    /** §6.7 setup link, step 3: the first operator's app signs card 0, uploads it and pins it (desktop and CLI). */
    class ServerSetup internal constructor(
        flow: EntryFlow,
        val instance: InstanceLabel,
        val step: ServerSetupStep,
        /** [ServerSetupStep.FINISHED]: what "Instance details" shows, with the card 0 hash for the store builds (§14.1). */
        val details: InstanceDetails?,
    ) : EntryScreen(flow)

    /** "Already have an account? Sign in": the three ways in (§12.1). */
    class SignInChoice internal constructor() : EntryScreen(null)

    /** "Email and master password": the server choice first (the public instance, or your own behind the Trust Gate). */
    class SignInServer internal constructor(
        val purpose: ServerPurpose,
        /** This build has a baked public instance to offer (§0.3). */
        val offersPublicInstance: Boolean,
    ) : EntryScreen(null)

    /**
     * The password screen of a sign-in (§4.4). **Issued only for an origin this device holds a pin for that can be
     * a password pin for a sign-in**: a baked pin or one this device made through the Trust Gate, which count for
     * any account, or the setup pin of the operator account this device enrolled. A pin that came only from a link
     * offer, an enrol link or a kit shows [TrustGate] first.
     *
     * The address is typed on this screen, so the gate is asked a second time, with it, before anything is sent:
     * [EntryApi.submitSignIn] answers [SignInAnswer.TRUST_GATE_FIRST] and shows the gate when the pin does not serve
     * that account (a setup pin and any account but its own, FS-B1). So nothing typed here reaches an origin that
     * nothing vouches for, for the account it is typed for.
     */
    class SignIn internal constructor(
        flow: EntryFlow,
        /** Names the instance and its origin; the person types the address. */
        val prompt: MasterPasswordPrompt,
        /** The account has two-step sign-in: ask for the code too. */
        val codeNeeded: Boolean,
    ) : EntryScreen(flow)

    /**
     * §8.7: the account requires new devices to be linked, and this is not a device it knows. **Reached only from a
     * sign-in whose password, and any two-step code, the server verified** (FC-8): a wrong password answers
     * [SignInAnswer.WRONG] and never this, so the screen tells nobody without the password anything.
     *
     * The design gives this screen no wording (§8.7); [title] and [body] are reserved for it ([CopyKey.reserved]).
     * The first button is [CopyKey.SIGN_IN_LINK_DEVICE], which is [EntryApi.linkInstead]; the other is
     * [CopyKey.CANCEL], which is [EntryApi.back].
     */
    class LinkRequired internal constructor(flow: EntryFlow, val instance: InstanceLabel, val email: String) : EntryScreen(flow) {
        val title: CopyKey get() = CopyKey.LINK_REQUIRED_TITLE

        /** {0} the account, {1} the instance's name, {2} its origin. */
        val body: CopyLine get() = CopyLine.of(CopyKey.LINK_REQUIRED_BODY, email, instance.name, instance.origin)
    }

    /**
     * "Link from your other device": the scanner, and the paste field on desktop. **The only place a device link is
     * taken** (§8.2 step 0, T2-B1).
     */
    class LinkDeviceEntry internal constructor() : EntryScreen(null)

    /**
     * The link is claimed with this device's commitment; the other device has yet to answer. No code exists yet:
     * it is fixed only by the other device's nonce, which this device holds from here on (T2-R-b).
     */
    class LinkDeviceWaiting internal constructor(flow: EntryFlow, val instance: InstanceLabel) : EntryScreen(flow)

    /**
     * The six digits to show, for the person to type into the other device (§8.2 step 5). **This is the only state
     * that carries them, and it exists only after this device committed to its nonce, received the other device's,
     * and revealed.** Before that there is nothing a screen could show.
     */
    class LinkDeviceCode internal constructor(flow: EntryFlow, val instance: InstanceLabel, val code: String) : EntryScreen(flow)

    /**
     * §8.2 step 7: the master password of the account being linked. **Issued only after the other device approved,
     * this device opened the approval, found its origin equal to the origin it pinned before the claim, and checked
     * the approval's MAC** (FC-3). A server that made up an approval for an address of its choosing never gets here.
     */
    class LinkDevicePassword internal constructor(
        flow: EntryFlow,
        /** Names the account (from the approval), the instance and its origin. */
        val prompt: MasterPasswordPrompt,
        val codeNeeded: Boolean,
    ) : EntryScreen(flow)

    /** The link ended without linking this device. */
    class LinkDeviceEnded internal constructor(
        val outcome: LinkDeviceEnd,
        /**
         * The wait the server named where it refused a step as one of too many requests ([LinkDeviceEnd.TOO_MANY]), kept
         * with this end: what is left of it, and whether it is over. Null where the server named none, and for every other
         * end. Additive.
         */
        val wait: NamedWait? = null,
    ) : EntryScreen(null) {
        /**
         * The end's line as it stands now: [CopyKey.DEVICE_LINK_TOO_MANY_WAIT_OVER] once the wait the server named is over
         * (never "the server named no wait"); [LinkDeviceEnd.sentence] otherwise, whose {0} is [NamedWait.secondsLeft] while
         * the wait runs. Read it again as time passes.
         */
        fun lineNow(): CopyKey? =
            if (outcome == LinkDeviceEnd.TOO_MANY && wait?.over == true) CopyKey.DEVICE_LINK_TOO_MANY_WAIT_OVER else outcome.sentence
    }

    /** "Forgot your master password?": the kit, or the operator's help where a server offers it. */
    class Forgot internal constructor() : EntryScreen(null)

    /**
     * "Scan your recovery kit": its scanner, and a form for a kit typed by hand. **The only place a kit is taken**
     * (§10, FS-B1).
     *
     * - Scanned, or its `andvari-kit:2:` text pasted, which counts as a scan: [EntryApi.submitKit]. The kit's
     *   `card0Hash` pins the server (the kit root, §4.4).
     * - Typed by hand: the account's address, the server's address and the eleven groups
     *   ([EntryApi.submitTypedKit]). No `card0Hash` is typed, so the kit vouches for no server: the Trust Gate opens
     *   for the typed address first, unless this device already holds a pin that serves this recovery.
     */
    class KitEntry internal constructor() : EntryScreen(null)

    /**
     * §10: before anything is sent, the screen names the account and the server ([title]) and says that this sets a
     * new master password for that existing account. The instance is pinned from the kit's `card0Hash`, or the
     * person passed the Trust Gate for it (a kit typed by hand, or a kit from before the server's identity was
     * reset, whose gate carries that warning).
     */
    class KitRecover internal constructor(
        flow: EntryFlow,
        /** The address from the kit. */
        val email: String,
        val instance: InstanceLabel,
    ) : EntryScreen(flow) {
        val title: CopyLine get() = CopyLine.of(CopyKey.KIT_RECOVER, email, instance.name, instance.origin)

        /** §10, under [title]: this sets a new master password for that existing account (a placeholder key, [CopyKey.awaitingOwner]). */
        val setsPasswordLine: CopyLine get() = CopyLine.of(CopyKey.KIT_RECOVER_SETS_PASSWORD, email)
    }

    /**
     * A new master password. **It exists only after the kit was accepted by the server it names
     * ([EntryApi.confirmKitRecovery]), or after the person looked at the account an operator's help delivered and
     * chose to go on ([CheckAccount], [EntryApi.acceptRecoveredAccount]).**
     *
     * While this screen is up core holds what the recovery opened. Core runs no idle timer for it: an app that
     * leaves the screen unattended (the old wizard's five minutes) calls [EntryApi.startOver], which drops it all.
     */
    class ReplacePassword internal constructor(
        flow: EntryFlow,
        /**
         * The address the recovery was started with: the kit's, or the one typed on "Ask the operator". After an
         * operator's help the answer names the account's address inside the account's own signature, and this device
         * takes only an answer naming the address typed (the assisted-recovery change of 2026-11-16); [CheckAccount]
         * still shows the account ID, the check that does not rest on this server.
         */
        val email: String,
        val instance: InstanceLabel,
        val after: RecoveryRoute,
    ) : EntryScreen(flow)

    /**
     * §9.3 step 1: "Ask the operator for help". Show [CopyKey.ASK_OPERATOR_WHO_CAN].
     *
     * The way out through the mailbox (decided on 2026-11-17): below the address, the quiet line [mailboxValueLine]
     * opens the field ([EntryApi.openMailboxValue]); while [mailboxValueOpen] the field is shown, labelled
     * [mailboxValueField], and its text goes with [EntryApi.requestOperatorHelp]. The field stays hidden until the line
     * was opened. What the screen after the request says does not depend on whether a value was given. Additive.
     */
    class AskOperator internal constructor(
        flow: EntryFlow,
        val instance: InstanceLabel,
        val mailboxValueOpen: Boolean = false,
    ) : EntryScreen(flow) {
        /** The quiet line that opens the mailbox value's field. */
        val mailboxValueLine: CopyKey get() = CopyKey.ASSIST_MAILBOX_VALUE_LINE

        /** The field's label while it is open; null while it is hidden. */
        val mailboxValueField: CopyKey? get() = if (mailboxValueOpen) CopyKey.ASSIST_MAILBOX_VALUE_FIELD else null
    }

    /**
     * §9.3 step 4: the operator's answer arrived and passed every check: it is signed by the recovery key this
     * device's pinned card names, it is for this request, it names the address the person typed inside the account's
     * own signature (the assisted-recovery change of 2026-11-16), and it opens the account's identity. A server that is
     * itself the attacker can still mint an identity and a copy naming that address, and a
     * fresh install holds no account to compare with. So the person checks: the screen shows [accountId] with
     * [compareLine] (the kit first: the emails come from this server), and no new password can be set until
     * [EntryApi.acceptRecoveredAccount] was taken twice, the second time on the [confirming] step. This screen is the
     * only way to [ReplacePassword] after an operator's help.
     *
     * Three choices: it is the same ([EntryApi.acceptRecoveredAccount]; [CopyKey.GATE_ITS_THE_SAME] is that wording
     * elsewhere), it is different ([EntryApi.rejectRecoveredAccount], which drops a request that took seven days,
     * for good), and a quiet "not now" ([EntryApi.recoveredAccountNotNow], which keeps it).
     *
     * GAP (§9.3 step 4): the design names none of the buttons.
     */
    class CheckAccount internal constructor(
        flow: EntryFlow,
        val instance: InstanceLabel,
        /** The address the person asked with. Nothing here says the delivered account is that address's. */
        val email: String,
        /** The delivered account's ID: its identity fingerprint's short form, 32 hex, as on a kit and in every notice (§11.2). */
        val accountId: String,
        /**
         * [EntryApi.acceptRecoveredAccount] on this screen does not go on yet: it shows this
         * screen again with [confirming] true, so the comparison's sentence is on screen before the second tap goes on.
         * Additive.
         */
        val confirming: Boolean = false,
        /**
         * The server's recovery key changed under the request, by rotations its old key signed ([AssistKeyChange.byOldKey]):
         * show [AssistKeyChange.line] on this screen too. Null otherwise (an unsigned change never reaches this screen).
         * Additive.
         */
        val keyChange: AssistKeyChange? = null,
    ) : EntryScreen(flow) {
        /**
         * What to say with [accountId]: compare it with the kit first; an email is the weaker source, as this server
         * sent it. Show it on this screen in both steps.
         */
        val compareLine: CopyKey get() = CopyKey.RECOVERY_CHECK_ACCOUNT_KIT

        /** The second step's line, while [confirming]. */
        val confirmLine: CopyKey? get() = if (confirming) CopyKey.RECOVERY_CHECK_ACCOUNT_CONFIRM else null
    }

    /** §9.3: a request for the operator's help, from the emailed code to the operator's answer. */
    class OperatorHelp internal constructor(
        flow: EntryFlow,
        val instance: InstanceLabel,
        val email: String,
        val stage: OperatorHelpStage,
        /**
         * The request code: six groups of four, for the person to read to the operator ([CopyKey.REQUEST_CODE_READ_OUT]).
         * It is made from this device's own request key, so a server cannot choose it.
         */
        val requestCode: List<String>,
        /** [OperatorHelpStage.HOLDING]: when the 7-day hold ends, unix milliseconds as the server said; 0 otherwise. */
        val holdEndsAtMs: Long,
        /**
         * [CopyKey.ASSIST_ANSWER_REPLACED] when the answer on the server turned out not to be the one this device opened
         * ([ReplacePasswordResult.ANSWER_REPLACED]): the request is kept, the operator uploads it again. Null otherwise.
         * Additive.
         */
        val answerReplaced: CopyKey? = null,
        /**
         * The server's recovery key is not the one the request was made under. Null while it is.
         * - [AssistKeyChange.byOldKey]: verified rotations, each signed by the outgoing key, cover the change. The request
         *   goes on under the new key; show [AssistKeyChange.line] with the stage.
         * - Not signed: the request is stopped at every look and nothing of an answer is opened, but it is kept. Show
         *   the warning ([AssistKeyChange.warningTitle], [AssistKeyChange.warningBody]) in place of the stage's own line,
         *   with [AssistKeyChange.stop] (the default: [EntryApi.abandonOperatorHelp]) and [AssistKeyChange.keepWaiting]
         *   (nothing is sent; the screen stays, and [EntryApi.refreshOperatorHelp] looks again later: a change the old
         *   key signs, served later, lets the request go on).
         * Additive.
         */
        val keyChange: AssistKeyChange? = null,
        /**
         * [CopyKey.ASSIST_REQUEST_UNKNOWN] when the server answered that it no longer knows this request:
         * this device keeps it until its own lifetime ends (a server can lose a row, or lie), never as expired.
         * Show it in place of the stage's own line, with [CopyKey.ASSIST_REQUEST_UNKNOWN_WAIT] (the screen stays;
         * [EntryApi.refreshOperatorHelp] asks again) and [CopyKey.ASSIST_REQUEST_UNKNOWN_START_AGAIN]
         * ([EntryApi.abandonOperatorHelp], then a new request). Null otherwise. Additive.
         */
        val requestUnknown: CopyKey? = null,
        /**
         * Spec 01 §7: [CopyKey.SIGN_IN_SERVER_KEYS_NOT_KNOWN_HERE] when the operator's answer delivered a key that is not
         * this account's as this device knows it (this device keeps the account, and the key does not open its copy's
         * sealed identity seed). Nothing was committed and nothing kept was replaced; the request is kept, and every
         * look stops here again until this device no longer keeps that copy. Show it in place of the stage's own line.
         * Null otherwise. Additive.
         */
        val keysNotKnownHere: CopyKey? = null,
        /**
         * [CopyKey.ASSIST_ANOTHER_ACCOUNT_KEPT] when the operator's answer arrived (or its commit was about to go) while this
         * device keeps another account, whose session the recovery's would not replace: nothing was opened for the person,
         * nothing committed, and the request is KEPT; once that account is signed out, [EntryApi.refreshOperatorHelp] picks
         * the answer up again. Show it in place of the stage's own line. Null otherwise. Additive.
         */
        val anotherAccountKept: CopyKey? = null,
        /**
         * [CopyKey.IDENTITY_FAULT_ADDRESS_KNOWN] when the operator's answer is for an account this device knows under
         * another account or key for the address (the identity fault a sign-in has): nothing was opened or committed and the
         * request is kept. Show it in place of the stage's own line. Null otherwise. Additive.
         */
        val identityFault: CopyKey? = null,
        /**
         * [CopyKey.OPERATOR_ACCOUNT_HELD_HERE] when this device holds its server's operator account (the keeper's own
         * reason): nothing was opened or committed and the request is kept. The way out is to remove that account from this
         * device ([AppSnapshot.heldOperator]'s removal), never a sign-out. Show it in place of the stage's own line. Null
         * otherwise. Additive.
         */
        val operatorAccountHeld: CopyKey? = null,
        /**
         * [CopyKey.KEPT_COPY_DAMAGED] when this device's copy of the account is damaged (the keeper's own reason): nothing
         * was opened or committed and the request is kept. The way out is to remove this device's copy (its sign-out, which
         * says first how many changes were not sent, or that it cannot tell), then look again. Show it in place of the stage's
         * own line. Null otherwise. Additive.
         */
        val keptCopyDamaged: CopyKey? = null,
        /**
         * [CopyKey.ASSIST_NOT_THE_KEPT_ACCOUNT] when the operator's answer names an account that is not the one this device
         * keeps for the address: nothing was shown to check, opened or committed, and the request stays as it is. Never
         * offers a sign-out: the person tells whoever runs the server. Show it in place of the stage's own line. Null
         * otherwise. Additive.
         */
        val notTheKeptAccount: CopyKey? = null,
    ) : EntryScreen(flow) {
        /**
         * The way out of the stop on show (one cause, one way out): the removal of this device's copy for [keysNotKnownHere]
         * and [keptCopyDamaged] (what stands in the way is this device's own copy of the account, never "another account"),
         * the kept account's sign-out for [anotherAccountKept], the held operator account's removal for
         * [operatorAccountHeld]; null for every other stage, the identity fault and [notTheKeptAccount]. Additive.
         */
        val wayOut: KeptWayOut?
            get() = when {
                keysNotKnownHere != null || keptCopyDamaged != null -> KeptWayOut.REMOVE_THIS_COPY
                anotherAccountKept != null -> KeptWayOut.SIGN_OUT_KEPT_ACCOUNT
                operatorAccountHeld != null -> KeptWayOut.REMOVE_HELD_OPERATOR_ACCOUNT
                else -> null
            }

        /**
         * The line for a request the server says is over from the account's side or its operator's
         * ([OperatorHelpStage.VETOED]): [CopyKey.ASSIST_REQUEST_ENDED], said in place of the stage's own line, true of every
         * cause the device cannot tell apart (a signed-in device refused it, the master password or recovery setting changed,
         * or whoever runs the server ended it). Nothing is left to wait for; a new request can be made. Null at every other
         * stage (an expired request and an answer that did not check out keep the apps' own lines). Additive.
         */
        val endedLine: CopyKey? get() = if (stage == OperatorHelpStage.VETOED) CopyKey.ASSIST_REQUEST_ENDED else null
    }
}

/**
 * A change of the server's recovery key seen for a request this device keeps ([EntryScreen.OperatorHelp.keyChange],
 * [EntryScreen.CheckAccount.keyChange]): the engine's `RecoveryKeyChange`, as a screen words it.
 */
class AssistKeyChange internal constructor(
    /** The server, as this device's pin names it. */
    val instance: InstanceLabel,
    /** Every step of the change is covered by a statement the outgoing key signed, verified on this device. */
    val byOldKey: Boolean,
    /** [byOldKey]: when the operator signed the newest such statement, unix milliseconds (the operator's own time); 0 otherwise. */
    val rotatedAtMs: Long,
) {
    /** [byOldKey]: the line beside the stage and on the account check; {0} is the date the app formats from [rotatedAtMs]. Null otherwise. */
    val line: CopyKey? get() = if (byOldKey) CopyKey.ASSIST_RECOVERY_KEY_ROTATED else null

    /** Not [byOldKey]: the warning's title, in spec 04 §5's approved words. Null otherwise. */
    val warningTitle: CopyLine? get() = if (byOldKey) null else CopyLine.of(CopyKey.RECOVERY_KEY_CHANGED_TITLE, instance.name, instance.origin)

    /** Not [byOldKey]: what the warning says under its title. Null otherwise. */
    val warningBody: CopyKey? get() = if (byOldKey) null else CopyKey.ASSIST_RECOVERY_KEY_CHANGED_BODY

    /** The default button of the warning: [EntryApi.abandonOperatorHelp]. */
    val stop: CopyKey get() = CopyKey.ASSIST_KEY_CHANGED_STOP

    /** The warning's second button: nothing is sent, the request stays kept and stopped until a signed change is served. */
    val keepWaiting: CopyKey get() = CopyKey.ASSIST_KEY_CHANGED_KEEP_WAITING
}

/** What a recovery's commit came to, for a person who left before its answer arrived ([LateRecoveryNotice]). */
enum class LateRecoveryResult {
    /** The server took it: the new password is in force, the old kit is dead, and the next sign-in makes a new kit. */
    RESET,

    /** The server refused it: the password is unchanged. */
    REFUSED,

    /** No usable answer: the reset may or may not have gone through. */
    UNKNOWN,
}

/**
 * The first screen's notice for a recovery the person left after its new password was sent ([EntryScreen.FirstRun.lateRecovery]):
 * the answer arrived after the leave, and nothing of it was used (no session opened, nothing kept). Published once by the
 * engine; shown until [EntryApi.dismissNotice] takes it away.
 */
class LateRecoveryNotice internal constructor(
    /** The address the recovery was for. */
    val email: String,
    /** The server, as this device's pin names it. */
    val instance: InstanceLabel,
    /** The kit, or the operator's help. */
    val via: RecoveryRoute,
    val result: LateRecoveryResult,
) {
    /** {0} the address, {1} the server's name, {2} its address. */
    val line: CopyLine
        get() = CopyLine.of(
            when (result) {
                LateRecoveryResult.RESET -> CopyKey.LATE_RECOVERY_RESET
                LateRecoveryResult.REFUSED -> CopyKey.LATE_RECOVERY_REFUSED
                LateRecoveryResult.UNKNOWN -> CopyKey.LATE_RECOVERY_UNKNOWN
            },
            email, instance.name, instance.origin,
        )
}

/**
 * What core keeps for the flow a screen belongs to: the server the screen's intents act on, and what the flow's
 * steps have gathered so far (an opened link, a verified address, keys that wait for a two-step code). A screen is
 * given its flow when it is made ([EntryScreen.flow]) and no intent reads any other, so there is no "current
 * server" for a screen to be out of step with. Each implementation of [AppApi] has its own kind of flow; a UI never
 * sees one.
 */
internal abstract class EntryFlow {
    /** The origin this flow's screens act on. */
    abstract val origin: String
}

/** What [EntryScreen.FirstRun] says once, after a journey that ended by itself. */
enum class FirstRunNotice {
    /**
     * The person said the account an operator's help delivered is not theirs ([EntryApi.rejectRecoveredAccount]):
     * andvari stopped, no password was set, and the request is gone from this device.
     *
     * GAP (§9.3 step 4): the design gives no wording for it.
     */
    RECOVERY_STOPPED,

    /**
     * The server ended this device's session (the device was revoked, the password was changed or recovered on
     * another device, or the account was disabled): the app is signed out.
     *
     * GAP (§7.8): the design gives no wording for it.
     */
    SIGNED_OUT_BY_SERVER,

    /**
     * The newest verified card of the session's server names the signed-in account as its operator (a handover made
     * this account the operator), and this is a phone, which must not hold the operator account (§12.2 rule 7, §9.1).
     * The app signed it out; nothing of the account is kept on this device. It needs no signal from the server, and it
     * is checked at every opening of the vault, a quick unlock included, and after every check of the card. The unlock
     * that finds it answers DONE (the password or the key was right); the snapshot is then this first screen.
     *
     * GAP (§12.2 rule 7): "the same sentence" as the operator refusal at sign-in
     * ([SignInAnswer.OPERATOR_NEEDS_COMPUTER]), which has no wording yet.
     */
    OPERATOR_NEEDS_COMPUTER,
}

/**
 * The first screen's notice after the person deleted their account on this device ([EntryScreen.FirstRun.accountDeleted]):
 * the server answered that the account is deleted, and everything this device held for it is gone. Show [line] once,
 * as a notice (not an error), with a dismiss ([EntryApi.dismissNotice]).
 */
class AccountDeletedNotice internal constructor(
    /** The deleted account's address. */
    val email: String,
    /** The server it was deleted from, as this device's pin names it. */
    val instance: InstanceLabel,
    /**
     * The server was forgotten with the account. False where this device holds another account's copy at that server:
     * only the deleted account's records went, and the server stays known with that account. Additive.
     */
    val serverForgotten: Boolean = true,
) {
    /** What went: the server with the account ([CopyKey.ACCOUNT_DELETED_SERVER_FORGOTTEN]), or the account only ([CopyKey.ACCOUNT_DELETED_SERVER_KEPT]). */
    val line: CopyLine get() = CopyLine.of(
        if (serverForgotten) CopyKey.ACCOUNT_DELETED_SERVER_FORGOTTEN else CopyKey.ACCOUNT_DELETED_SERVER_KEPT, email, instance.name, instance.origin,
    )
}

/**
 * After a deletion whose outcome is not known ([DeletionScreen.outcomeUnknown], [LockedScreen.deletionOutcomeUnknown],
 * [EntryScreen.FirstRun.deletionOutcomeUnknown]): the offer to forget that account on this device, read from
 * [AppApi.forgetAfterUnknownDeletionCheck]. Show [offerLine] as the offer; on its tap show [confirmLine] as a confirmation,
 * and only on the person's own confirmation call [AppApi.forgetAfterUnknownDeletion] with this object. The account's
 * session record, keys, identity record and this device's copy go; the server's pin stays. Nothing is sent but the end
 * of that session at its server. Additive.
 */
class ForgetUnknownDeletion internal constructor(
    /** The account's address. */
    val email: String,
    /** Its server, as this device's pin names it (the address alone where no card is readable). */
    val instance: InstanceLabel,
    internal val origin: String,
    internal val userId: String,
    /**
     * The account's changes made here and not sent, which go with it, counted as a sign-out counts them, with its signed
     * changes to shared vaults; null: this device cannot tell. Additive.
     */
    val unsentChanges: Int? = null,
) {
    val offerLine: CopyLine get() = CopyLine.of(CopyKey.DELETION_UNKNOWN_FORGET_OFFER)
    val confirmLine: CopyLine get() = CopyLine.of(CopyKey.DELETION_UNKNOWN_FORGET_CONFIRM, email, instance.name, instance.origin)

    /** Below [confirmLine]: how many changes not sent go ({0}), that none does, or that this device cannot tell. Additive. */
    val unsentLine: CopyLine get() = when (val n = unsentChanges) {
        null -> CopyLine.of(CopyKey.DELETION_UNKNOWN_FORGET_UNSENT_CANNOT_TELL)
        0 -> CopyLine.of(CopyKey.DELETION_UNKNOWN_FORGET_ALL_SENT)
        1 -> CopyLine.of(CopyKey.DELETION_UNKNOWN_FORGET_ONE_UNSENT)
        else -> CopyLine.of(CopyKey.DELETION_UNKNOWN_FORGET_UNSENT, n.toString())
    }
}

/**
 * The first screen's notice for a deletion whose outcome is unknown ([EntryScreen.FirstRun.deletionOutcomeUnknown]): the
 * deletion was sent from this device and no answer came, and the server then ended the session (the likely sign that
 * it landed, but not a proof). Show [line] once, as a notice (not an error), with a dismiss ([EntryApi.dismissNotice]).
 * Signing in again tells: the account is there, or the sign-in is refused as for an address with no account.
 */
class DeletionOutcomeUnknownNotice internal constructor(
    /** The account's address. */
    val email: String,
    /** Its server, as this device's pin names it. */
    val instance: InstanceLabel,
) {
    val line: CopyLine get() = CopyLine.of(CopyKey.ACCOUNT_DELETION_UNKNOWN, email, instance.name, instance.origin)
}

/**
 * An account this phone holds, stopped and locked, because a card it verified names it as its server's operator
 * ([EntryScreen.FirstRun.heldAsOperator]). [line] says so; [removeLine] is the confirmation before
 * [EntryApi.removeHeldOperatorAccount], which says what is lost.
 */
class HeldOperatorAccount internal constructor(
    /** The account's address. */
    val email: String,
    /** Its server, as this device's pin names it (the address twice when no card can be read). */
    val instance: InstanceLabel,
    /**
     * The changes made here and not sent, counted when the account was stopped while its vault was open; null when this
     * device could not count them (it was stopped while locked, and counting would need the vault opened).
     */
    val unsentChanges: Int?,
) {
    val line: CopyLine get() = CopyLine.of(CopyKey.OPERATOR_HELD_ON_PHONE, email, instance.name, instance.origin)
    val removeLine: CopyLine
        get() = if (unsentChanges == null) CopyLine.of(CopyKey.OPERATOR_HELD_REMOVE_UNKNOWN, email)
        else CopyLine.of(CopyKey.OPERATOR_HELD_REMOVE_LOSES, email, unsentChanges.toString())
}

/** What was being opened when a server's card named another address ([EntryScreen.AddressMismatch]). */
enum class AddressMismatchFor {
    /** An address typed under "Use your own server" or at the server choice of a sign-in, or the public instance chosen there. */
    TYPED_ADDRESS,

    /** A device link scanned on "Link from your other device". */
    DEVICE_LINK,

    /** A recovery kit scanned on "Scan your recovery kit". */
    KIT,

    /** A recovery kit typed by hand there, with its server's address. */
    TYPED_KIT,

    /**
     * An invite (a connect, register, enrol or setup link) opened signed out: the link's server served a card made for
     * another address (the engine's `RecipientStep.OriginMismatch`). Never redirected: the link names its address, so
     * the person asks the one who sent it for a new one.
     */
    INVITE,
}

/**
 * What an instance says about new accounts (§7.1 `signup`): a hint for the screen. The server enforces. It is the
 * engine's `SignupOffer`, with the mode typed.
 */
class SignupStatus internal constructor(
    val mode: JoinMode,
    /** The cap is reached. */
    val full: Boolean,
    /** Sign-up shows "I am 13 or older", and it must be ticked. */
    val ageConfirmRequired: Boolean,
    /** Sign-up computes a proof of work first (§7.5). */
    val proofOfWork: Boolean,
) {
    /** An account can be created with a verified address now. */
    val takingAccounts: Boolean get() = mode == JoinMode.ANYONE && !full
}

/** §7.1 `ANDVARI_SIGNUP_MODE`, as in force: the wire's `SignupMode` values, typed. */
enum class JoinMode {
    /** `open`: email-verified sign-up, plus links. */
    ANYONE,

    /** `links`: register links only. */
    INVITATION_ONLY,

    /** `closed`: sign-in only. */
    CLOSED,

    /**
     * The server has not answered yet, or could not be reached. **It is never presented as closed**: a screen that
     * offers sign-up keeps offering it, and the intent behind the button ([EntryApi.createAccountOnAndvari],
     * [EntryApi.createAccountHere]) asks the server and answers with the mode it says
     * ([ServerResult.NOT_TAKING_ACCOUNTS], with the screen republished, when it takes none). Core itself sends
     * nothing on a guess: every route that creates an account is refused by the server when the mode forbids it.
     */
    NOT_KNOWN,
}

/** What authorises the registration a [EntryScreen.CreateAccount] form is for (§7.3 `auth`). */
enum class RegistrationVia {
    /** A verified address (`signupTicket`), with nobody to connect with. */
    EMAIL_CODE,

    /** A verified address, and a connect link whose answer is posted right after (§6.7). */
    CONNECT_LINK,

    /** A register link (`auth.link`): no email code, and the two accounts are pinned to each other in one step. */
    INVITATION_LINK,

    /** A host-minted enrol link (`auth.enrol`): no email code, and nobody is pinned. */
    ENROLMENT_LINK,

    /** A setup link (`auth.setup`): the account becomes the instance's operator. Desktop and CLI only. */
    SETUP_LINK,
}

/** §4.5 `posture`, typed: the wire's `RecoveryPosture` values. */
enum class WhoCanRecover {
    /** `private`: the person's own kit only. */
    ONLY_ME,

    /** `operator`: the kit, and an escrow the instance's recovery key can open. */
    ME_OR_OPERATOR,
}

/** What the server choice of a sign-in is for. */
enum class ServerPurpose { SIGN_IN, ASK_OPERATOR }

enum class ServerSetupStep {
    /** Card 0 is being signed and uploaded. */
    SIGNING,

    /**
     * It could not be uploaded: [EntryApi.retryServerSetup]. The account exists, so a later sign-in offers to finish
     * ([OperatorConsole.setupUnfinished], [OperatorApi.finishServerSetup]; §6.7 Resume).
     */
    NOT_UPLOADED,
    FINISHED,
}

/** Which recovery led to a new master password. */
enum class RecoveryRoute { KIT, OPERATOR_HELP }

/**
 * How a device link ended on the new device: the engine's `NewStep.Stopped` reasons, grouped by what the person is
 * told. Nothing was linked in any of them.
 */
enum class LinkDeviceEnd(val sentence: CopyKey?) {
    /** Cancelled on the other device, by a wrong code typed there, or by a newer link (§8.2). */
    CANCELLED(CopyKey.DEVICE_LINK_CANCELLED),

    /** One of the link's five-minute steps ran out. */
    EXPIRED(null),

    /** Someone else claimed the link first (T12). */
    ALREADY_CLAIMED(null),

    /** §8.2 step 8: the bundle disagreed with the pin made before the claim. This device signed out and dropped that pin. */
    WRONG_SERVER(CopyKey.DEVICE_LINK_WRONG_SERVER),

    /** A check failed (a MAC, a changed nonce, an approval for another origin, a bundle that does not open). Any session was signed out at once. */
    DID_NOT_CHECK_OUT(null),

    /**
     * The server did not answer the pickup (§8.2 step 7). The link is spent on this device: nothing was linked and no
     * session was kept; start a new link from the other device. GAP: the design gives no wording.
     */
    NO_ANSWER(null),

    /**
     * Spec 01 §7: this device keeps the linked account, and the key the server's copy opened with the typed password is
     * not that account's key as this device knows it. The session the pickup opened was ended alone, at its server, and
     * nothing kept was replaced: the sign-in's own sentence. Additive.
     */
    SERVER_KEYS_NOT_KNOWN_HERE(CopyKey.SIGN_IN_SERVER_KEYS_NOT_KNOWN_HERE),

    /**
     * This device keeps another account's session, and that session is not given up for the link: the session the
     * pickup opened was ended alone, at its server, and nothing of the link was used. Additive.
     */
    ANOTHER_SESSION_KEPT(CopyKey.DEVICE_LINK_ANOTHER_SESSION_KEPT),

    /**
     * §5.2: the link's account is known on this device under another account or key (the identity fault a sign-in has).
     * Nothing was linked, nothing kept was replaced, and any session the pickup opened was ended alone. Additive.
     */
    IDENTITY_FAULT(CopyKey.IDENTITY_FAULT_ADDRESS_KNOWN),

    /**
     * As [IDENTITY_FAULT], at the link's approval, where this device holds a record of the link's account's key and so cannot
     * tell from the link alone a remade account from a substitution: no offer is made, and the line points to a sign-in
     * with the master password, which can tell. Additive.
     */
    IDENTITY_FAULT_CANNOT_TELL(CopyKey.DEVICE_LINK_IDENTITY_CANNOT_TELL),

    /** This device holds its server's operator account (the keeper's own reason): remove it from this device first. Additive. */
    OPERATOR_ACCOUNT_HELD(CopyKey.OPERATOR_ACCOUNT_HELD_HERE),

    /**
     * This device's copy of the account is damaged (the keeper's own reason): remove it (its sign-out says first how many
     * changes were not sent, or that it cannot tell), then sign in or recover. Additive.
     */
    KEPT_COPY_DAMAGED(CopyKey.KEPT_COPY_DAMAGED),

    /** The link stopped after the two-step code was sent: the server did not take it. Start again with a new link. Additive. */
    REFUSED_AFTER_CODE(CopyKey.DEVICE_LINK_REFUSED_AFTER_CODE),

    /**
     * The server refused a step of the link that cannot wait as one of too many requests: the link stopped there and
     * nothing was linked. Never "unreachable": the server answered. The wait it named, when it named one, is
     * [AppApi.retryAfterSeconds] (the line's {0}). Additive.
     */
    TOO_MANY(CopyKey.DEVICE_LINK_TOO_MANY),
}

/**
 * A wait the server named (`Retry-After`) at the end of a device link it refused as one of too many requests, kept with that
 * end: the moment it runs out is fixed when the end comes, on the clock [AppApi.retryAfterSeconds] counts on (one the person
 * cannot set), so a later refusal elsewhere does not change it and a wait that ran out is said as over, never as none.
 */
class NamedWait internal constructor(private val endsAtMs: Long, private val clock: () -> Long) {
    /** Seconds left of the wait, rounded up; 0 once it is over. */
    fun secondsLeft(): Int {
        val now = clock()
        return if (endsAtMs <= now) 0 else ((endsAtMs - now + 999) / 1000).toInt()
    }

    /** The wait the server named has run out. */
    val over: Boolean get() = secondsLeft() == 0
}

/** §9.3, as the poll reports it. */
enum class OperatorHelpStage {
    /** `unverified`: the emailed code is still to be typed. An address without operator recovery never gets one, and nothing here says so. */
    CODE_NEEDED,

    /** `holding`: the 7 days during which the account's devices can cancel. */
    HOLDING,

    /** `awaiting_operator`: the hold is over; the operator has yet to act. */
    AWAITING_OPERATOR,

    /**
     * `vetoed`: a signed-in device of the account cancelled it, the server ended it because the account's master password
     * or recovery setting changed, or whoever runs the server ended it. The device is told only the state:
     * [EntryScreen.OperatorHelp.endedLine] is true of every cause.
     */
    VETOED,
    EXPIRED,

    /** The operator's answer was not signed by the recovery key this device's pinned card names, or did not match the request. Nothing was applied. */
    DID_NOT_CHECK_OUT,
}

/**
 * What a Trust Gate shows (§4.4, §12.3). The address was checked against the origin grammar before the gate opened
 * (R4). It is the engine's `FirstPin.NeedsTrustGate`, whose ticket stays inside core: confirming pins exactly the
 * chain this prompt was made from.
 *
 * [wording] is the engine's [TrustGateWording], so each wording is its own value and no screen can show one for
 * another: `TYPED_ADDRESS` and `ENROL_LINK` (the typed-address wording; an enrol link passes the same gate),
 * `DEVICE_LINK`, `LINK_OFFER_SIGN_IN` (signing in where the only pin is not a password pin), and `KIND_CHANGE`.
 */
class TrustGatePrompt internal constructor(
    val wording: TrustGateWording,
    /** The exact origin the app will use. */
    val origin: String,
    /**
     * What the server calls itself, from the card it serves. Except in `KIND_CHANGE`, where the card continues this
     * device's pin, nobody vouches for it: it is not an [InstanceLabel], and it is shown only inside the gate's own
     * sentence.
     */
    val name: String,
    /** The operator key's short form, 32 hex, for anyone who wants to check (§4.4). */
    val operatorKeyShort: String,
    /** A server is already set on this device: the title asks about switching. */
    val switching: Boolean,
    /** The name is internationalised and shown in its `xn--` form: say so, since it can imitate another. */
    val punycodeCaution: Boolean,
    /** Plain http (a loopback address, for development): say so. */
    val httpCaution: Boolean,
    /**
     * The gate stands in for a kit whose `card0Hash` no longer matches the served chain (§4.4; the engine's
     * `FirstPin.KitAnchorMismatch`): [lines] start with [CopyKey.GATE_KIT_IDENTITY_CHANGED]. A pin this device
     * already holds for the server does not spare the person this gate: the kit vouched for another identity.
     */
    val kitIdentityChanged: Boolean,
    /**
     * The gate was raised for a kit typed by hand ([EntryApi.submitTypedKit]): the address on show is the one the
     * person read off their kit. Its wording is the owner's approved entry 9: [title] is [CopyKey.GATE_TITLE_KIT_TYPED],
     * [lines] is [CopyKey.GATE_KIT_TYPED_BODY], and the confirm button is [CopyKey.GATE_ITS_THE_SAME].
     */
    val typedKit: Boolean,
    /** `KIND_CHANGE`: what the server now says it is; null in every other wording. */
    val claimedKind: ServerKind?,
) {
    /**
     * The title.
     *
     * GAP (§12.3): the design gives no title for the `kind`-change gate; null there.
     */
    val title: CopyLine?
        get() = when {
            typedKit && wording == TrustGateWording.TYPED_ADDRESS -> CopyLine.of(CopyKey.GATE_TITLE_KIT_TYPED)
            else -> titleOf(wording)
        }

    private fun titleOf(wording: TrustGateWording): CopyLine? =
        when (wording) {
            TrustGateWording.DEVICE_LINK -> CopyLine.of(CopyKey.GATE_TITLE_DEVICE_LINK)
            TrustGateWording.KIND_CHANGE -> null
            TrustGateWording.TYPED_ADDRESS, TrustGateWording.ENROL_LINK, TrustGateWording.LINK_OFFER_SIGN_IN ->
                CopyLine.of(if (switching) CopyKey.GATE_TITLE_SWITCH else CopyKey.GATE_TITLE_CONNECT)
        }

    /** The body's sentences, in order. The cautions and [operatorKeyShort] are shown beside them. */
    val lines: List<CopyLine>
        get() {
            val callsItself = CopyLine.of(CopyKey.GATE_CALLS_ITSELF, name)
            val baseline = CopyLine.of(CopyKey.GATE_BASELINE)
            val body = when (wording) {
                TrustGateWording.TYPED_ADDRESS -> if (typedKit) listOf(CopyLine.of(CopyKey.GATE_KIT_TYPED_BODY, origin, name)) else listOf(baseline, callsItself)
                TrustGateWording.ENROL_LINK -> listOf(baseline, callsItself)
                TrustGateWording.LINK_OFFER_SIGN_IN -> listOf(baseline, callsItself, CopyLine.of(CopyKey.GATE_ENTERING_PASSWORD))
                TrustGateWording.DEVICE_LINK -> listOf(CopyLine.of(CopyKey.GATE_DEVICE_LINK_BODY, origin, name))
                TrustGateWording.KIND_CHANGE -> listOf(
                    CopyLine.of(CopyKey.GATE_KIND_CHANGE, name, origin, if (claimedKind == ServerKind.PUBLIC_SERVER) "public" else "private"),
                )
            }
            return if (kitIdentityChanged) listOf(CopyLine.of(CopyKey.GATE_KIT_IDENTITY_CHANGED)) + body else body
        }

    /** The confirm button, where the design names it: "It's the same" in the device-link wording and for a typed kit (entry 9). */
    val confirmLabel: CopyKey?
        get() = if (wording == TrustGateWording.DEVICE_LINK || (typedKit && wording == TrustGateWording.TYPED_ADDRESS)) CopyKey.GATE_ITS_THE_SAME else null
}

/**
 * What a screen that asks for an existing account's master password must name (§4.4): the account, the instance and
 * its origin.
 */
class MasterPasswordPrompt internal constructor(
    /** The account, when the flow knows it (a device link's approval, a kit); null when the person types it (sign-in). */
    val email: String?,
    val instance: InstanceLabel,
    /**
     * Where this prompt shows a session kept on this device ([LockedScreen.prompt], [AppSnapshot.keptSignedOut]): an
     * opaque mark of that kept copy. It is the same for as long as the same copy is kept, also across a restart, and
     * changes whenever another is taken (another account, or the same account taken again). Compare it with
     * [KitWipedNotice.namedKept] only for equality; never show it. Empty where the prompt shows no kept session. Additive.
     */
    val keptMark: String = "",
) {
    /** [CopyKey.MASTER_PASSWORD_FOR] for [email]; null while the person has yet to type the address. */
    val title: CopyLine? get() = email?.let { titleFor(it) }

    /** [CopyKey.MASTER_PASSWORD_FOR] for the address [typedEmail], as the person typed it on this screen. */
    fun titleFor(typedEmail: String): CopyLine = CopyLine.of(CopyKey.MASTER_PASSWORD_FOR, typedEmail, instance.name, instance.origin)
}

/** What the person typed into a [EntryScreen.CreateAccount] form. Not a data class: no `toString` of the password. */
class NewAccountInput(
    /** Ignored when the form's address is fixed. */
    val email: String,
    val displayName: String,
    val password: String,
    /** "I am 13 or older" is ticked. */
    val ageConfirmed: Boolean,
)

/** The signed-out journey's intents. See [EntryScreen] for what each screen is and when it exists. */
interface EntryApi {
    /**
     * Leave the screen on show for the one before it. Nothing is sent. False when there is no way back: the kit
     * before the vault opens, a server's setup that is being finished, and a device link from its claim on
     * ([EntryScreen.LinkDeviceWaiting], [EntryScreen.LinkDeviceCode], [EntryScreen.LinkDevicePassword]): a claimed link
     * is left only by [startOver], which gives it up.
     *
     * The screen it returns to acts on its own server, as when it was first shown, whatever was opened since.
     */
    fun back(): Boolean

    /**
     * Abandon the journey and return to the first screen. A device link this device claimed is given up (the other
     * device sees it end); nothing else is sent. It does nothing on the kit before the vault opens or during a
     * server's setup.
     */
    fun startOver()

    // ---- §12.1: the first screen ----

    fun openInviteEntry(screen: EntryScreen.FirstRun)

    /**
     * "Create an account on andvari": pin the baked public instance (card 0 of the served chain must hash to the
     * baked value, §4.4) and begin sign-up there. The server is asked what it says about new accounts now, whatever
     * [EntryScreen.FirstRun.signup] showed: [ServerResult.NOT_TAKING_ACCOUNTS] when it takes none, with the first
     * screen republished to say why.
     */
    suspend fun createAccountOnAndvari(screen: EntryScreen.FirstRun): ServerResult

    /** Take [EntryScreen.FirstRun.notice] away: the person has seen it. */
    fun dismissNotice(screen: EntryScreen.FirstRun)

    /**
     * The person removes [account] ([EntryScreen.FirstRun.heldAsOperator]) from this device, after the app's own
     * confirmation that showed [HeldOperatorAccount.removeLine]: this device's copy of it is deleted, and nothing is sent.
     * DONE, then the first screen as for no account; STALE for an [account] no longer on show. The only way that copy
     * goes (the owner's decision of 2026-11-16).
     */
    suspend fun removeHeldOperatorAccount(account: HeldOperatorAccount): PlainResult

    fun openOwnServer(screen: EntryScreen.FirstRun)

    fun openSignIn(screen: EntryScreen.FirstRun)

    /**
     * Show the request for an operator's help this device still holds ([EntryScreen.FirstRun.operatorHelpWaiting]):
     * [EntryScreen.OperatorHelp], or [EntryScreen.CheckAccount] when the answer arrived meanwhile.
     */
    suspend fun resumeOperatorHelp(screen: EntryScreen.FirstRun): ServerResult

    // ---- invites ----

    /**
     * An invite scanned or pasted on "Scan an invite". **Only an invite is acted on**: a device link answers
     * [InviteResult.DEVICE_LINK_NOT_HERE], a kit [InviteResult.KIT_NOT_AN_INVITE], and neither starts anything. The
     * link is checked in the order of §6.8 before any screen shows, and nothing is sent until the person confirms
     * on that screen.
     *
     * **At the baked origin every kind of link pins through the baked root** (§4.4): the build vouches for the
     * public instance, so an invite to it never shows a Trust Gate, an enrol link included, and the pin it leaves is
     * a password pin. An enrol link to any other server passes the typed-address gate first.
     *
     * Core keeps no memory across the three entries, so the rule is the app's too (the design's flow-conformance
     * list): no screen forwards a payload refused here to [submitDeviceLink] or [submitKit], and a kit handed in here
     * starts no recovery.
     */
    suspend fun submitInvite(screen: EntryScreen.InviteEntry, payload: String, source: PayloadSource): InviteResult

    /** "Create an account on … to connect with …": begin sign-up on the invite's instance. */
    suspend fun joinFromInvite(screen: EntryScreen.JoinInvite): ServerResult

    /**
     * Sign in to an account the person already has on the invite's instance. A link offer is not a password pin
     * (§4.4), so this shows the Trust Gate in its `LINK_OFFER_SIGN_IN` wording first, unless this device already
     * holds a password pin for that origin, as it always does for the public instance (the baked root, whatever
     * link led there).
     */
    suspend fun signInFromInvite(screen: EntryScreen.JoinInvite): ServerResult

    /** The same, from the dead end: the person has an account on the server that takes no new ones. */
    suspend fun signInWhereInvited(screen: EntryScreen.NotTakingAccounts): ServerResult

    // ---- "Use your own server" ----

    /**
     * An address typed under "Use your own server"; on desktop, also a server's setup link (a phone answers
     * [ServerResult.SETUP_NEEDS_COMPUTER] to one, here as on "Scan an invite"). The address must pass the origin
     * grammar ([ServerResult.NOT_AN_ADDRESS]); a new one opens the Trust Gate.
     */
    suspend fun submitServerAddress(screen: EntryScreen.OwnServer, input: String): ServerResult

    /** Begin sign-up on the server the app is connected to. */
    suspend fun createAccountHere(screen: EntryScreen.Server): ServerResult

    /** Sign in on the server the app is connected to ([EntryScreen.SignIn] says when the Trust Gate comes first). */
    suspend fun signInHere(screen: EntryScreen.Server): ServerResult

    // ---- the Trust Gate ----

    /** Confirm the gate: pin the newest card the origin serves, and go on with what raised the gate. */
    suspend fun confirmTrustGate(screen: EntryScreen.TrustGate): ServerResult

    /** Decline: the flow ends, and nothing was sent to the origin but the request for its card. */
    fun declineTrustGate(screen: EntryScreen.TrustGate)

    // ---- §7.2: sign-up ----

    /**
     * Ask for a code. [SignUpStartResult.DONE] means the request was taken, for every address alike: it never says
     * whether the address has an account. While the proof of work runs, the screen is republished with
     * [EntryScreen.SignUpEmail.provingWork].
     */
    suspend fun startSignUp(screen: EntryScreen.SignUpEmail, email: String, ageConfirmed: Boolean): SignUpStartResult

    /** The six digits. A wrong, expired or used-up code, and no code at all, are one answer ([CodeResult.WRONG_CODE]). */
    suspend fun verifySignUpCode(screen: EntryScreen.SignUpCode, code: String): CodeResult

    /** Ask for another code for the same address; it replaces the one before. */
    suspend fun resendSignUpCode(screen: EntryScreen.SignUpCode): SignUpStartResult

    // ---- §7.3, §7.7: registration ----

    /** Show the warning that comes before operator recovery can be chosen ([EntryScreen.RecoveryWarning]). */
    fun reviewOperatorRecovery(screen: EntryScreen.CreateAccount)

    /**
     * "Turn on operator recovery": back to the form with [WhoCanRecover.ME_OR_OPERATOR]. It does nothing unless
     * [understood], the warning's checkbox, is ticked. False: nothing changed.
     */
    fun acceptOperatorRecovery(screen: EntryScreen.RecoveryWarning, understood: Boolean): Boolean

    /** "Keep it private": back to the form with [WhoCanRecover.ONLY_ME]. */
    fun keepRecoveryPrivate(screen: EntryScreen.RecoveryWarning)

    /** Choose "Only me" again on the form. */
    fun chooseOnlyMe(screen: EntryScreen.CreateAccount)

    /**
     * Register. On [CreateAccountResult.DONE] the account exists and the journey is at its recovery kit
     * ([EntryScreen.Kit]), or, through a setup link, at [EntryScreen.ServerSetup] first; the vault opens only after the
     * kit is confirmed.
     */
    suspend fun createAccount(screen: EntryScreen.CreateAccount, input: NewAccountInput): CreateAccountResult

    /**
     * Sign and upload card 0 again after [ServerSetupStep.NOT_UPLOADED] (the engine's `SetupResume.finish`). The
     * upload is a re-authenticated route, so it takes the operator account's master [password]
     * ([ServerResult.WRONG_PASSWORD]).
     */
    suspend fun retryServerSetup(screen: EntryScreen.ServerSetup, password: String): ServerResult

    /**
     * Leave the finished setup for the new account's recovery kit ([EntryScreen.Kit]); the vault opens once it is
     * confirmed. The setup comes before the kit because card 0 is signed inside the registration and the kit names it.
     */
    fun finishServerSetup(screen: EntryScreen.ServerSetup)

    // ---- sign-in ----

    fun openLinkDevice(screen: EntryScreen.SignInChoice)

    fun openPasswordSignIn(screen: EntryScreen.SignInChoice)

    fun openForgot(screen: EntryScreen.SignInChoice)

    /** The public instance, pinned from the baked root. */
    suspend fun choosePublicInstance(screen: EntryScreen.SignInServer): ServerResult

    /**
     * Your own server: the address, then the Trust Gate unless this device holds a pin for it that can be a password
     * pin for what [EntryScreen.SignInServer.purpose] says (see [EntryScreen.SignIn]).
     */
    suspend fun chooseOwnServer(screen: EntryScreen.SignInServer, address: String): ServerResult

    /**
     * Sign in. Prelogin, the password-derived key and the code go only to the origin [screen] was issued for, and
     * only once the password gate answered `proceed` for [email] there: it is asked here, before prelogin, because
     * this is where the account is first known ([SignInAnswer.TRUST_GATE_FIRST] otherwise, with nothing sent).
     * When the account has two-step sign-in this answers [SignInAnswer.CODE_NEEDED] and the screen asks for the code:
     * [submitSignInCode] then sends it, and the password is not asked again.
     */
    suspend fun submitSignIn(screen: EntryScreen.SignIn, email: String, password: String): SignInAnswer

    /**
     * The two-step code, on the screen [SignInAnswer.CODE_NEEDED] left ([EntryScreen.SignIn.codeNeeded]). It goes with
     * the keys derived from the password already given, which core holds in memory until the code is taken or the
     * screen is left; the password is never sent again. [SignInAnswer.STALE] on a screen that asks for no code. A wrong
     * code ([SignInAnswer.WRONG]) drops those keys: the screen asks for the password again.
     */
    suspend fun submitSignInCode(screen: EntryScreen.SignIn, code: String): SignInAnswer

    /** From "this account requires linking" to "Link from your other device". */
    fun linkInstead(screen: EntryScreen.LinkRequired)

    // ---- §8.2: linking this device ----

    /**
     * A device link scanned or pasted on "Link from your other device". **Only a device link is acted on**
     * ([DeviceLinkScanResult.NOT_A_DEVICE_LINK] for anything else). Nothing is sent to the link's origin until this
     * device holds a password pin for it: without one the Trust Gate opens in its device-link wording, and the
     * claim follows its confirmation.
     *
     * No screen forwards a payload refused here to [submitInvite] or [submitKit]; a kit handed in here starts no
     * recovery (core keeps no memory across the entries, so this is the app's rule too).
     */
    suspend fun submitDeviceLink(screen: EntryScreen.LinkDeviceEntry, payload: String, source: PayloadSource): DeviceLinkScanResult

    /**
     * The master password of the account being linked. It goes only to the origin pinned before the claim. On
     * [LinkPasswordResult.DONE] this device is signed in; when a later check fails the session is signed out at once
     * and [EntryScreen.LinkDeviceEnded] says why. [LinkPasswordResult.CODE_NEEDED]: the screen asks for the two-step
     * code, which [submitLinkCode] sends.
     */
    suspend fun submitLinkPassword(screen: EntryScreen.LinkDevicePassword, password: String): LinkPasswordResult

    /**
     * The two-step code of the account being linked, on the screen [LinkPasswordResult.CODE_NEEDED] left. It goes with
     * the keys derived from the password already given; the password is never sent again.
     */
    suspend fun submitLinkCode(screen: EntryScreen.LinkDevicePassword, code: String): LinkPasswordResult

    /** Leave the ended link for "Link from your other device". */
    fun dismissLinkDevice(screen: EntryScreen.LinkDeviceEnded)

    // ---- §10, §9.3: forgot the master password ----

    fun openKitEntry(screen: EntryScreen.Forgot)

    /** "I lost my master password and my recovery kit": the server choice, then "Ask the operator for help". */
    fun openAskOperator(screen: EntryScreen.Forgot)

    /**
     * A kit scanned on "Scan your recovery kit", or its `andvari-kit:2:` text pasted there, which counts as a scan
     * (a kit typed by hand is [submitTypedKit]). **Only a kit is acted on, and only here**: no other intent takes one. The instance is pinned from the kit's `card0Hash`; a kit made before the server's identity
     * was reset falls back to the Trust Gate in its kit wording. Nothing is sent before [confirmKitRecovery].
     *
     * Only a kit scanned or pasted on this screen starts a recovery: no screen forwards a payload another entry
     * refused to here, nor one refused here to another entry (core keeps no memory across them).
     */
    suspend fun submitKit(screen: EntryScreen.KitEntry, payload: String, source: PayloadSource): KitScanResult

    /**
     * A kit typed by hand on "Scan your recovery kit": the account's address, the server's address, and the
     * secret's eleven groups as typed (spaces and line breaks among them are ignored, nothing else is, §10). **Only
     * here**, like [submitKit]. A typed kit carries no `card0Hash`, so the server is not pinned from the kit: the
     * Trust Gate opens for the typed address first, unless this device already holds a pin that serves this
     * account's recovery (§4.4). Nothing is sent before [confirmKitRecovery], and whether the address has an account
     * there and the groups are its kit is the server's one uniform answer to that.
     *
     * The gate a typed kit raises is the typed-address gate with the kit's own words ([TrustGatePrompt.typedKit],
     * approved entry 9).
     */
    suspend fun submitTypedKit(screen: EntryScreen.KitEntry, email: String, serverAddress: String, groups: String): KitScanResult

    /**
     * "Recover … on …": prove the kit to the server it names. One uniform refusal, whatever was wrong.
     *
     * **A kit is proved once.** Whatever the answer, core has dropped the kit's secret by the time this returns:
     * on anything but [KitRecoverResult.DONE] (a refusal, no answer, an identity fault) the journey is back at
     * [EntryScreen.KitEntry], a pin this recovery made is gone again, and the kit has to be scanned or typed again.
     */
    suspend fun confirmKitRecovery(screen: EntryScreen.KitRecover): KitRecoverResult

    /**
     * From [EntryScreen.AddressMismatch], where [EntryScreen.AddressMismatch.canRecoverThere]: start the kit's
     * recovery again at the address the server's card names (the engine's `KitRecovery.retargetOrigin`). Every
     * check runs again there, from the card chain on: the kit's own card hash must still anchor it, or the Trust
     * Gate opens with the kit warning. [KitScanResult.STALE] for any other mismatch.
     */
    suspend fun recoverAtNamedAddress(screen: EntryScreen.AddressMismatch): KitScanResult

    /**
     * The new master password. The commit replaces the kit in the same step (FS-B1), ends every other session, and
     * turns off two-step sign-in and "new devices must be linked"; the journey goes on to the new kit.
     */
    suspend fun chooseReplacementPassword(screen: EntryScreen.ReplacePassword, password: String): ReplacePasswordResult

    /** Ask the operator. The answer is the same for every address ([AskOperatorResult.DONE]). With no mailbox value. */
    suspend fun requestOperatorHelp(screen: EntryScreen.AskOperator, email: String): AskOperatorResult

    /**
     * [requestOperatorHelp] with the text of the mailbox value's field ([EntryScreen.AskOperator.mailboxValueOpen]); blank
     * is none. Typed in any case, with or without spaces and dashes. A text that is not a value's form is
     * [AskOperatorResult.NOT_A_MAILBOX_VALUE] before anything is sent, and the screen stays with its field. Nothing the
     * device shows afterwards depends on it. Additive.
     */
    suspend fun requestOperatorHelpWithValue(screen: EntryScreen.AskOperator, email: String, mailboxValue: String): AskOperatorResult

    /** The quiet line [EntryScreen.AskOperator.mailboxValueLine] was taken: the screen now shows the field. Nothing is sent. */
    fun openMailboxValue(screen: EntryScreen.AskOperator)

    /** The emailed code of a request. At most five tries a request and ten a day per address; one uniform refusal. */
    suspend fun verifyOperatorHelp(screen: EntryScreen.OperatorHelp, code: String): CodeResult

    /**
     * Ask the server where the request stands now. When the operator's answer is there and checks out, the journey
     * goes on to [EntryScreen.CheckAccount], never straight to a new password.
     */
    suspend fun refreshOperatorHelp(screen: EntryScreen.OperatorHelp): ServerResult

    /**
     * The person compared the account ID with the one on their kit (or an email older than the request) and goes on to
     * a new master password for the delivered account. An explicit choice, and the only way there after an operator's
     * help (§9.3 step 4). Taken on the screen's first step it shows the screen again with
     * [EntryScreen.CheckAccount.confirming] (one tap does not pass the comparison); taken on that
     * step it goes on.
     */
    fun acceptRecoveredAccount(screen: EntryScreen.CheckAccount)

    /**
     * The account ID is not the person's: stop. The request is dropped from this device, for good, and the journey
     * returns to the first screen, which says so once ([FirstRunNotice.RECOVERY_STOPPED]); no password was set and
     * the server is told nothing.
     */
    fun rejectRecoveredAccount(screen: EntryScreen.CheckAccount)

    /**
     * "Not now": leave the check without answering it. The request stays on this device
     * ([EntryScreen.FirstRun.operatorHelpWaiting]), and [resumeOperatorHelp] shows the check again. Nothing is sent
     * and nothing is dropped: the person may need to find the email with their account ID first.
     */
    fun recoveredAccountNotNow(screen: EntryScreen.CheckAccount)

    /** Drop the request from this device. The server is told nothing; the request lapses there. */
    fun abandonOperatorHelp(screen: EntryScreen.OperatorHelp)

    /**
     * "Forget the earlier account on this device" on [offer] ([AppSnapshot.earlierAccount], at its first step): the second
     * confirmation is shown ([EarlierAccountKnown.confirming]). Nothing is forgotten and nothing is sent. False when [offer]
     * is not the one on show, or is already confirming. Additive.
     */
    fun askToForgetEarlierAccount(offer: EarlierAccountKnown): Boolean

    /** "Cancel" on [offer]: from the second confirmation back to the offer; from the offer, the offer goes. Additive. */
    fun keepEarlierAccount(offer: EarlierAccountKnown)

    /**
     * The second confirmation's "Forget it" on [confirmation] (the one on show, [EarlierAccountKnown.confirming]): this
     * device forgets the earlier account under the address at that server, and deletes everything of it it holds. Local
     * only: nothing is sent to any server, and what this device knows of the server stays. Additive.
     */
    suspend fun forgetEarlierAccount(confirmation: EarlierAccountKnown): ForgetEarlierResult
}

/** What became of a payload handed in as an invite (§6.1, §6.8, §12.1). */
enum class InviteResult(override val trouble: Trouble? = null, override val sentence: CopyKey? = null) : IntentResult {
    /** It is an invite and it checked out: the snapshot shows what it is. */
    DONE,

    /** Not a link this app knows. */
    NOT_AN_INVITE,

    /** A device link: taken only on "Link from your other device". Nothing started. */
    DEVICE_LINK_NOT_HERE(sentence = CopyKey.DEVICE_LINK_GOES_ELSEWHERE),

    /** A recovery kit: taken only on "Scan your recovery kit". Nothing started, and the sentence gives no directions. */
    KIT_NOT_AN_INVITE(sentence = CopyKey.KIT_NOT_AN_INVITE),
    EXPIRED,

    /** Someone answered or used it already. */
    ALREADY_USED,

    /** Unknown, or revoked by whoever made it. */
    NOT_FOUND,

    /** This account made the link. */
    OWN_LINK,

    /**
     * A check of §6.8 failed (the envelope, the kind, the signature, the creator's fingerprint, the card): nothing
     * was sent, nothing pinned.
     */
    DOES_NOT_CHECK_OUT,

    /**
     * §2.4 `origin_mismatch`: the offer, or the card the link's server serves, names another address than the
     * link's ([ServerResult.OTHER_ADDRESS]). Nothing was sent, nothing pinned.
     *
     * - Signed out, when the card the link's server serves names another address (the engine's
     *   `RecipientStep.OriginMismatch`): [EntryScreen.AddressMismatch] follows, with both addresses and
     *   [AddressMismatchFor.INVITE].
     * - When the signed offer itself names another address (`RecipientStep.Stopped(ORIGIN_MISMATCH)`), and always
     *   while signed in: no screen follows and no address is carried; the stop names neither.
     */
    OTHER_ADDRESS,

    /**
     * The link's server is blocked on this device: its chain does not continue this device's pin for it (§4.4
     * fork), or that pin's record is damaged ([ServerResult.IDENTITY_CONFLICT]). Signed out,
     * [EntryScreen.ServerChanged] shows it.
     */
    IDENTITY_CONFLICT,

    /**
     * The link's server, under this device's pin, moved, changed its `kind` or serves an older chain
     * ([ServerResult.SERVER_CHANGED]). Signed out, [EntryScreen.ServerChanged] shows it.
     */
    SERVER_CHANGED,

    /** A setup link on a phone (§9.5). Nothing else happens. */
    SETUP_NEEDS_COMPUTER(sentence = CopyKey.SETUP_LINK_NEEDS_COMPUTER),

    /** A setup link for a server that already has its identity card. */
    SETUP_ALREADY_DONE,

    /**
     * A register or enrol link, opened while signed in on that instance. Nothing was sent and the link stays usable.
     * Show [AccountSnapshot.inviteNotUsed] in place (the owner's approved words, filled by core); the fake and the
     * engine set it with this result.
     */
    NOT_USABLE_SIGNED_IN,
    STALE(Trouble.STALE),
    UNREACHABLE(Trouble.UNREACHABLE),
    RATE_LIMITED(Trouble.RATE_LIMITED),
    UPDATE_REQUIRED(Trouble.UPDATE_REQUIRED),
    FAILED(Trouble.FAILED),
    ;

    override val done: Boolean get() = this == DONE
}

/** What became of choosing, typing or confirming a server. */
enum class ServerResult(override val trouble: Trouble? = null, override val sentence: CopyKey? = null) : IntentResult {
    DONE,

    /** As [ProofResult.KEYS_NOT_KNOWN_HERE] (finishing a server's setup): never a wrong password while the session knows it. Additive. */
    KEYS_NOT_KNOWN_HERE(sentence = CopyKey.KEYS_NOT_KNOWN_HERE),

    /** As [ProofResult.PROOF_REFUSED] (finishing a server's setup): never a wrong password. Additive. */
    PROOF_REFUSED(sentence = CopyKey.SERVER_REFUSED_PROOF),

    /**
     * [LinksApi.switchInstance] without the person's second confirmation while changes made on this device were not
     * sent: nothing was signed out, deleted or sent (as [PlainResult.UNSENT_NOT_CONFIRMED]). Additive.
     */
    UNSENT_NOT_CONFIRMED(sentence = CopyKey.UNSENT_NOT_CONFIRMED),

    /** The origin grammar cannot carry it (§2.2). */
    NOT_AN_ADDRESS(sentence = CopyKey.ADDRESS_NEEDS_HTTPS_DOMAIN),

    /** The server has no identity card yet (its setup is unfinished): there is nothing to pin. */
    NOT_SET_UP_YET,

    /**
     * The served chain does not contain this device's pin, or the baked card 0 (§4.4 fork), or this device's pin
     * record for the server is damaged. Either way the server is blocked on this device until it is forgotten: the
     * journey shows [EntryScreen.ServerChanged] for it, whose card says which ([InstanceCardState.Stopped],
     * [InstanceCardState.Damaged]). Nothing was sent.
     */
    IDENTITY_CONFLICT,

    /**
     * The server's identity card was not accepted (the engine's `FirstPin.Refused`): its chain does not verify, or
     * it is not the chain the root anchors (a baked or kit card hash, an offer's card). Nothing was pinned, and
     * nothing was sent. A card that verifies and names another address is [OTHER_ADDRESS].
     *
     * GAP (§2.4): the design gives the verdicts and no wording.
     */
    CARD_NOT_ACCEPTED,

    /**
     * §2.4 pinning, `origin_mismatch`: the server's newest card names another address than the one this app dialed
     * (the engine's `FirstPin.OriginMismatch`). Cards are public, so any server can serve another server's genuine
     * chain; without this a look-alike address would pass the Trust Gate under the real server's name and key.
     * Nothing was pinned, and nothing was sent. The journey shows [EntryScreen.AddressMismatch], which carries both
     * addresses.
     */
    OTHER_ADDRESS,

    /** The server takes no new accounts by email now: the screen's [SignupStatus] says why. */
    NOT_TAKING_ACCOUNTS,

    /** "Ask the operator": this server offers no operator recovery (its card names no recovery key, or it is public, §7.7). */
    NO_OPERATOR_RECOVERY,

    /** A setup link that expired, was used, is unknown or did not check out. */
    SETUP_LINK_NOT_USABLE,

    /** A setup link typed under "Use your own server" on a phone (§9.5): the same answer as on "Scan an invite". */
    SETUP_NEEDS_COMPUTER(sentence = CopyKey.SETUP_LINK_NEEDS_COMPUTER),

    /** A setup link for a server that already has its identity card. */
    SETUP_ALREADY_DONE,

    /** [EntryApi.retryServerSetup]: the master password did not re-authenticate. Nothing was uploaded. */
    WRONG_PASSWORD,

    /**
     * The server's chain, under this device's pin for it, moved to another address or changed its `kind` (the
     * engine's `FirstPin.PinChanged`), or ends below that pin (`withheld` under an existing pin). The journey shows
     * [EntryScreen.ServerChanged] for that server. A move is handled first, and the flow is opened again once the
     * person followed it; an older chain can only be waited out.
     */
    SERVER_CHANGED,
    STALE(Trouble.STALE),
    UNREACHABLE(Trouble.UNREACHABLE),
    RATE_LIMITED(Trouble.RATE_LIMITED),
    UPDATE_REQUIRED(Trouble.UPDATE_REQUIRED),
    FAILED(Trouble.FAILED),
    ;

    override val done: Boolean get() = this == DONE
}

/** §7.2 `POST /signup/start`. */
enum class SignUpStartResult(override val trouble: Trouble? = null, override val sentence: CopyKey? = null) : IntentResult {
    /** `202`: the same for every address. */
    DONE,
    INVALID_EMAIL,

    /** `400 email_domain_blocked`: the same for every address of that domain, and it says nothing about any account (S3-Q3). */
    EMAIL_DOMAIN_NOT_ACCEPTED,

    /** "I am 13 or older" must be ticked. */
    AGE_CONFIRMATION_NEEDED,
    SIGNUP_CLOSED,
    SIGNUP_FULL,

    /** `503 mail_unavailable`, for every address alike. */
    MAIL_UNAVAILABLE(sentence = CopyKey.MAIL_UNAVAILABLE),

    /**
     * This device keeps another account, one its server signed out ([AppSnapshot.keptSignedOut]): a new account is never
     * the one kept here, so nothing was sent, no address and no code. As [CreateAccountResult.ANOTHER_ACCOUNT_KEPT],
     * which it now comes before.
     */
    ANOTHER_ACCOUNT_KEPT,

    /**
     * This device holds its server's operator account ([EntryScreen.FirstRun.heldAsOperator]): nothing was sent; it is
     * removed from this device first. As [CreateAccountResult.OPERATOR_ACCOUNT_HELD]. Additive.
     */
    OPERATOR_ACCOUNT_HELD(sentence = CopyKey.OPERATOR_ACCOUNT_HELD_HERE),
    STALE(Trouble.STALE),
    UNREACHABLE(Trouble.UNREACHABLE),
    RATE_LIMITED(Trouble.RATE_LIMITED),
    UPDATE_REQUIRED(Trouble.UPDATE_REQUIRED),
    FAILED(Trouble.FAILED),
    ;

    override val done: Boolean get() = this == DONE
}

/** A six-digit code from an email: sign-up (§7.2) and an operator's help (§9.3). */
enum class CodeResult(override val trouble: Trouble? = null, override val sentence: CopyKey? = null) : IntentResult {
    DONE,

    /** `400 bad_code`, uniform: wrong, expired, used up, or never sent. */
    WRONG_CODE,

    /**
     * A request's code ([EntryApi.verifyOperatorHelp]) answered `404`: the server no longer knows the request. It is kept
     * on this device until its own lifetime ends, and its screen says so ([EntryScreen.OperatorHelp.requestUnknown]).
     * Never "expired". Additive.
     */
    REQUEST_UNKNOWN(sentence = CopyKey.ASSIST_REQUEST_UNKNOWN),

    /**
     * A request's code answered `409 request_state` (the server cancelled the request: the account's password or
     * recovery setting changed, or the account was recovered, after it was made; or whoever runs the server ended it:
     * [CopyKey.ASSIST_REQUEST_CANCELLED] is true of each). The request is forgotten on this
     * device and the journey is back at the first screen; a new request can be made. Additive.
     */
    REQUEST_CANCELLED(sentence = CopyKey.ASSIST_REQUEST_CANCELLED),
    STALE(Trouble.STALE),
    UNREACHABLE(Trouble.UNREACHABLE),
    RATE_LIMITED(Trouble.RATE_LIMITED),
    UPDATE_REQUIRED(Trouble.UPDATE_REQUIRED),
    FAILED(Trouble.FAILED),
    ;

    override val done: Boolean get() = this == DONE
}

/** §7.3 `POST /auth/register`, by the step that refused. */
enum class CreateAccountResult(override val trouble: Trouble? = null, override val sentence: CopyKey? = null) : IntentResult {
    DONE,

    /** Below the master-password floor. Nothing was sent. */
    WEAK_PASSWORD,
    INVALID_EMAIL,
    EMAIL_TAKEN,

    /** `403 email_mismatch`: the enrol link is bound to another address. */
    EMAIL_NOT_THE_LINKS,
    AGE_CONFIRMATION_NEEDED,
    SIGNUP_CLOSED,
    SIGNUP_FULL,

    /** `429 signup_daily_max`: the day's new accounts are used up. */
    DAILY_LIMIT,

    /** `400 bad_ticket`: the verified address lapsed (30 minutes): start again. */
    VERIFICATION_EXPIRED,

    /** The link expired, was used or was revoked meanwhile. */
    LINK_GONE,

    /** `409 setup_incomplete`: the server has no identity card yet. */
    SERVER_NOT_SET_UP,

    /** `403 setup_done`: the server already has an operator. */
    SETUP_ALREADY_DONE,

    /** `400 operator_recovery_unavailable`. */
    OPERATOR_RECOVERY_UNAVAILABLE,

    /** `400 escrow_wrong_form`: the server no longer stores the form of recovery copy this app sealed; no account was created. Additive. */
    ESCROW_WRONG_FORM(sentence = CopyKey.REGISTER_ESCROW_WRONG_FORM),

    /**
     * §5.2: the server's answer did not carry back the identity this device registered (the engine's
     * `Registration.IdentityFault`). Nothing was opened and no session is kept; an account may exist under the
     * address, and this device will not use it. Said in the identity fault's own line, which it carries.
     */
    IDENTITY_FAULT(sentence = CopyKey.IDENTITY_FAULT_ADDRESS_KNOWN),

    /** No answer: the account may exist (the engine's `Registration.Unknown`). Offer to sign in. */
    MAY_EXIST,

    /**
     * This device keeps another account, one its server signed out ([AppSnapshot.keptSignedOut]): nothing was sent,
     * and no account was made. As [SignInAnswer.ANOTHER_ACCOUNT_KEPT].
     */
    ANOTHER_ACCOUNT_KEPT,

    /**
     * The account WAS made at the server, and this device then did not keep its session, because what it keeps changed
     * while the registration was under way (another account is kept here now). Its first kit is on show
     * ([KitScreen.notKeptLine]) and is kept until the person confirmed it; the account opens with its master password
     * once the other account is signed out on this device. Additive.
     */
    ACCOUNT_MADE_NOT_KEPT(sentence = CopyKey.KIT_REGISTERED_NOT_KEPT),

    /**
     * The account WAS made at the server, and this device then did not keep its session, because it came to hold its
     * server's operator account while the registration was under way ([EntryScreen.FirstRun.heldAsOperator]). Its first
     * kit is on show ([KitScreen.notKeptLine]) and is kept until the person confirmed it; the account opens here once the
     * held operator account is removed from this device (a sign-out is not the way out). Never "another account is
     * kept". Additive.
     */
    ACCOUNT_MADE_OPERATOR_ACCOUNT_HELD(sentence = CopyKey.KIT_REGISTERED_OPERATOR_ACCOUNT_HELD),

    /**
     * The account WAS made at the server, and this device then refused its session for a fault of the account's
     * identity (the keeper's reason is neither "another account kept" nor "operator account held": for a fresh account
     * only a server answering with keys or an id that do not match is left). Its first kit is on show
     * ([KitScreen.notKeptLine]) and is kept until the person confirmed it; nothing of the account is kept here. Never
     * [IDENTITY_FAULT], which says nothing is known to be made. Additive.
     */
    ACCOUNT_MADE_IDENTITY_FAULT(sentence = CopyKey.KIT_REGISTERED_IDENTITY_FAULT),

    /**
     * This device holds its server's operator account ([EntryScreen.FirstRun.heldAsOperator]): no account is made here
     * until it is removed from this device. Nothing was sent. Never "another account is kept". Additive.
     */
    OPERATOR_ACCOUNT_HELD(sentence = CopyKey.OPERATOR_ACCOUNT_HELD_HERE),
    STALE(Trouble.STALE),
    UNREACHABLE(Trouble.UNREACHABLE),
    RATE_LIMITED(Trouble.RATE_LIMITED),
    UPDATE_REQUIRED(Trouble.UPDATE_REQUIRED),
    FAILED(Trouble.FAILED),
    ;

    override val done: Boolean get() = this == DONE
}

/** `POST /auth/login` (§8.7, spec 03 §2): the engine's `SignIn` outcomes. */
enum class SignInAnswer(override val trouble: Trouble? = null, override val sentence: CopyKey? = null) : IntentResult {
    /** Signed in. The journey is at the kit when it was never saved, else the vault opens. */
    DONE,

    /** `401 totp_required`: the screen now asks for the code. The password was right. */
    CODE_NEEDED,

    /** `401 invalid_credentials`, uniform: the address, the master password or the code. */
    WRONG,

    /** `403 link_required`: the screen is now [EntryScreen.LinkRequired]. Only after the password and any code verified. */
    LINK_REQUIRED,

    /**
     * The account is its server's operator account, and this is a phone: the operator account signs in only in the
     * desktop app and the command-line tool (§9.1). Answered only after the password and any code verified; the
     * session that sign-in opened is ended at once, and nothing of the account is kept on this device.
     *
     * GAP (§9.1): the design gives no sentence for it.
     */
    OPERATOR_NEEDS_COMPUTER,

    /**
     * §5.2: the account's keys do not match its genesis record or this device's record of it. Nothing was opened. Said in
     * the identity fault's own line, which it carries.
     */
    IDENTITY_FAULT(sentence = CopyKey.IDENTITY_FAULT_ADDRESS_KNOWN),

    /**
     * The pin for this origin is not a password pin for this account (the engine's `SignIn.TrustGateFirst`): a setup
     * pin and another account than the operator it enrolled, or a pin that went away while the screen was open. The
     * screen is now the Trust Gate, and nothing was sent.
     */
    TRUST_GATE_FIRST,

    /**
     * This device keeps another account, one its server signed out ([AppSnapshot.keptSignedOut]): it is not replaced
     * by another sign-in. Nothing of this account is kept. Say "Sign out of *that account* first"; [AppApi.signOut],
     * behind its usual warning, deletes that account's copy, and the sign-in can be tried again. The password is not
     * sent when the address or the server already tells the accounts apart.
     */
    ANOTHER_ACCOUNT_KEPT,

    /**
     * Spec 01 §7: this device keeps the account, and the key the server's copy opened with the typed password is not that
     * account's key as this device knows it. Nothing kept was replaced, the server's new session was ended, and nothing
     * was opened. Additive.
     */
    SERVER_KEYS_NOT_KNOWN_HERE(sentence = CopyKey.SIGN_IN_SERVER_KEYS_NOT_KNOWN_HERE),

    /**
     * The keeper's own reason: this device holds its server's operator account ([EntryScreen.FirstRun.heldAsOperator]); it
     * is removed from this device first ([EntryApi.removeHeldOperatorAccount]), never signed out. Nothing was sent, or the
     * session the server opened was ended alone. Never "another account is kept". Additive.
     */
    OPERATOR_ACCOUNT_HELD(sentence = CopyKey.OPERATOR_ACCOUNT_HELD_HERE),

    /**
     * The keeper's own reason: this device's copy of the account is damaged and nothing compared the typed password with
     * it. Nothing kept was replaced. The way out is to remove this device's copy (its sign-out, which says first how many
     * changes were not sent, or that it cannot tell), then sign in. Additive.
     */
    KEPT_COPY_DAMAGED(sentence = CopyKey.KEPT_COPY_DAMAGED),

    /**
     * The server did not take the two-step code. It answers a wrong code and a wrong master password alike, but it asked
     * for the code only after this password, so most likely the code was wrong or already used: never "wrong password".
     * The screen is back at the password. Additive.
     */
    REFUSED_AFTER_CODE(sentence = CopyKey.SIGN_IN_REFUSED_AFTER_CODE),
    STALE(Trouble.STALE),
    UNREACHABLE(Trouble.UNREACHABLE),
    RATE_LIMITED(Trouble.RATE_LIMITED),
    UPDATE_REQUIRED(Trouble.UPDATE_REQUIRED),
    FAILED(Trouble.FAILED),
    ;

    override val done: Boolean get() = this == DONE
}

/** A device link handed in on "Link from your other device". */
enum class DeviceLinkScanResult(override val trouble: Trouble? = null, override val sentence: CopyKey? = null) : IntentResult {
    /** A device link: the snapshot shows the Trust Gate, the wait, or how the claim ended. */
    DONE,

    /** An invite, a kit, or nothing this app knows. */
    NOT_A_DEVICE_LINK,

    /** The link's server serves a card chain that does not continue this device's pin for it, or that pin's record is damaged: [EntryScreen.ServerChanged] shows it ([ServerResult.IDENTITY_CONFLICT]). */
    IDENTITY_CONFLICT,

    /** The link's server, under this device's pin, moved, changed its `kind` or serves an older chain: [EntryScreen.ServerChanged] shows it ([ServerResult.SERVER_CHANGED]). */
    SERVER_CHANGED,

    /** The link's server serves a card that is not accepted for a first pin ([ServerResult.CARD_NOT_ACCEPTED]). Nothing was sent to it. */
    CARD_NOT_ACCEPTED,

    /**
     * The link's server serves a card made for another address: [EntryScreen.AddressMismatch] shows both
     * ([ServerResult.OTHER_ADDRESS]). Nothing was claimed. A device link is never redirected: the person starts
     * again from the other device.
     */
    OTHER_ADDRESS,
    STALE(Trouble.STALE),
    UNREACHABLE(Trouble.UNREACHABLE),
    RATE_LIMITED(Trouble.RATE_LIMITED),
    UPDATE_REQUIRED(Trouble.UPDATE_REQUIRED),
    FAILED(Trouble.FAILED),
    ;

    override val done: Boolean get() = this == DONE
}

/** §8.2 step 7 `pickup`, and the checks of step 8. */
enum class LinkPasswordResult(override val trouble: Trouble? = null, override val sentence: CopyKey? = null) : IntentResult {
    /** This device is linked and signed in. */
    DONE,
    CODE_NEEDED,

    /** The uniform `401`, counted against the account's backoff. */
    WRONG,

    /** The link ended: [EntryScreen.LinkDeviceEnded] says how. */
    ENDED,

    /**
     * The linked account is its server's operator account, and this is a phone (§9.1): as
     * [SignInAnswer.OPERATOR_NEEDS_COMPUTER]. The session the pickup opened is ended at once, nothing of the account
     * is kept, and the journey is back at the first screen.
     */
    OPERATOR_NEEDS_COMPUTER,

    /**
     * This device keeps another account, one its server signed out ([AppSnapshot.keptSignedOut]): as
     * [SignInAnswer.ANOTHER_ACCOUNT_KEPT]. The password is not sent when the link's server is another than that
     * account's; otherwise the session the pickup opened was ended at once and nothing of it is kept.
     */
    ANOTHER_ACCOUNT_KEPT,

    /** The link ended as [LinkDeviceEnd.SERVER_KEYS_NOT_KNOWN_HERE], which [EntryScreen.LinkDeviceEnded] now shows. Additive. */
    SERVER_KEYS_NOT_KNOWN_HERE(sentence = CopyKey.SIGN_IN_SERVER_KEYS_NOT_KNOWN_HERE),

    /** The link ended as [LinkDeviceEnd.ANOTHER_SESSION_KEPT], which [EntryScreen.LinkDeviceEnded] now shows. Additive. */
    ANOTHER_SESSION_KEPT(sentence = CopyKey.DEVICE_LINK_ANOTHER_SESSION_KEPT),

    /** The link ended as [LinkDeviceEnd.IDENTITY_FAULT], which [EntryScreen.LinkDeviceEnded] now shows. Additive. */
    IDENTITY_FAULT(sentence = CopyKey.IDENTITY_FAULT_ADDRESS_KNOWN),

    /**
     * This device holds its server's operator account (the keeper's own reason): nothing was sent (the app's own check),
     * or the link ended as [LinkDeviceEnd.OPERATOR_ACCOUNT_HELD], which [EntryScreen.LinkDeviceEnded] now shows. Never
     * "another account is kept". Additive.
     */
    OPERATOR_ACCOUNT_HELD(sentence = CopyKey.OPERATOR_ACCOUNT_HELD_HERE),

    /** The link ended as [LinkDeviceEnd.KEPT_COPY_DAMAGED], which [EntryScreen.LinkDeviceEnded] now shows. Additive. */
    KEPT_COPY_DAMAGED(sentence = CopyKey.KEPT_COPY_DAMAGED),

    /** The link ended as [LinkDeviceEnd.REFUSED_AFTER_CODE] (the server did not take the two-step code), which [EntryScreen.LinkDeviceEnded] now shows. Additive. */
    REFUSED_AFTER_CODE(sentence = CopyKey.DEVICE_LINK_REFUSED_AFTER_CODE),

    /**
     * The server did not take this master password, although it opens this device's copy of the account (the account's
     * password may have been changed elsewhere since): never "wrong password". The link and the password screen stay; the
     * person types the account's current password. Past the link's time the link ends instead ([ENDED]). Additive.
     */
    PROOF_REFUSED(sentence = CopyKey.LINK_PROOF_REFUSED_TYPE_CURRENT),

    /**
     * The server refused the pickup after its two-step code step (it answers a wrong code and a wrong password alike from
     * then on), within the link's time: never "wrong password". The link stays; the password screen is back at the
     * password ([EntryScreen.LinkDevicePassword.codeNeeded] false), and the person types the password and then the current
     * code again. Past the link's time the link ends instead ([REFUSED_AFTER_CODE]). Additive.
     */
    CODE_REFUSED_LINK_STAYS(sentence = CopyKey.DEVICE_LINK_CODE_REFUSED_LINK_STAYS),
    STALE(Trouble.STALE),
    UNREACHABLE(Trouble.UNREACHABLE),

    /**
     * The server refused the pickup as one of too many requests: the link ended as [LinkDeviceEnd.TOO_MANY], which
     * [EntryScreen.LinkDeviceEnded] now shows, with the wait of [AppApi.retryAfterSeconds]. Never "unreachable".
     */
    RATE_LIMITED(Trouble.RATE_LIMITED),
    UPDATE_REQUIRED(Trouble.UPDATE_REQUIRED),
    FAILED(Trouble.FAILED),
    ;

    override val done: Boolean get() = this == DONE
}

/** A payload handed in on "Scan your recovery kit". */
enum class KitScanResult(override val trouble: Trouble? = null, override val sentence: CopyKey? = null) : IntentResult {
    DONE,

    /** An invite, a device link, or nothing this app knows; or typed groups that are not a kit's secret (43 characters of its alphabet). */
    NOT_A_KIT,

    /** A typed kit: the address is not an email address. Nothing was sent. */
    INVALID_EMAIL,

    /** A typed kit: the origin grammar cannot carry the server's address (§2.2). Nothing was sent. */
    NOT_AN_ADDRESS(sentence = CopyKey.ADDRESS_NEEDS_HTTPS_DOMAIN),

    /** The kit's server serves a card chain that does not continue this device's pin for it, or that pin's record is damaged: [EntryScreen.ServerChanged] shows it ([ServerResult.IDENTITY_CONFLICT]). */
    IDENTITY_CONFLICT,

    /** The kit's server, under this device's pin, moved, changed its `kind` or serves an older chain: [EntryScreen.ServerChanged] shows it ([ServerResult.SERVER_CHANGED]). */
    SERVER_CHANGED,

    /** The kit's server serves a card that is not accepted for a first pin ([ServerResult.CARD_NOT_ACCEPTED]). Nothing was sent to it. */
    CARD_NOT_ACCEPTED,

    /**
     * The kit's server serves a card made for another address: [EntryScreen.AddressMismatch] shows both
     * ([ServerResult.OTHER_ADDRESS]). A kit made before its server moved ends here, and
     * [EntryApi.recoverAtNamedAddress] goes on at the address the card names.
     */
    OTHER_ADDRESS,

    /**
     * This device keeps an account at another server, or one it holds as a server's operator: the session a recovery
     * opens could not be kept here, so nothing was sent to the kit's server and the kit's secret is gone from this
     * device. The way out is to sign that account out first ([AppSnapshot.keptSignedOut], [AppApi.signOut], whose check
     * says how many of its changes were not sent), then hand the kit in again. Additive.
     */
    ANOTHER_ACCOUNT_KEPT(sentence = CopyKey.RECOVERY_ANOTHER_ACCOUNT_KEPT),

    /** This device holds its server's operator account: nothing is sent to the kit's server until it is removed here. Additive. */
    OPERATOR_ACCOUNT_HELD(sentence = CopyKey.OPERATOR_ACCOUNT_HELD_HERE),
    STALE(Trouble.STALE),
    UNREACHABLE(Trouble.UNREACHABLE),
    RATE_LIMITED(Trouble.RATE_LIMITED),
    UPDATE_REQUIRED(Trouble.UPDATE_REQUIRED),
    FAILED(Trouble.FAILED),
    ;

    override val done: Boolean get() = this == DONE
}

/**
 * `POST /recovery/self/verify`. On anything but [DONE] the kit's secret is gone from this device and the journey is
 * back at [EntryScreen.KitEntry] ([EntryApi.confirmKitRecovery]).
 */
enum class KitRecoverResult(override val trouble: Trouble? = null, override val sentence: CopyKey? = null) : IntentResult {
    DONE,

    /** The uniform `401`: no such account, another account's kit, or a kit a newer one replaced. */
    KIT_NOT_ACCEPTED,

    /**
     * §5.2: what the server served does not open to the account's own identity key, or is not the account this device knows
     * under the address. Nothing was changed. Said in the identity fault's own line, which it carries.
     */
    IDENTITY_FAULT(sentence = CopyKey.IDENTITY_FAULT_ADDRESS_KNOWN),

    /**
     * The kit is the server's operator account's (its pinned card names that account as the operator), and this is a
     * phone (§9.1): as [SignInAnswer.OPERATOR_NEEDS_COMPUTER]. Nothing was changed; recover it in the desktop app or
     * `andvari-cli`. The kit's secret is gone from this device, as on every refusal here.
     */
    OPERATOR_NEEDS_COMPUTER,

    /**
     * The kit is another account's than the one this device keeps signed out by its server
     * ([AppSnapshot.keptSignedOut]): as [SignInAnswer.ANOTHER_ACCOUNT_KEPT]. Nothing was sent and nothing changed.
     */
    ANOTHER_ACCOUNT_KEPT,

    /**
     * Spec 01 §7: this device keeps the kit's account, and the key the kit opened does not open what the copy holds
     * sealed under the account's key. No commit was sent, no session exists, nothing kept changed; the kit's secret is
     * gone from this device, as on every refusal here. The sign-in's own sentence. Additive.
     */
    SERVER_KEYS_NOT_KNOWN_HERE(sentence = CopyKey.SIGN_IN_SERVER_KEYS_NOT_KNOWN_HERE),

    /** This device holds its server's operator account (the keeper's own reason): nothing was sent or committed. Additive. */
    OPERATOR_ACCOUNT_HELD(sentence = CopyKey.OPERATOR_ACCOUNT_HELD_HERE),

    /**
     * This device's copy of the kit's account is damaged (the keeper's own reason): nothing was committed; the way out is
     * to remove this device's copy (its sign-out says first how many changes were not sent), then recover. Additive.
     */
    KEPT_COPY_DAMAGED(sentence = CopyKey.KEPT_COPY_DAMAGED),
    STALE(Trouble.STALE),
    UNREACHABLE(Trouble.UNREACHABLE),
    RATE_LIMITED(Trouble.RATE_LIMITED),
    UPDATE_REQUIRED(Trouble.UPDATE_REQUIRED),
    FAILED(Trouble.FAILED),
    ;

    override val done: Boolean get() = this == DONE
}

/** The commit of a recovery (§10, §9.3 step 5). */
enum class ReplacePasswordResult(override val trouble: Trouble? = null, override val sentence: CopyKey? = null) : IntentResult {
    DONE,
    WEAK_PASSWORD,

    /**
     * A recovery with the kit lapsed or was used meanwhile: start again. (After the operator's help the same refusal is
     * [REQUEST_ENDED], whose line is the shared code's.)
     */
    TOO_LATE,

    /**
     * After the operator's help: the commit was refused because the request can no longer be finished (it ran out of
     * time or was used, or whoever runs the server ended it). Nothing was committed; what was opened of the answer is
     * dropped and the journey is back at the first screen; a new request can be made. Its line is
     * [CopyKey.ASSIST_ANSWERED_REQUEST_ENDED]. Additive.
     */
    REQUEST_ENDED(sentence = CopyKey.ASSIST_ANSWERED_REQUEST_ENDED),

    /**
     * `403 commit_mismatch` (or this device's own check of the stored answer): the answer the server
     * holds now is not the one this device opened. The request is KEPT, and nothing needs to be started again: the
     * operator uploads the answer again, and the journey is back on the request's screen
     * ([EntryScreen.OperatorHelp.answerReplaced] says the same), whose next look picks the new upload up. Never worded
     * as "start again". Additive.
     */
    ANSWER_REPLACED(sentence = CopyKey.ASSIST_ANSWER_REPLACED),

    /**
     * The commit answered `404`: the server no longer knows the request. What was opened is
     * dropped, the request is KEPT until its own lifetime ends, and the journey is back on the request's screen
     * ([EntryScreen.OperatorHelp.requestUnknown]). Never "too late". Additive.
     */
    REQUEST_UNKNOWN(sentence = CopyKey.ASSIST_REQUEST_UNKNOWN),

    /** `400 recovery_account_not_active`: the account is disabled; the operator re-enables it first. */
    ACCOUNT_DISABLED,

    /**
     * The commit was sent and no answer came: it may have worked, and then the old kit and password are dead. The
     * journey is now at [EntryScreen.SignIn] for the server: sign in with the new password. A recovery started again
     * with the old kit may be refused.
     *
     * GAP (§10, §9.3): the design gives no wording for it.
     */
    MAY_HAVE_WORKED,

    /**
     * The recovered account is its server's operator account, and this is a phone (§9.1), found only from the
     * session the commit answered with (a kit recovery is refused before that, at [KitRecoverResult.OPERATOR_NEEDS_COMPUTER],
     * when the pinned card names the account as its operator). The commit went through: **the new master password is
     * in force** and the old kit is dead. The session it opened is ended at once and nothing of the account is kept
     * here; the journey is back at the first screen. Sign in with the new password in the desktop app or
     * `andvari-cli`, which then makes the account's new kit.
     *
     * GAP (§9.1): the design gives no sentence for it.
     */
    OPERATOR_NEEDS_COMPUTER,

    /**
     * This device keeps another account, one its server signed out ([AppSnapshot.keptSignedOut]), and the session the
     * commit opened was refused: as [SignInAnswer.ANOTHER_ACCOUNT_KEPT]. The commit went through, so **the new master
     * password is in force**; sign out of that account, then sign in with the new password. (The kit's own check,
     * [KitRecoverResult.ANOTHER_ACCOUNT_KEPT], stops this before anything is sent whenever the kit names the account.)
     * Its sentence says that the change was made, never "nothing was changed".
     */
    ANOTHER_ACCOUNT_KEPT(sentence = CopyKey.RECOVERY_COMMITTED_ANOTHER_ACCOUNT_KEPT),

    /**
     * Spec 01 §7, checked again just before the commit: this device keeps the account, and the recovered key does not
     * open what the copy holds sealed under the account's key. NOTHING was committed: the old password and kit still
     * stand, and nothing kept changed. After a kit, the journey is back where the kit is handed in; after the operator's
     * help, on the request's screen, which keeps the request ([EntryScreen.OperatorHelp.keysNotKnownHere]). The
     * sign-in's own sentence. Additive.
     */
    SERVER_KEYS_NOT_KNOWN_HERE(sentence = CopyKey.SIGN_IN_SERVER_KEYS_NOT_KNOWN_HERE),

    /**
     * Asked again just before the commit: this device keeps another account now (at another server, held as an
     * operator, or another account at this one), whose session the commit's would not replace. NOTHING was committed:
     * the old password and kit still stand. After a kit, the journey is back where the kit is handed in; after the
     * operator's help, on the request's screen, which keeps the request ([EntryScreen.OperatorHelp.anotherAccountKept]).
     * The way out is to sign that account out first. Unlike [ANOTHER_ACCOUNT_KEPT], no new password is in force. Additive.
     */
    ANOTHER_ACCOUNT_KEPT_NOT_COMMITTED(sentence = CopyKey.RECOVERY_ANOTHER_ACCOUNT_KEPT),

    /**
     * §5.2, the identity fault a sign-in has: the address is known on this device under another account or key. Before the
     * commit (the usual case), nothing was committed, and the journey is back where the kit is handed in, or on the
     * request's screen ([EntryScreen.OperatorHelp.identityFault]). NOTHING was committed. (After a commit the same fault
     * is [IDENTITY_FAULT_COMMITTED].) Additive.
     */
    IDENTITY_FAULT(sentence = CopyKey.IDENTITY_FAULT_ADDRESS_KNOWN),

    /**
     * The server took the commit, and this device then refused the session it opened because the address is known here
     * under another account or key (the keeper's identity fault). **The new master password is in force and the old kit
     * no longer works**; the new kit is on show ([KitScreen.notKeptLine] is this sentence) and is kept until confirmed.
     * After the operator's help, the request is used up. Nothing of the account opens here. Additive.
     */
    IDENTITY_FAULT_COMMITTED(sentence = CopyKey.RECOVERY_COMMITTED_IDENTITY_FAULT),

    /**
     * The server took the commit, and this device then refused its session because the session's key does not open what
     * this device keeps of the account (spec 01 §7, the keeper's own check). **The new master password is in force and
     * the old kit no longer works**; the new kit is on show, kept until confirmed. Unlike [SERVER_KEYS_NOT_KNOWN_HERE],
     * which is said before anything was committed. Additive.
     */
    SERVER_KEYS_NOT_KNOWN_HERE_COMMITTED(sentence = CopyKey.RECOVERY_COMMITTED_SERVER_KEYS_NOT_KNOWN_HERE),

    /**
     * The server took the commit, and this device then refused its session for a reason of the keeper's that no other
     * result names. **The new master password is in force and the old kit no longer works**; the new kit is on show,
     * kept until confirmed. Additive.
     */
    COMMITTED_NOT_KEPT(sentence = CopyKey.RECOVERY_COMMITTED_NOT_KEPT),

    /**
     * The server took the commit (**the new master password is in force and the old kit no longer works**; with the
     * operator's help, the request is used up), but what it answered did not open the account on this device (a fault
     * while opening: an identity seed that does not open, or an answer that is not the session it must be). Nothing of
     * the account is kept here and no new kit could be shown; the journey is back at the first screen. The way on is a
     * sign-in with the new password, which shows a new kit. Never "nothing was committed". Additive.
     */
    COMMITTED_NOT_OPENED(sentence = CopyKey.RECOVERY_COMMITTED_NOT_OPENED),

    /**
     * The server took the commit, and this device then refused its session because it holds its server's operator
     * account. **The new master password is in force and the old kit no longer works**; the new kit is on show. Additive.
     */
    OPERATOR_ACCOUNT_HELD_COMMITTED(sentence = CopyKey.RECOVERY_COMMITTED_OPERATOR_ACCOUNT_HELD),

    /**
     * The server took the commit, and this device then refused its session because its copy of the account is damaged.
     * **The new master password is in force and the old kit no longer works**; the new kit is on show. Additive.
     */
    KEPT_COPY_DAMAGED_COMMITTED(sentence = CopyKey.RECOVERY_COMMITTED_KEPT_COPY_DAMAGED),

    /**
     * Before the commit: this device holds its server's operator account (the keeper's own reason, or the app's own
     * check). NOTHING was committed; after a kit, back where the kit is handed in; after the operator's help, on the
     * request's screen ([EntryScreen.OperatorHelp.operatorAccountHeld]), which keeps the request. Additive.
     */
    OPERATOR_ACCOUNT_HELD(sentence = CopyKey.OPERATOR_ACCOUNT_HELD_HERE),

    /**
     * Before the commit: this device's copy of the account is damaged. NOTHING was committed; the way out is to remove
     * this device's copy, then recover again ([EntryScreen.OperatorHelp.keptCopyDamaged] on the request's screen). Additive.
     */
    KEPT_COPY_DAMAGED(sentence = CopyKey.KEPT_COPY_DAMAGED),

    /**
     * Before the commit: the operator's answer names an account that is not the one this device keeps for the address.
     * NOTHING was committed, the request stays as it is ([EntryScreen.OperatorHelp.notTheKeptAccount]); never a sign-out.
     * Additive.
     */
    NOT_THE_KEPT_ACCOUNT(sentence = CopyKey.ASSIST_NOT_THE_KEPT_ACCOUNT),
    STALE(Trouble.STALE),
    UNREACHABLE(Trouble.UNREACHABLE),
    RATE_LIMITED(Trouble.RATE_LIMITED),
    UPDATE_REQUIRED(Trouble.UPDATE_REQUIRED),
    FAILED(Trouble.FAILED),
    ;

    override val done: Boolean get() = this == DONE
}

/** `POST /recovery/requests`. */
enum class AskOperatorResult(override val trouble: Trouble? = null, override val sentence: CopyKey? = null) : IntentResult {
    /** `202`, for every address alike. */
    DONE,
    INVALID_EMAIL,
    MAIL_UNAVAILABLE(sentence = CopyKey.MAIL_UNAVAILABLE),

    /**
     * The mailbox value's field holds text that is not a value's form (16 symbols of its alphabet, spaces and dashes
     * aside): nothing was sent, and the screen stays with its field and the text. Additive.
     */
    NOT_A_MAILBOX_VALUE(sentence = CopyKey.ASSIST_NOT_A_MAILBOX_VALUE),
    STALE(Trouble.STALE),
    UNREACHABLE(Trouble.UNREACHABLE),
    RATE_LIMITED(Trouble.RATE_LIMITED),
    UPDATE_REQUIRED(Trouble.UPDATE_REQUIRED),
    FAILED(Trouble.FAILED),
    ;

    override val done: Boolean get() = this == DONE
}
