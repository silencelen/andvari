package io.silencelen.andvari.core.app.fake

import io.silencelen.andvari.core.app.AccountSnapshot
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CompareScreen
import io.silencelen.andvari.core.app.DeviceLinkHost
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.HowDeviceJoined
import io.silencelen.andvari.core.app.JoinMode
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.OpenedInvite
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.RoleInVault
import io.silencelen.andvari.core.app.ServerKind
import io.silencelen.andvari.core.app.ShareChoice
import io.silencelen.andvari.core.app.VaultLogState
import io.silencelen.andvari.core.app.WhoCanRecover
import io.silencelen.andvari.core.trust.MemberRole
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine

/**
 * A place in the app a preview or a UI test can start from: [FakeScenes.at] gives a fresh fake that is there. Each
 * scene gets there the way a person would, through the intents, so what it shows is what the flow really produces.
 */
enum class FakeScene {
    // ---- signed out ----
    FIRST_RUN,
    FIRST_RUN_SIGNUP_FULL,

    /** The public instance has not answered yet: the three choices show as usual. */
    FIRST_RUN_SIGNUP_NOT_KNOWN,

    /** A build without a baked public instance. */
    FIRST_RUN_NO_PUBLIC_INSTANCE,
    FIRST_RUN_HELP_WAITING,

    /** After "it's different" on the account check: the first screen says the recovery stopped. */
    FIRST_RUN_RECOVERY_STOPPED,

    /** An old store could not be deleted at the first launch (§12.4): the notice is due. */
    OLD_DATA_LEFT,
    INVITE_ENTRY,
    OWN_SERVER,
    GATE_TYPED_ADDRESS,
    GATE_ENROL_LINK,
    GATE_DEVICE_LINK,
    GATE_SIGN_IN_AFTER_INVITE,
    GATE_KIT_IDENTITY_CHANGED,

    /** The gate of a kit typed by hand. */
    GATE_TYPED_KIT,

    /** A typed address whose server serves a card made for another address. */
    ADDRESS_MISMATCH,

    /** A kit from before its server moved: the mismatch offers to recover at the address the card names. */
    ADDRESS_MISMATCH_KIT,
    SERVER,

    /** A typed server that takes accounts by invitation only. */
    SERVER_INVITATION_ONLY,
    JOIN_INVITE,
    NOT_TAKING_ACCOUNTS,
    SIGN_UP_EMAIL,
    SIGN_UP_PROVING_WORK,
    SIGN_UP_CODE,
    CREATE_ACCOUNT,
    CREATE_ACCOUNT_INVITED,
    CREATE_ACCOUNT_ENROLLED,
    CREATE_ACCOUNT_RECOVERY_CHOICE,
    RECOVERY_WARNING,
    KIT_REVEAL,
    KIT_CONFIRM,
    KIT_MAKING,
    KIT_NOT_MADE,
    SIGN_IN_CHOICE,
    SIGN_IN_SERVER,
    SIGN_IN,
    SIGN_IN_CODE_NEEDED,

    /** A pinned server that moved, found by a flow that opened it. */
    SERVER_CHANGED,

    /** A pinned server whose chain forked, found by a flow that opened it: the stop, and "Forget this server". */
    SERVER_STOPPED,

    /** A pinned server that serves an older chain, found by a flow that opened it. */
    SERVER_WITHHELD,
    LINK_REQUIRED,
    LINK_DEVICE_ENTRY,
    LINK_DEVICE_WAITING,
    LINK_DEVICE_CODE,
    LINK_DEVICE_PASSWORD,
    LINK_DEVICE_CANCELLED,
    LINK_DEVICE_WRONG_SERVER,
    FORGOT,
    KIT_ENTRY,
    KIT_RECOVER,
    REPLACE_PASSWORD,
    KIT_AFTER_RECOVERY,
    ASK_OPERATOR,
    OPERATOR_HELP_CODE_NEEDED,
    OPERATOR_HELP_HOLDING,
    OPERATOR_HELP_AWAITING,
    OPERATOR_HELP_VETOED,
    OPERATOR_HELP_NOT_GENUINE,
    OPERATOR_HELP_CHECK_ACCOUNT,
    REPLACE_PASSWORD_AFTER_HELP,
    LOCKED,

    /** Locked, and the session's server is stopped on this device: no password opens it. */
    LOCKED_SERVER_STOPPED,

    // ---- signed in ----
    VAULTS,
    VAULT_STATES,
    PROMPTS,
    PROMPT_RECOVERY_KEY_CHANGED,
    PROMPT_KEEP_OPERATOR_RECOVERY,

    /** An account made to connect with someone whose link's answer was not taken. */
    PROMPT_CONNECTION_NOT_MADE,
    PEOPLE_LIST,
    CONTACTS,

    /** The list of people was put off: the contacts screen says nobody on it is used here yet. */
    CONTACTS_NOT_REVIEWED,
    COMPARE_WAITING,
    COMPARE_READY,
    COMPARE_LINK_FAILED,
    COMPARE_MATCHED,
    LINKS,
    OPENED_CONNECT,
    OPENED_KEY_CHANGED,
    OPENED_OTHER_INSTANCE,

    /** An enrol link for a server this device never used, opened while signed in elsewhere: its Trust Gate. */
    OPENED_TRUST_GATE,

    /** An invite for another pinned server that moved since. */
    OPENED_SERVER_CHANGED,

    /** "Connect" was answered: the invite names the contact it made. */
    OPENED_CONNECTED,
    MEMBERS,
    MEMBERS_MAY_BE_INCOMPLETE,
    SHARE_WARNING,
    MOVE_EVERYTHING,
    MOVE_EVERYTHING_FROZEN,
    DEVICES,
    HOST_LINK_SHOWN,
    HOST_LINK_CLAIMED,
    HOST_LINK_TYPE_DIGITS,
    HOST_LINK_APPROVABLE,
    HOST_LINK_APPROVED,
    HOST_LINK_CANCELLED,
    RECOVERY,
    RECOVERY_WARNING_IN_SETTINGS,
    KIT_IN_SETTINGS,
    DELETION,
    DELETION_BLOCKED,
    DELETION_OUTCOME_UNKNOWN,
    CARD_WITHHELD,
    CARD_STOPPED,
    CARD_DAMAGED,
    CARD_NOT_VERIFIED,
    CARD_MOVED,

    /** A move to an address this device already holds a pin for: nothing moves until one of the two is forgotten. */
    CARD_MOVE_ALREADY_PINNED,
    CARD_KIND_CHANGED,

    /** The `kind` change's gate was answered "not now". */
    CARD_KIND_CHANGE_PUT_OFF,
    CARD_UPDATE_ANDVARI,

    // ---- desktop only ----
    SETUP_FORM,
    SERVER_SETUP_NOT_UPLOADED,
    SERVER_SETUP_FINISHED,
    OPERATOR_CONSOLE,
    OPERATOR_SETUP_UNFINISHED,
}

/** Fresh fakes at a [FakeScene], for previews and as the starting point of UI tests. */
object FakeScenes {
    /** The master password of every account a scene makes. */
    const val PASSWORD: String = "correct horse battery staple"

    /** The address of the account a signed-in scene is signed in to. */
    const val EMAIL: String = "ada@example.com"

    /** A family's own server, in the scenes that need one: private, invitation-only, with operator recovery. */
    const val FAMILY_ORIGIN: String = "https://vault.family.example"

    /** A phone app (iOS) at [scene]. A desktop-only scene gives a fake at the first screen. */
    fun at(scene: FakeScene): FakeAppApi = FakeAppApi().also { Stage(it).go(scene) }

    /** A phone app on [platform] at [scene]. */
    fun onPlatform(platform: AppPlatform, scene: FakeScene): FakeAppApi = FakeAppApi(platform, null).also { Stage(it).go(scene) }

    /** A phone app on [platform] at [scene], whose vault content runs over [contentCrypto] (an app's JVM tests). */
    fun onPlatform(platform: AppPlatform, scene: FakeScene, contentCrypto: io.silencelen.andvari.core.crypto.CryptoProvider): FakeAppApi =
        FakeAppApi(platform, null, contentCrypto).also { Stage(it).go(scene) }

    /** A desktop app at [scene]. */
    fun desktopAt(scene: FakeScene): FakeDesktopAppApi = FakeDesktopAppApi().also { Stage(it).go(scene) }

    /** Whether [scene] exists only in a desktop app (setup links and the operator views). */
    fun desktopOnly(scene: FakeScene): Boolean = scene >= FakeScene.SETUP_FORM
}

/** Runs the fake's `suspend` intents without a coroutine scope: they do not suspend unless a hold stops them. */
internal object FakeRun {
    /** Run [block] to its end on the calling thread. */
    fun <T> now(block: suspend () -> T): T {
        var out: Result<T>? = null
        block.startCoroutine(Continuation(EmptyCoroutineContext) { out = it })
        return (out ?: error("an intent of the fake is held: release it first")).getOrThrow()
    }

    /** Start [block] and leave it wherever a hold stops it. */
    fun start(block: suspend () -> Unit) {
        block.startCoroutine(Continuation(EmptyCoroutineContext) { it.getOrThrow() })
    }
}

/** The walks behind the scenes. */
private class Stage(val app: FakeAppApi) {
    private val script = app.script
    private val entry = app.entry
    private val pw = FakeScenes.PASSWORD

    private fun <T> run(block: suspend () -> T): T = FakeRun.now(block)

    private inline fun <reified S : EntryScreen> on(): S =
        app.snapshot.entry as? S ?: error("the scene expected ${S::class.simpleName} and is on ${app.snapshot.entry?.let { it::class.simpleName }}")

    private val account: AccountSnapshot get() = app.snapshot.account ?: error("the scene expected a signed-in account")

    private val family: FakeServer by lazy {
        script.addServer(FakeScenes.FAMILY_ORIGIN, "Family", ServerKind.PRIVATE_SERVER).also { it.recoveryKey = true }
    }

    fun go(scene: FakeScene) {
        if (FakeScenes.desktopOnly(scene) && app !is FakeDesktopAppApi) {
            app.start()
            return
        }
        when (scene) {
            FakeScene.FIRST_RUN -> app.start()
            FakeScene.FIRST_RUN_SIGNUP_FULL -> {
                script.publicInstance.full = true
                app.start()
            }
            FakeScene.FIRST_RUN_SIGNUP_NOT_KNOWN -> {
                script.publicStatusNotFetched = true
                app.start()
            }
            FakeScene.FIRST_RUN_NO_PUBLIC_INSTANCE -> {
                script.noBakedInstance = true
                app.start()
            }
            FakeScene.FIRST_RUN_HELP_WAITING -> {
                helpHolding()
                entry.startOver()
            }
            FakeScene.FIRST_RUN_RECOVERY_STOPPED -> {
                helpCheckAccount()
                entry.rejectRecoveredAccount(on())
            }
            FakeScene.OLD_DATA_LEFT -> {
                script.oldStoresThatStay += io.silencelen.andvari.core.app.PreCutoverStore.OFFLINE_CACHE
                app.start()
            }
            FakeScene.INVITE_ENTRY -> inviteEntry()
            FakeScene.OWN_SERVER -> ownServer()
            FakeScene.GATE_TYPED_ADDRESS -> gateTyped()
            FakeScene.GATE_ENROL_LINK -> {
                inviteEntry()
                run { entry.submitInvite(on(), script.enrolLink(family, "ada@family.example"), PayloadSource.SCANNED) }
                on<EntryScreen.TrustGate>()
            }
            FakeScene.GATE_DEVICE_LINK -> {
                linkEntry()
                val other = family.addAccount(FakeScenes.EMAIL, pw)
                run { entry.submitDeviceLink(on(), script.deviceLinkFrom(other, "MacBook"), PayloadSource.SCANNED) }
                on<EntryScreen.TrustGate>()
            }
            FakeScene.GATE_SIGN_IN_AFTER_INVITE -> {
                family.mode = JoinMode.ANYONE
                inviteEntry()
                run { entry.submitInvite(on(), script.connectInvite(family, "Bo"), PayloadSource.SCANNED) }
                run { entry.signInFromInvite(on()) }
                on<EntryScreen.TrustGate>()
            }
            FakeScene.GATE_KIT_IDENTITY_CHANGED -> {
                kitEntry()
                val kit = script.kitOf(family.addAccount(FakeScenes.EMAIL, pw))
                script.kitPredatesReset(kit)
                run { entry.submitKit(on(), kit, PayloadSource.SCANNED) }
                on<EntryScreen.TrustGate>()
            }
            FakeScene.GATE_TYPED_KIT -> {
                kitEntry()
                val account = family.addAccount(FakeScenes.EMAIL, pw)
                run { entry.submitTypedKit(on(), FakeScenes.EMAIL, FakeScenes.FAMILY_ORIGIN, script.kitGroupsOf(account)) }
                on<EntryScreen.TrustGate>()
            }
            FakeScene.ADDRESS_MISMATCH -> {
                // A look-alike address that serves the family server's genuine card.
                script.addServer("https://vau1t.family.example", "Family", ServerKind.PRIVATE_SERVER).also {
                    it.servesAnotherServersCard = true
                    it.cardNamesOrigin = FakeScenes.FAMILY_ORIGIN
                }
                ownServer()
                run { entry.submitServerAddress(on(), "https://vau1t.family.example") }
                on<EntryScreen.AddressMismatch>()
            }
            FakeScene.ADDRESS_MISMATCH_KIT -> {
                kitEntry()
                val kit = script.kitFromBeforeMove(family.addAccount(FakeScenes.EMAIL, pw), "https://old.family.example")
                run { entry.submitKit(on(), kit, PayloadSource.SCANNED) }
                on<EntryScreen.AddressMismatch>()
            }
            FakeScene.SERVER -> {
                family.mode = JoinMode.ANYONE
                gateTyped()
                run { entry.confirmTrustGate(on()) }
                on<EntryScreen.Server>()
            }
            FakeScene.SERVER_INVITATION_ONLY -> {
                gateTyped()
                family.mode = JoinMode.INVITATION_ONLY
                run { entry.confirmTrustGate(on()) }
                on<EntryScreen.Server>()
            }
            FakeScene.JOIN_INVITE -> {
                inviteEntry()
                run { entry.submitInvite(on(), script.connectInvite(script.publicInstance, "Bo"), PayloadSource.SCANNED) }
                on<EntryScreen.JoinInvite>()
            }
            FakeScene.NOT_TAKING_ACCOUNTS -> {
                inviteEntry()
                run { entry.submitInvite(on(), script.connectInvite(family, "Bo"), PayloadSource.SCANNED) }
                on<EntryScreen.NotTakingAccounts>()
            }
            FakeScene.SIGN_UP_EMAIL -> signUpEmail()
            FakeScene.SIGN_UP_PROVING_WORK -> {
                script.publicInstance.powBits = 20
                signUpEmail()
                script.holdProofOfWork = true
                val screen = on<EntryScreen.SignUpEmail>()
                FakeRun.start { entry.startSignUp(screen, FakeScenes.EMAIL, true) }
                script.setWorkProgress(40)
            }
            FakeScene.SIGN_UP_CODE -> signUpCode()
            FakeScene.CREATE_ACCOUNT -> createAccount()
            FakeScene.CREATE_ACCOUNT_INVITED -> {
                inviteEntry()
                run { entry.submitInvite(on(), script.invitation(family, "Bo"), PayloadSource.SCANNED) }
                on<EntryScreen.CreateAccount>()
            }
            FakeScene.CREATE_ACCOUNT_ENROLLED -> {
                inviteEntry()
                run { entry.submitInvite(on(), script.enrolLink(script.publicInstance, "ada@example.com"), PayloadSource.PASTED) }
                on<EntryScreen.CreateAccount>()
            }
            FakeScene.CREATE_ACCOUNT_RECOVERY_CHOICE -> recoveryChoice()
            FakeScene.RECOVERY_WARNING -> {
                recoveryChoice()
                entry.reviewOperatorRecovery(on())
                on<EntryScreen.RecoveryWarning>()
            }
            FakeScene.KIT_REVEAL -> kitReveal()
            FakeScene.KIT_CONFIRM -> {
                kitReveal()
                app.kit.proceedToConfirm(on<EntryScreen.Kit>().kit)
            }
            FakeScene.KIT_MAKING -> {
                script.holdKitCommit = true
                signInNeverSaved()
            }
            FakeScene.KIT_NOT_MADE -> {
                script.kitCommitFails = true
                signInNeverSaved()
            }
            FakeScene.SIGN_IN_CHOICE -> signInChoice()
            FakeScene.SIGN_IN_SERVER -> signInServer()
            FakeScene.SIGN_IN -> signIn()
            FakeScene.SERVER_CHANGED -> {
                // A server this device pinned earlier now says it lives at another address.
                app.pin(family, io.silencelen.andvari.core.client.pin.PinRoot.TRUST_GATE, null)
                family.movedUnderPinTo = "https://family.example"
                signInServer()
                run { entry.chooseOwnServer(on(), FakeScenes.FAMILY_ORIGIN) }
                on<EntryScreen.ServerChanged>()
            }
            FakeScene.SERVER_STOPPED -> {
                // A server this device pinned earlier now serves a chain that does not contain that pin.
                script.thisDevicePins(family)
                family.identityChanged = true
                signInServer()
                run { entry.chooseOwnServer(on(), FakeScenes.FAMILY_ORIGIN) }
                on<EntryScreen.ServerChanged>()
            }
            FakeScene.SERVER_WITHHELD -> {
                script.thisDevicePins(family)
                family.servesOlderChain = true
                signInServer()
                run { entry.chooseOwnServer(on(), FakeScenes.FAMILY_ORIGIN) }
                on<EntryScreen.ServerChanged>()
            }
            FakeScene.SIGN_IN_CODE_NEEDED -> {
                script.publicInstance.addAccount(FakeScenes.EMAIL, pw).twoStepCode = "654321"
                signIn()
                run { entry.submitSignIn(on(), FakeScenes.EMAIL, pw) }
            }
            FakeScene.LINK_REQUIRED -> {
                script.publicInstance.addAccount(FakeScenes.EMAIL, pw).requireLink = true
                signIn()
                run { entry.submitSignIn(on(), FakeScenes.EMAIL, pw) }
                on<EntryScreen.LinkRequired>()
            }
            FakeScene.LINK_DEVICE_ENTRY -> linkEntry()
            FakeScene.LINK_DEVICE_WAITING -> linkWaiting()
            FakeScene.LINK_DEVICE_CODE -> linkCode()
            FakeScene.LINK_DEVICE_PASSWORD -> linkPassword()
            FakeScene.LINK_DEVICE_CANCELLED -> {
                linkCode()
                script.otherDeviceCancels()
                on<EntryScreen.LinkDeviceEnded>()
            }
            FakeScene.LINK_DEVICE_WRONG_SERVER -> {
                linkPassword()
                script.bundleDisagreesWithPin = true
                run { entry.submitLinkPassword(on(), pw) }
                on<EntryScreen.LinkDeviceEnded>()
            }
            FakeScene.FORGOT -> forgot()
            FakeScene.KIT_ENTRY -> kitEntry()
            FakeScene.KIT_RECOVER -> kitRecover()
            FakeScene.REPLACE_PASSWORD -> replacePassword()
            FakeScene.KIT_AFTER_RECOVERY -> {
                replacePassword()
                run { entry.chooseReplacementPassword(on(), "a brand new master password") }
                on<EntryScreen.Kit>()
            }
            FakeScene.ASK_OPERATOR -> askOperator()
            FakeScene.OPERATOR_HELP_CODE_NEEDED -> helpCodeNeeded()
            FakeScene.OPERATOR_HELP_HOLDING -> helpHolding()
            FakeScene.OPERATOR_HELP_AWAITING -> {
                helpHolding()
                script.advance(7 * FakeScript.DAY)
                run { entry.refreshOperatorHelp(on()) }
            }
            FakeScene.OPERATOR_HELP_VETOED -> {
                helpHolding()
                script.accountDeviceCancelsRequest()
                run { entry.refreshOperatorHelp(on()) }
            }
            FakeScene.OPERATOR_HELP_NOT_GENUINE -> {
                helpHolding()
                script.advance(7 * FakeScript.DAY)
                script.operatorAnswers(forged = true)
                run { entry.refreshOperatorHelp(on()) }
            }
            FakeScene.OPERATOR_HELP_CHECK_ACCOUNT -> helpCheckAccount()
            FakeScene.REPLACE_PASSWORD_AFTER_HELP -> {
                helpCheckAccount()
                entry.acceptRecoveredAccount(on())
                on<EntryScreen.ReplacePassword>()
            }
            FakeScene.LOCKED -> {
                script.storeSession(script.publicInstance.addAccount(FakeScenes.EMAIL, pw))
                app.start()
            }
            FakeScene.LOCKED_SERVER_STOPPED -> {
                signedIn()
                script.cardForked()
                app.lock()
            }

            FakeScene.VAULTS -> signedIn()
            FakeScene.VAULT_STATES -> {
                val me = signedIn()
                val states = listOf(
                    VaultLogState.NOT_CHECKED_YET, VaultLogState.FAILED, VaultLogState.WITHHELD, VaultLogState.FROZEN,
                    VaultLogState.PURGED, VaultLogState.REMOVED, VaultLogState.KEY_REFUSED, VaultLogState.KEY_MISSING,
                )
                for (state in states) me.addVault(state.name.lowercase().replace('_', ' '), RoleInVault.WRITER).log = state
                me.vaults.first { it.log == VaultLogState.PURGED }.heldUntilMs = script.nowMs + 30 * FakeScript.DAY
                me.vaults.first { it.log == VaultLogState.REMOVED }.also {
                    it.heldUntilMs = script.nowMs + 30 * FakeScript.DAY
                    it.removedByOwner = true
                }
                me.vaults.first { it.name == "Family" }.also {
                    it.historyHint = true
                    it.ownerOutOfSpace = true
                    it.changeWaiting = true
                }
                // A stranger shares a vault, and so does someone another device of the account connected with.
                script.strangerSharesVault("Mallory")
                script.otherDeviceAddsContact("Dee", "iPad")?.let { script.contactSharesVault(it, "Trips") }
            }
            FakeScene.PROMPTS -> {
                val me = signedInFamily()
                val bo = me.contacts.first { it.label == "Bo" }
                script.contactSharesVault(bo, "Holiday")
                script.otherDeviceAddsContact("Dee", "iPad")
                script.contactKeyChanges(me.contacts.first { it.label == "Cy" })
                script.someoneAsksOperator(AppPlatform.ANDROID)
            }
            FakeScene.PROMPT_RECOVERY_KEY_CHANGED -> {
                signedInFamily()
                script.recoveryKeyChangesUnsigned()
            }
            FakeScene.PROMPT_KEEP_OPERATOR_RECOVERY -> {
                // Signed in with only the password: this device has no record of its own of the recovery choice.
                family.addAccount(FakeScenes.EMAIL, pw).whoCanRecover = WhoCanRecover.ME_OR_OPERATOR
                signInServer()
                run { entry.chooseOwnServer(on(), FakeScenes.FAMILY_ORIGIN) }
                run { entry.confirmTrustGate(on()) }
                run { entry.submitSignIn(on(), FakeScenes.EMAIL, pw) }
            }
            FakeScene.PROMPT_CONNECTION_NOT_MADE -> {
                // An account made to connect with Bo, whose link's answer got no answer from the server.
                script.connectAnswerFails = io.silencelen.andvari.core.app.ConnectResult.UNREACHABLE
                inviteEntry()
                run { entry.submitInvite(on(), script.connectInvite(script.publicInstance, "Bo"), PayloadSource.SCANNED) }
                run { entry.joinFromInvite(on()) }
                run { entry.startSignUp(on(), FakeScenes.EMAIL, true) }
                run { entry.verifySignUpCode(on(), script.emailCode) }
                run { entry.createAccount(on(), NewAccountInput("", "Ada", pw, true)) }
                saveKit()
            }
            FakeScene.PEOPLE_LIST -> peopleList()
            FakeScene.CONTACTS -> {
                signedIn()
                run { app.contacts.openContacts() }
            }
            FakeScene.CONTACTS_NOT_REVIEWED -> {
                peopleList()
                app.contacts.peopleLater(account.prompts.filterIsInstance<io.silencelen.andvari.core.app.AccountPrompt.PeopleList>().first())
                run { app.contacts.openContacts() }
            }
            FakeScene.COMPARE_WAITING -> {
                signedIn()
                run { app.links.openInvite(script.connectInvite(script.publicInstance, "Eve"), PayloadSource.SCANNED) }
                run { app.links.connect(account.opened as OpenedInvite.Connect) }
                compare("Eve")
            }
            FakeScene.COMPARE_READY -> compareReady()
            FakeScene.COMPARE_LINK_FAILED -> {
                val me = signedIn()
                script.linkFails(me.contacts.first { it.label == "Cy" })
                compare("Cy")
            }
            FakeScene.COMPARE_MATCHED -> {
                compareReady()
                val ready = account.comparing as CompareScreen.Ready
                run { app.contacts.submitComparison(ready, script.codeTheyReadOut(ready.userId)!!) }
            }
            FakeScene.LINKS -> {
                val me = signedIn()
                run { app.links.createConnectLink(listOf(ShareChoice(me.vaults.first().vaultId, MemberRole.WRITER)), 15) }
                script.someoneAnswers(account.links!!.links.first(), "Fay")
                run { app.links.createConnectLink(emptyList(), 60) }
            }
            FakeScene.OPENED_CONNECT -> {
                signedIn()
                run { app.links.openInvite(script.connectInvite(script.publicInstance, "Eve"), PayloadSource.SCANNED) }
            }
            FakeScene.OPENED_KEY_CHANGED -> {
                val me = signedIn()
                val invite = script.connectInvite(script.publicInstance, "Bo")
                script.inviteIsNewKeyOf(invite, me.contacts.first { it.label == "Bo" })
                run { app.links.openInvite(invite, PayloadSource.PASTED) }
            }
            FakeScene.OPENED_OTHER_INSTANCE -> {
                signedIn()
                run { app.links.openInvite(script.connectInvite(family, "Gus"), PayloadSource.SCANNED) }
            }
            FakeScene.OPENED_TRUST_GATE -> {
                signedIn()
                run { app.links.openInvite(script.enrolLink(family, null), PayloadSource.SCANNED) }
            }
            FakeScene.OPENED_SERVER_CHANGED -> {
                signedIn()
                script.thisDevicePins(family)
                family.movedUnderPinTo = "https://family.example"
                run { app.links.openInvite(script.connectInvite(family, "Gus"), PayloadSource.SCANNED) }
            }
            FakeScene.OPENED_CONNECTED -> {
                signedIn()
                run { app.links.openInvite(script.connectInvite(script.publicInstance, "Eve"), PayloadSource.SCANNED) }
                run { app.links.connect(account.opened as OpenedInvite.Connect) }
            }
            FakeScene.MEMBERS -> members(hint = false)
            FakeScene.MEMBERS_MAY_BE_INCOMPLETE -> members(hint = true)
            FakeScene.SHARE_WARNING -> {
                members(hint = false)
                run { app.contacts.openContacts() }
                val cy = account.contacts!!.contacts.first { it.label == "Cy" }
                run { app.vaults.addMember(account.members!!, cy, MemberRole.READER) }
            }
            FakeScene.MOVE_EVERYTHING -> {
                signedIn()
                run { app.vaults.openMoveEverything(account.vaults.first { it.name == "Family" }) }
            }
            FakeScene.MOVE_EVERYTHING_FROZEN -> {
                val me = signedIn()
                me.vaults.first { it.name == "Family" }.log = VaultLogState.FROZEN
                script.changed()
                run { app.vaults.openMoveEverything(account.vaults.first { it.name == "Family" }) }
            }
            FakeScene.DEVICES -> {
                signedIn()
                run { app.devices.openDevices() }
                // Set from this device, so the screen knows it (the server serves no read of it).
                run { app.devices.setRequireLink(true, pw) }
            }
            FakeScene.HOST_LINK_SHOWN -> hostLink(0)
            FakeScene.HOST_LINK_CLAIMED -> hostLink(1)
            FakeScene.HOST_LINK_TYPE_DIGITS -> hostLink(2)
            FakeScene.HOST_LINK_APPROVABLE -> hostLink(3)
            FakeScene.HOST_LINK_APPROVED -> hostLink(4)
            FakeScene.HOST_LINK_CANCELLED -> {
                hostLink(2)
                script.newerLinkMadeElsewhere()
            }
            FakeScene.RECOVERY -> {
                signedInFamily()
                run { app.recovery.openRecovery() }
            }
            FakeScene.RECOVERY_WARNING_IN_SETTINGS -> {
                val me = signedInFamily()
                me.whoCanRecover = WhoCanRecover.ONLY_ME
                family.unsignedRecoveryKeyChange = true
                run { app.recovery.openRecovery() }
                app.recovery.reviewOperatorRecovery(account.recovery!!)
            }
            FakeScene.KIT_IN_SETTINGS -> {
                signedIn()
                run { app.recovery.makeKit(pw) }
            }
            FakeScene.DELETION -> {
                val me = signedIn()
                me.vaults.removeAll { it.role == RoleInVault.OWNER }
                run { app.settings.openDeletion() }
            }
            FakeScene.DELETION_BLOCKED -> {
                signedIn()
                script.unknownDeletionBlocker = true
                run { app.settings.openDeletion() }
            }
            FakeScene.DELETION_OUTCOME_UNKNOWN -> {
                val me = signedIn()
                me.vaults.removeAll { it.role == RoleInVault.OWNER }
                run { app.settings.openDeletion() }
                script.deletionAnswerLost = true
                run { app.settings.deleteAccount(account.deletion!!, FakeScenes.EMAIL, pw, null) }
            }
            FakeScene.CARD_WITHHELD -> {
                signedIn()
                script.cardWithheld()
            }
            FakeScene.CARD_STOPPED -> {
                signedIn()
                script.cardForked()
            }
            FakeScene.CARD_DAMAGED -> {
                signedIn()
                script.pinRecordDamaged(null)
            }
            FakeScene.CARD_NOT_VERIFIED -> {
                signedIn()
                script.cardNotVerified()
            }
            FakeScene.CARD_MOVED -> {
                signedInFamily()
                script.cardMoved("https://vault.newhome.example")
            }
            FakeScene.CARD_MOVE_ALREADY_PINNED -> {
                signedInFamily()
                // This device set up the new address by itself earlier: the move cannot replace that pin.
                script.thisDevicePins(script.addServer("https://vault.newhome.example", "Family", ServerKind.PRIVATE_SERVER))
                script.cardMoved("https://vault.newhome.example")
            }
            FakeScene.CARD_KIND_CHANGED -> {
                signedInFamily()
                script.cardKindChanged()
            }
            FakeScene.CARD_KIND_CHANGE_PUT_OFF -> {
                signedInFamily()
                script.cardKindChanged()
                app.instance.kindChangeNotNow(app.snapshot.instance?.card as io.silencelen.andvari.core.app.InstanceCardState.KindChanged)
            }
            FakeScene.CARD_UPDATE_ANDVARI -> {
                signedIn()
                script.cardMoved("https://vault.elsewhere.example")
            }

            FakeScene.SETUP_FORM -> setupForm()
            FakeScene.SERVER_SETUP_NOT_UPLOADED -> {
                script.cardUploadFails = true
                setupDone()
            }
            FakeScene.SERVER_SETUP_FINISHED -> setupDone()
            FakeScene.OPERATOR_CONSOLE -> operatorConsole(unfinished = false)
            FakeScene.OPERATOR_SETUP_UNFINISHED -> operatorConsole(unfinished = true)
        }
    }

    // ---- signed out ----

    private fun inviteEntry() {
        app.start()
        entry.openInviteEntry(on())
    }

    private fun ownServer() {
        app.start()
        entry.openOwnServer(on())
    }

    private fun gateTyped() {
        family.mode = JoinMode.ANYONE
        ownServer()
        run { entry.submitServerAddress(on(), FakeScenes.FAMILY_ORIGIN) }
        on<EntryScreen.TrustGate>()
    }

    private fun signUpEmail() {
        app.start()
        run { entry.createAccountOnAndvari(on()) }
        on<EntryScreen.SignUpEmail>()
    }

    private fun signUpCode() {
        signUpEmail()
        run { entry.startSignUp(on(), FakeScenes.EMAIL, true) }
        on<EntryScreen.SignUpCode>()
    }

    private fun createAccount() {
        signUpCode()
        run { entry.verifySignUpCode(on(), script.emailCode) }
        on<EntryScreen.CreateAccount>()
    }

    private fun recoveryChoice() {
        inviteEntry()
        run { entry.submitInvite(on(), script.invitation(family, "Bo"), PayloadSource.SCANNED) }
        check(on<EntryScreen.CreateAccount>().recovery != null) { "the scene expected a recovery choice" }
    }

    private fun kitReveal() {
        createAccount()
        run { entry.createAccount(on(), NewAccountInput(FakeScenes.EMAIL, "Ada", pw, true)) }
        on<EntryScreen.Kit>()
    }

    private fun signInChoice() {
        app.start()
        entry.openSignIn(on())
    }

    private fun signInServer() {
        signInChoice()
        entry.openPasswordSignIn(on())
    }

    private fun signIn() {
        signInServer()
        run { entry.choosePublicInstance(on()) }
        on<EntryScreen.SignIn>()
    }

    private fun signInNeverSaved() {
        script.publicInstance.addAccount(FakeScenes.EMAIL, pw).kitSaved = false
        signIn()
        run { entry.submitSignIn(on(), FakeScenes.EMAIL, pw) }
        on<EntryScreen.Kit>()
    }

    /** Read the kit on show in the journey and type its groups back: the vault opens. */
    private fun saveKit() {
        val reveal = on<EntryScreen.Kit>().kit
        val groups = app.kit.kitDocument(reveal)?.groups ?: error("the scene expected a kit on its reveal step")
        app.kit.proceedToConfirm(reveal)
        val confirm = on<EntryScreen.Kit>().kit
        run { app.kit.confirmKit(confirm, confirm.groupsToType.map { groups[it - 1] }) }
        check(app.phase == AppPhase.UNLOCKED) { "the scene expected the vault to open" }
    }

    /** A password-only sign-in to an account that has contacts: the one-tap list of §8.5. */
    private fun peopleList() {
        val me = script.publicInstance.addAccount(FakeScenes.EMAIL, pw)
        me.addContact("Bo", compared = true)
        me.addContact("Cy", compared = false)
        signIn()
        run { entry.submitSignIn(on(), FakeScenes.EMAIL, pw) }
    }

    private fun linkEntry() {
        signInChoice()
        entry.openLinkDevice(on())
    }

    private fun linkWaiting() {
        val other = script.publicInstance.addAccount(FakeScenes.EMAIL, pw)
        linkEntry()
        run { entry.submitDeviceLink(on(), script.deviceLinkFrom(other, "MacBook"), PayloadSource.SCANNED) }
        on<EntryScreen.LinkDeviceWaiting>()
    }

    private fun linkCode() {
        linkWaiting()
        script.otherDeviceAnswers()
        on<EntryScreen.LinkDeviceCode>()
    }

    private fun linkPassword() {
        linkCode()
        script.otherDeviceApproves()
        on<EntryScreen.LinkDevicePassword>()
    }

    private fun forgot() {
        signInChoice()
        entry.openForgot(on())
    }

    private fun kitEntry() {
        forgot()
        entry.openKitEntry(on())
    }

    private fun kitRecover() {
        val lost = script.publicInstance.addAccount(FakeScenes.EMAIL, pw)
        kitEntry()
        run { entry.submitKit(on(), script.kitOf(lost), PayloadSource.SCANNED) }
        on<EntryScreen.KitRecover>()
    }

    private fun replacePassword() {
        kitRecover()
        run { entry.confirmKitRecovery(on()) }
        on<EntryScreen.ReplacePassword>()
    }

    private fun askOperator() {
        family.addAccount(FakeScenes.EMAIL, pw).whoCanRecover = WhoCanRecover.ME_OR_OPERATOR
        forgot()
        entry.openAskOperator(on())
        run { entry.chooseOwnServer(on(), FakeScenes.FAMILY_ORIGIN) }
        run { entry.confirmTrustGate(on()) }
        on<EntryScreen.AskOperator>()
    }

    private fun helpCodeNeeded() {
        askOperator()
        run { entry.requestOperatorHelp(on(), FakeScenes.EMAIL) }
        on<EntryScreen.OperatorHelp>()
    }

    private fun helpHolding() {
        helpCodeNeeded()
        run { entry.verifyOperatorHelp(on(), script.emailCode) }
    }

    private fun helpCheckAccount() {
        helpHolding()
        script.advance(7 * FakeScript.DAY)
        script.operatorAnswers(forged = false)
        run { entry.refreshOperatorHelp(on()) }
        on<EntryScreen.CheckAccount>()
    }

    // ---- signed in ----

    /** Ada on the public instance: two contacts, a vault she owns and one she is a writer of, two more devices. */
    private fun signedIn(): FakeAccount = populate(script.publicInstance.addAccount(FakeScenes.EMAIL, pw)).also(script::signedInAs)

    /** Ada on the family server, having chosen operator recovery. */
    private fun signedInFamily(): FakeAccount {
        val me = populate(family.addAccount(FakeScenes.EMAIL, pw))
        me.whoCanRecover = WhoCanRecover.ME_OR_OPERATOR
        script.signedInAs(me)
        return me
    }

    private fun populate(me: FakeAccount): FakeAccount {
        val bo = me.addContact("Bo", compared = true)
        val cy = me.addContact("Cy", compared = false)
        cy.codesReady = true
        cy.code = "271828"
        val shared = me.addVault("Family", RoleInVault.OWNER)
        shared.addMember("Bo", RoleInVault.WRITER, bo)
        shared.addMember("someone the server calls Dan", RoleInVault.READER, null)
        val work = me.addVault("Work", RoleInVault.WRITER)
        work.addMember("Bo", RoleInVault.OWNER, bo)
        me.addDevice("MacBook", AppPlatform.MACOS, HowDeviceJoined.LINKED).linkedFrom = "iPhone"
        me.addDevice("Old phone", AppPlatform.ANDROID, HowDeviceJoined.PASSWORD).live = false
        return me
    }

    private fun compare(label: String) {
        run { app.contacts.openContacts() }
        run { app.contacts.openCompare(account.contacts!!.contacts.first { it.label == label }) }
    }

    private fun compareReady() {
        signedIn()
        compare("Cy")
        check(account.comparing is CompareScreen.Ready) { "the scene expected the codes to be ready" }
    }

    private fun members(hint: Boolean) {
        val me = signedIn()
        val vault = me.vaults.first { it.name == "Family" }
        vault.historyHint = hint
        vault.members.first { it.contact == null && it.userId != me.userId }.deletedByOperator = true
        script.changed()
        run { app.vaults.openMembers(account.vaults.first { it.name == "Family" }) }
    }

    /** A device link shown by this device, [steps] steps along: 0 shown … 4 approved, where this device's part ends. */
    private fun hostLink(steps: Int) {
        signedIn()
        run { app.devices.startDeviceLink() }
        if (steps >= 1) script.joiningDeviceClaims("Pixel 9", AppPlatform.ANDROID)
        if (steps >= 2) script.joiningDeviceReveals(matches = true)
        if (steps >= 3) run { app.devices.submitDeviceDigits(account.deviceLink as DeviceLinkHost.TypeDigits, script.joiningDeviceCode) }
        if (steps >= 4) run { app.devices.approveWithPassword(account.deviceLink as DeviceLinkHost.Approvable, pw) }
        if (steps >= 5) script.joiningDevicePicksUp()
    }

    // ---- desktop ----

    private val fresh: FakeServer by lazy { script.addServer("https://vault.newfamily.example", "New family", ServerKind.PRIVATE_SERVER) }

    private fun setupForm() {
        ownServer()
        run { entry.submitServerAddress(on(), script.setupLink(fresh)) }
        on<EntryScreen.CreateAccount>()
    }

    private fun setupDone() {
        setupForm()
        // Card 0 is signed inside the registration, so the setup comes before the kit.
        run { entry.createAccount(on(), NewAccountInput("operator@newfamily.example", "Operator", pw, false)) }
        on<EntryScreen.ServerSetup>()
    }

    private fun operatorConsole(unfinished: Boolean) {
        val desktop = app as FakeDesktopAppApi
        val operator = family.addAccount("operator@family.example", pw)
        operator.isOperator = true
        val bo = family.addAccount("bo@family.example", pw)
        bo.whoCanRecover = WhoCanRecover.ME_OR_OPERATOR
        bo.addDevice("Bo's iPhone", AppPlatform.IOS, HowDeviceJoined.REGISTERED)
        family.addAccount("cy@family.example", pw).also {
            it.disabled = true
            it.disabledAtMs = script.nowMs - 40 * FakeScript.DAY
        }
        family.mailStalled = true
        family.hasCard = !unfinished
        script.signedInAs(operator)
        run { desktop.operatorApi.openConsole() }
        check(desktop.operatorApi.console != null) { "the scene expected the operator console" }
        check(app.phase == AppPhase.UNLOCKED)
    }
}
