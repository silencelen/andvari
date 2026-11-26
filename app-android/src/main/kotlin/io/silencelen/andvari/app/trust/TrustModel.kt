package io.silencelen.andvari.app.trust

import io.silencelen.andvari.app.launchOvertakable
import io.silencelen.andvari.core.app.AccountPrompt
import io.silencelen.andvari.core.app.AppApi
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.ConnectResult
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.IntentResult
import io.silencelen.andvari.core.app.InviteResult
import io.silencelen.andvari.core.app.LinkCreateResult
import io.silencelen.andvari.core.app.OpenedInvite
import io.silencelen.andvari.core.app.OwnNameResult
import io.silencelen.andvari.core.app.ShareChoice
import io.silencelen.andvari.core.app.Trouble
import io.silencelen.andvari.core.app.content.VaultContent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import java.net.URI

/**
 * The new path's state holder: a thin layer over [AppApi] (onboarding and trust design §18.1, IF-3). Core owns where
 * the app is ([AppApi.snapshots]); this holds only what core leaves to the app:
 *
 * - **What an intent answered**, to show in place ([said]) on the screen it was answered on. It goes as soon as the
 *   screen changes, so a refusal never lingers on a screen it was not about.
 * - **The update notice**: where core's state says it shows ([updateNoticeOn]).
 * - **A tapped app link** ([openLink]). Core holds no link across a lock or a start, so it is kept here and handed to
 *   [AppApi.openAppLink] once a person can see what it opens. Only `https://andvaripass.com/l` is taken: a device
 *   link (`/d`) is never an app link (§12.1, T2-B1).
 * - **Locking** ([touched], [tick], [backgrounded]): the API keeps no idle clock; the app calls [AppApi.lock].
 *
 * No Android type appears here, so the JVM tests drive it against the fake.
 *
 * @param joinBase the product origin whose `/l` path is this app's one app link ([BuildConstants.JOIN_BASE]).
 * @param monotonicMs a clock that keeps counting while the device sleeps and that the person cannot set.
 */
/** This device's autofill records as [TrustModel] ends them (note 11); Android's are two preference files. */
interface AutofillRecords {
    /** Every trusted browser and remembered app is forgotten; the owner too. */
    fun clear()

    /** The account the records were made under ([AccountSnapshot.accountId]), or null. */
    fun owner(): String?

    fun setOwner(accountId: String)

    /**
     * What the autofill status screen recorded of the last fills (the calling app, the page's host) and its debug toggle
     * are forgotten. Only at an account's deletion, or at the forgetting of an account whose deletion got no answer: they
     * say which apps and sites that account filled on. A sign-out and "Forget this server" leave them.
     */
    fun forgetFills()

    object None : AutofillRecords {
        override fun clear() = Unit
        override fun forgetFills() = Unit
        override fun owner(): String? = null
        override fun setOwner(accountId: String) = Unit
    }
}

class TrustModel(
    val api: AppApi,
    private val scope: CoroutineScope,
    private val joinBase: String,
    private val monotonicMs: () -> Long,
    /**
     * The sealed session file is there but could not be opened (its Keystore key is gone), so core reads "no session".
     * The person lands on the first screen; this says why ([savedSignInUnreadable]).
     */
    private val sessionFileUnreadable: () -> Boolean = { false },
    /** A new session opened ([AppPhase.UNLOCKED]): the unreadable file has been replaced and its kept copy may go. */
    private val sessionReplaced: () -> Unit = {},
    /** This device's autofill records (trusted browsers, remembered apps), ended by the person's own acts only. */
    private val autofillRecords: AutofillRecords = AutofillRecords.None,
) {
    /**
     * The remembered apps and trusted browsers are this person's judgements on this device,
     * so they end with the new path's own ends: a sign-out, "Forget this server", an account deletion (call
     * [personEnded] with the intent's result), and another account opening here ([onSnapshot]). Not a session the
     * server ended: under the design's new rule only the person's acts delete.
     */
    fun personEnded(result: IntentResult) {
        // A sign-out or "Forget this server" that did not end the session leaves no mark of the person's end (the
        // deletion's answer says that itself: deletionAnswered).
        if (result !is io.silencelen.andvari.core.app.DeletionResult) personEndAnswered(result.done)
        if (result == io.silencelen.andvari.core.app.PlainResult.DONE || result == io.silencelen.andvari.core.app.DeletionResult.DONE) {
            runCatching { autofillRecords.clear() }
        }
        if (result == io.silencelen.andvari.core.app.DeletionResult.DONE) runCatching { autofillRecords.forgetFills() }
    }

    /**
     * The person forgot an account whose deletion got no answer: this phone forgets it as at a deletion, so its autofill
     * records and what the status screen recorded of its fills go; and the outcome this phone could not tell is no longer
     * its to tell (the person was told so at the confirmation), so the first screen says nothing of it.
     */
    private fun unknownDeletionForgotten() {
        deletionUnknownFor = null
        runCatching { autofillRecords.clear() }
        runCatching { autofillRecords.forgetFills() }
    }

    private fun checkAutofillOwner(s: AppSnapshot) {
        val id = s.account?.accountId ?: return
        runCatching {
            val owner = autofillRecords.owner()
            if (owner != null && owner != id) autofillRecords.clear()
            if (owner != id) autofillRecords.setOwner(id)
        }
    }

    private val unreadableFlow = MutableStateFlow(false)
    private var unreadableDismissed = false

    /** Show the first screen's "this device's saved sign-in could not be read" (GAP: the API has no FirstRunNotice for it). */
    val savedSignInUnreadable: StateFlow<Boolean> get() = unreadableFlow

    fun dismissSavedSignInNotice() {
        unreadableDismissed = true
        unreadableFlow.value = false
    }

    private val contentFlow = MutableStateFlow<VaultContent?>(null)

    /** The account (its email and id) whose opening [GuardedContent.opening] the content on show belongs to; null with none. */
    private var openingAccount: String? = null

    /**
     * The open vault's content: [AppApi.content], read again whenever a snapshot arrives, and null in every phase but
     * [AppPhase.UNLOCKED]. Core makes a new instance at every unlock and closes the old one at a lock, so nothing here
     * keeps one across a lock.
     */
    val content: StateFlow<VaultContent?> get() = contentFlow

    private fun refreshContent(s: AppSnapshot) {
        val now = if (s.phase == AppPhase.UNLOCKED) api.content else null
        val old = contentFlow.value as? GuardedContent
        if (old?.inner === now) return
        // What a lock cut short is the next unlock's content's to say (its notice of kind LOCK, with each thing in
        // lockCut): the app keeps nothing of the closed content.
        // Every call the screens make on it is contained: one vault's fault never takes the app down.
        // The opening goes on only where the vault was composed again with no lock between (the content never went to
        // null) for the same account: the policy's wipe of the copy, after which the account goes on from the server.
        val account = s.account?.accountId?.let { s.account?.email + "|" + it }
        val opening = if (old != null && now != null && account != null && account == openingAccount) old.opening else Any()
        openingAccount = if (now != null) account else null
        contentFlow.value = now?.let { GuardedContent(it, opening, ::fault) }
        // A fault said about the last unlock's content is not about this one.
        if (now != null) wentWrongFlow.value = null
    }

    private fun refreshUnreadable(s: AppSnapshot) {
        if (s.phase == AppPhase.UNLOCKED && sessionFileUnreadable()) sessionReplaced()
        unreadableFlow.value = !unreadableDismissed && s.entry is EntryScreen.FirstRun && sessionFileUnreadable()
    }

    /**
     * The idle auto-lock window: the account's [io.silencelen.andvari.core.app.ServerPolicy.autoLockSeconds] (author
     * note 5; already clamped by core, so a server can only shorten it), or the old app's default while no account is open.
     */
    fun autoLockMs(): Long = api.snapshot.account?.policy?.autoLockSeconds?.let { it * 1000L } ?: DEFAULT_AUTO_LOCK_MS

    /**
     * How long a copied secret stays on the clipboard: the account's
     * [io.silencelen.andvari.core.app.ServerPolicy.clipboardClearSeconds], else the old app's 30 s. Nothing on the new
     * path copies a secret yet (the kit has no Copy button); the item screens read this when they land.
     */
    fun clipboardClearMs(): Long = (api.snapshot.account?.policy?.clipboardClearSeconds ?: DEFAULT_CLIPBOARD_CLEAR_S) * 1000L
    val snapshots: StateFlow<AppSnapshot> get() = api.snapshots

    /**
     * What the last intent answered, and where. [section] names the part of the screen that shows it in place (the
     * password change, the deletion, a device link: [runIn]); null for the line under the screen's top ([SaidHere]).
     */
    class Said internal constructor(internal val place: Place, val result: IntentResult?, val text: UiText, val section: String? = null)

    private val saidFlow = MutableStateFlow<Said?>(null)
    val said: StateFlow<Said?> get() = saidFlow

    /**
     * As on the desktop, "update required" is a notice, never a wall, on the lock screen
     * and above the open vault (signed out, the entry screen says it in place, as every answer). Core keeps it per
     * server ([io.silencelen.andvari.core.app.InstanceSnapshot.updateRequired]: only ever the session's own server, and
     * cleared by a later answer there that is not "update required"); the app no longer infers it from the answers.
     */
    fun updateNoticeOn(s: AppSnapshot): Boolean =
        (s.phase == AppPhase.LOCKED || s.phase == AppPhase.UNLOCKED) && s.instance?.updateRequired == true

    /** The place a snapshot shows: the phase and the kind of screen, not the screen object (a refusal may republish it). */
    data class Place internal constructor(val phase: AppPhase, val screen: Class<*>?)

    fun placeOf(s: AppSnapshot): Place = Place(s.phase, s.entry?.javaClass ?: s.locked?.javaClass)

    /** What was said on the screen [s] shows; null when it was said elsewhere or nothing was. */
    fun saidOn(s: AppSnapshot): Said? = saidFlow.value?.takeIf { it.place == placeOf(s) }

    fun clearSaid() {
        saidFlow.value = null
    }

    /** Say [text] in place, on the screen on show (a check the app makes before calling an intent). */
    fun say(text: UiText) {
        saidFlow.value = Said(placeOf(api.snapshot), null, text)
    }

    /**
     * Run one intent. Its answer is shown in place on the screen it was asked on; an answer of [Trouble.UPDATE_REQUIRED]
     * raises the update wall. [after] sees the result (to clear a field, say).
     */
    fun <R : IntentResult> run(intent: suspend AppApi.() -> R, after: (R) -> Unit = {}): Job = launchIntent(intent, null, after)

    /**
     * As [runSaying], with the answer shown in place by the part of the screen called [section] ([SaidIn]), not under
     * the screen's top. [words] null: as [run] would word it.
     */
    fun <R : IntentResult> runIn(section: String, intent: suspend AppApi.() -> R, words: ((R) -> UiText?)? = null, after: (R) -> Unit = {}): Job =
        launchIntent(intent, words, after, section)

    /** What was said in place by [section] on the screen [s] shows; null otherwise. */
    fun saidIn(s: AppSnapshot, section: String): Said? = saidOn(s)?.takeIf { it.section == section }

    /**
     * As [run], with the screen's own [words] for a result where the API's sentence is not what the screen says (quick
     * unlock's CANCELLED says nothing, say). [words] answering null says nothing.
     */
    fun <R : IntentResult> runSaying(intent: suspend AppApi.() -> R, words: (R) -> UiText?, after: (R) -> Unit = {}): Job =
        launchIntent(intent, words, after)

    /**
     * The one place where the app launches an intent. A lock can overtake it (the key fix): core then answers STALE,
     * or, on a path it has not converted yet, throws "the keys are gone". Either is said as the lock it is, where the
     * person now is (the lock screen), never as a failure or a wrong password; the screen it was asked on is gone, and a
     * screen still there keeps what was typed ([after] is not called for a throw).
     */
    private fun <R : IntentResult> launchIntent(intent: suspend AppApi.() -> R, words: ((R) -> UiText?)?, after: (R) -> Unit, section: String? = null): Job {
        val place = placeOf(api.snapshot)
        saidFlow.value = null
        // The refusal beside a kit on show when the kit's confirm was asked: said on the first screen once it is typed back.
        val refusalAtAsk = kitRefusalFlow.value
        val lockedAwayAtAsk = kitsLockedAway
        val endAsked = personAsks()
        val endsLandedAtAsk = personEndsLanded
        return scope.launch {
            val r = try {
                api.intent()
            } catch (t: Throwable) {
                // The person's own end whose act threw is not made: a later end by the server is never said as theirs.
                if (endAsked) personEndAnswered(false)
                when {
                    io.silencelen.andvari.app.Overtaken.isLock(t) -> lockOvertook(personEndsLanded != endsLandedAtAsk)
                    // Any other fault of the shared code is contained and said where the person
                    // now is, in place, without a word of the exception; [after] is not called, so a screen still
                    // there keeps what was typed, and the person can try again.
                    Contained.isFault(t) -> saidFlow.value = Said(placeOf(safeSnapshot() ?: return@launch), null, wentWrongWords(place), section)
                    else -> throw t
                }
                return@launch
            }
            if (overtakenByLock(place, r)) {
                lockOvertook(personEndsLanded != endsLandedAtAsk)
            } else if (kitsLockedAway != lockedAwayAtAsk && movesWithPerson(r) && api.snapshot.entry !is EntryScreen.Kit) {
                // The kit this answer came with arrived while the app was away and was locked away before it was drawn:
                // what the result would say beside it ("save this kit now") is not so; the shared code's notice says the
                // kit is gone and what stands in the way here.
                saidFlow.value = null
                kitRefusalFlow.value = null
            } else if (r == io.silencelen.andvari.core.app.KitConfirmResult.DONE && refusalAtAsk != null) {
                kitTypedBack(refusalAtAsk, api.snapshot)
            } else {
                val text = if (words != null) words(r) else wordsFor(r)
                if (!landed(place, r, text)) note(place, r, text, section)
            }
            after(r)
        }
    }

    // ---- a result that moves the person to another screen (check A17, property 5) ----

    /**
     * The result of a recovery's commit or of a registration that the server took while this phone refused the session:
     * its words, kept beside the new kit for as long as that kit is on show ([KitScreenView]), on every step of it, and
     * then said on the first screen the journey lands on once the kit was typed back. Null when the kit's own line
     * ([io.silencelen.andvari.core.app.KitScreen.notKeptLine]) already is the result's sentence.
     */
    class KitRefusal internal constructor(val result: IntentResult, val text: UiText?)

    private val kitRefusalFlow = MutableStateFlow<KitRefusal?>(null)

    /** The refusal that came with the kit on show, if any ([KitRefusal]). */
    val kitRefusal: StateFlow<KitRefusal?> get() = kitRefusalFlow

    /**
     * [r] moved the person from [asked] to another screen (the kit after a committed change, the kit's entry or the
     * request's screen after a stop before the commit): it is said where the person now is, unless that screen already
     * says the same sentence itself. True when it was said here (or needs nothing more), false when [note] says it in place.
     */
    private fun landed(asked: Place, r: IntentResult, text: UiText?): Boolean {
        if (!movesWithPerson(r)) return false
        val now = api.snapshot
        val here = placeOf(now)
        if (here == asked) return false
        val sentence = r.sentence
        when (val e = now.entry) {
            is EntryScreen.Kit -> {
                val line = e.kit.notKeptLine
                // A kit with a refusal: the result goes with the kit, on every step, and not under the screen's top.
                if (line != null) {
                    kitRefusalFlow.value = KitRefusal(r, if (sentence != null && sentence == line) null else text)
                    saidFlow.value = null
                    return true
                }
            }
            is EntryScreen.OperatorHelp -> if (operatorHelpStop(e) != null) {
                // The request's screen says why in place of the stage's line (its own words for the request), with its
                // way out: the recovery's sentence is not said again above it.
                saidFlow.value = null
                return true
            }
            else -> Unit
        }
        saidFlow.value = text?.let { Said(here, r, it) }
        return true
    }

    /** The kit with a refusal was typed back: the journey is at the first screen, which says the refusal and its way out. */
    private fun kitTypedBack(refusal: KitRefusal, s: AppSnapshot) {
        if (s.entry is EntryScreen.Kit) return
        kitRefusalFlow.value = null
        if (s.entry is EntryScreen.FirstRun) {
            // No kit is left: the shared code's reason line for the result, in place of its sentence (which says to save
            // the kit now); the result stays with it, for its way out.
            val text = io.silencelen.andvari.core.app.KeptStops.lineWithoutKit(refusal.result)?.let { UiText.of(it) }
                ?: refusal.text ?: UiText.forResult(refusal.result, 0)
            saidFlow.value = text?.let { Said(placeOf(s), refusal.result, it) }
        }
    }

    /**
     * The kit with a refusal is no longer on show: what stood beside it goes with it. Typed back, the confirm's own
     * answer says it on the first screen ([kitTypedBack]); taken by a lock (section AZ: a lock wipes every kit on show),
     * the shared code's notice says the kit is gone, and nothing of the refusal is kept here.
     */
    private fun followKitRefusal(s: AppSnapshot) {
        val kit = (s.entry as? EntryScreen.Kit)?.kit
        if (kit?.notKeptLine == null) kitRefusalFlow.value = null
    }

    // ---- the removal of this phone's operator account, from a screen that is not the first ----

    private val removeHeldAskFlow = MutableStateFlow(false)

    /** The first screen opens its confirmation to remove the held operator account ([HeldOperatorCard]). */
    val removeHeldAsked: StateFlow<Boolean> get() = removeHeldAskFlow

    /**
     * "Remove this account from this phone" under a stop because this phone holds its server's operator account: the
     * removal lives on the first screen (only it carries [EntryScreen.FirstRun.heldAsOperator]), so the journey goes
     * there and that screen opens its confirmation. Nothing is removed before the person confirms it there.
     */
    fun askRemoveHeldOperator() {
        act { entry.startOver() }
        removeHeldAskFlow.value = (api.snapshot.entry as? EntryScreen.FirstRun)?.heldAsOperator != null
    }

    fun removeHeldAskTaken() {
        removeHeldAskFlow.value = false
    }

    // ---- a sign-in's two-step code that the server already used ----

    private val codeSpentFlow = MutableStateFlow(false)

    /**
     * The sign-in's two-step code was answered with anything but DONE while the screen still asks for a code: the shared
     * code used up the step's pending code before it called the server, so every further code would be refused as stale
     * until the person went back. The code field gives way to the way back ([SignInScreen]).
     */
    val signInCodeSpent: StateFlow<Boolean> get() = codeSpentFlow

    /** Send the sign-in's two-step code ([io.silencelen.andvari.core.app.EntryApi.submitSignInCode]). */
    fun submitSignInCode(screen: EntryScreen.SignIn, code: String, after: () -> Unit = {}) {
        run({ entry.submitSignInCode(screen, code) }) { r ->
            if (!r.done && (api.snapshot.entry as? EntryScreen.SignIn)?.codeNeeded == true) codeSpentFlow.value = true
            after()
        }
    }

    /**
     * STALE to an intent asked with the vault open, which is no longer open, or asked in the journey (a kit on show
     * holds the account's keys), which is now at the lock screen: a lock (or the session's end) overtook it.
     */
    internal fun overtakenByLock(asked: Place, r: IntentResult, now: AppSnapshot = api.snapshot): Boolean =
        r.trouble == io.silencelen.andvari.core.app.Trouble.STALE &&
            ((asked.phase == AppPhase.UNLOCKED && now.phase != AppPhase.UNLOCKED) || (asked.phase == AppPhase.ENTRY && now.phase == AppPhase.LOCKED))

    /**
     * Work a lock overtook: said on the screen on show now. Should the app still show the vault open, it locks: the
     * account's keys are gone, so the open vault could do nothing more anyway.
     */
    private fun lockOvertook(personEndedSinceAsk: Boolean = false) {
        if (api.snapshot.phase == AppPhase.UNLOCKED) api.lock()
        val now = api.snapshot
        saidFlow.value = Said(placeOf(now), null, UiText.ph(overtookWords(now, personEndedSinceAsk)))
    }

    /**
     * What overtook the work, as the snapshot [now] shows it after the fact: the shared code's throw ("the keys are gone",
     * [io.silencelen.andvari.core.client.AccountWipedException] among them) and its STALE are the same for a lock and for
     * the end of the session by its server, so only the screen the person is on tells them apart. A lock screen of a
     * session this phone still holds is a lock ([Placeholder.LOCK_OVERTOOK]); the lock screen of a session its server
     * ended ([io.silencelen.andvari.core.app.LockedScreen.signedOutByServer], where unlocking opens the copy read-only)
     * and the first screen (nothing to unlock) are the session's end ([Placeholder.SESSION_ENDED_OVERTOOK]).
     */
    internal fun overtookWords(now: AppSnapshot, personEndedSinceAsk: Boolean = false): Placeholder = when {
        now.phase == AppPhase.LOCKED && now.locked?.signedOutByServer != true -> Placeholder.LOCK_OVERTOOK
        // The person's own end (a sign-out, the account's deletion, "Forget this server", the switch to another server's
        // invitation) put the app on the first screen: the server did not end anything. Work asked before that end
        // landed counts it even once the person has asked something since ([personEndedSinceAsk]).
        (personEnd != null || personEndedSinceAsk) && now.phase != AppPhase.LOCKED -> Placeholder.PERSON_ENDED_OVERTOOK
        else -> Placeholder.SESSION_ENDED_OVERTOOK
    }

    /** Where the person's own end of the session stands: asked (its answer not in yet), or landed on the journey. */
    private enum class PersonEnd { ASKED, LANDED }

    private var personEnd: PersonEnd? = null

    /**
     * The person confirmed an end of this session here: a sign-out (of the open account or the one kept), the account's
     * deletion, "Forget this server", or the switch to another server's invitation. Work still under way that it overtakes
     * is said as not done by the person's end ([Placeholder.PERSON_ENDED_OVERTOOK]), never as the server's.
     */
    internal fun personEnds() {
        personEnd = PersonEnd.ASKED
        endAskPending = true
    }

    /** [personEnds] was called and the intent that is the end itself has not been asked yet. */
    private var endAskPending = false

    /** How many of the person's ends landed on the journey: work asked before one of them counts it ([overtookWords]). */
    private var personEndsLanded = 0

    /**
     * The person asks something (an intent, a plain act): the first thing asked after their own end landed takes its mark
     * away, so that a later end by the server is not said as theirs. Answers whether this is the end itself.
     */
    private fun personAsks(): Boolean {
        val endAsked = endAskPending
        endAskPending = false
        if (!endAsked && personEnd == PersonEnd.LANDED) personEnd = null
        return endAsked
    }

    /**
     * What that end answered: one that did not end the session ([done] false, or its act threw) leaves nothing of it
     * here, also where it was asked on the journey and so counted as landed at once ("Forget this server" on the first
     * screen, the kept account's sign-out there).
     */
    internal fun personEndAnswered(done: Boolean) {
        if (done) return
        if (personEnd == PersonEnd.LANDED) personEndsLanded--
        personEnd = null
    }

    /** The person's end lands on the journey; once a session is on show again (a lock screen, an open vault), it is over. */
    private fun followPersonEnd(s: AppSnapshot) {
        when {
            personEnd == null -> Unit
            s.phase == AppPhase.ENTRY -> {
                if (personEnd == PersonEnd.ASKED) personEndsLanded++
                personEnd = PersonEnd.LANDED
            }
            personEnd == PersonEnd.LANDED && (s.phase == AppPhase.LOCKED || s.phase == AppPhase.UNLOCKED) -> personEnd = null
        }
    }

    /**
     * What [r] says when the screen gives no words of its own: a kept-account refusal names the account this phone
     * keeps ([AppSnapshot.keptSignedOut]); everything else as [UiText.forResult].
     */
    internal fun wordsFor(r: IntentResult): UiText? =
        api.snapshot.let { s -> keptAccountWords(r, s.keptSignedOut, s.keptSignedOutNotConfirmed) } ?: UiText.forResult(r, api.retryAfterSeconds())

    /**
     * The confirmation of "Sign out" ([SignOutAsk]): in Settings, on the lock screen, and for the account this phone
     * keeps although its server signed it out (from the journey, after the warning). The copy is deleted, and the app
     * is back at the first screen; it is the person's own act.
     */
    fun signOutAsk(): SignOutAsk = SignOutAsk(this, { signOut() }, { signOutConfirmed(it) }) { personEnded(it) }

    /** The confirmation of the switch to another server's invitation, which signs out of this one ([SignOutAsk]). */
    fun switchAsk(opened: io.silencelen.andvari.core.app.OpenedInvite.OtherInstance): SignOutAsk =
        SignOutAsk(this, { links.switchInstance(opened) }, { links.switchInstanceConfirmed(opened, it) }, switching = true) {}

    /**
     * From a device link's end whose line points to the sign-in with the master password ([linkEndOffersPasswordSignIn]):
     * that sign-in, reached as the person would reach it (the first screen, "Sign in", the password sign-in), each step
     * only from the screen it is asked on. Nothing is sent; the server is chosen there.
     */
    fun openPasswordSignInAfterLink(screen: EntryScreen.LinkDeviceEnded) = act {
        if (snapshot.entry !== screen) return@act
        entry.startOver()
        (snapshot.entry as? EntryScreen.FirstRun)?.let { entry.openSignIn(it) }
        (snapshot.entry as? EntryScreen.SignInChoice)?.let { entry.openPasswordSignIn(it) }
    }

    /** Run a plain intent that answers nothing. A fault it throws is contained and said on the screen on show. */
    fun act(intent: AppApi.() -> Unit) {
        saidFlow.value = null
        val place = placeOf(api.snapshot)
        personAsks()
        try {
            api.intent()
        } catch (t: Throwable) {
            when {
                io.silencelen.andvari.app.Overtaken.isLock(t) -> lockOvertook()
                Contained.isFault(t) -> saidFlow.value = Said(placeOf(safeSnapshot() ?: return), null, wentWrongWords(place))
                else -> throw t
            }
        }
    }

    // ---- a fault the app contained ----

    /**
     * What a contained fault in an intent says. The vault's line ("…your other vaults and the rest of andvari still
     * work") only while a vault is open AND the fault names it ([vaultId]): an intent is the account's, not one vault's,
     * so it says the general line; so does every fault while locked or unlocking, where nothing is open.
     */
    internal fun wentWrongWords(asked: Place, vaultId: String? = null): UiText =
        if (asked.phase == AppPhase.UNLOCKED && vaultId != null) UiText.ph(Placeholder.VAULT_WENT_WRONG) else UiText.ph(Placeholder.WENT_WRONG)

    /** The snapshot, or null if reading it failed (then nothing can be said in place, and the fault is said above). */
    private fun safeSnapshot(): AppSnapshot? = try {
        api.snapshot
    } catch (t: Throwable) {
        if (!Contained.isFault(t)) throw t
        fault(null)
        null
    }

    /** A contained fault with no answer shown in place: which vault, if known (never shown), and the words. */
    class WentWrong internal constructor(val vaultId: String?, val text: UiText)

    private val wentWrongFlow = MutableStateFlow<WentWrong?>(null)

    /** The line above every screen for a fault the app contained in work that answers nothing in place; null when none. */
    val wentWrong: StateFlow<WentWrong?> get() = wentWrongFlow

    /**
     * Something the shared code threw was contained ([GuardedContent], the engine's scope, a redraw): say it once above
     * the screen. Nothing of the exception reaches here. [vaultId] is the vault it was about when the call named one.
     */
    fun fault(vaultId: String?) {
        // The vault's line only when the fault names a vault and a vault is open now; a snapshot that cannot be read
        // says the general line (and is not reported again: that would loop).
        val open = vaultId != null && try {
            api.snapshot.phase == AppPhase.UNLOCKED
        } catch (t: Throwable) {
            if (!Contained.isFault(t)) throw t
            false
        }
        wentWrongFlow.value = WentWrong(vaultId, UiText.ph(if (open) Placeholder.VAULT_WENT_WRONG else Placeholder.WENT_WRONG))
    }

    fun dismissWentWrong() {
        wentWrongFlow.value = null
    }

    /**
     * The person dismissed the notice that a recovery kit on show was wiped ([AppSnapshot.kitWiped]), the one on show
     * ([notice]). This is the only call of [AppApi.dismissKitWiped] in the app: nothing else takes the notice away
     * (section BL, first point), and the app keeps nothing of it; it draws what the snapshot carries.
     */
    fun dismissKitWiped(notice: io.silencelen.andvari.core.app.KitWipedNotice) = contained { api.dismissKitWiped(notice) }

    /**
     * The person dismissed the notice that the server's policy removed this phone's copy ([AppSnapshot.policyWipe]), the
     * one on show ([notice]). The only call of [AppApi.dismissPolicyWipe] in the app: a lock, an unlock, a sign-in or a
     * start never takes it away, and the app keeps none of it (it draws what the snapshot carries, for its account only).
     */
    fun dismissPolicyWipe(notice: io.silencelen.andvari.core.app.PolicyWipeNotice) = contained { api.dismissPolicyWipe(notice) }

    /**
     * The person dismissed a move's note ([io.silencelen.andvari.core.app.AccountSnapshot.moveNotes]), the one on show.
     * The shared code takes it through [io.silencelen.andvari.core.app.MoveNotes], asked for on the vaults' interface;
     * nothing else in the app takes a note away.
     */
    fun dismissMoveNote(note: io.silencelen.andvari.core.app.MoveNote) = contained {
        (api.vaults as? io.silencelen.andvari.core.app.MoveNotes)?.dismissMoveNote(note)
    }

    // ---- "Forget the earlier account on this device" (decided on 2026-11-17) ----
    // Each step reads the offer from the snapshot at the person's tap: the app keeps, makes and caches none, so a lock,
    // a screen change or a restart (which the shared code answers by taking the confirmation back) can never be crossed.

    /** "Forget the earlier account on this device" on the offer on show: its second step. Nothing is forgotten yet. */
    fun askToForgetEarlierAccount() = contained {
        val offer = api.snapshot.earlierAccount?.takeIf { !it.confirming } ?: return@contained
        api.entry.askToForgetEarlierAccount(offer)
    }

    /** Cancel: from the second step back to the offer, from the offer away. */
    fun keepEarlierAccount() = contained {
        api.snapshot.earlierAccount?.let { api.entry.keepEarlierAccount(it) }
    }

    /**
     * The second step's button, from the person's own tap only: the confirmation on show now, never one kept from before.
     * Its result's line is said in place ([io.silencelen.andvari.core.app.EarlierAccountKnown.lineFor]); STALE says
     * nothing (the snapshot shows what holds now). A call that throws is said as a fault in place, the second step stays
     * on show for the person's next tap, and the app never calls it again by itself.
     */
    fun forgetEarlierAccount() {
        val confirmation = api.snapshot.earlierAccount?.takeIf { it.confirming } ?: return
        runSaying({ entry.forgetEarlierAccount(confirmation) }, { r -> confirmation.lineFor(r)?.let { UiText.of(it) } })
    }

    /** The notice that this phone now remembers the new account under the address: its dismiss. */
    fun dismissNewAccountRemembered(notice: io.silencelen.andvari.core.app.NewAccountRememberedNotice) =
        contained { api.dismissNewAccountRemembered(notice) }

    // ---- forgetting an account after a deletion whose outcome is not known ----
    // Drawn as the other forgetting is: the offer, then the second step; each step reads the shared code's check at the
    // person's tap, the call is made only from the second step's own tap, never again by the app, and a lock or a new
    // check object closes the second step.

    private val forgetUnknownAskedFlow = MutableStateFlow<io.silencelen.andvari.core.app.ForgetUnknownDeletion?>(null)

    /** The check whose second step is on show (the very object the shared code handed out), or null: the offer only. */
    val forgetUnknownAsked: StateFlow<io.silencelen.andvari.core.app.ForgetUnknownDeletion?> get() = forgetUnknownAskedFlow

    /** The shared code's offer to forget the account after a deletion of unknown outcome, read now; null where none. */
    fun forgetUnknownCheck(): io.silencelen.andvari.core.app.ForgetUnknownDeletion? = try {
        api.forgetAfterUnknownDeletionCheck()
    } catch (t: Throwable) {
        if (!Contained.isFault(t)) throw t
        fault(null)
        null
    }

    /** The offer's tap: the second step, for the check on show now. Nothing is forgotten yet. */
    fun askToForgetUnknownDeletion() {
        forgetUnknownAskedFlow.value = forgetUnknownCheck()
    }

    /** Cancel at the second step: back to the offer. */
    fun keepUnknownDeletion() {
        forgetUnknownAskedFlow.value = null
    }

    /**
     * The second step's button, from the person's own tap only: the check read now must be the one the step was opened
     * for; otherwise the step closes and the offer is read again. DONE lands where the shared code puts it (the first
     * screen) and says nothing of its own; STALE closes the step; a throw is said in place and the step stays.
     */
    fun forgetUnknownDeletion(section: String? = null) {
        val asked = forgetUnknownAskedFlow.value ?: return
        if (forgetUnknownCheck() !== asked) {
            forgetUnknownAskedFlow.value = null
            return
        }
        val settled = { r: io.silencelen.andvari.core.app.PlainResult -> r.done || r == io.silencelen.andvari.core.app.PlainResult.STALE }
        val words = { r: io.silencelen.andvari.core.app.PlainResult -> if (settled(r)) null else UiText.forResult(r, api.retryAfterSeconds()) }
        val after = { r: io.silencelen.andvari.core.app.PlainResult ->
            if (r.done) unknownDeletionForgotten()
            if (settled(r)) forgetUnknownAskedFlow.value = null
        }
        // Said where the step is drawn: the deletion section's own place on the deletion screen, the screen's otherwise.
        if (section != null) runIn(section, { forgetAfterUnknownDeletion(asked) }, words, after) else runSaying({ forgetAfterUnknownDeletion(asked) }, words, after)
    }

    private var lastPhase: AppPhase? = null

    /** A lock, or a check that is no longer the one the second step was opened for, closes the second step. */
    private fun followForgetUnknown(s: AppSnapshot) {
        val locked = s.phase == AppPhase.LOCKED && lastPhase != null && lastPhase != AppPhase.LOCKED
        lastPhase = s.phase
        val asked = forgetUnknownAskedFlow.value ?: return
        if (locked || forgetUnknownCheck() !== asked) forgetUnknownAskedFlow.value = null
    }

    /** Run [block] for the app's own bookkeeping around the shared code; a fault there is contained and said above. */
    private inline fun contained(block: () -> Unit) {
        try {
            block()
        } catch (t: Throwable) {
            if (!Contained.isFault(t)) throw t
            fault(null)
        }
    }

    /** The open vault's content as the app reaches it, every call contained ([GuardedContent]); null when none is open. */
    fun contentNow(): VaultContent? {
        val raw = try {
            api.content
        } catch (t: Throwable) {
            if (!Contained.isFault(t)) throw t
            fault(null)
            return null
        }
        val shown = contentFlow.value as? GuardedContent
        return when {
            raw == null -> null
            shown != null && shown.inner === raw -> shown
            else -> GuardedContent(raw, onFault = ::fault)
        }
    }

    /**
     * andvari's own window came on show (not the autofill window, which shares the process). A vault the autofill window
     * opened for filling while the account's kit is not confirmed
     * ([io.silencelen.andvari.core.app.AccountSnapshot.kitDueAtOpening]) is locked first: quick unlock stays off until a
     * kit is confirmed, so the next unlock is with the master password and shows the fresh kit. Contained.
     */
    fun openedAsTheApp() = contained {
        val s = api.snapshot
        if (s.phase == AppPhase.UNLOCKED && s.account?.kitDueAtOpening == true) lockNow()
    }

    /**
     * The app came back to the foreground (the one lifecycle event the API takes besides lock()), contained. A lock that
     * fell due while the app was away (the kit's own limit, or the app's window, counted while the phone slept too) is
     * made FIRST, and only then is the shared code told that the app is back: told first, it would take a kit that was
     * never drawn as seen.
     */
    fun returnedToForeground() {
        contained {
            val s = api.snapshot
            if (locksNow(s) && idleLockDueInMs(s) == 0L) lockNow()
        }
        away = false
        contained { api.returnedToForeground() }
        contained { refreshKeepScreenOn(api.snapshot) }
    }

    /**
     * The platform says a network is back: live updates alone are told ([AppApi.networkReturned]),
     * in the foreground and the background alike; nothing is read or synced. Contained.
     */
    fun networkReturned() = contained { api.networkReturned() }

    /** [AppApi.start] (idempotent), contained: a fault in it is said, and the app's screens still come up. */
    fun start() = contained { api.start() }

    internal fun note(place: Place, r: IntentResult, text: UiText? = UiText.forResult(r, api.retryAfterSeconds()), section: String? = null) {
        saidFlow.value = text?.let { Said(place, r, it, section) }
    }

    // ---- app links ----

    private var pendingLink: String? = null

    /** The link kept for later, if any (for tests). */
    val heldLink: String? get() = pendingLink

    /** Whether [url] is this app's one app link: `https://<join host>/l`, with its fragment. */
    fun isAppLink(url: String): Boolean {
        val u = runCatching { URI(url) }.getOrNull() ?: return false
        val base = runCatching { URI(joinBase) }.getOrNull() ?: return false
        return u.scheme == "https" && u.host != null && u.host == base.host && u.port == -1 && u.rawPath == "/l"
    }

    /**
     * A link the system handed to the activity. Anything but the `/l` app link is dropped unopened. The link is
     * opened at once when a person can see what it opens, else kept and opened from [onSnapshot].
     */
    fun openLink(url: String) {
        if (!isAppLink(url)) return
        pendingLink = url
        tryPendingLink(api.snapshot)
    }

    // ---- a device link made on this phone ----

    /**
     * The device-link screen was left (Back, or it left the screen for any other reason): a running link is cancelled at
     * the server and closed; an approved or ended one is closed. Nothing is said: the person left. A lock and the end of
     * the session cancel it in core, and the screen is gone by then, so this finds no link.
     */
    fun leaveDeviceLink() {
        val host = api.snapshot.account?.deviceLink ?: return
        if (deviceLinkRunning(host)) {
            // A lock overtaking the cancel: core cancels the link at the lock itself, and the screen is gone.
            scope.launchOvertakable {
                val r = api.devices.cancelDeviceLink()
                when {
                    r.done -> api.devices.dismissDeviceLink()
                    // The link ended meanwhile (approved, or another end): closing it is all that is left.
                    r == io.silencelen.andvari.core.app.PlainResult.STALE -> api.devices.dismissDeviceLink()
                    // Never swallowed: the link is still on show, and the screen says why it was not cancelled.
                    else -> note(placeOf(api.snapshot), r, wordsFor(r), DEVICE_LINK_SECTION)
                }
            }
        } else {
            api.devices.dismissDeviceLink()
        }
    }

    // ---- how an account deletion ended, once its screen is gone ----
    // A deletion that is done is said by the shared code's own first-screen notice (EntryScreen.FirstRun.accountDeleted),
    // shown once and dismissed with entry.dismissNotice. Only an outcome nobody can tell yet is the app's own here.

    /** A deletion of this account ([AccountSnapshot.accountId]) answered with no outcome, and no check has said the account is there. */
    private var deletionUnknownFor: String? = null

    /** Call with what a deletion answered. */
    fun deletionAnswered(r: io.silencelen.andvari.core.app.DeletionResult) {
        personEndAnswered(r == io.silencelen.andvari.core.app.DeletionResult.DONE || r == io.silencelen.andvari.core.app.DeletionResult.OUTCOME_UNKNOWN)
        if (r == io.silencelen.andvari.core.app.DeletionResult.DONE) deletionUnknownFor = null
        // The session may have ended before the answer was taken: the account it was asked for counts.
        if (r == io.silencelen.andvari.core.app.DeletionResult.OUTCOME_UNKNOWN) deletionUnknownFor = api.snapshot.account?.accountId ?: lastAccountId
        personEnded(r)
    }

    private var lastAccountId: String? = null

    /** The address and the server of the last account open here: the account a deletion with no outcome was for. */
    private var lastAccountAt: Pair<String, String?>? = null

    /**
     * Whether this phone still keeps a copy of the account whose deletion nobody can tell yet: on the lock screen (its
     * session is stored), and on the first screen only while the account kept there ([AppSnapshot.keptSignedOut]) is
     * that one. Once that copy was signed out, the line must not say it is kept.
     */
    fun deletionCopyKept(s: AppSnapshot = api.snapshot): Boolean {
        if (s.phase == AppPhase.LOCKED) return true
        val kept = s.keptSignedOut ?: return false
        val at = lastAccountAt ?: return false
        return kept.email.equals(at.first, ignoreCase = true) && (at.second == null || kept.instance.origin == at.second)
    }

    private fun followDeletion(s: AppSnapshot) {
        val account = s.account
        if (account != null) {
            lastAccountId = account.accountId
            lastAccountAt = account.email to s.instance?.label?.origin
        }
        val deletion = account?.deletion
        when {
            deletion?.outcomeUnknown == true -> deletionUnknownFor = account.accountId
            // Another account opened here: an earlier one's unknown outcome is not this one's.
            account != null && account.accountId != deletionUnknownFor -> deletionUnknownFor = null
            // The preview or a check answered with the account there: it was not deleted.
            account != null && deletion != null && deletion.plan != null -> deletionUnknownFor = null
        }
    }

    /**
     * The deletion's outcome is still unknown and the vault is no longer open: a lock, or the end of the session, which
     * after an unknown outcome cannot be told from the deletion's own (the account-deletion design, step 7). The lock
     * screen and the first screen say andvari cannot tell yet; never "deleted".
     */
    fun deletionCannotTell(s: AppSnapshot = api.snapshot): Boolean = deletionUnknownFor != null && s.phase != AppPhase.UNLOCKED

    // ---- the name this account goes by in its links (§6.7) ----

    /**
     * What the person asked for that sends the account's name in a link: making a connect link or an invitation,
     * "Connect" on an opened link, or sending again the answer a sign-in still owes. Each waits for the name when this
     * phone keeps none, and goes on once the person typed one.
     */
    sealed class LinkAct {
        class MakeConnectLink(val shares: List<ShareChoice>, val minutes: Int) : LinkAct()
        class MakeInvitation(val minutes: Int) : LinkAct()
        class Connect(val opened: OpenedInvite.Connect) : LinkAct()
        class RetryConnection(val prompt: AccountPrompt.ConnectionNotMade) : LinkAct()
    }

    /**
     * The question for the name ([CopyKey.LINK_NAME_NEEDED]) and the act that waits for it. [refused] is the sentence
     * of a name the shared code did not keep ([CopyKey.LINK_NAME_NOT_A_NAME]); the field keeps what was typed, [typed],
     * which is only ever the person's own text.
     */
    class NameAsk internal constructor(val act: LinkAct, internal val after: (IntentResult) -> Unit, val refused: CopyKey?, val typed: String = "")

    private val nameAskFlow = MutableStateFlow<NameAsk?>(null)

    /** The open question for the name, if any ([LinkNameDialog]). */
    val nameAsk: StateFlow<NameAsk?> get() = nameAskFlow

    /**
     * Do [act]. The shared code keeps no name for an account made on another device, and the server serves none, so
     * when [LinksApi.ownName] is null, or the call answers `NAME_NEEDED` (nothing was made or sent), the person is asked
     * for it first ([nameAsk]); the app never fills one in. [after] sees the act's result once it ran.
     */
    fun linkAct(act: LinkAct, after: (IntentResult) -> Unit = {}) {
        if (api.links.ownName() == null) {
            nameAskFlow.value = NameAsk(act, after, null)
            return
        }
        val intent: suspend AppApi.() -> IntentResult = when (act) {
            is LinkAct.MakeConnectLink -> { { links.createConnectLink(act.shares, act.minutes) } }
            is LinkAct.MakeInvitation -> { { links.createInvitation(act.minutes) } }
            is LinkAct.Connect -> { { links.connect(act.opened) } }
            is LinkAct.RetryConnection -> { { links.retryConnection(act.prompt) } }
        }
        // NAME_NEEDED is said by the question itself, not as a refusal under the screen's top.
        runSaying(intent, { r -> if (nameNeeded(r)) null else wordsFor(r) }) { r ->
            if (nameNeeded(r)) current(act, api.snapshot)?.let { nameAskFlow.value = NameAsk(it, after, null) } else after(r)
        }
    }

    private fun nameNeeded(r: IntentResult): Boolean = r == LinkCreateResult.NAME_NEEDED || r == ConnectResult.NAME_NEEDED

    /**
     * The person's answer to the question for the name: kept exactly as typed ([LinksApi.setOwnName]), then the act
     * that waited goes on. A name the shared code refuses keeps the question open with its sentence; nothing was kept.
     */
    fun giveOwnName(name: String) {
        val ask = nameAskFlow.value ?: return
        val place = placeOf(api.snapshot)
        val r = api.links.setOwnName(name)
        when {
            r == OwnNameResult.DONE -> {
                nameAskFlow.value = null
                val act = current(ask.act, api.snapshot)
                if (act != null) linkAct(act, ask.after)
            }
            r == OwnNameResult.NOT_A_NAME -> nameAskFlow.value = NameAsk(ask.act, ask.after, CopyKey.LINK_NAME_NOT_A_NAME, name)
            else -> {
                nameAskFlow.value = null
                if (overtakenByLock(place, r)) lockOvertook() else note(place, r, wordsFor(r))
            }
        }
    }

    /** Close the question for the name: nothing is kept, and the act that waited is not done. */
    fun dropNameAsk() {
        nameAskFlow.value = null
    }

    /** The question for the name goes with the open vault, and with the opened link or the prompt its act was for. */
    private fun followNameAsk(s: AppSnapshot) {
        val ask = nameAskFlow.value ?: return
        if (current(ask.act, s) == null) nameAskFlow.value = null
    }

    /**
     * [act] as it stands in [s]: null once the vault is closed, the opened link was put away, or no connection is owed
     * to that person any more. The prompt for an owed connection is republished when its reason changes (it then says
     * the name is needed), so it is found again by the person it is for.
     */
    private fun current(act: LinkAct, s: AppSnapshot): LinkAct? {
        val account = s.account?.takeIf { s.phase == AppPhase.UNLOCKED } ?: return null
        return when (act) {
            is LinkAct.Connect -> act.takeIf { account.opened === act.opened }
            is LinkAct.RetryConnection -> account.prompts.filterIsInstance<AccountPrompt.ConnectionNotMade>()
                .firstOrNull { it.canRetry && it.from == act.prompt.from }?.let { if (it === act.prompt) act else LinkAct.RetryConnection(it) }
            else -> act
        }
    }

    /** Call on every snapshot: a kept link is opened once the app can show it. */
    fun onSnapshot(s: AppSnapshot) {
        if (s.entry !is EntryScreen.Kit) kitCoverFlow.value = false
        followKitOnShow(s)
        followKitRefusal(s)
        if ((s.entry as? EntryScreen.SignIn)?.codeNeeded != true) codeSpentFlow.value = false
        if (s.phase != AppPhase.ENTRY || (s.entry as? EntryScreen.FirstRun)?.let { it.heldAsOperator == null } == true) removeHeldAskFlow.value = false
        followNameAsk(s)
        followDeletion(s)
        followForgetUnknown(s)
        // Each step reaches the shared code; a fault in one is contained and the others still run.
        contained { refreshContent(s) }
        contained { refreshUnreadable(s) }
        checkAutofillOwner(s)
        contained { tryPendingLink(s) }
    }

    private var linkRunning = false

    private fun tryPendingLink(s: AppSnapshot) {
        val url = pendingLink ?: return
        if (linkRunning || s.busy || !canShowLink(s)) return
        linkRunning = true
        val place = placeOf(s)
        // A lock overtaking the opening keeps the link for the next chance, as STALE does.
        scope.launchOvertakable(onLock = { linkRunning = false }) {
            val r = api.openAppLink(url)
            linkRunning = false
            // STALE: the app could not take it after all (a kit came up meanwhile); keep it for the next chance.
            if (r != InviteResult.STALE) {
                pendingLink = null
                // The already-signed-in refusal is said by the account screen in the owner's words (inviteNotUsed).
                if (r == InviteResult.NOT_USABLE_SIGNED_IN && api.snapshot.account?.inviteNotUsed != null) note(place, r, null) else note(place, r)
            }
        }
    }

    /** §12.1, IF-3: a link is acted on only when a person can see what it opens, and never over a screen that cannot be left. */
    private fun canShowLink(s: AppSnapshot): Boolean = when (s.phase) {
        AppPhase.UNLOCKED -> true
        AppPhase.ENTRY -> when (s.entry) {
            is EntryScreen.Kit, is EntryScreen.ServerSetup,
            is EntryScreen.LinkDeviceWaiting, is EntryScreen.LinkDeviceCode, is EntryScreen.LinkDevicePassword,
            null -> false
            else -> true
        }
        AppPhase.STARTING, AppPhase.LOCKED -> false
    }

    // ---- locking ----

    private var lastActivityMs: Long = monotonicMs()

    /** The person touched or typed. */
    fun touched() {
        lastActivityMs = monotonicMs()
        kitIdleWarningFlow.value = null
    }

    private val kitIdleWarningFlow = MutableStateFlow<io.silencelen.andvari.core.app.CopyLine?>(null)

    /**
     * The shared code's warning, its slot filled ([io.silencelen.andvari.core.app.KitScreen.idleWarning]: the short line
     * names the limit), while a kit with an idle limit of its own is about to be locked away: from
     * [io.silencelen.andvari.core.app.KitScreen.idleWarnBeforeMs] before that limit until the lock. A touch or a key ends
     * it and starts the count again. Null otherwise.
     */
    val kitIdleWarning: StateFlow<io.silencelen.andvari.core.app.CopyLine?> get() = kitIdleWarningFlow

    /**
     * When the kit on show came on show (by "a kit is on show", not by the screen object: a step change gives a new one),
     * on [monotonicMs]'s clock; null while none is. The kit's idle count starts there, or at the last touch after it.
     */
    private var kitOnShowSinceMs: Long? = null

    private fun followKitOnShow(s: AppSnapshot) {
        if (!kitOnShow(s)) {
            kitOnShowSinceMs = null
            kitIdleWarningFlow.value = null
        } else if (kitOnShowSinceMs == null) {
            kitOnShowSinceMs = monotonicMs()
        }
    }

    /** Call about once a second while the app is visible (the activity started): locks an open vault after the idle window. */
    fun tick() = contained { tickNow() }

    /**
     * How long until the idle lock acts on what [s] shows, on [monotonicMs]'s clock (zero once it is due), or null where
     * nothing is under the lock clock ([locksNow]). A kit with a limit of its own counts it from the later of its coming on
     * show and the last touch or key; everything else counts the app's window ([autoLockMs]) from the last touch or key.
     * The hard lock ([io.silencelen.andvari.app.autofill.ContentFillSession.HardLock]) waits this long while the app is
     * not in the foreground (behind the system's print screen, after an unlock from the autofill window).
     */
    internal fun idleLockDueInMs(s: AppSnapshot = api.snapshot): Long? {
        if (!locksNow(s)) return null
        val now = monotonicMs()
        val kitLimit = kitUnderClock(s)?.idleLockAfterMs
        val left = if (kitLimit != null) kitLimit - (now - maxOf(lastActivityMs, kitOnShowSinceMs ?: now)) else autoLockMs() - (now - lastActivityMs)
        return left.coerceAtLeast(0L)
    }

    private fun tickNow() {
        val s = api.snapshot
        followKitOnShow(s)
        val now = monotonicMs()
        val idle = now - lastActivityMs
        // Every kit carries the shared code's limit (the lock time of the policy kept for its server, five minutes where
        // none is kept, at most five for a kit shown with a refusal) and its warning: counted on this one timer from the
        // later of the kit coming on show and the last touch or key. At the limit the app locks; the lock wipes the kit
        // (and, for one shown with a refusal, the shared code then says so above the screen, AppSnapshot.kitWiped). The
        // app's own window stays only for a kit that carries no limit.
        val kit = kitUnderClock(s)
        val kitLimit = kit?.idleLockAfterMs
        if (kit != null && kitLimit != null) {
            val onKit = now - maxOf(lastActivityMs, kitOnShowSinceMs ?: now)
            val warnFrom = kitLimit - (kit.idleWarnBeforeMs ?: 0L)
            kitIdleWarningFlow.value = kit.idleWarning?.takeIf { onKit in warnFrom until kitLimit }
            if (onKit >= kitLimit) {
                kitIdleWarningFlow.value = null
                lockNow()
            }
            refreshKeepScreenOn(api.snapshot)
            return
        }
        kitIdleWarningFlow.value = null
        // Every other kit step holds the account's keys too, and lock() acts there (the kit is wiped; the next unlock makes
        // a fresh one) at the app's own window, as the desktop's idle timer does.
        if (locksNow(s) && idle >= autoLockMs()) lockNow()
        // A verified recovery left unattended on its new-password screen is dropped (the old wizard's five minutes,
        // HealthSurfaceTest's recoverTimedOut). Core runs no timer for it: IF-3 leaves it to the app (startOver).
        if (s.entry is EntryScreen.ReplacePassword && idle >= RECOVERY_IDLE_MS) {
            api.entry.startOver()
            say(UiText.ph(Placeholder.RECOVERY_IDLE_DROPPED))
        }
        refreshKeepScreenOn(api.snapshot)
    }

    /** What the idle window and the background lock act on: an open vault, and the kit step (its keys are open). */
    internal fun locksNow(s: AppSnapshot): Boolean = s.phase == AppPhase.UNLOCKED || s.entry is EntryScreen.Kit

    /** A recovery kit is on show in [s]: the journey's kit step, or a kit made in Settings over the open vault. */
    internal fun kitOnShow(s: AppSnapshot): Boolean = kitUnderClock(s) != null

    /** The kit on show in [s] whose own limit and warning the idle clock runs from: the journey's, or the Settings one. */
    private fun kitUnderClock(s: AppSnapshot): io.silencelen.andvari.core.app.KitScreen? =
        (s.entry as? EntryScreen.Kit)?.kit ?: s.account?.kit?.takeIf { s.phase == AppPhase.UNLOCKED }

    /**
     * The app went to the background: an open vault locks (the old app's lock-on-background, design 2026-08-23 §7),
     * and so does the kit step: core's `lock()` acts there now, wiping the kit and the keys; the next unlock makes a
     * fresh kit. The kit is also covered, so a kit step lock() leaves in place (none with keys open) is not shown.
     */
    fun backgrounded() = contained { backgroundedNow() }

    private fun backgroundedNow() {
        away = true
        // The shared code is told first, so that a kit it publishes from here on is known as never seen.
        contained { api.wentAway() }
        val s = api.snapshot
        if (s.entry is EntryScreen.Kit) cover()
        if (locksNow(s)) lockNow()
        // As the old app's lock-on-background did for its recovery wizard: a verified recovery does not wait in the background.
        if (s.entry is EntryScreen.ReplacePassword) api.entry.startOver()
        refreshKeepScreenOn(api.snapshot)
    }

    /**
     * The app's process left the foreground in a way that does not lock now (an excursion such as the system's print
     * screen, or an autofill window closing): nothing of the app is on show, so a kit that comes on show from here on is
     * locked away at once ([followSnapshots]). The hard lock keeps the clock meanwhile. A kit on show is covered, as on
     * the other roads away, so that the return shows nothing of it before the clock's own lock lands (one that fell due
     * while the phone slept included).
     */
    fun wentAway() = contained {
        away = true
        // The shared code is told as the app's own mark is set ([AppApi.wentAway]): a kit it publishes meanwhile and a
        // lock then wipes is said as never shown.
        contained { api.wentAway() }
        if (kitOnShow(api.snapshot)) cover()
        refreshKeepScreenOn(api.snapshot)
    }

    /**
     * Nothing of the app is on show: set by [backgrounded] and [wentAway], cleared by [returnedToForeground]. A kit that
     * comes on show meanwhile (the answer of a commit asked before the person left) is never drawn at the return.
     */
    private var away = false

    /** Whether a kit was on show in the last snapshot [followSnapshots] saw: a kit's arrival is the change to one. */
    private var kitWasOnShow = false

    /** How many kits came on show while the app was away and were locked away at once. */
    private var kitsLockedAway = 0

    /**
     * The model's own subscription to the shared code's snapshots, whatever the app's lifecycle state (the composition
     * stops collecting below STARTED, and so does the timer): when a kit came on show is recorded here, as
     * the shared code publishes it. A kit that comes on show while the app is away is locked at once, the ordinary one
     * included (the lock wipes it and its keys; the shared code's notice or the next unlock then says what happened), and
     * covered in case the lock leaves it in place. Whatever the app itself still holds of a kit for printing is dropped
     * as soon as no kit is on show ([KitHolds]).
     */
    private fun followSnapshots(s: AppSnapshot) {
        val onShow = kitOnShow(s)
        val arrived = onShow && !kitWasOnShow
        kitWasOnShow = onShow
        followKitOnShow(s)
        followPersonEnd(s)
        if (!onShow) KitHolds.dropAll()
        if (arrived && away) {
            if (s.entry is EntryScreen.Kit) cover()
            kitsLockedAway++
            lockNow()
            if (!kitOnShow(api.snapshot)) KitHolds.dropAll()
        }
        refreshKeepScreenOn(api.snapshot)
    }

    private val kitCoverFlow = MutableStateFlow(false)

    /** What the kit screens draw from; emptied by every lock and every cover, whether or not anything recomposes. */
    internal val kitScreen = KitScreenHold()

    /** The model's own lock of what is under the clock: whatever the screens hold of a kit goes with it. */
    private fun lockNow() {
        forgetUnknownAskedFlow.value = null
        api.lock()
        kitScreen.drop()
    }

    /** The kit on show is covered: out of the screens' memory until "Show the kit again" makes it again. */
    private fun cover() {
        kitCoverFlow.value = true
        kitScreen.drop()
    }

    /** The kit before the vault opens was left in the background and is covered ([backgrounded]). */
    val kitCovered: StateFlow<Boolean> get() = kitCoverFlow

    /** "Show the kit again" on the cover. */
    fun uncoverKit() {
        kitCoverFlow.value = false
        refreshKeepScreenOn(api.snapshot)
    }

    private val keepScreenOnFlow = MutableStateFlow(false)

    /**
     * While a kit is on show (not covered, the app in the foreground), the phone's screen stays on until the kit's own
     * limit, so that the limit and its warning end it and not the phone's screen timeout without a word. Nothing else
     * keeps the screen on, and this goes the moment no kit is on show.
     */
    val keepScreenOn: StateFlow<Boolean> get() = keepScreenOnFlow

    private fun refreshKeepScreenOn(s: AppSnapshot) {
        keepScreenOnFlow.value = !away && !kitCoverFlow.value && kitOnShow(s) && (idleLockDueInMs(s) ?: 0L) > 0L
    }

    // ---- a session the server ended ----

    /**
     * The open vault is the copy of a session the server ended (design §4.4), opened read-only: the account's own
     * [io.silencelen.andvari.core.app.AccountSnapshot.signedOutByServer], never inferred from an earlier lock screen
     * (an earlier version followed the snapshots itself while core did not carry it).
     */
    fun openedSignedOutByServer(s: AppSnapshot = api.snapshot): Boolean = signedOutCopy(s)

    companion object {
        /** The old app's default auto-lock window (spec 01 §8), used while no account's policy is open. */
        const val DEFAULT_AUTO_LOCK_MS: Long = 5L * 60 * 1000

        /** The old app's default clipboard window, used while no account's policy is open. */
        const val DEFAULT_CLIPBOARD_CLEAR_S: Int = 30

        /** The old recovery wizard's idle limit on a verified recovery (`VM:133-139`): 300 seconds. */
        const val RECOVERY_IDLE_MS: Long = 300L * 1000

    }

    // Last in the class, so that everything it reaches is initialised: the subscription runs at once on an immediate
    // dispatcher, with the snapshot on show now.
    init {
        scope.launch {
            try {
                api.snapshots.collect { s -> contained { followSnapshots(s) } }
            } catch (t: Throwable) {
                if (!Contained.isFault(t)) throw t
                fault(null)
            }
        }
    }
}

/** The open vault is a copy the server signed out ([io.silencelen.andvari.core.app.AccountSnapshot.signedOutByServer]). */
fun signedOutCopy(s: AppSnapshot): Boolean = s.phase == AppPhase.UNLOCKED && s.account?.signedOutByServer == true
