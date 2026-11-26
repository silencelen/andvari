package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.AppApi
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.DeletionResult
import io.silencelen.andvari.core.app.DeletionScreen
import io.silencelen.andvari.core.app.DesktopAppApi
import io.silencelen.andvari.core.app.DeviceLinkHost
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.InstanceCardState
import io.silencelen.andvari.core.app.InstanceSnapshot
import io.silencelen.andvari.core.app.IntentResult
import io.silencelen.andvari.core.app.ServerPolicy
import io.silencelen.andvari.core.app.Subscription
import io.silencelen.andvari.core.app.Trouble
import io.silencelen.andvari.core.app.content.ContentState
import io.silencelen.andvari.core.app.content.VaultContent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

/**
 * The new path's state holder on desktop: a thin layer over [DesktopAppApi] (onboarding and trust design §18.1,
 * IF-3), ported from the Android app's `TrustModel`. Core owns where the app is ([AppApi.snapshots]); this holds only
 * what core leaves to the app:
 *
 * - **What an intent answered**, shown in place ([said]) on the screen it was answered on. It goes as soon as the
 *   screen changes, so a refusal never lingers on a screen it was not about.
 * - **The update notice** ([updateRequiredOn]): core's [InstanceSnapshot.updateRequired] for the session's server. A
 *   notice above a vault that stays open and readable, never a wall.
 * - **Locking** ([touched], [tick], [lockNow]): the API keeps no idle clock; the app calls [AppApi.lock]. The desktop
 *   locks on idle and on Ctrl+L, as the old app did; it has no lock-on-background and no quick unlock.
 * - **Keeping the sign-in on this computer** ([keepSignIn]), the desktop's opt-in.
 *
 * The desktop takes **no app links** (design §6.7: "On desktop the button is Paste an invite link"); nothing here or
 * in any screen calls [AppApi.openAppLink], and the build registers no URL handler.
 *
 * No Compose type appears here, so the JVM tests drive it against the fake.
 *
 * @param monotonicMs a clock the person cannot set. On Linux it stops while the computer sleeps.
 * @param wallMs the wall clock, which keeps counting through sleep. Idle time is read on
 *   both and the larger reading counts ([TwoClockMark]); tests that do not care pass the monotonic one twice.
 */
class TrustModel(
    val api: DesktopAppApi,
    private val scope: CoroutineScope,
    private val monotonicMs: () -> Long,
    private val keeping: SignInKeeping = SignInKeeping.Never,
    private val wallMs: () -> Long = monotonicMs,
    private val faultLog: (String) -> Unit = io.silencelen.andvari.desktop.DesktopDiagnostics::log,
    private val clearClipboard: () -> Unit = { io.silencelen.andvari.desktop.clearVaultClipboard() },
) {
    val snapshots: StateFlow<AppSnapshot> get() = api.snapshots

    // ---- the vault's content ----

    private val contentFlow = MutableStateFlow<VaultContent?>(null)

    /**
     * The open vault's content: [AppApi.content], read again whenever a snapshot arrives, and null in every phase but
     * [AppPhase.UNLOCKED]. Core makes a new instance at every unlock and closes the old one at a lock, so nothing here
     * keeps one across a lock.
     */
    val content: StateFlow<VaultContent?> get() = contentFlow

    /**
     * Call on every snapshot. Each part follows on its own: one that the shared code makes throw is a fault
     * ([faulted]) and the others still follow, so the next snapshot is followed as well.
     */
    fun onSnapshot(s: AppSnapshot) {
        if (s.phase == AppPhase.UNLOCKED && unlockedBefore != AppPhase.UNLOCKED) {
            unlocksFlow.value += 1
            lockedHere = false
        }
        unlockedBefore = s.phase
        val now = if (s.phase == AppPhase.UNLOCKED) Overtaken.read(fault, null, contentFlow.value) { api.content } else null
        quietly { refreshContent(s, now) }
        // An import asked for under a vault that has since locked is not carried into the next unlock.
        if (now == null) importFlow.value = false
        // A restore belongs to the content it was opened over: a lock, or another content, ends it on screen.
        if (restoreFlow.value?.content.let { it != null && it !== now }) restoreFlow.value = null
        quietly { keepFollows(s) }
        quietly { keepRefresh() }
        quietly { devicesFollowTheLink(s) }
        quietly { operator.onSnapshot(s) }
        quietly { kitResultFollows(s) }
        quietly { forgetFollows(s) }
        // A print of a kit lasts only as long as a kit is on show: once none is, nothing of it is held for a print.
        // A kit that went with a lock of another road (the lock screen now on show) is the lock's too.
        if (!showsAKit(s)) dropKitPrints(byLock = s.phase == AppPhase.LOCKED)
        // A lock (or the session's end) puts the name window away; the next unlock does not open it again.
        if (s.phase != AppPhase.UNLOCKED) linkName.cancel()
    }

    // ---- what the shared code threw that nobody expected ----

    /** The last fault logged, so one that repeats at each tick or redraw is logged once, not once a second. */
    private var lastLogged: String? = null

    /**
     * Something the shared code threw that is neither the lock nor a cancellation: said on the screen on show as
     * "something went wrong" ([Placeholder.SOMETHING_WENT_WRONG], or [Placeholder.SOMETHING_WENT_WRONG_IN_VAULT]
     * naming [vault] for work on one vault), with nothing of the exception; the log gets its class name and nothing
     * else (no message, no trace: either could hold a secret). Nothing is locked or
     * closed for it, so every other vault, the lock and the rest of the app go on. A "keys are gone" is the lock
     * ([lockOvertook]), as before.
     */
    fun faulted(t: Throwable, vault: String? = null) = faulted(t, vault, background = false)

    /** [faulted]; [background]: thrown in the shared code's own work, not in anything on show, which is said as that. */
    private fun faulted(t: Throwable, vault: String?, background: Boolean) {
        if (Overtaken.isLock(t)) return lockOvertook()
        val cls = faultClass(t)
        val line = "something went wrong :: $cls" + (if (vault != null) " (one vault)" else "") + (if (background) " (background)" else "")
        if (line != lastLogged) {
            lastLogged = line
            runCatching { faultLog(line) }
        }
        // Each slot its own value, one by one: the vault's name, or nothing. The kind of error goes to the log only, as the
        // approved words for these lines leave it out (it means nothing to a person).
        val text = when {
            vault != null -> UiText.ph(Placeholder.SOMETHING_WENT_WRONG_IN_VAULT, plainName(vault))
            // "Here" and "nothing else was affected" are not known of the shared code's own work (a sync, the save
            // queue, a session's end), which nothing on show asked for.
            background -> UiText.ph(Placeholder.SOMETHING_WENT_WRONG_IN_BACKGROUND)
            else -> UiText.ph(Placeholder.SOMETHING_WENT_WRONG)
        } as UiText.Ph
        val place = runCatching { placeOf(api.snapshot) }.getOrNull() ?: return
        // The same fault said again (a redraw that throws each time) changes nothing, so it draws nothing again.
        val now = saidFlow.value
        val same = now != null && now.place == place && (now.text as? UiText.Ph)?.let { it.placeholder == text.placeholder && it.args == text.args } == true
        if (!same) saidFlow.value = Said(place, null, text)
    }

    /** The class a fault names: the class's own short name, never its message. */
    private fun faultClass(t: Throwable): String = t.javaClass.simpleName.ifEmpty { "Exception" }

    /** [faulted], as the screens and the scopes take it. */
    internal val fault: FaultSink = FaultSink { t, vault -> faulted(t, vault) }

    /**
     * Something the shared code threw in its own scope (the engine's, which the desktop builds over [TrustSeam]'s
     * handler): a fault said where the person is. A "keys are gone" there is a lock that already happened, possibly
     * of an earlier session: nothing is done for it, so a vault opened since is never locked by it.
     */
    fun faultedInBackground(t: Throwable) {
        if (Overtaken.isLock(t) || t is kotlinx.coroutines.CancellationException) return
        faulted(t, null, background = true)
    }

    /** Run [block], which calls the shared code, as a fault rather than a crash; nothing said is cleared. */
    fun quietly(block: () -> Unit) {
        try {
            block()
        } catch (t: Throwable) {
            if (t is kotlinx.coroutines.CancellationException) throw t
            faulted(t)
        }
    }

    /** A read of the shared code (a countdown, say): [fallback] when it threw, as a fault ([faulted]). */
    fun <T> readOr(fallback: T, read: () -> T): T = Overtaken.read(fault, null, fallback, read)

    /** The app interface's one lifecycle event (the window is the desktop's foreground), as a fault rather than a crash. */
    fun returnedToForeground() = quietly { api.returnedToForeground() }

    /**
     * Nothing of the app is on show any more, and nothing locked (the window minimised or hidden): the shared code is told,
     * so that a kit which comes on show meanwhile and is wiped before the return is never said as the kit that was on the
     * screen ([io.silencelen.andvari.core.app.KitWipedNotice.unseen]).
     */
    fun wentAway() = quietly { api.wentAway() }

    /**
     * The window is on show again: a lock that fell due meanwhile comes first ([tick]: the idle limit, a kit's own, a late
     * tick), and only then is the shared code told that the app is back, so a kit never drawn is never said as seen.
     */
    fun cameBack() {
        tick()
        returnedToForeground()
    }

    /**
     * The first thing the window does: the first-launch wipe (§12.4) and what this computer kept. An unexpected
     * exception there is said on the starting screen ([faulted]), never the end of the app.
     */
    fun start() = quietly { api.start() }

    /** The operator's console (design §9.2): only the operator account's open vault has one ([OperatorModel.available]). */
    val operator: OperatorModel = OperatorModel(this)

    /** The window that asks for the name this account's links carry, when this computer keeps none ([LinkNameAsk]). */
    internal val linkName: LinkNameAsk = LinkNameAsk(this)

    // ---- what a lock overtook on the open vault (the key fix) ----

    private var contentWatch: Subscription? = null

    /** The open content's last state; core stops telling it at close(), so after a lock this is the state the lock found. */
    @Volatile private var lastContentState: ContentState? = null

    private fun refreshContent(s: AppSnapshot, now: VaultContent?) {
        val old = contentFlow.value
        if (old !== now) {
            // Core closes the old content at a lock (or the session's end) before it wipes the keys; a new content
            // while the vault stays open (core composing it again) is not a lock.
            if (old != null && s.phase != AppPhase.UNLOCKED) contentClosed(lastContentState, s)
            contentWatch?.close()
            lastContentState = null
            contentWatch = now?.observe { lastContentState = it }
            contentFlow.value = now
        }
    }

    /**
     * The vault closed while a change of the person's ran on it (the content says busy): the lock screen says so at
     * the moment of the lock ([Placeholder.LOCK_OVERTOOK]). What the lock cut short, by kind and with counts, is the
     * shared code's own notice at the next unlock ([ContentState.notice] with [ContentState.noticeKind] LOCK and
     * [ContentState.lockCut]), shown with the vault's other notices; the desktop keeps no notice of its own any more.
     */
    private fun contentClosed(last: ContentState?, s: AppSnapshot) {
        if (last?.busy != true) return
        // Whether the change went through is not known (the content answers "not done" once closed): never "do it again".
        // Cut by the server's end only where andvari did not lock: a lock of its own in a session the server had ended
        // earlier is the lock (the check of 2026-11-18).
        if (s.phase == AppPhase.LOCKED) saidFlow.value = Said(placeOf(s), null, changeCutLine(s))
    }

    /**
     * What the lock screen says of a change cut short ([contentClosed]): the lock's line; the server's end where the server
     * ended the session and andvari did not lock; and where this computer could not confirm the session in time, that end
     * as the shared code says it, never as the server's.
     */
    internal fun changeCutLine(s: AppSnapshot): UiText {
        val end = if (lockedHere) null else notConfirmedEnd(null, s)
        return when {
            end != null -> UiText.ph(Placeholder.CHANGE_CUT_BY_NOT_CONFIRMED, UiText.of(end).shown())
            s.locked?.signedOutByServer == true && !lockedHere -> UiText.ph(Placeholder.CHANGE_CUT_BY_SERVER_END)
            else -> UiText.ph(Placeholder.CHANGE_CUT_BY_LOCK)
        }
    }

    private var linkBefore: DeviceLinkHost? = null

    /**
     * A device link this computer showed was approved: the devices list on show is read again, so the new device is in
     * it (core reads the list once, at its opening).
     */
    private fun devicesFollowTheLink(s: AppSnapshot) {
        val link = s.account?.deviceLink
        if (link is DeviceLinkHost.Approved && linkBefore !is DeviceLinkHost.Approved && s.account?.devices != null) {
            // The app's own re-read: the link was approved all the same, so a lock that cuts the re-read says nothing of
            // its own (a "do it again" would invite a second approval).
            scope.launchOvertakable(::lockedQuietly, fault) { api.devices.openDevices() }
        }
        linkBefore = link
    }

    private var unlockedBefore: AppPhase? = null
    private val unlocksFlow = MutableStateFlow(0)

    /**
     * How many times the vault has opened in this run. A new unlock starts the signed-in pages at home; core composing
     * the open vault again (a new [content] object, as "keep me signed in" switched off does) is not an unlock, so the
     * page on show stays.
     */
    val unlocks: StateFlow<Int> get() = unlocksFlow

    // ---- the menu's vault commands ----

    private val importFlow = MutableStateFlow(false)

    /** The menu's "Import" asked for the CSV import; the vault page opens its file dialog and calls [importTaken]. */
    val importRequested: StateFlow<Boolean> get() = importFlow

    /** The menu's Import: only while a vault is open (it is the content that imports). */
    fun requestImport() {
        if (contentFlow.value != null) importFlow.value = true
    }

    fun importTaken() {
        importFlow.value = false
    }

    // ---- "Restore a backup" ----

    private val restoreFlow = MutableStateFlow<RestoreFlow?>(null)

    /** The restore on show: only over the content it was opened over, so nothing of it survives a lock. */
    internal val restoring: StateFlow<RestoreFlow?> get() = restoreFlow

    /** A backup file was picked and read ([bytes], at most `Backup.MAX_FILE_BYTES`) for the vault open as [c]. */
    fun openRestore(c: VaultContent, fileName: String, bytes: ByteArray) {
        if (contentFlow.value === c) restoreFlow.value = RestoreFlow(api.restores, c, fileName, bytes)
    }

    fun closeRestore() {
        restoreFlow.value = null
    }

    /**
     * The menu's Sync now (and the top bar's): the open vault syncs as the person asked
     * ([VaultContent.refresh]: its notice says "Synced." or what went wrong). Nothing while the vault is locked.
     */
    fun syncNow(): Job? {
        val c = contentFlow.value ?: return null
        return scope.launchOvertakable(::lockOvertook, fault) { c.refresh() }
    }

    // ---- the client policy ----

    /**
     * The idle auto-lock window: the account's [io.silencelen.andvari.core.app.ServerPolicy.autoLockSeconds], which
     * core clamps (a server can only shorten it) and reports as its own default before any policy was read; the
     * same default while no account is open.
     */
    fun autoLockMs(): Long = (api.snapshot.account?.policy?.autoLockSeconds ?: ServerPolicy.DEFAULT_AUTO_LOCK_SECONDS) * 1000L

    /** How long a copied secret stays on the clipboard: the account's policy, which is core's default before it is read. */
    fun clipboardClearMs(): Long = (api.snapshot.account?.policy?.clipboardClearSeconds ?: ServerPolicy.DEFAULT_CLIPBOARD_CLEAR_SECONDS) * 1000L

    // ---- what an intent answered ----

    /** What the last intent answered, and where. */
    class Said internal constructor(internal val place: Place, val result: IntentResult?, val text: UiText)

    private val saidFlow = MutableStateFlow<Said?>(null)
    val said: StateFlow<Said?> get() = saidFlow

    /**
     * The session's server answered that this build is too old ([InstanceSnapshot.updateRequired], core's per-server
     * state). A notice, never a wall, and only for the session's own server (an answer
     * while signed out is said in place on its screen). While it stands the vault is read-only (core's content says
     * the server is stopped, and the desktop offers no save); it clears when a later answer from that server is not
     * "update required".
     */
    fun updateRequiredOn(s: AppSnapshot): Boolean =
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

    /** Run one intent. Its answer is shown in place on the screen it was asked on. [after] sees the result (to clear a field, say). */
    fun <R : IntentResult> run(intent: suspend DesktopAppApi.() -> R, after: (R) -> Unit = {}): Job = launchIntent(intent, null, after)

    /**
     * As [run], with the screen's own [words] for a result; [words] answering null says nothing. [failed] runs when the
     * intent threw something unexpected (a fault, said by [faulted]), for a screen that must put away what it opened.
     */
    fun <R : IntentResult> runSaying(intent: suspend DesktopAppApi.() -> R, words: (R) -> UiText?, failed: () -> Unit = {}, after: (R) -> Unit = {}): Job =
        launchIntent(intent, words, after, failed)

    /**
     * The one place where the desktop launches an intent. A lock can overtake it (the key fix): core then answers
     * STALE, or, on a path it has not converted yet, throws "the keys are gone". Either is said as the lock it is, where
     * the person now is (the lock screen), never as a failure or a wrong password ([lockOvertook]). For a throw [after]
     * is not called, so a screen still there keeps what was typed. Any other exception but a cancellation is a fault
     * said where it was asked ([faulted]), never a crash.
     */
    private fun <R : IntentResult> launchIntent(intent: suspend DesktopAppApi.() -> R, words: ((R) -> UiText?)?, after: (R) -> Unit, failed: () -> Unit = {}): Job {
        val place = placeOf(api.snapshot)
        saidFlow.value = null
        return scope.launch {
            val r = try {
                api.intent()
            } catch (t: Throwable) {
                if (t is kotlinx.coroutines.CancellationException && !Overtaken.isLock(t)) throw t
                if (Overtaken.isLock(t)) lockOvertook() else {
                    faulted(t)
                    runCatching { failed() }
                }
                return@launch
            }
            // The intent answered; only the handling of its answer met the wiped keys. A done answer was done.
            Overtaken.act({ if (r.done) doneAsTheKeysWent(r) else lockOvertook() }, fault) { answered(place, r, words, after) }
        }
    }

    /** What [launchIntent] does with an answer: said in place, then [after]. */
    private fun <R : IntentResult> answered(place: Place, r: R, words: ((R) -> UiText?)?, after: (R) -> Unit) {
        // A waiting change's act that answered STALE did nothing: the row is drawn again from the snapshot, and nothing is
        // said, also where a lock came between (the lock screen is drawn then; there is nothing to do again).
        if (r === io.silencelen.andvari.core.app.WaitingResult.STALE) {
            saidFlow.value = null
            after(r)
            return
        }
        if (overtakenByLock(place, r)) {
            lockOvertook()
        } else if (doneAsTheLockCame(place, r)) {
            // Done, but the screen it was asked on went with the lock before the answer came: the lock screen says
            // what was done (found in a run against a local server: a password change went through and nothing said so, and the
            // old password then read as wrong).
            saidFlow.value = Said(placeOf(api.snapshot), r, doneUnderLockWords(r))
        } else {
            val text = if (words != null) words(r) else UiText.forResult(r, api.retryAfterSeconds())
            val now = api.snapshot
            val carried = kitResultFlow.value
            when {
                // The answer that brought a kit this computer did not keep (a recovery or a registration committed, its
                // session refused): kept with that kit for as long as it is on show, on every step, and not as a bar a
                // later step clears.
                place.screen != EntryScreen.Kit::class.java && notKeptKitOf(now) != null -> {
                    val kit = notKeptKitOf(now)!!
                    kitResultFlow.value = KitResult(kit.email, kit.instance.origin, r, text)
                    saidFlow.value = null
                }
                // That kit was typed back: the journey is at the first screen, where the answer's way out (the kept
                // account's sign-out, the removal of a damaged copy) is offered now, with the shared code's line for that
                // moment in place of the answer's own sentence, which tells the person to save a kit that is gone.
                carried != null && r === io.silencelen.andvari.core.app.KitConfirmResult.DONE && place.screen == EntryScreen.Kit::class.java &&
                    notKeptKitOf(now) == null -> {
                    kitResultFlow.value = null
                    note(placeOf(now), carried.result, io.silencelen.andvari.core.app.KeptStops.lineWithoutKit(carried.result)?.let { UiText.of(it) } ?: carried.text)
                }
                // The session keeper's own refusal is said where the person now is: a kit's refusal, say, wipes the kit and
                // goes back to the screen it is handed in on, and the way on must be in view there. A screen that says the
                // stop itself (the request for the operator's help, a device link that ended) is not told twice.
                isKeeperAnswer(r) && !saysTheStopItself(now) -> note(placeOf(now), r, text)
                // A device link's step refused as too many ended the link: its own line says it, with the wait.
                endedLinkSaysIt(r, now) -> saidFlow.value = null
                else -> note(place, r, text)
            }
        }
        after(r)
    }

    /** The answer that brought a kit this computer did not keep, with the kit it belongs to. */
    internal class KitResult(val email: String, val origin: String, val result: IntentResult, val text: UiText?)

    private val kitResultFlow = MutableStateFlow<KitResult?>(null)
    internal val kitResult: StateFlow<KitResult?> get() = kitResultFlow

    /**
     * An open vault, a lock (which takes every kit on show off the screen, this one too: decided on 2026-11-17),
     * or a kit this computer keeps, means the kit the answer belonged to is over: the answer goes.
     */
    private fun kitResultFollows(s: AppSnapshot) {
        val entry = s.entry
        if (s.phase == AppPhase.UNLOCKED || s.phase == AppPhase.LOCKED || (entry is EntryScreen.Kit && entry.kit.notKeptLine == null)) {
            kitResultFlow.value = null
        }
        if (kitIdleLimitOf(s) == null) kitIdleWarningFlow.value = null
    }

    /**
     * The kit screen's idle limit from the shared code ([KitScreen.idleLockAfterMs], on every kit it makes, in the journey
     * and in Settings): the same one idle clock as the vault's lock ([tick]), with the kit's own figures.
     * [KitScreen.idleWarningLine] is on show from [KitScreen.idleWarnBeforeMs] before the limit, which is from the start of
     * the screen where the limit is not longer than that ([warnsFromStart]); a click, a scroll or a key puts it away at
     * once, except where it is shown from the start (a moving pointer does not count on a kit: [touched]). At the limit
     * the app locks, which wipes the kit; for a kit shown with a refusal the screen it leaves says so
     * ([AppSnapshot.kitWiped]). The app's own lock time ([autoLockMs]) is used only where a kit carries no limit.
     */
    private val kitIdleWarningFlow = MutableStateFlow<io.silencelen.andvari.core.app.CopyKey?>(null)
    internal val kitIdleWarning: StateFlow<io.silencelen.andvari.core.app.CopyKey?> get() = kitIdleWarningFlow

    /**
     * Asked once each time a kit's idle warning comes on show ([tick]); not again while it stays, and again for the next
     * warning after a touch put it away. The window sets its own ([WindowKitWarningSignal]); until then nothing is asked.
     */
    internal var kitWarningSignal: KitWarningSignal = KitWarningSignal.None

    /**
     * Locks what [lockable] holds; a kit this computer did not keep goes with the lock, and so does its kept answer. A
     * print of the kit goes too ([dropKitPrints]), and what the app put on the clipboard is cleared here, at every lock:
     * a lock of a kit shown with a refusal and no session established leaves the phase as it was, so the clear that
     * follows a phase change (TrustApp) does not come there (the check of 2026-11-18).
     */
    private fun lockHere(s: AppSnapshot) {
        if (showsNotKeptKit(s)) kitResultFlow.value = null
        kitIdleWarningFlow.value = null
        forgetAskedFlow.value = null
        dropKitPrints(byLock = true)
        if (s.phase == AppPhase.UNLOCKED) lockedHere = true
        try {
            api.lock()
        } finally {
            runCatching { clearClipboard() }
        }
    }

    /**
     * The vault was locked by andvari itself ([lockHere]: Ctrl+L, the menu, the idle limit, a screen's failure) since it
     * last opened: the lock screen's lines then say the lock, also in a session the server had ended earlier, whose
     * lines otherwise say that andvari did not lock. The next opening of the vault forgets it.
     */
    private var lockedHere = false

    // ---- what a print of a kit holds ----

    private val kitPrints = java.util.concurrent.CopyOnWriteArrayList<KitPrintHold>()

    /** A hold on [doc] for one print ([printKit]), dropped at the next lock or once no kit is on show. */
    internal fun holdForPrint(doc: io.silencelen.andvari.core.app.KitDocument): KitPrintHold {
        kitPrints.removeAll { !it.held }
        return KitPrintHold(doc).also { kitPrints += it }
    }

    /**
     * Every print of a kit lets go of it: its page source has no page from now on, and its job is cancelled. [byLock]: a
     * lock let go of it, which the print says when it returns ([printKit]).
     */
    internal fun dropKitPrints(byLock: Boolean = false) {
        for (h in kitPrints) h.drop(byLock)
        kitPrints.clear()
    }

    /** A kit is on show in [s]: in the journey, or made in Settings over the open vault. */
    private fun showsAKit(s: AppSnapshot): Boolean =
        (s.phase == AppPhase.ENTRY && s.entry is EntryScreen.Kit) || (s.phase == AppPhase.UNLOCKED && s.account?.kit != null)

    /** [KitResult] while its kit is on show in [s]; null otherwise. */
    internal fun kitResultOn(s: AppSnapshot): KitResult? {
        val kit = notKeptKitOf(s) ?: return null
        return kitResultFlow.value?.takeIf { it.email == kit.email && it.origin == kit.instance.origin }
    }

    /**
     * STALE to an intent asked with the vault open, which is no longer open, or asked in the journey (a kit on show
     * holds the account's keys), which is now at the lock screen: a lock (or the session's end) overtook it. Any other
     * STALE keeps its screen's own words.
     */
    internal fun overtakenByLock(asked: Place, r: IntentResult, now: AppSnapshot = api.snapshot): Boolean =
        r.trouble == Trouble.STALE &&
            ((asked.phase == AppPhase.UNLOCKED && now.phase != AppPhase.UNLOCKED) || (asked.phase == AppPhase.ENTRY && now.phase == AppPhase.LOCKED))

    /** Done, asked with the vault open, and the vault locked before the answer came: its screen is gone. */
    internal fun doneAsTheLockCame(asked: Place, r: IntentResult, now: AppSnapshot = api.snapshot): Boolean =
        (r.done || r == io.silencelen.andvari.core.app.PasswordChangeResult.CHANGED_PREVIOUS_OPENS_HERE) &&
            asked.phase == AppPhase.UNLOCKED && now.phase == AppPhase.LOCKED

    /**
     * Work a lock overtook: said on the screen on show now, in one sentence ([Placeholder.LOCK_OVERTOOK]). Should the
     * desktop still show the vault open, it locks: the account's keys are gone, so the open vault could do nothing more.
     * Nothing is logged. The next unlock clears the sentence, as it clears anything said.
     */
    fun lockOvertook() {
        val before = api.snapshot
        if (before.phase == AppPhase.UNLOCKED) api.lock()
        saidFlow.value = Said(placeOf(api.snapshot), null, overtookWords(before, api.snapshot))
    }

    /**
     * The same throw ("the keys are gone") and the same STALE come when the SERVER ended the session: there andvari did
     * not lock, and on the first screen there is nothing to unlock. So the line is the lock's only at the lock screen of
     * a lock; the session the server ended has its own, and the first screen a line that names neither.
     */
    internal fun overtookWords(before: AppSnapshot, now: AppSnapshot): UiText = when {
        // A lock of andvari's own (by hand or at the idle limit) in a session the server had ended earlier is the lock's.
        lockedHere && now.phase == AppPhase.LOCKED -> UiText.ph(Placeholder.LOCK_OVERTOOK)
        // A session this computer could not confirm is not one its server ended: the end as the shared code says it.
        notConfirmedEnd(before, now) != null -> UiText.ph(Placeholder.NOT_CONFIRMED_BEFORE_DONE, UiText.of(notConfirmedEnd(before, now)!!).shown())
        before.account?.signedOutByServer == true || now.locked?.signedOutByServer == true -> UiText.ph(Placeholder.SERVER_ENDED_BEFORE_DONE)
        now.phase == AppPhase.ENTRY -> UiText.ph(Placeholder.STOPPED_BEFORE_DONE)
        else -> UiText.ph(Placeholder.LOCK_OVERTOOK)
    }

    /**
     * The shared code's line for a session this computer could not confirm in time, as the screen on show now names it
     * (the lock screen's), else as the open copy named it; null where the session was not so ended.
     */
    internal fun notConfirmedEnd(before: AppSnapshot?, now: AppSnapshot): io.silencelen.andvari.core.app.CopyKey? =
        now.locked?.takeIf { it.sessionNotConfirmed }?.let { it.endLine ?: io.silencelen.andvari.core.app.CopyKey.SESSION_NOT_CONFIRMED }
            ?: before?.account?.takeIf { it.sessionNotConfirmed }?.let { it.endLine ?: io.silencelen.andvari.core.app.CopyKey.SESSION_NOT_CONFIRMED_COPY_OPEN }

    /** A lock met the app's own work, which the person did not ask for: the vault is locked, and nothing is said of it. */
    private fun lockedQuietly() {
        if (api.snapshot.phase == AppPhase.UNLOCKED) api.lock()
    }

    /** An intent that answered done, whose answer's handling met the wiped keys: said as done as the lock came. */
    private fun doneAsTheKeysWent(r: IntentResult) {
        if (api.snapshot.phase == AppPhase.UNLOCKED) api.lock()
        saidFlow.value = Said(placeOf(api.snapshot), r, doneUnderLockWords(r))
    }

    /** Run a plain intent that answers nothing. One a lock overtook (the keys are gone) is said as the lock. */
    fun act(intent: DesktopAppApi.() -> Unit) {
        saidFlow.value = null
        Overtaken.act(::lockOvertook, fault) { api.intent() }
    }

    internal fun note(place: Place, r: IntentResult, text: UiText? = UiText.forResult(r, api.retryAfterSeconds())) {
        saidFlow.value = text?.let { Said(place, r, it) }
    }

    // ---- a change to a shared vault that waits ----

    /**
     * The acts on a waiting change ([io.silencelen.andvari.core.app.WaitingChanges], asked for on the app interface's
     * vaults); null where the shared code offers none, and then no button of theirs is drawn. A test may hand its own.
     */
    internal var waitingActs: () -> io.silencelen.andvari.core.app.WaitingChanges? = { api.vaults as? io.silencelen.andvari.core.app.WaitingChanges }

    /**
     * The person's tap on a waiting change's button: [act] on [change], the very object the row drew from the snapshot on
     * show. Its answer is said in the result's own sentence ([waitingAnswer]); STALE says nothing.
     */
    internal fun actOnWaiting(change: io.silencelen.andvari.core.app.WaitingChange, act: WaitingAct): Job? {
        val acts = waitingActs() ?: return null
        return runSaying({
            when (act) {
                WaitingAct.WITHDRAW -> acts.withdrawWaiting(change)
                WaitingAct.DELETE_NOW -> acts.deleteWaitingNow(change)
            }
        }, { waitingAnswer(it, api.retryAfterSeconds()) })
    }

    /** The person dismissed [notice], the object on show: the shared code forgets it. */
    fun dismissWaitingNotice(notice: io.silencelen.andvari.core.app.WaitingNotice) = quietly { waitingActs()?.dismissWaitingNotice(notice) }

    /** A notice's undo ([undoNoticeAct]), said in the ordinary act's own words. */
    fun undoWaiting(notice: io.silencelen.andvari.core.app.WaitingNotice, moveInstead: Boolean = false): Job =
        runSaying({ undoNoticeAct(notice, moveInstead) }, { undoWords(it, api.retryAfterSeconds()) })

    /** "Close this move" on [row], the row on show. DONE says nothing; STALE (no such move now) says nothing, and the row is drawn again. */
    fun closeFrozenMove(row: io.silencelen.andvari.core.app.SharedVaultRow) = quietly {
        val acts = waitingActs() ?: return@quietly
        val r = acts.closeFrozenMove(row)
        note(placeOf(api.snapshot), r, if (r == io.silencelen.andvari.core.app.VaultActionResult.STALE) null else UiText.forResult(r, api.retryAfterSeconds()))
    }

    // ---- locking ----

    /** The last activity, on both clocks. */
    private val lastActivity = TwoClockMark(monotonicMs, wallMs)

    /** The last tick, on both clocks: a tick that comes [LATE_TICK_MS] or more after it means the app was not running. */
    private val lastTick = TwoClockMark(monotonicMs, wallMs)

    /** A kit with the shared code's idle limit was on show at the last [tick]. */
    private var kitLimitedBefore = false

    /**
     * The person touched or typed (the window's key and pointer preview call this). [moved]: only the pointer moved (or
     * entered or left the window), which keeps an open vault awake as before but not a kit with the shared code's idle
     * limit ([KitScreen.idleLockAfterMs]): there only a click, a scroll or a key counts.
     */
    fun touched(moved: Boolean = false) {
        val kit = kitIdleLimitOf(api.snapshot)
        if (moved && kit != null) return
        lastActivity.reset()
        // A warning on show from the start of its kit's screen stays (a person is always told that a touch keeps the kit),
        // and is not asked of the operating system again at every touch.
        if (kit == null || !warnsFromStart(kit)) kitIdleWarningFlow.value = null
    }

    /**
     * A system file dialog returned with the person's answer: they were here all along. The idle clock starts again,
     * and the tick that follows is not taken for a late one, should the dialog have held the window's ticks.
     */
    fun dialogReturned() {
        lastActivity.reset()
        lastTick.reset()
    }

    /**
     * What a lock acts on: an open vault, the recovery kit on show in the journey (after sign-up, a recovery, an unlock
     * that found the kit never saved: the account's keys are open there), and a sign-in's
     * code step, which holds the typed password. Core decides what the lock does at each: the kit is wiped and the app goes to the lock screen; the code step's password is wiped.
     */
    fun lockable(s: AppSnapshot = api.snapshot): Boolean = when (s.phase) {
        AppPhase.UNLOCKED -> true
        AppPhase.ENTRY -> s.entry.let { it is EntryScreen.Kit || (it is EntryScreen.SignIn && it.codeNeeded) }
        else -> false
    }

    /** Ctrl+L and the menu's Lock: what is [lockable] locks now. Anything else is left as it is. */
    fun lockNow() = quietly {
        val s = api.snapshot
        if (lockable(s)) lockHere(s)
    }

    /**
     * Call about once a second: locks an open vault after the idle window.
     *
     * On Linux the monotonic clock stops while the computer sleeps, so idleness is read on
     * the wall clock as well and the larger reading counts; a wall clock set back never lengthens the window, because
     * the monotonic reading still counts. A tick that arrives [LATE_TICK_MS] or more after the previous one (the process
     * was suspended, the computer slept) locks too, whatever either clock says of the activity.
     */
    fun tick() {
        val s = api.snapshot
        // A kit with the shared code's idle limit that has just come on show: its count starts now (a step from the reveal
        // to the confirm is the same kit on show, and keeps counting).
        val kitLimited = kitIdleLimitOf(s)
        if (kitLimited != null && !kitLimitedBefore) lastActivity.reset()
        kitLimitedBefore = kitLimited != null
        val idle = lastActivity.elapsedMs()
        val late = lastTick.elapsedMs() >= LATE_TICK_MS
        lastTick.reset()
        // A fault here is said, and the next tick comes all the same: the idle lock never stops ticking.
        val limit = kitLimited?.idleLockAfterMs ?: autoLockMs()
        // That kit: the shared code's warning, its own time before the limit.
        val warnFrom = limit - (kitLimited?.idleWarnBeforeMs ?: 0L)
        val warnedBefore = kitIdleWarningFlow.value != null
        kitIdleWarningFlow.value = kitLimited?.idleWarningLine?.takeIf { !late && idle in warnFrom until limit }
        // The warning has just come: the operating system's signals, once. A failure there is logged, and the lock still comes.
        if (!warnedBefore && kitIdleWarningFlow.value != null) {
            runCatching { kitWarningSignal.warningCame() }.onFailure { runCatching { faultLog("kit warning signal :: ${faultClass(it)}") } }
        }
        quietly { if (lockable(s) && (idle >= limit || late)) lockHere(s) }
        // A verified recovery left unattended on its new-password screen is dropped (the old wizard's five minutes).
        // Core runs no timer for it: IF-3 leaves it to the app (startOver).
        if (s.entry is EntryScreen.ReplacePassword && idle >= RECOVERY_IDLE_MS) {
            quietly {
                api.entry.startOver()
                say(UiText.ph(Placeholder.RECOVERY_IDLE_DROPPED))
            }
        }
    }

    // ---- a session the server ended ----

    /**
     * "Sign in again" on a session the server ended (design §4.4): from the open, read-only copy it locks first, then
     * opens the journey from the lock screen ([AppApi.signInAgain]); signing in to the same account takes the copy back
     * and sends what waited. Nothing happens anywhere else.
     */
    fun signInAgain() {
        saidFlow.value = null
        val s = api.snapshot
        if (s.phase == AppPhase.UNLOCKED) {
            if (s.account?.signedOutByServer != true) return
            api.lock()
        }
        val locked = api.snapshot.locked ?: return
        if (locked.signedOutByServer) api.signInAgain(locked)
    }

    // ---- linking a new device from this computer ----

    /**
     * The screen that shows this computer's device link was left (another page, the kit, the window composed again
     * after a lock): a link still running is cancelled at the server, so nobody can go on with it unseen; an approved
     * or ended one is closed. A lock and a session's end cancel it in core itself; this covers leaving it in place.
     */
    fun leftDeviceLink(): Job? {
        val s = api.snapshot
        if (s.phase != AppPhase.UNLOCKED) return null
        return when (s.account?.deviceLink) {
            null -> null
            is DeviceLinkHost.Approved, is DeviceLinkHost.Ended -> {
                api.devices.dismissDeviceLink()
                null
            }
            // A lock overtaking the cancel: core cancels the link at the lock itself, so nothing is left to do again and
            // nothing is said beyond the lock screen.
            else -> scope.launchOvertakable(::lockedQuietly, fault) { api.devices.cancelDeviceLink() }
        }
    }

    // ---- deleting the account ----

    /**
     * The account was deleted (DONE): the first screen says so until dismissed, from core's own notice
     * ([EntryScreen.FirstRun.accountDeleted]), which took the place of the desktop's own flag; dismissed
     * with the screen's other notice ([io.silencelen.andvari.core.app.EntryApi.dismissNotice]). Core has wiped this
     * computer's state for it (the kept session, its copy, the identity record) and the switch "keep me signed in" went
     * off with the session ([keepFollows]), which deletes the kept file, its key-store item and the cache files.
     */
    fun accountDeletedNotice(s: AppSnapshot = api.snapshot): io.silencelen.andvari.core.app.AccountDeletedNotice? =
        (s.entry as? EntryScreen.FirstRun)?.accountDeleted

    /** Delete the account; each end is said in its own words ([deletionLine]). A deletion that is done is a person's own end ([personEnded]). */
    fun deleteAccount(screen: DeletionScreen, typedEmail: String, password: String, code: String?, after: (DeletionResult) -> Unit = {}): Job =
        runSaying({ settings.deleteAccount(screen, typedEmail, password, code) }, { deletionLine(it, api.retryAfterSeconds()) }) { r ->
            personEnded(r)
            after(r)
        }

    /**
     * "Check whether it went through", after an unknown outcome ([deletionCheckLine]). A check the session's end
     * answered (a `401` cannot be told from any other end) leaves core's own record standing: the lock screen says it
     * cannot tell ([io.silencelen.andvari.core.app.LockedScreen.deletionOutcomeUnknown]), and so does the first
     * screen after "Sign in again" ([EntryScreen.FirstRun.deletionOutcomeUnknown]); the desktop keeps no flag of its own.
     */
    fun checkDeletion(screen: DeletionScreen): Job =
        runSaying({ settings.checkDeletion(screen) }, { deletionCheckLine(it, api.retryAfterSeconds()) })

    // ---- forgetting the account after a deletion whose outcome is not known ----

    /** The shared code's offer, the same object for as long as it holds; null where none is offered (or the read threw). */
    fun forgetUnknownCheck(): io.silencelen.andvari.core.app.ForgetUnknownDeletion? = readOr(null) { api.forgetAfterUnknownDeletionCheck() }

    private val forgetAskedFlow = MutableStateFlow<io.silencelen.andvari.core.app.ForgetUnknownDeletion?>(null)
    private var forgetAskedIn: AppPhase? = null

    /**
     * The offer whose second step (its confirmation) is on show: only that very object, while it is still the one the
     * shared code offers, in the phase it was asked in, with no lock since ([forgetFollows], [lockHere]). Null otherwise.
     */
    internal val forgetUnknownAsked: StateFlow<io.silencelen.andvari.core.app.ForgetUnknownDeletion?> get() = forgetAskedFlow

    /** The offer's tap: its second step comes on show; nothing is sent. */
    fun askToForgetAfterUnknownDeletion(check: io.silencelen.andvari.core.app.ForgetUnknownDeletion) {
        if (forgetUnknownCheck() !== check) return
        forgetAskedIn = api.snapshot.phase
        forgetAskedFlow.value = check
    }

    /** Cancel on the second step: back to the offer; nothing is forgotten. */
    fun keepAfterUnknownDeletion() {
        forgetAskedFlow.value = null
    }

    /**
     * The second step's own button, from the person's click: the forgetting, called once with the confirmation on show and
     * never tried again by the app. STALE closes the step, so the offer as it stands now is read and shown again; done is a
     * person's own end ([personEnded]), as a sign-out is. A call that threw is said as a fault and leaves the step on show.
     */
    fun forgetAfterUnknownDeletion(check: io.silencelen.andvari.core.app.ForgetUnknownDeletion): Job? {
        if (forgetAskedFlow.value !== check) return null
        return runSaying({ forgetAfterUnknownDeletion(check) }, { if (it === PlainResult.STALE) null else UiText.forResult(it, api.retryAfterSeconds()) }) { r ->
            if (r.done || r === PlainResult.STALE) forgetAskedFlow.value = null
            personEnded(r)
        }
    }

    /** The second step closes at another phase, and wherever the shared code's offer is no longer the object it was asked on. */
    private fun forgetFollows(s: AppSnapshot) {
        val asked = forgetAskedFlow.value ?: return
        if (s.phase != forgetAskedIn || forgetUnknownCheck() !== asked) forgetAskedFlow.value = null
    }

    // ---- keeping the sign-in ----

    private val keepFlow = MutableStateFlow(keeping.on)

    /** Whether the person keeps the sign-in (tokens, keys, the offline copy) on this computer. Off by default. */
    val keepSignIn: StateFlow<Boolean> get() = keepFlow

    private val keepUnknownFlow = MutableStateFlow(keeping.unknown)

    /**
     * The switch's settings file could not be read: nothing kept is read or deleted
     * because of it, and the app says so and asks ([answerKeepUnknown]).
     */
    val keepUnknown: StateFlow<Boolean> get() = keepUnknownFlow

    /** The server's policy, once read, forbids an offline copy: it wins over the switch, which stays off. */
    fun keepForbidden(s: AppSnapshot = api.snapshot): Boolean = s.account?.policy?.let { it.known && !it.offlineCacheAllowed } ?: false

    /**
     * Under a policy that forbids the copy, the shared code owes its removal (one try to send what waits, the count, then
     * the removal), so the desktop neither deletes it nor switches the sign-in off meanwhile. Read from the snapshot
     * ([AppSnapshot.policyWipeOwed]): the session's own account only, the same after a lock and a restart; another
     * account's copy on this computer never makes it owed.
     */
    internal fun policyRemovalOwed(s: AppSnapshot = api.snapshot): Boolean = s.policyWipeOwed

    /**
     * Settings' switch. On: the sign-in is kept for the account on show (it belongs to that account). Off: the
     * switch's own record turns off, core is told before any file is deleted
     * ([SignInKeeping.set] calls the app interface's `atRestConsentChanged`), so an open vault goes on from memory with
     * what is queued to send, and then the files go.
     */
    fun setKeepSignIn(on: Boolean): Job? {
        if (on) {
            if (keepForbidden()) {
                say(UiText.ph(Placeholder.KEEP_FORBIDDEN))
                return null
            }
            // Note N2: no silent fallback. Without a key store the person is told and chooses ([answerNoKeyStore]).
            if (!keeping.keyStoreReady()) {
                askFlow.value = true
                keepRefresh()
                return null
            }
            keeping.set(true, api.snapshot.account?.accountId)
            // Ticked by the account open: the switch is its own now (the set above made it so on disk).
            foreign = false
            keepFlow.value = keeping.on
            keepRefresh()
            return null
        }
        // While the shared code owes the policy's removal of the copy, unticking deletes nothing ahead of it: the switch
        // goes off by itself once the copy is gone ([keepFollows]); meanwhile the removal's own line is said.
        if (keepForbidden() && policyRemovalOwed()) {
            say(contentFlow.value?.state?.removingLine?.let { UiText.Plain(it) } ?: UiText.ph(Placeholder.KEEP_FORBIDDEN))
            return null
        }
        switchOff()
        return null
    }

    // ---- quitting over changes held in memory only ----

    /** How the app ends once the person confirmed it (the window sets it: the application's exit). */
    @Volatile
    var quit: () -> Unit = {}

    private val quitAskedFlow = MutableStateFlow<QuitAsk?>(null)

    /** The question before quitting, while on show ([askBeforeQuit]); null otherwise. */
    val quitAsked: StateFlow<QuitAsk?> get() = quitAskedFlow

    /**
     * The person asked to quit (the window's close, the menu's Quit). Where changes made here wait in memory only, which
     * quitting loses ([io.silencelen.andvari.core.app.AppApi.waitingInMemory]), the question comes first: with the number
     * above 0, without one where the shared code cannot tell (null). With nothing waiting the app ends at once. A read
     * that threw cannot tell either: asked without a number, never ended unasked.
     */
    fun askBeforeQuit() {
        val waiting = try {
            api.waitingInMemory()
        } catch (t: Throwable) {
            if (t is kotlinx.coroutines.CancellationException) throw t
            faulted(t)
            null
        }
        if (waiting == 0) {
            quitAskedFlow.value = null
            quit()
        } else {
            quitAskedFlow.value = QuitAsk(waiting)
        }
    }

    /** "Stay": nothing is quit, nothing is lost. */
    fun stayAfterQuestion() {
        quitAskedFlow.value = null
    }

    /** "Quit anyway", from the question on show: the app ends, and what waited in memory with it. */
    fun quitAfterQuestion() {
        if (quitAskedFlow.value == null) return
        quitAskedFlow.value = null
        quit()
    }

    // ---- the person's own ends ----

    /** "Sign out", confirmed: a person's own end ([personEnded]). With changes waiting the shared code refuses it ([signOut] with a check). */
    fun signOut(): Job = signOut(null)

    /**
     * "Sign out" from its confirmation ([SignOutAsk]): plain when [confirmed] is null (nothing waits), otherwise the
     * person's second confirmation of that check, which alone signs out over changes not sent. The refusal that the
     * check no longer holds is not said on the page: the confirmation shows the new check ([after] sees it).
     */
    fun signOut(confirmed: io.silencelen.andvari.core.app.SignOutCheck?, after: (PlainResult) -> Unit = {}): Job =
        runSaying(
            { if (confirmed == null) signOut() else signOutConfirmed(confirmed) },
            { if (it === PlainResult.UNSENT_NOT_CONFIRMED) null else UiText.forResult(it, api.retryAfterSeconds()) },
        ) {
            personEnded(it)
            after(it)
        }

    /**
     * The invitation for another server's switch, from its window ([SignOutAsk]): as [signOut], the switch signs out
     * here, so over changes not sent only the second confirmation of [confirmed] goes on, and a switch that was done is
     * a person's own end ([personEnded]), as a sign-out is.
     */
    fun switchInstance(
        opened: io.silencelen.andvari.core.app.OpenedInvite.OtherInstance,
        confirmed: io.silencelen.andvari.core.app.SignOutCheck?,
        after: (io.silencelen.andvari.core.app.ServerResult) -> Unit = {},
    ): Job =
        runSaying(
            { if (confirmed == null) links.switchInstance(opened) else links.switchInstanceConfirmed(opened, confirmed) },
            { if (it === io.silencelen.andvari.core.app.ServerResult.UNSENT_NOT_CONFIRMED) null else UiText.forResult(it, api.retryAfterSeconds()) },
        ) {
            personEnded(it)
            after(it)
        }

    /** "Forget this server", confirmed: a person's own end when it ends the account kept here ([personEnded]). */
    fun forgetServer(instance: InstanceSnapshot): Job = run({ this.instance.forgetServer(instance) }) { personEnded(it) }

    /** "Forget the server at the new address", confirmed: as [forgetServer]. */
    fun forgetServerAtNewAddress(card: InstanceCardState.Moved): Job = run({ this.instance.forgetServerAtNewAddress(card) }) { personEnded(it) }

    /**
     * The switch "keep me signed in", and everything it deletes, change
     * only as the result of something the person did on purpose: a completed sign-out, "Forget this server", a completed
     * account deletion, or unticking the switch ([setKeepSignIn]). No change of screen and no answer from a server does
     * it: a session the server ends keeps this computer's copy and the changes waiting to be sent (§4.4), "Sign in
     * again" included. So the switch goes off here only when such an act was done and no account is kept on this
     * computer any more (at the first screen, with no account its server signed out still kept): forgetting another
     * server, or signing out of nothing, leaves it as it is.
     */
    private fun personEnded(r: IntentResult) {
        if (!r.done) return
        val s = api.snapshot
        // The account that ended was not the one the switch belongs to; nothing kept goes.
        if (foreign) {
            if (s.phase == AppPhase.ENTRY) foreignEnds()
            return
        }
        if (!keepFlow.value) return
        // The engine can reach the first screen with its session still kept (forgetting another server ends the
        // journey); that act did not end the account kept here.
        if (s.phase == AppPhase.ENTRY && s.keptSignedOut == null && !keeping.sessionKept) switchOff()
    }

    /** Another account than the switch's is open ([keepFollows]). */
    private var foreign = false

    private fun foreignEnds() {
        foreign = false
        keeping.foreign(false)
        keepFlow.value = keeping.on
    }

    private fun switchOff() {
        keeping.set(false, null)
        keepFlow.value = keeping.on
        askFlow.value = false
        keepRefresh()
    }

    /** The person's answer to "could not read its settings": written as a new file; the unreadable one is kept aside. */
    fun answerKeepUnknown(on: Boolean) {
        val keep = on && !keepForbidden()
        keeping.answerUnknown(keep, if (keep) api.snapshot.account?.accountId else null)
        keepUnknownFlow.value = keeping.unknown
        keepFlow.value = keeping.on
        if (keep && !keeping.keyStoreReady()) askFlow.value = true
        keepRefresh()
    }

    /**
     * Assisted recovery's request is kept for this run only: this computer has no key store to wrap it, and it is
     * never written unwrapped. The operator-help screens say so ([Placeholder.ASSIST_REQUEST_THIS_RUN_ONLY]).
     */
    fun assistRequestThisRunOnly(): Boolean = keeping.assistRequestThisRunOnly

    // ---- the key store (note N2) ----

    /** The person switched it on and this computer's key store gave no key: asked, not yet answered. */
    private val askFlow = MutableStateFlow(false)

    private val noKeyStoreFlow = MutableStateFlow(keeping.choiceNeeded)

    /**
     * Keeping the sign-in here needs a choice, because this computer has no key store (or
     * it refused): the session would be kept in a file only the person's account can read. Raised when the switch
     * is turned on without a key store, and when a kept sign-in finds none (a session an earlier build kept
     * unwrapped; a write the store refused). Until the answer ([answerNoKeyStore]) nothing is written unwrapped.
     */
    val noKeyStoreQuestion: StateFlow<Boolean> get() = noKeyStoreFlow

    private val unopenableFlow = MutableStateFlow(keeping.keptUnopenable)

    /**
     * The sign-in kept here is wrapped and this computer's key store could not open it: unknown, never "nothing
     * kept". The person is asked to sign in again; the file is left as it is (moved aside, unread, when a new sign-in
     * is kept).
     */
    val keptUnopenable: StateFlow<Boolean> get() = unopenableFlow

    /** The person's answer to [noKeyStoreQuestion]: keep the sign-in in a file only their account can read, or not keep it. */
    fun answerNoKeyStore(keepInFile: Boolean): Job? {
        askFlow.value = false
        if (keepInFile && !keepForbidden()) {
            keeping.keepInPlainFile(api.snapshot.account?.accountId)
            foreign = false
            keepFlow.value = keeping.on
            keepRefresh()
            return null
        }
        keepRefresh()
        return if (keeping.on) setKeepSignIn(false) else null
    }

    private fun keepRefresh() {
        noKeyStoreFlow.value = askFlow.value || keeping.choiceNeeded
        unopenableFlow.value = keeping.keptUnopenable
    }


    /**
     * The switch belongs to the account (N2): it is bound to the account at its unlock, another account never inherits
     * it, and a policy that forbids an offline copy switches it off, but only once the shared code has removed the copy
     * ([policyRemovalOwed]): the shared code tries once to send what waits in it, counts, and removes it itself, under its
     * own lock; the desktop deletes nothing of it before. It is otherwise reset by the person's own ends only
     * ([personEnded]), never by a change of phase: a session the server ended, "Sign in again" from it, and every other
     * way to the first screen keep the copy.
     */
    private fun keepFollows(s: AppSnapshot) {
        val account = s.account ?: return
        if (foreign) {
            if (account.accountId == keeping.keptFor) foreignEnds()
            return
        }
        if (!keepFlow.value) return
        if (keepForbidden(s)) {
            // The copy is the shared code's to send from, count and remove: the switch, the kept sign-in and the cache
            // files stay as they are until it is gone (then nothing of it is left for the switch to delete).
            if (policyRemovalOwed(s)) return
            switchOff()
            say(UiText.ph(Placeholder.KEEP_FORBIDDEN))
            return
        }
        when (keeping.keptFor) {
            null -> keeping.set(true, account.accountId)
            account.accountId -> {}
            // Another account's switch: the kept account could not be opened, so core let this
            // one in. Opening it is not an end of the kept one: nothing of that is deleted, and this one inherits nothing
            // (held in memory; core moves its open vault there). The switch reads off for it; ticking it is its own.
            else -> {
                foreign = true
                keeping.foreign(true)
                keepFlow.value = false
                say(UiText.ph(Placeholder.KEEP_BELONGS_TO_ANOTHER))
            }
        }
    }

    companion object {
        /** The old recovery wizard's idle limit on a verified recovery: 300 seconds. */
        const val RECOVERY_IDLE_MS: Long = 300L * 1000

        /** A tick this long after the previous one (they come once a second) means the app was not running: it locks. */
        const val LATE_TICK_MS: Long = 10L * 1000
    }
}

/**
 * What the lock screen says of an intent that was done as the lock came: a password change says which password now
 * opens this computer's copy (the person will type one next); anything else that it was done.
 */
internal fun doneUnderLockWords(r: IntentResult): UiText = when (r) {
    io.silencelen.andvari.core.app.PasswordChangeResult.CHANGED_PREVIOUS_OPENS_HERE -> UiText.ph(Placeholder.PASSWORD_CHANGED_PREVIOUS_OPENS_HERE)
    is io.silencelen.andvari.core.app.PasswordChangeResult -> UiText.ph(Placeholder.PASSWORD_CHANGED)
    else -> UiText.ph(Placeholder.LOCK_AFTER_DONE)
}


/**
 * A moment read on two clocks: the monotonic one, which the person cannot set but which stops while a Linux computer
 * sleeps, and the wall clock, which counts through sleep but can be set. [elapsedMs] is the larger of the two
 * readings, so the clock that says more time has passed wins; a clock that went backwards reads as nothing on its
 * side and never takes from what the other counted.
 */
internal class TwoClockMark(private val monotonicMs: () -> Long, private val wallMs: () -> Long) {
    private var mono = monotonicMs()
    private var wall = wallMs()

    @Synchronized
    fun reset() {
        mono = monotonicMs()
        wall = wallMs()
    }

    @Synchronized
    fun elapsedMs(): Long = maxOf(monotonicMs() - mono, wallMs() - wall, 0L)
}

/** The question before quitting ([TrustModel.askBeforeQuit]): [waiting] changes held in memory only, or null where that cannot be told. */
class QuitAsk internal constructor(val waiting: Int?)
