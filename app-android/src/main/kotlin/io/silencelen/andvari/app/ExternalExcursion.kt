package io.silencelen.andvari.app

import android.os.SystemClock

/**
 * The exemption list for lock-on-background (design 2026-08-23 §7 / §5.1).
 *
 * Locking when the app goes to the background is the change that makes removing the lock button
 * safe — before it, NOTHING locked on `onStop` and the vault sat unlocked in memory for up to
 * [io.silencelen.andvari.core.client.ClientPolicyClamps.AUTO_LOCK_MAX_SECONDS] after the user put
 * the phone down. But four flows leave the app *on purpose*, at the user's request, and mean to
 * come straight back:
 *
 *  - the vault-health verification run's Custom Tab (the whole point is to open the site),
 *  - the CSV import file picker,
 *  - the attachment picker (and the two save-as dialogs),
 *  - the system autofill-service picker (AutofillStatusScreen).
 *
 * Locking those would be a bug wearing a security feature's clothes: the user taps "Open site",
 * signs in, comes back, and the vault they were mid-task in is sealed.
 *
 * **Deliberately a one-shot, not a boolean the caller must remember to clear.** [begin] arms a
 * single skip; the next background transition consumes it, and returning to the foreground clears
 * it either way. A launch that never happens (the user cancels the chooser, no browser is
 * installed, the intent throws) therefore cannot leave the app permanently unlockable — the worst
 * case is one skipped lock, and the inactivity timer still stands behind it.
 *
 * **…and the one-shot EXPIRES ([ARM_TTL_MS]).** Audit 2026-09-13 H57, the G64 residue: every arm
 * is cleared by a process ON_STOP (consumed) or a process ON_START (dropped), and an ON_START
 * cannot happen without a preceding ON_STOP. That closes the loop only for launches that actually
 * stop this activity. The autofill-service picker does not on every OEM — where it renders as a
 * dialog over the still-STARTED activity, no lifecycle event fires at all, and the arm sat live
 * indefinitely, ready to exempt the user's NEXT genuine backgrounding (Home, app switch, screen
 * off) hours later. That is a single-shot defeat of the control the whole §7 design rests on, and
 * nothing in the app could observe it. So an arm now carries the moment it was made and is honoured
 * only inside a window: an older arm is not "the excursion the user asked for", it is a leak, and
 * a leaked arm must fail SAFE (lock) rather than open.
 *
 * **The TTL has a partner: the ACTIVITY-resumed clear** (R17, `MainActivity`'s
 * `repeatOnLifecycle(RESUMED)` block). At the owner's five-minute window the TTL alone does not
 * bound the OEM case above — five minutes is easily long enough to reach the user's next genuine
 * backgrounding — so [clear] is also called every time this activity resumes, which is the ONE
 * lifecycle hook the dialog-style picker does fire. It is a no-op for every excursion that really
 * stopped the process (ON_STOP already consumed the arm) and drops exactly the leaked ones.
 *
 * The clock is [SystemClock.elapsedRealtime] — monotonic AND counting deep sleep, which is exactly
 * the state a phone put down mid-excursion is in. `System.nanoTime`/`currentTimeMillis` would each
 * be wrong here in the direction that keeps a stale arm alive (suspend-excluding, and settable).
 *
 * Nothing here is a secret or survives the process; it is scheduling, not state.
 */
object ExternalExcursion {

    /**
     * How long an unused arm stays valid, in elapsed-realtime milliseconds.
     *
     * **Five minutes (owner decision, audit 2026-09-13 H57).** The window has to cover the whole
     * human round trip the arm exists for — open the saved site in a Custom Tab and actually sign
     * in, walk the system Settings picker, find a file in the SAF chooser — and those are minutes,
     * not seconds; a window too short would re-introduce the bug the exemption fixed (the vault
     * sealing under a user who is mid-task) on slow devices and slow humans. It only has to be
     * short enough that a *leaked* arm cannot survive to a later, unrelated backgrounding, and the
     * failure it bounds is one skipped lock with the idle timer still standing behind it.
     */
    const val ARM_TTL_MS: Long = 5 * 60 * 1000L

    /** Test seam. Never reassigned in production code — see [ARM_TTL_MS] for why the default is
     *  elapsed-realtime and not a wall clock. */
    @Volatile
    internal var clock: () -> Long = { SystemClock.elapsedRealtime() }

    /** When the live arm was made, or null for "no arm". */
    @Volatile
    private var armedAtMs: Long? = null

    /** Call IMMEDIATELY before launching an intent that hands the screen to another app. */
    fun begin() { armedAtMs = clock() }

    /**
     * Consume the one-shot. Returns true when this background transition is exempt — which
     * requires BOTH an arm and that arm being fresher than [ARM_TTL_MS]. A stale arm is dropped
     * and answers false: the lock happens.
     */
    fun consume(): Boolean {
        val at = armedAtMs ?: return false
        armedAtMs = null
        return clock() - at <= ARM_TTL_MS
    }

    /** Back in the foreground — drop any unused arm so it cannot apply to a LATER, unrelated
     *  backgrounding (the user opens the site, returns, then puts the phone down). Called from
     *  BOTH foreground hooks: the process ON_START, and (R17) the activity's RESUMED entry, which
     *  is the only one of the two a dialog-style picker fires. */
    fun clear() { armedAtMs = null }
}
