package io.silencelen.andvari.app

/**
 * The exemption list for lock-on-background (design 2026-08-23 §7 / §5.1).
 *
 * Locking when the app goes to the background is the change that makes removing the lock button
 * safe — before it, NOTHING locked on `onStop` and the vault sat unlocked in memory for up to
 * [io.silencelen.andvari.core.client.ClientPolicyClamps.AUTO_LOCK_MAX_SECONDS] after the user put
 * the phone down. But three flows leave the app *on purpose*, at the user's request, and mean to
 * come straight back:
 *
 *  - the vault-health verification run's Custom Tab (the whole point is to open the site),
 *  - the CSV import file picker,
 *  - the attachment picker.
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
 * Nothing here is a secret or survives the process; it is scheduling, not state.
 */
object ExternalExcursion {

    @Volatile
    private var armed = false

    /** Call IMMEDIATELY before launching an intent that hands the screen to another app. */
    fun begin() { armed = true }

    /** Consume the one-shot. Returns true when this background transition is exempt. */
    fun consume(): Boolean {
        val was = armed
        armed = false
        return was
    }

    /** Back in the foreground — drop any unused arm so it cannot apply to a LATER, unrelated
     *  backgrounding (the user opens the site, returns, then puts the phone down). */
    fun clear() { armed = false }
}
