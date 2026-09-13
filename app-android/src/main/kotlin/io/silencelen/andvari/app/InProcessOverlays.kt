package io.silencelen.andvari.app

import android.app.Activity
import android.app.Application
import android.os.Bundle

/**
 * The third lock-on-background exemption the 0.26.0 design ratified and the code never grew
 * (design 2026-08-23 §7: "Exempted, explicitly: … `AutofillUnlockActivity` / `SaveConfirmActivity`";
 * audit 2026-09-13 H09).
 *
 * The autofill overlays — the unlock prompt, the "Save to andvari?" confirm and the "Trust
 * {browser}" confirm — are Activities of THIS process, so their start/stop drives
 * `ProcessLifecycleOwner` exactly like MainActivity's does. Whenever MainActivity's composition is
 * alive in the background (the user opened andvari earlier, then switched to a browser), an
 * overlay's own `finish()` is the last activity stop in the process: 700 ms later the process
 * reaches ON_STOP and `lockFromBackground()` seals the session the overlay just opened. The
 * dataset picker still fills (the values ride the FillResponse parcel), but the very next fill on
 * the same page — a two-step email→password login, a 2FA field, the save overlay after submit —
 * finds no session and demands the master password again. When MainActivity's composition is NOT
 * alive (cold process started by the autofill service), no observer exists and the same gesture
 * leaves the session governed by the idle window and `AutofillHardLock` — the posture the design
 * intended for an overlay-originated session. Two security postures for one gesture, decided by
 * process history rather than by any rule.
 *
 * The rule, then: an overlay closing is not "leaving the app". It tracks, via
 * [Application.ActivityLifecycleCallbacks], whether the most recent activity lifecycle event in
 * the process was one of the three overlays stopping; `lockFromBackground` ignores a process
 * ON_STOP that arrives in that state. MainActivity stopping resets it, so a session unlocked in
 * the main app still locks on leaving — the load-bearing pin of 0.26.0 stands.
 *
 * Known residual (accepted, documented): if MainActivity stops and an overlay starts within
 * ProcessLifecycleOwner's 700 ms ON_STOP debounce, the overlay's later stop is what the process
 * observes, and that ON_STOP is skipped — the main-app session then lives until the idle window
 * (or `AutofillHardLock`) ends it. A sub-second race, bounded by the same controls that bound
 * every overlay-originated session.
 *
 * The state machine is pure ([noteStarted] / [noteStopped]) so `InProcessOverlaysTest` can pin it
 * without an Activity; [install] is the one Android seam.
 */
object InProcessOverlays {
    /** Fully-qualified names, kept as literals so the manifest pin can compare them verbatim. */
    val OVERLAY_ACTIVITIES: Set<String> = setOf(
        "io.silencelen.andvari.app.autofill.AutofillUnlockActivity",
        "io.silencelen.andvari.app.autofill.SaveConfirmActivity",
        "io.silencelen.andvari.app.autofill.TrustBrowserActivity",
    )

    @Volatile
    private var lastEventWasOverlayStop = false

    fun isOverlay(activity: Activity): Boolean = activity.javaClass.name in OVERLAY_ACTIVITIES

    /** Any activity started: whatever stops next decides the next process ON_STOP. */
    fun noteStarted() { lastEventWasOverlayStop = false }

    /** An activity stopped; [isOverlay] says whether it was one of the three overlays. */
    fun noteStopped(isOverlay: Boolean) { lastEventWasOverlayStop = isOverlay }

    /** True when the process ON_STOP being handled was caused by an overlay closing. */
    fun lastStopWasOverlay(): Boolean = lastEventWasOverlayStop

    /** Register once from [AndvariApplication.onCreate] — before any Activity exists. */
    fun install(app: Application) {
        app.registerActivityLifecycleCallbacks(object : Application.ActivityLifecycleCallbacks {
            override fun onActivityStarted(activity: Activity) = noteStarted()
            override fun onActivityStopped(activity: Activity) = noteStopped(isOverlay(activity))
            override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {}
            override fun onActivityResumed(activity: Activity) {}
            override fun onActivityPaused(activity: Activity) {}
            override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}
            override fun onActivityDestroyed(activity: Activity) {}
        })
    }
}
