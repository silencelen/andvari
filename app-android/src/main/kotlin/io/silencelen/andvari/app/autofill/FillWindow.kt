package io.silencelen.andvari.app.autofill

import android.app.Activity
import android.os.Build
import android.view.MotionEvent
import android.view.WindowManager
import android.widget.Toast
import io.silencelen.andvari.app.trust.Placeholder
import io.silencelen.andvari.app.trust.UiText

/**
 * The defences every autofill window of andvari shares (the unlock, the app-fill and card confirms, the chooser, the
 * trust card).
 *
 * - The window is opaque and covers the screen (`Theme.Andvari.FillWindow` in the manifest), so nothing of the
 *   requesting app shows around the card to frame it with its own words.
 * - It is a secure window; touches that pass through another window are dropped (`filterTouchesWhenObscured`); on
 *   Android 12 and later other apps' overlay windows are hidden while it is shown.
 * - On Android 10 and 11, where overlays cannot be hidden, a touch that arrives while ANY part of the window is
 *   covered by another app's window is dropped too ([dropsTouch]): `filterTouchesWhenObscured` looks only at the
 *   touch point, so an overlay could cover the card's words and leave the button bare.
 */
internal object FillWindow {
    /** `MotionEvent.FLAG_WINDOW_IS_OBSCURED`: the touch passed through another visible window. */
    const val FLAG_OBSCURED = 0x1

    /** `MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED` (API 29): some part of the window is covered by another app's window. */
    const val FLAG_PARTIALLY_OBSCURED = 0x2

    /** The first release that can hide other apps' overlays (`Window.setHideOverlayWindows`). */
    const val HIDES_OVERLAYS_FROM = 31

    /**
     * Whether a touch with [eventFlags] is dropped on a phone running [sdk]: one that passed through another window,
     * always; one that arrived while the window was partly covered, where overlays cannot be hidden (Android 10, 11).
     */
    fun dropsTouch(sdk: Int, eventFlags: Int): Boolean =
        (eventFlags and FLAG_OBSCURED) != 0 || (sdk < HIDES_OVERLAYS_FROM && (eventFlags and FLAG_PARTIALLY_OBSCURED) != 0)

    /** Before anything is drawn: a secure window, touches through another window dropped, overlays hidden (API 31+). */
    fun shield(activity: Activity) {
        val window = activity.window
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        window.decorView.filterTouchesWhenObscured = true
        if (Build.VERSION.SDK_INT >= HIDES_OVERLAYS_FROM) window.setHideOverlayWindows(true)
    }

    /**
     * An activity's `dispatchTouchEvent`: a touch [dropsTouch] drops reaches the window only as a cancel (so a press
     * already under way never completes), and the person is told once per window why nothing happened.
     */
    fun dispatch(activity: Activity, ev: MotionEvent, told: BooleanArray, deliver: (MotionEvent) -> Boolean): Boolean {
        if (!dropsTouch(Build.VERSION.SDK_INT, ev.flags)) return deliver(ev)
        val cancel = MotionEvent.obtain(ev)
        try {
            cancel.action = MotionEvent.ACTION_CANCEL
            deliver(cancel)
        } finally {
            cancel.recycle()
        }
        if (!told[0]) {
            told[0] = true
            runCatching { Toast.makeText(activity.applicationContext, UiText.ph(Placeholder.FILL_TOUCH_OBSCURED).shown(), Toast.LENGTH_LONG).show() }
        }
        return true
    }
}
