package io.silencelen.andvari.app.autofill

import android.content.Context

/**
 * Security review 2026-10, A14 (F7): the (package → signer digest) pairs a member confirmed on this
 * device for package-only app fills. A later fill into the same package AND signer skips the confirm;
 * the same package with another signer confirms again, with a warning ([AppFillGate.decide]).
 *
 * Device-local and NOT synced: it records what this device saw, like [ApprovedBrowsers]. Unlike the
 * browser approvals, sign-out clears it (AndvariViewModel.signOut): the confirm was this member's
 * judgement about their own vault's logins, and another member signing in here makes their own (one
 * tap per app).
 */
object AppSignerBindings {
    private const val PREFS = "andvari_app_signer_bindings"

    fun rememberedDigest(context: Context, pkg: String): String? =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(pkg, null)

    fun remember(context: Context, pkg: String, digest: String) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString(pkg, digest).apply()
    }

    fun clearAll(context: Context) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().clear().apply()
    }
}
