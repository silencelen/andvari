package io.silencelen.andvari.app.autofill

import android.content.Context

/**
 * Security review 2026-10, A14 (F7): the (package → signer digest) pairs a member confirmed on this
 * device for package-only app fills. A later fill into the same package AND signer skips the confirm;
 * the same package with another signer confirms again, with a warning ([AppFillGate.decide]).
 *
 * Device-local and NOT synced: it records what this device saw, like [ApprovedBrowsers], and it is
 * excluded from cloud backup and device-to-device transfer (data_extraction_rules.xml, backup_rules.xml;
 * A14 review N5). Unlike the browser approvals, it ends with the account session: sign-out
 * (AndvariViewModel.signOut) and every other path that ends it — a definitive 401, a revocation purge,
 * a refused refresh, a server switch, another account saved over this one — all of which go through
 * [io.silencelen.andvari.app.SessionStore] (clear, clearSessionTokens, save). The confirm was this
 * member's judgement about their own vault's logins, and another member signing in here makes their
 * own (one tap per app). Remembered only when a confirmed fill was actually delivered.
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
