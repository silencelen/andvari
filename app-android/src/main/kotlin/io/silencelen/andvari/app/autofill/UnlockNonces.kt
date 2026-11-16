package io.silencelen.andvari.app.autofill

import android.content.Intent
import java.security.SecureRandom

/**
 * Tokens that can be used once: minted by the service, retired when used. Pure (no platform), so the replay rule is
 * a plain function a JVM test calls. At most [cap] are live; the oldest beyond that is dropped, which only makes an
 * old row refuse (the person taps the field again).
 */
internal class OneUseTokens(private val cap: Int, private val newToken: () -> String) {
    private val live = LinkedHashSet<String>()

    @Synchronized
    fun mint(): String {
        val t = newToken()
        live += t
        while (live.size > cap) live.remove(live.first())
        return t
    }

    /** [token] was minted here and not used yet. */
    @Synchronized
    fun isLive(token: String?): Boolean = token != null && token in live

    /** Use [token]: true exactly once for a live token, false for every later call and for any unknown one. */
    @Synchronized
    fun retire(token: String?): Boolean = token != null && live.remove(token)
}

/**
 * Android review 1, ruling 1: the unlock cannot be replayed. The requesting app holds the unlock row's IntentSender
 * and can fire it again whenever it likes. Each unlock PendingIntent carries a nonce in its BASE intent (which a
 * fill-in cannot override, the [FillBinding] rule); the unlock activity refuses a nonce that is not live, and retires
 * it when it delivers a result. So once a result was delivered, the same sender shows nothing and returns nothing.
 * A prompt the person cancelled does not retire it: the same row can be tried again.
 *
 * The live set is this process's memory: a sender minted before the process died finds nothing live and shows
 * nothing (the safer reading; the person taps the field again and gets a new row).
 */
internal object UnlockNonces {
    private const val EXTRA = "io.silencelen.andvari.autofill.UNLOCK_NONCE"
    private val random = SecureRandom()

    val tokens = OneUseTokens(cap = 64) {
        val b = ByteArray(16).also(random::nextBytes)
        b.joinToString("") { "%02x".format(it) }
    }

    /** A new nonce, into [intent] (the PendingIntent's base). */
    fun bake(intent: Intent): Intent = intent.putExtra(EXTRA, tokens.mint())

    fun of(intent: Intent): String? = runCatching { intent.getStringExtra(EXTRA) }.getOrNull()
}
