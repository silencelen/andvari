package io.silencelen.andvari.core.app

/**
 * Where the app tells its own extensions which server it uses (iOS: the App Group, which the Safari extension
 * reads through its native-message handler). Only the origin goes here: it is not a secret, and nothing else is.
 */
fun interface ServerShare {
    /** [origin] is the Trust-Gate-confirmed origin the app dials now, or null when it has none. */
    fun publish(origin: String?)
}
