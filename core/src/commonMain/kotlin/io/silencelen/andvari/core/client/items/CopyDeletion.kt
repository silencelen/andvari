package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.client.session.SessionEndReason

/**
 * Why this device's copy of an account at an origin is deleted: the item cache ([ItemCacheNames.delete]) and the
 * content's kept records, files set aside and save queue (`ContentStores.drop`, `ContentKeeping.dropAll`). Design
 * §4.4, "A session the server ends does not delete the device's copy": only the person deletes it, so every value here
 * is the person's own act, or the server's policy the person accepted. There is deliberately no value for a session
 * the server ended (a refused refresh, a revoked session, a `revoked` bell frame, a 401 that ends the session): such a
 * copy stays, opens read-only from itself, and is sent from again when the person signs in to the same account at the
 * same origin with its pin in force.
 */
enum class CopyDeletion {
    /** The person signed out on this device ("Sign out"). */
    SIGNED_OUT,

    /** The person chose "Forget this server" (or forgot this account on this device). */
    FORGOT_SERVER,

    /** The person deleted the account. */
    ACCOUNT_DELETED,

    /** The server's client policy forbids an offline copy (design §7.1 `offlineCacheAllowed` false). */
    POLICY_FORBIDS_OFFLINE_COPY,

    ;

    companion object {
        /**
         * What a session end means for the copy: the deletion it calls for, or null when the copy stays. Only the person's
         * sign-out and a forgotten server or account delete; [SessionEndReason.REFRESH_REFUSED] and any reason added
         * later keep the copy (the safe default: a server's answer never deletes it).
         */
        fun forSessionEnd(reason: SessionEndReason): CopyDeletion? = when (reason) {
            SessionEndReason.SIGNED_OUT -> SIGNED_OUT
            SessionEndReason.FORGOTTEN -> FORGOT_SERVER
            else -> null
        }
    }
}
