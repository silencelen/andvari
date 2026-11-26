package io.silencelen.andvari.core.client

/**
 * A user id of all zeros (the nil UUID) is never an account. An honest server never assigns it (the escrow's canary uses
 * it), so a client refuses it wherever a server or another party hands one over: as a contact, as a member a log action
 * names, as the account a session or recovery answer names.
 */
object UserIds {
    const val NIL: String = "00000000-0000-0000-0000-000000000000"

    /** True when [userId] is the nil UUID, in any letter case. */
    fun isNil(userId: String?): Boolean = userId != null && userId.equals(NIL, ignoreCase = true)
}
