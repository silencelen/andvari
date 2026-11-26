package io.silencelen.andvari.core.client.session

/**
 * What a session-grade store (the engine's `secure`) can say beyond its records: that it holds a session record
 * ([SessionKeeper.KEY]) it cannot read now. A platform's store that answers "nothing" for such a record (the iPhone's
 * Keychain before the first unlock since boot, Android's Keystore while it does not answer, the desktop's key store while
 * the keyring is locked) implements this beside [io.silencelen.andvari.core.client.DeviceState], so that the engine can tell
 * "no session record" from "a session record that cannot be read now". While it says so the engine takes nothing that the
 * record could protect: the forgetting of an earlier account is neither offered nor made (the record may be that account's),
 * and the sweep of accounts the device no longer knows removes nothing. A store that throws at the read of that record
 * says the same.
 */
interface SessionRecordReadability {
    /** True while this store holds a session record it cannot read now (and answers "nothing" for it meanwhile). */
    val sessionRecordUnreadable: Boolean
}
