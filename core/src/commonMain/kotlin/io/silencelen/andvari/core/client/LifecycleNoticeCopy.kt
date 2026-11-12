package io.silencelen.andvari.core.client

import kotlinx.datetime.Instant
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime

/**
 * What a lifecycle notice (spec 03 §11) says, and whether it is a warning. Android's `noticeBody` (SharingScreen.kt)
 * says the same, sentence for sentence; its tests pin the two together. Attribution ("by its owner") is EARNED by a
 * verified proof, and the anomaly wordings are warnings.
 *
 * [day] formats a date for "kept sealed until …"; [heldAt], when this client has one, names where the sealed copy of a
 * vault whose removal could not be verified is kept (Android: "Sharing → the trash icon").
 */
object LifecycleNoticeCopy {
    fun body(n: LifecycleNotice, day: (Long?) -> String = ::englishDay, heldAt: String? = null): Pair<String, Boolean> {
        val name = n.vaultName.ifBlank { "a vault" }
        return when (n.kind) {
            "deleted" -> Pair(
                "“$name” was deleted by its owner. Its items were moved off this device" +
                    (n.purgeAt?.let { " (kept sealed until ${day(it)}, then removed)." } ?: ".") +
                    (n.parkedCount?.let { " $it of your edits hadn’t synced — they’ll be recovered if the vault is restored this week." } ?: ""),
                false,
            )
            "removed" -> when (n.reason) {
                SyncEngine.ALREADY_RECORDED -> Pair(HouseholdCopy.removalAlreadyRecordedNotice(name), false)
                SyncEngine.REMOVED_LEGACY -> Pair(HouseholdCopy.removedLegacyNotice(name), false)
                else -> Pair("Your access to “$name” was removed.", false)
            }
            "left" -> when (n.reason) {
                SyncEngine.LEFT_UNPROVEN -> Pair(HouseholdCopy.leftUnprovenNotice(name), true)
                SyncEngine.ALREADY_RECORDED -> Pair(HouseholdCopy.leftAlreadyRecordedNotice(name), false)
                else -> Pair("You left “$name”.", false)
            }
            "restored" -> Pair("“$name” was restored.", false)
            "transfer-complete" -> Pair(
                if (n.becameMine) "You are now the owner of “$name”." else "“$name” now has a new owner.",
                false,
            )
            "transfer-anomaly" -> Pair(
                "The server says “$name” changed owners, but this couldn’t be verified with the vault’s own key. " +
                    "If nobody in your household did this, tell your admin — the server may be misbehaving.",
                true,
            )
            "replay-denied" -> if (n.reason == SyncEngine.REMOVAL_REPLAY) Pair(HouseholdCopy.removalReplayDeniedNotice(name), true)
                else Pair(HouseholdCopy.replayDeniedNotice(n.parkedCount ?: 0, name), false)
            "added" -> Pair(HouseholdCopy.addedNotice(name, n.byLabel), false)
            "grant-anomaly" -> Pair(HouseholdCopy.grantAnomalyNotice(n.reason), true)
            "write-rejected" -> Pair(HouseholdCopy.writeRejectedNotice(n.parkedCount ?: 0, name, n.reason), true)
            "vk-mismatch" -> Pair(HouseholdCopy.vkMismatchNotice(name), true)
            "key-unreadable" -> Pair(HouseholdCopy.KEY_UNREADABLE_NOTICE, true)
            "wrong-vault" -> Pair(HouseholdCopy.WRONG_VAULT_NOTICE, true)
            "bad-id" -> Pair(HouseholdCopy.BAD_ID_NOTICE, true)
            else -> Pair( // "anomaly"
                "The server says you lost access to “$name”, but this couldn’t be verified as a real owner action. " +
                    "A sealed copy of its data is kept on this device for 30 days" + (heldAt?.let { " ($it)" } ?: "") + ". " +
                    "If nobody in your household did this, tell your admin — the server may be misbehaving.",
                true,
            )
        }
    }

    private val MONTHS = listOf("January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December")

    /** "November 19" (UTC), or "soon" when there is no date: Android's `fmtDay` in English. */
    fun englishDay(ms: Long?): String {
        if (ms == null || ms <= 0) return "soon"
        val date = Instant.fromEpochMilliseconds(ms).toLocalDateTime(TimeZone.UTC).date
        return "${MONTHS[date.monthNumber - 1]} ${date.dayOfMonth}"
    }
}
