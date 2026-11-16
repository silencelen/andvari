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
            "transfer-anomaly" -> if (n.reason == SyncEngine.TRANSFER_NOT_OFFERED) {
                Pair(HouseholdCopy.transferNotOfferedNotice(name), true)
            } else {
                Pair(
                    "The server says “$name” changed owners, but this couldn’t be verified with the vault’s own key. " +
                        "If nobody in your household did this, tell your admin — the server may be misbehaving.",
                    true,
                )
            }
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

/**
 * What "Recently removed" says of a vault in the holding area (sharing review 2026-11, item 6), by the reason the server
 * gave and how its proof checked on this device ([HeldVaultInfo.proof]), and whether the line is a warning. [sentence]
 * is the iOS wording; [fragment] the Android and desktop lists'. A removal whose proof verified no longer reads as
 * unverified.
 */
object HeldVaultCopy {
    private enum class What { DELETED, DELETE_UNVERIFIED, LEFT, LEFT_UNPROVEN, LEFT_UNVERIFIED, REMOVED, REMOVED_LEGACY, REMOVED_ELSEWHERE, REMOVAL_REPLAYED, REMOVAL_UNVERIFIED }

    private fun what(h: HeldVaultInfo): What = when (h.reason) {
        "deleted" -> if (h.verified) What.DELETED else What.DELETE_UNVERIFIED
        // An entry kept before the verdict was recorded (null) said "you left", as it does now.
        "left" -> when (h.proof) {
            null, "VALID", "ALREADY_RECORDED" -> What.LEFT
            "LEFT_UNPROVEN" -> What.LEFT_UNPROVEN
            else -> What.LEFT_UNVERIFIED
        }
        else -> when (h.proof) {
            "VALID" -> What.REMOVED
            "VALID_LEGACY" -> What.REMOVED_LEGACY
            "ALREADY_RECORDED" -> What.REMOVED_ELSEWHERE
            "REPLAY_DENIED" -> What.REMOVAL_REPLAYED
            else -> if (h.proof == null && h.verified) What.REMOVED else What.REMOVAL_UNVERIFIED
        }
    }

    private fun warns(w: What): Boolean = w in setOf(What.DELETE_UNVERIFIED, What.LEFT_UNPROVEN, What.LEFT_UNVERIFIED, What.REMOVAL_REPLAYED, What.REMOVAL_UNVERIFIED)

    /** The line under the vault's name, as a sentence (iOS), and whether it is a warning. */
    fun sentence(h: HeldVaultInfo, day: (Long?) -> String = LifecycleNoticeCopy::englishDay): Pair<String, Boolean> {
        val w = what(h)
        val kept = "Kept until ${day(h.expungeAt)}."
        val line = when (w) {
            What.DELETED -> "Deleted by its owner. Kept sealed until ${day(h.purgeAt ?: h.expungeAt)}."
            What.DELETE_UNVERIFIED -> "The server says it was deleted, but this couldn't be verified. $kept"
            What.LEFT -> "You left. $kept"
            What.LEFT_UNPROVEN -> "The server says you left, with no proof from your device. Didn't do this? Tell your admin. $kept"
            What.LEFT_UNVERIFIED -> "The server says you left, but this couldn't be verified. $kept"
            What.REMOVED -> "Your access was removed. $kept"
            What.REMOVED_LEGACY -> "Your access was removed (sent by an older app version). $kept"
            What.REMOVED_ELSEWHERE -> "Your access was removed, as another of your devices already recorded. $kept"
            What.REMOVAL_REPLAYED -> "The server sent a removal notice that was already used once, so andvari did not trust it. $kept"
            What.REMOVAL_UNVERIFIED -> "The server says your access was removed, but this couldn't be verified. $kept"
        }
        return line to warns(w)
    }

    /** The line under the vault's name, in the Android and desktop lists' style, and whether it is a warning. */
    fun fragment(h: HeldVaultInfo, day: (Long?) -> String): Pair<String, Boolean> {
        val w = what(h)
        val kept = "kept until ${day(h.expungeAt)}"
        val line = when (w) {
            What.DELETED -> "deleted by its owner · kept sealed until ${day(h.purgeAt ?: h.expungeAt)}"
            What.DELETE_UNVERIFIED -> "unverified deletion · $kept"
            What.LEFT -> "you left · $kept"
            What.LEFT_UNPROVEN -> "you left, says the server, with no proof · $kept"
            What.LEFT_UNVERIFIED -> "unverified leave · $kept"
            What.REMOVED -> "access removed · $kept"
            What.REMOVED_LEGACY -> "access removed (older app version) · $kept"
            What.REMOVED_ELSEWHERE -> "access removed, recorded on another of your devices · $kept"
            What.REMOVAL_REPLAYED -> "replayed removal notice, not trusted · $kept"
            What.REMOVAL_UNVERIFIED -> "unverified removal · $kept"
        }
        return line to warns(w)
    }
}
