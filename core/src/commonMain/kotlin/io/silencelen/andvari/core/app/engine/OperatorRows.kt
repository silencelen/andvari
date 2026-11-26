package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.model.wire.AccountSummary
import io.silencelen.andvari.core.model.wire.AdminRecoveryRequest
import io.silencelen.andvari.core.model.wire.Device
import io.silencelen.andvari.core.trust.TrustGrammar

/**
 * Every field of an operator list's row
 * that a screen draws or a clipboard takes is checked where the row is read, before it reaches either. What is checked:
 *
 * - **A recovery request:** the request id is `b64_16`; the account id a `uuid`; the address a normalised address (it
 *   equals its own `emailNorm`); the request key (`rPub`) 32 bytes of canonical base64url; the server's account ID 32
 *   lowercase hex; the platform one of the closed list ([TrustGrammar.PLATFORMS]); the times whole and not negative. A
 *   row that fails any of these is not shown at all; a list that names one request twice is refused whole, as before.
 * - **An account:** the address normalised; the role, status and recovery posture each one of their closed values. A row
 *   that fails is not shown. The display name is the server's text: shown only when it passes the `name` rule of §2.2
 *   (no control, direction-override, zero-width or line-separator characters, at most 64 bytes), and otherwise blanked.
 * - **A device:** the id a `uuid`, the platform one of the closed list, `linkedFrom` a `uuid` when given; a row that
 *   fails is not shown. The device name and the client version are the server's text, blanked (the version: dropped)
 *   when they fail the same `name` rule.
 *
 * Every drop or blank is counted, so that the console can say the server sent something it should not have
 * ([io.silencelen.andvari.core.app.OperatorConsole.serverSentBadRows]). Nothing here makes a row more trusted than the
 * server's word: it only keeps what cannot be a well-formed value away from the screen and the clipboard.
 */
internal object OperatorRows {
    private val ROLES = setOf("operator", "member")
    private val STATUSES = setOf("active", "disabled")
    private val POSTURES = setOf("private", "operator")
    private val REQUEST_STATES = setOf("holding", "awaiting_operator", "ready")

    private fun hex32(s: String): Boolean = s.length == 32 && s.all { it in '0'..'9' || it in 'a'..'f' }
    private fun hex64(s: String): Boolean = s.length == 64 && s.all { it in '0'..'9' || it in 'a'..'f' }

    private fun normalised(email: String): Boolean = TrustGrammar.emailNorm(email) == email

    /** The server's text as a screen may draw it, or null when it is not plain text of the `name` rule. */
    private fun plain(text: String): String? = text.takeIf { TrustGrammar.encodeName(it) != null }

    class Checked<T>(val rows: List<T>, val bad: Int)

    /** The rows that hold; null when the list names one request twice (a list that contradicts itself is refused whole). */
    fun requests(list: List<AdminRecoveryRequest>): Checked<AdminRecoveryRequest>? {
        if (list.map { it.requestId }.toSet().size != list.size) return null
        val rows = list.filter {
            TrustGrammar.isB64_16(it.requestId) && TrustGrammar.isUuid(it.userId) && normalised(it.email) && TrustGrammar.isB64_32(it.rPub) &&
                hex32(it.accountId) && TrustGrammar.isPlatform(it.platform) && it.createdAt >= 0 && it.verifiedAt >= 0 && it.holdEndsAt >= 0 &&
                // spec 03 §18.6: the additive `state`, when sent, is one of the three listed states.
                (it.state == null || it.state in REQUEST_STATES) &&
                // The additive `escrowFingerprint`, when sent, is a hex64 key fingerprint.
                (it.escrowFingerprint == null || hex64(it.escrowFingerprint))
        }
        return Checked(rows, list.size - rows.size)
    }

    fun accounts(list: List<AccountSummary>): Checked<AccountSummary> {
        var bad = 0
        val rows = list.mapNotNull { a ->
            if (!normalised(a.email) || a.role !in ROLES || a.status !in STATUSES || a.recovery !in POSTURES) {
                bad++
                return@mapNotNull null
            }
            val name = if (a.displayName.isEmpty()) "" else plain(a.displayName)
            if (name == null) {
                bad++
                a.copy(displayName = "")
            } else {
                a
            }
        }
        return Checked(rows, bad)
    }

    fun devices(list: List<Device>): Checked<Device> {
        var bad = 0
        val rows = list.mapNotNull { d ->
            if (!TrustGrammar.isUuid(d.deviceId) || !TrustGrammar.isPlatform(d.platform) || (d.linkedFrom != null && !TrustGrammar.isUuid(d.linkedFrom))) {
                bad++
                return@mapNotNull null
            }
            val name = if (d.name.isEmpty()) "" else plain(d.name)
            val version = d.clientVersion?.let { plain(it) }
            if (name == null || (d.clientVersion != null && version == null)) {
                bad++
                d.copy(name = name ?: "", clientVersion = version)
            } else {
                d
            }
        }
        return Checked(rows, bad)
    }
}
