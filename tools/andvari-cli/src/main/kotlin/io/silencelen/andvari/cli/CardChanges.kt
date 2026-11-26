package io.silencelen.andvari.cli

import io.silencelen.andvari.core.client.account.CardChangeResult
import io.silencelen.andvari.core.client.account.WireOperatorCards
import io.silencelen.andvari.core.client.pin.CardPin
import io.silencelen.andvari.core.client.pin.CardStatus
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.trust.Checked
import io.silencelen.andvari.core.trust.RecoveryRotation
import io.silencelen.andvari.core.trust.TrustGrammar

/**
 * The tool's side of the operator's card changes (design §4.2, §4.3, §4.5, §9.1; spec 03 §17.2, §17.3).
 * Every change goes through the shared code's own path, [WireOperatorCards] ([Host.operatorCards]), as the desktop's
 * console does, so the two hosts cannot drift apart: one change per card, built from this device's verified pin and
 * checked as every verifier would before the password is touched; a change from one recovery key to another only with its
 * signed rotation; the rotations uploaded before the card. What this file adds is what a command line needs around it:
 * reading the offline tool's statements from a file, checking them against this device's pin before the master password
 * is asked at all, and saying each outcome in words.
 */
object CardChanges {
    /** The most a rotation file may hold: `recovery-cli rotate` prints one statement and a few lines of text. */
    const val ROTATION_FILE_MAX = 64 * 1024
    const val ROTATIONS_MAX = 16

    /** What the person types to remove the recovery key (`card sign --recovery-fp none`). */
    const val REMOVE_PHRASE = "REMOVE RECOVERY KEY"

    /** A card that was stored and that this device's pin did not land on: say so, and sign nothing more at that number. */
    const val KEY_CARD_NOT_SHOWN = "card_stored_not_shown"

    /** A card upload whose answer never came. */
    const val KEY_CARD_UNKNOWN = "card_outcome_unknown"

    private val B64URL = Regex("^[A-Za-z0-9_-]{64,}$")

    /**
     * The 0x08 statements in a file `recovery-cli rotate` wrote (its whole output, or only the statement lines), oldest
     * first: each line that is one run of base64url, decoded. Its explanatory lines hold spaces and are passed over.
     * Refused before anything else: a file too large, one with no statement, or one with too many.
     */
    fun statements(text: String): List<ByteArray> {
        if (text.length > ROTATION_FILE_MAX) throw CliError("--file holds more than a rotation file does (${text.length} characters): nothing was asked or sent", 2)
        val frames = text.lines().map { it.trim() }.filter { B64URL.matches(it) }.map {
            runCatching { Bytes.fromB64(it) }.getOrNull() ?: throw CliError("--file: a statement line does not decode as base64url: nothing was asked or sent", 2)
        }
        if (frames.isEmpty()) throw CliError("--file holds no rotation statement (the line `recovery-cli rotate` prints last): nothing was asked or sent")
        if (frames.size > ROTATIONS_MAX) throw CliError("--file holds ${frames.size} statements, more than $ROTATIONS_MAX: nothing was asked or sent")
        return frames
    }

    /**
     * The fingerprint [frames] lead to from [pin]'s `recoveryFp`, each statement verified as the shared code verifies it
     * (signed by the key the fingerprint reached so far names, for this instance); refused with the verdict otherwise.
     * Run before the master password is asked: a statement that does not verify costs nothing and sends nothing.
     * [typedFp], when given, must be where the statements lead.
     */
    fun leadsTo(crypto: CryptoProvider, pin: CardPin, frames: List<ByteArray>, typedFp: String?): String {
        if (pin.recoveryFp == TrustGrammar.NONE) throw CliError(
            "the card names no recovery key, so there is none to rotate from: name one with `card sign --recovery-fp <fingerprint>`. Nothing was asked or sent",
        )
        var reached = pin.recoveryFp
        for ((i, frame) in frames.withIndex()) {
            when (val v = RecoveryRotation.verify(crypto, frame, pin.instanceId, reached)) {
                is Checked.Ok -> reached = v.value.fields.toFp
                is Checked.Refused -> throw CliError(
                    "rotation statement ${i + 1} of ${frames.size} does not verify against this server's card (${v.verdict.code}): it is not a statement " +
                        "recovery-cli rotate made with this server's current recovery seed for instance ${pin.instanceId}. Nothing was asked or sent",
                )
            }
        }
        if (reached == pin.recoveryFp) throw CliError("the statements lead back to the key the card names already: nothing to change. Nothing was asked or sent")
        if (typedFp != null && typedFp != reached) throw CliError(
            "--recovery-fp $typedFp is not the key the rotation statement leads to ($reached): check which one you meant. Nothing was asked or sent",
        )
        return reached
    }

    /** A typed fingerprint as the card writes it: lowercase hex, spaces and dashes dropped; `none` stays. */
    fun typedFp(raw: String): String = if (raw.trim().equals(TrustGrammar.NONE, ignoreCase = true)) TrustGrammar.NONE
        else raw.lowercase().filter { it != ' ' && it != '-' }

    /**
     * What a card change came to, as the person reads it; a refusal or an uncertain outcome is thrown. [before] is this
     * device's pin before the change (the stored card is the one after it).
     */
    fun outcome(r: CardChangeResult, origin: String, before: CardPin?): String {
        val seq = before?.let { it.seq + 1 }
        return when (r) {
            is CardChangeResult.Changed -> "card ${r.pin.seq} stored: ${r.hash}"
            is CardChangeResult.Stored -> when (val st = r.status) {
                // A move: the old server keeps serving the chain, and this device follows it only on the person's word.
                is CardStatus.Moved -> "card ${st.newest.seq} stored: ${r.hash}. It moves the server to ${st.newest.origin}: run `andvari-cli card follow --yes` to follow it here"
                else -> throw CliError(
                    "card ${seq ?: "?"} was stored (${r.hash}), but this device's pin did not land on it (${st::class.simpleName}): the server does not show it yet. " +
                        "Do not sign another card now; run `andvari-cli card show` later",
                    1, KEY_CARD_NOT_SHOWN,
                )
            }
            is CardChangeResult.NotCurrent -> throw CliError(
                "this device's pin of $origin is not at the server's newest card (${r.status::class.simpleName}), so no card can be built on it: nothing was signed or sent",
            )
            CardChangeResult.NotOperator -> throw CliError("the newest card does not name this account and its key as the operator: this account cannot sign the next card. Nothing was sent")
            is CardChangeResult.HeadMoved -> throw CliError("another card was stored first, so this one is not the next: nothing was stored. Run the command again")
            CardChangeResult.BadCard -> throw CliError("the server refused the card (bad_card): nothing was stored")
            CardChangeResult.HandoverTargetInvalid -> throw CliError(
                "the server refused the new operator (handover_target_invalid): the account is not active, has operator recovery on, or on a public server owns a shared vault. Nothing changed",
            )
            is CardChangeResult.BadRotation -> throw CliError(
                if (r.verdict != null) "the rotation statement does not verify (${r.verdict}): nothing was sent"
                else "the server refused the rotation statement (bad_rotation): the card was not sent",
            )
            CardChangeResult.PublicRefusesRecoveryKey -> throw CliError("a public server's card names no recovery key: nothing was signed or sent")
            is CardChangeResult.Invalid -> throw CliError(invalid(r.code), if (r.code == WireOperatorCards.NO_CHANGE) 1 else 2)
            CardChangeResult.NoSession -> throw CliError("this device may not send the password to $origin now: nothing was sent")
            CardChangeResult.WrongPassword -> throw CliError("wrong master password: nothing was sent")
            is CardChangeResult.Refused -> throw when (r.code) {
                RATE_LIMITED -> tooManyPasswords(r.retryAfterSeconds, "Nothing was stored")
                // The engine's word: the proof was made here and sent, and the server refused it. Never a wrong password.
                io.silencelen.andvari.core.client.account.Reauthed.PROOF_REFUSED -> proofRefusedError(origin)
                else -> CliError("the card was refused: ${r.code}")
            }
            CardChangeResult.Unknown -> throw CliError(
                "no answer from $origin: card ${seq ?: "?"} may have been stored. Run `andvari-cli card show` (after `andvari-cli sync`) before signing again",
                1, KEY_CARD_UNKNOWN,
            )
        }
    }

    private fun invalid(code: String): String = when (code) {
        WireOperatorCards.BAD_NAME -> "--name is not a name a card can carry: nothing was signed or sent"
        WireOperatorCards.BAD_ORIGIN -> "--move-to must be an https address with a domain name: nothing was signed or sent"
        WireOperatorCards.BAD_KEY -> "the new operator's user id or signing key is not well formed (a uuid, and 43 characters of base64url for an Ed25519 key): nothing was signed or sent"
        WireOperatorCards.HANDOVER_KEY_MISMATCH -> "the signing key given is not the key of the contact this account compared codes with: nothing was signed or sent"
        WireOperatorCards.BAD_FP -> "--recovery-fp must be the 64 hex digits recovery-cli keygen printed: nothing was signed or sent"
        WireOperatorCards.RECOVERY_KEY_SET -> "the card names a recovery key already: a change from one key to another needs its signed rotation " +
            "(`recovery-cli rotate` offline with the current seed, then `andvari-cli card rotation --file F`). An unsigned change is refused. Nothing was signed or sent"
        WireOperatorCards.ORIGIN_PINNED -> "this device already keeps a pin for the address to move to: forget it first (`forget-server --yes --origin ...`). Nothing was signed or sent"
        WireOperatorCards.NO_CHANGE -> "that is what the card says already: nothing was signed or sent"
        else -> "the change was refused on this device ($code): nothing was signed or sent"
    }
}
