package io.silencelen.andvari.recovery

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Fingerprint
import io.silencelen.andvari.core.trust.InstanceCard
import io.silencelen.andvari.core.trust.RecoveryRotation
import io.silencelen.andvari.core.trust.RecoveryVerdict
import io.silencelen.andvari.core.trust.RotationFields
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * A recovery key that was replaced on the way to the current one (spec 04 §5): [fp] names it, [since] is when the card
 * that moved every device off it was signed (ms), and [chain] is the rotations, oldest first, from [fp] to the current
 * key, each signed by the key it leaves.
 */
internal class OutgoingKey(val fp: String, val since: Long, val chain: List<ByteArray>)

/**
 * The server's recovery keys, as its own `GET /instance` answer `{cards, rotations}` (spec 03 §17.1) shows them and as
 * this tool checked them, offline (spec 04 §5, "A copy sealed to an outgoing key").
 *
 * [current] is the newest card's `recoveryFp`: the key every device now takes an answer signed by (spec 04 §7 step 4).
 * [outgoing] is the keys it replaced, newest first, as far back as signed rotations connect them to [current]; a copy
 * an account has not sealed again since a rotation is sealed to one of them. [currentSince] is when the newest card
 * that changed the key was signed (null: the key never changed). [pending] is a rotation from [current] that is stored
 * while no card names its new key yet: devices still take only [current]. [unsignedBefore] is set when an older change
 * of the key was made without a rotation: copies sealed before it cannot be answered.
 *
 * [anchored]: the file's card 0 hashes to the `--card0-hash` the operator gave, so the whole chain is checked from
 * something the operator holds. False only with `--instance-file-unchecked`: then nothing ties the file to the server
 * the operator knows (the server could have made up every card and rotation in it), and [note] says so on every line
 * the tool prints about it.
 */
internal class KeyHistory(
    val instanceId: String,
    val current: String,
    val currentSince: Long?,
    val outgoing: List<OutgoingKey>,
    val pending: RotationFields?,
    val unsignedBefore: Long?,
    val anchored: Boolean = true,
) {
    /** What every line about the file ends with when it is not checked against anything the operator holds. */
    val note: String get() = if (anchored) "" else UNCHECKED_NOTE

    companion object {
        private val json = Json

        /** spec 04 §5: the words every line about an unchecked file carries. */
        const val UNCHECKED_NOTE = " [by --instance-file, NOT checked against anything you hold]"

        private fun refuse(name: String, sentence: String): Nothing = throw RecoverRefused("REFUSED ($name): $sentence")

        /**
         * Read and check [bytes], the `GET /instance` answer the operator saved, for [instanceId] (the `--instance` the
         * operator gave), from [card0Hash], the hash of the server's first card that the operator holds (null: the
         * operator gave `--instance-file-unchecked`). In this order, each with its name, before any seed is asked for:
         * 1. at most [ToolInput.INSTANCE_FILE_MAX] bytes, strict UTF-8, no object giving a key twice and no nesting deeper
         *    than [ToolInput.JSON_DEPTH_MAX], and a JSON object whose `cards` and `rotations` are lists of canonical
         *    base64url frames, at most [ToolInput.CARDS_MAX] and [ToolInput.ROTATIONS_MAX] (other fields are ignored):
         *    `bad_instance_file`;
         * 2. card 0 hashes to [card0Hash] (`card0_mismatch`), checked before anything else of the chain; the cards,
         *    verified as one chain from card 0 (spec 01 §5.2): `bad_card_chain`; card 0 is another instance's:
         *    `instance_mismatch`; the newest card names no recovery key: `no_recovery_key`;
         * 3. every rotation verifies from a key the history reaches (the card chain's keys, then the keys rotations lead
         *    to): signed by the recovery key its `fromFp` names, with a good signature (`rotation_not_verified`), for this
         *    instance (`instance_mismatch`); a rotation from a key nothing reaches is `rotation_chain_broken`;
         * 4. the change of key into the newest card's is covered by signed rotations (`rotation_chain_broken`).
         */
        fun read(crypto: CryptoProvider, bytes: ByteArray, expectedInstanceId: String?, card0Hash: String?): KeyHistory {
            if (bytes.size > ToolInput.INSTANCE_FILE_MAX) {
                refuse("bad_instance_file", "--instance-file is larger than ${ToolInput.size(ToolInput.INSTANCE_FILE_MAX)}, so it is not the server's GET /api/v1/instance answer")
            }
            val text = try {
                bytes.decodeToString(throwOnInvalidSequence = true)
            } catch (e: CharacterCodingException) {
                refuse("bad_instance_file", "--instance-file is not UTF-8 text, so it is not the server's GET /api/v1/instance answer")
            }
            ToolInput.jsonProblem(text)?.let { refuse("bad_instance_file", "--instance-file is not the server's GET /api/v1/instance answer: $it") }
            val root = try {
                json.parseToJsonElement(text) as? JsonObject
            } catch (e: Throwable) {
                null
            } ?: refuse("bad_instance_file", BAD_FILE)
            val cards = frames(root["cards"]) ?: refuse("bad_instance_file", BAD_FILE)
            val rotations = frames(root["rotations"]) ?: refuse("bad_instance_file", BAD_FILE)
            if (cards.size > ToolInput.CARDS_MAX || rotations.size > ToolInput.ROTATIONS_MAX) {
                refuse(
                    "bad_instance_file",
                    "--instance-file carries ${cards.size} cards and ${rotations.size} rotations, more than the ${ToolInput.CARDS_MAX} and " +
                        "${ToolInput.ROTATIONS_MAX} the tool checks: it is not a server's GET /api/v1/instance answer it can use",
                )
            }

            // 2. The card chain: first its card 0 against what the operator holds, then from card 0, as a device verifies it.
            if (cards.isEmpty()) refuse("bad_card_chain", "the file holds no card: this server has not been set up")
            if (card0Hash != null && io.silencelen.andvari.core.trust.SignedFrame.hash(crypto, cards.first()) != card0Hash) {
                refuse(
                    "card0_mismatch",
                    "the first card in --instance-file does not hash to the --card0-hash you gave (${card0Hash.take(16)}…): this file is not the card " +
                        "chain of the server you hold the hash of, or the hash was mistyped. Do not take the hash from this file or the server. Nothing was asked for.",
                )
            }
            val verified = InstanceCard.verifyChain(crypto, cards)
            verified.verdict?.let { refuse("bad_card_chain", "card ${verified.failedAt} of the file does not verify (${it.code}). Fetch the answer again; if it happens again, the server's card chain is damaged or forged") }
            val chain = verified.chain.cards.map { it.fields }
            // assist names its instance (--instance); the fleet check takes card 0's.
            val instanceId = expectedInstanceId ?: chain.first().instanceId
            if (chain.first().instanceId != instanceId) {
                refuse("instance_mismatch", "the file is the card chain of another server (instance ${chain.first().instanceId}), not of --instance $instanceId")
            }
            val current = chain.last().recoveryFp ?: refuse("no_recovery_key", "the newest card names no recovery key: operator recovery is off on this server, and no device takes an answer")

            // 3. Every rotation, from a key the history reaches.
            val reached = LinkedHashSet<String>()
            chain.mapNotNullTo(reached) { it.recoveryFp }
            // Each rotation is tried against each reached key once at most (the keys reached are kept in order, and a
            // rotation remembers how far it got), so a file at the limits is checked in bounded time.
            val order = ArrayList(reached)
            val left = rotations.mapTo(ArrayList()) { it to 0 }
            val fields = ArrayList<RotationFields>()
            var progress = true
            while (progress && left.isNotEmpty()) {
                progress = false
                val iter = left.listIterator()
                while (iter.hasNext()) {
                    val (frame, from) = iter.next()
                    var ok: io.silencelen.andvari.core.trust.VerifiedRotation? = null
                    for (j in from until order.size) {
                        ok = RecoveryRotation.verify(crypto, frame, instanceId, order[j]).valueOrNull()
                        if (ok != null) break
                    }
                    if (ok == null) {
                        iter.set(frame to order.size)
                        continue
                    }
                    fields += ok.fields
                    if (reached.add(ok.fields.toFp)) order += ok.fields.toFp
                    iter.remove()
                    progress = true
                }
            }
            for ((frame, _) in left) {
                // Not from any key reached: either it claims one and fails there, or it starts from a key nothing names.
                val verdicts = reached.map { fp -> RecoveryRotation.verify(crypto, frame, instanceId, fp).verdictOrNull() }
                when (val v = verdicts.firstOrNull { it != null && it != RecoveryVerdict.FP_MISMATCH }) {
                    null -> refuse("rotation_chain_broken", "a rotation in the file starts from a recovery key that no card and no other rotation names: the rotations do not connect")
                    RecoveryVerdict.INSTANCE_MISMATCH -> refuse("instance_mismatch", "a rotation in the file was signed for another server, not for instance $instanceId")
                    else -> refuse("rotation_not_verified", "a rotation in the file does not verify (${v.code}): it is not signed by the recovery key it says it replaces")
                }
            }

            // 4. Back from the newest card: each key the cards replaced, while signed rotations connect it to the current key.
            val outgoing = ArrayList<OutgoingKey>()
            var unsignedBefore: Long? = null
            var currentSince: Long? = null
            var i = chain.lastIndex
            var key: String = current
            while (true) {
                while (i > 0 && chain[i - 1].recoveryFp == key) i--
                if (i == 0) break
                val since = chain[i].issuedAt
                if (currentSince == null) currentSince = since
                val before = chain[i - 1].recoveryFp ?: break // operator recovery was off before: nothing older to answer
                val links = RecoveryRotation.chain(crypto, rotations, instanceId, before, current)
                if (links == null) {
                    if (outgoing.isEmpty()) {
                        refuse(
                            "rotation_chain_broken",
                            "the server's recovery key changed to ${short(current)} (card ${chain[i].seq}) without a rotation signed by the key it replaced, " +
                                "${short(before)}: no device takes an answer for a copy sealed to that key. If this account has sealed a copy to the current " +
                                "key since, run again without --instance-file and with the current sheet alone",
                        )
                    }
                    unsignedBefore = since
                    break
                }
                if (before != current && outgoing.none { it.fp == before }) outgoing += OutgoingKey(before, since, links)
                key = before
                i--
            }
            val named = chain.mapNotNull { it.recoveryFp }.toSet()
            val pending = fields.firstOrNull { it.fromFp == current && it.toFp !in named }
            return KeyHistory(instanceId, current, currentSince, outgoing, pending, unsignedBefore, anchored = card0Hash != null)
        }

        /**
         * `--card0-hash` as the operator typed it: spaces and tabs removed (a hash may be printed in groups), then exactly
         * 64 lowercase hex (`bad_card0_hash`); the case is not changed.
         */
        fun card0HashArg(typed: String, usage: String): String =
            typed.filter { it != ' ' && it != '\t' }.takeIf { HEX64.matches(it) }
                ?: throw RecoverRefused("REFUSED (bad_card0_hash): --card0-hash must be the hash of the server's first card: 64 lowercase hex\n$usage")

        private val HEX64 = Regex("^[0-9a-f]{64}$")

        /**
         * The instance file's two options, decided while the command line is read, before any file is read
         * (spec 04 §5): with `--instance-file`, exactly one of `--card0-hash` (checked) and `--instance-file-unchecked`;
         * without it, neither. The `--card0-hash` value, or null for an unchecked file (or no file).
         */
        fun anchorOptions(instanceFile: String?, card0Hash: String?, unchecked: Boolean, usage: String): String? {
            if (instanceFile == null) {
                if (card0Hash != null || unchecked) {
                    throw RecoverRefused("REFUSED (instance_file_missing): ${if (unchecked) "--instance-file-unchecked" else "--card0-hash"} is about --instance-file, which was not given\n$usage")
                }
                return null
            }
            if (card0Hash != null && unchecked) {
                throw RecoverRefused("REFUSED (bad_card0_hash): give --card0-hash or --instance-file-unchecked, not both\n$usage")
            }
            if (card0Hash == null && !unchecked) throw RecoverRefused("REFUSED (card0_hash_required): $CARD0_HASH_REQUIRED\n$usage")
            return card0Hash?.let { card0HashArg(it, usage) }
        }

        /** spec 04 §5: why the tool wants the hash, where the operator reads it, and the one way on without it. */
        const val CARD0_HASH_REQUIRED =
            "--instance-file is the server's own word: a server can make up a whole card chain under its real instance ID. The tool checks " +
                "it from the hash of the server's first card, which you hold: give it with --card0-hash <64 hex>. Read it on your operator " +
                "device, never from the server or this file: `andvari-cli card show` (the line card0Hash), or the desktop app's Instance " +
                "details on the device that signed card 0 (\"card 0's hash\"). Your recovery kit's QR text carries it too, as its fourth field " +
                "(andvari-kit:2:…:<hash>:…). To go on without that check, give --instance-file-unchecked instead: every line about the file then " +
                "says that it is not checked against anything you hold."

        private const val BAD_FILE =
            "--instance-file is not the server's GET /api/v1/instance answer (expected {cards, rotations}, each a list of base64url frames)"

        /** A JSON list of canonical base64url strings, each a frame; null when [e] is anything else. */
        private fun frames(e: kotlinx.serialization.json.JsonElement?): List<ByteArray>? {
            val list = e as? JsonArray ?: return null
            return list.map { item ->
                val s = (item as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return null
                Bytes.fromB64Canonical(s)?.takeIf { it.isNotEmpty() } ?: return null
            }
        }

        /** A fingerprint as the operator compares it with a sheet: its first 32 hex, in groups of four. */
        fun short(fp: String): String = Fingerprint.groupedShort(fp).replace("\n", " ")

        /** A time the cards or rotations carry, in UTC to the second. */
        fun date(ms: Long): String = java.time.Instant.ofEpochMilli(ms).truncatedTo(java.time.temporal.ChronoUnit.SECONDS).toString()
    }

    /** What the tool says before it asks for any seed, when the key has changed (spec 04 §5): which sheet does what, and since when. */
    fun sayItFirst(forAssist: Boolean = true): List<String> = buildList {
        if (!anchored) {
            add("--instance-file is NOT checked against anything you hold (--instance-file-unchecked): the server could have made up its whole card chain")
            add("and every rotation in it, so each line below about the file is only the server's word$note.")
        }
        val source = if (anchored) "--instance-file, checked here from its first card, whose hash you gave" else "--instance-file, not checked against anything you hold"
        if (outgoing.isEmpty()) {
            add("The server's recovery key is ${short(current)}; it has not changed (by $source).${if (forAssist) " You need that one sheet." else ""}$note")
        } else {
            add("The server's recovery key has changed (the card chain and the signed rotations in $source):$note")
            add("  CURRENT sheet:  ${short(current)}${currentSince?.let { ", since ${date(it)}" } ?: ""}. It signs the answer: every device now takes only an answer signed with it.$note")
            for (k in outgoing) add("  OUTGOING sheet: ${short(k.fp)}, outgoing since ${date(k.since)}. A copy the account has not sealed again since then is sealed to it, and only it opens that copy.$note")
            if (forAssist) {
                add("You need the CURRENT sheet in any case, and the tool asks for it first. If this account's copy does not open with it, the copy was sealed before$note")
                add("the change, and the tool then asks for the OUTGOING sheet${if (outgoing.size > 1) "s, newest first" else ""}, to open the copy; the answer is still signed with the current one.$note")
            }
        }
        unsignedBefore?.let { add("Before ${date(it)} the key changed without a signed rotation: a copy sealed before then cannot be answered.$note") }
        pending?.let { add("A rotation to ${short(it.toFp)} is stored, but no card names that key yet: devices still take only ${short(current)}.$note") }
    }
}
