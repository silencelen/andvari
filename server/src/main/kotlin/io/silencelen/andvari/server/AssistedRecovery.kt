package io.silencelen.andvari.server

import io.ktor.server.routing.Route
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.RecoveryPollRequest
import io.silencelen.andvari.core.model.wire.RecoveryPollResponse
import io.silencelen.andvari.core.model.wire.RecoveryPosture
import io.silencelen.andvari.core.model.wire.RecoveryRequestCommit
import io.silencelen.andvari.core.model.wire.RecoveryRequestCreate
import io.silencelen.andvari.core.model.wire.RecoveryRequestCreated
import io.silencelen.andvari.core.model.wire.RecoveryRequestState
import io.silencelen.andvari.core.model.wire.RecoveryRequestSummary
import io.silencelen.andvari.core.model.wire.RecoveryRequestVerified
import io.silencelen.andvari.core.model.wire.RecoveryRequestVerify
import io.silencelen.andvari.core.model.wire.RecoveryVetoRequest
import io.silencelen.andvari.core.model.wire.SessionResponse
import io.silencelen.andvari.core.model.wire.WireErrors
import io.silencelen.andvari.core.model.wire.WireGrammar
import io.silencelen.andvari.core.model.wire.WireRoute
import java.security.MessageDigest
import java.sql.Connection

/**
 * Operator-assisted recovery (spec 03 §18; design §9.3), private instances only: every route here is **R**.
 * No temporary password exists at any point; the operator's answer is a 0x09 statement signed offline by
 * the recovery key and sealed to the requesting device's one-time key, which the server only stores.
 */
object Assisted {
    const val CODE_TTL_MS = 15 * 60_000L
    const val UNVERIFIED_TTL_MS = Clock.DAY_MS
    const val HOLD_MS = 7 * Clock.DAY_MS
    const val AFTER_HOLD_TTL_MS = 30 * Clock.DAY_MS
    const val ATTEMPTS = 5
    const val SEALED_MAX_BYTES = 1024

    /**
     * `POST /recovery/requests` per address (design §9.3): 5 a day, keyed on the address hash; silent. "A day" is a window
     * of 24 hours that starts at the first request it counts.
     */
    val ADDRESS_BUCKET = Bucket.givenPerDay("recovery_request_address", 5)

    /**
     * `POST /recovery/requests/{requestId}/verify` per caller address: 20 an hour, as `POST /signup/verify`. Its name
     * is its own: under the kit route's `recovery_verify` (5 a minute per IP) the two limits undid each other.
     */
    val VERIFY_BUCKET = Bucket.ipPerHour("recovery_request_verify", 20)

    /**
     * Requests taken past [ADDRESS_BUCKET] because they named a mailbox value of the address (spec 03 §18.1): a ceiling
     * of their own, 5 per window of 24 hours that starts at the first request it counts, keyed on the address hash. Its
     * window and [ADDRESS_BUCKET]'s start independently, so an address receives at most five plus five request mails
     * within one window of each, and across their edges up to twenty inside 24 hours (spec 03 §18.1 states the bound).
     */
    val MAILBOX_BUCKET = Bucket.givenPerDay("recovery_request_mailbox", 5)

    /** How long a mailbox value can be used (spec 03 §18.1): seven days from the mail that carried it. */
    const val MAILBOX_TTL_MS = 7 * Clock.DAY_MS

    /**
     * The mailbox value's 32 symbols: the capital letters without I and O, and the digits 2 to 9, so that nothing in it
     * reads as another symbol. Sixteen of them are 80 bits.
     */
    const val MAILBOX_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    const val MAILBOX_CHARS = 16

    /** The longest `mailboxValue` string a request may carry (spec 03 §18.1); a longer one, or one that is not a string, is `400 bad_mailbox_value`. */
    const val MAILBOX_FIELD_MAX = 64

    /** What is hashed in place of a value when a request names none, or one that is not of the value's form: no value is this. */
    private const val NO_MAILBOX_VALUE = "-"

    /**
     * What a refused verify compares and updates when the requestId names no usable request: a requestId no request
     * can have (not b64_16) and a MAC no code can have (not 64 hex), so the work is a real request's and matches nothing.
     */
    const val NO_REQUEST = "-"
    val NO_MAC = "-".repeat(64)

    private val crypto = createCryptoProvider()

    /** The emailed code's MAC, keyed by the instance's sign-up secret (or the enumeration secret without one). */
    fun codeMac(s: Services, requestId: String, code: String): String {
        val key = s.config.signupSecret ?: s.config.enumSecret.copyOf(32)
        return Bytes.toHexLower(crypto.hmacSha256(key, "andvari/v2|recovery-request-code|$requestId|$code".encodeToByteArray()))
    }

    /**
     * A fresh mailbox value (spec 03 §18.1): 80 bits from the secure random source, as [MAILBOX_CHARS] symbols of
     * [MAILBOX_ALPHABET], five bits each.
     */
    fun newMailboxValue(): String {
        val bytes = crypto.randomBytes(10)
        val sb = StringBuilder(MAILBOX_CHARS)
        var buffer = 0
        var bits = 0
        for (b in bytes) {
            buffer = (buffer shl 8) or (b.toInt() and 0xFF)
            bits += 8
            while (bits >= 5) {
                bits -= 5
                sb.append(MAILBOX_ALPHABET[(buffer shr bits) and 0x1F])
            }
        }
        bytes.fill(0)
        return sb.toString()
    }

    /** The display form of a mailbox value, as the mail shows it: four groups of four, separated by single spaces. */
    fun mailboxDisplay(value: String): String = value.chunked(4).joinToString(" ")

    /**
     * A typed mailbox value in its one form, in ASCII only: spaces, tabs and dashes removed and the letters a to z raised;
     * null when what remains is not [MAILBOX_CHARS] symbols of [MAILBOX_ALPHABET] (such a value is a wrong one, and
     * changes nothing). No other character is mapped: a character from outside ASCII that a full case mapping would turn
     * into letters of the alphabet (the long s, the sharp s, a ligature, a full-width letter) stays what it is, and so
     * makes the value a wrong one.
     */
    fun mailboxValueOf(typed: String?): String? {
        if (typed == null) return null
        val v = StringBuilder(typed.length)
        for (ch in typed) {
            when (ch) {
                ' ', '\t', '-' -> Unit
                in 'a'..'z' -> v.append(ch - ('a' - 'A'))
                else -> v.append(ch)
            }
        }
        return v.toString().takeIf { it.length == MAILBOX_CHARS && it.all { ch -> ch in MAILBOX_ALPHABET } }
    }

    /**
     * The stored hash of [value] for the address of [emailHash] (the address's keyed hash, [Config.addressHash]; the plain
     * one for a value mailed before 2026-11-18), keyed as the request code's MAC ([codeMac]). The address
     * is inside the hash, so a value of another address is looked up exactly as a wrong one and finds nothing. With
     * [value] null the same work is done for a value no mail carries.
     */
    fun mailboxHash(s: Services, emailHash: String, value: String?): String {
        val key = s.config.signupSecret ?: s.config.enumSecret.copyOf(32)
        return Bytes.toHexLower(crypto.hmacSha256(key, "andvari/v2|recovery-mailbox-value|$emailHash|${value ?: NO_MAILBOX_VALUE}".encodeToByteArray()))
    }

    /**
     * Every mailbox value of the address [emailNorm] is forgotten: its account was deleted, its recovery completed, or
     * it switched to the private posture. The rows are found by the address's keyed hash ([Config.addressHash]), and by
     * its plain hash for a value mailed before 2026-11-18 (such a row lives seven days at most).
     */
    fun forgetMailboxValues(c: Connection, config: Config, emailNorm: String): Int =
        c.exec("DELETE FROM recovery_mailbox_values WHERE emailHash IN (?,?)", config.addressHash(emailNorm), Grammar.emailHash(emailNorm))

    /** [forgetMailboxValues] for the address of the account [userId], read from its row (nothing when it has none). */
    fun forgetMailboxValuesOf(c: Connection, config: Config, userId: String): Int =
        c.queryOne("SELECT email FROM users WHERE userId=?", userId) { it.getString(1) }?.let { forgetMailboxValues(c, config, it) } ?: 0

    /** A stored request; [userId] is null on a decoy (spec 03 §18.1), which has no code and is never verified. */
    class Row(
        val requestId: String, val userId: String?, val emailHash: String, val rPub: String, val pollHash: String, val platform: String,
        val codeMac: String?, val codeExpiresAt: Long?, val attempts: Int, val state: String, val createdAt: Long,
        val verifiedAt: Long?, val holdEndsAt: Long?, val sealed: String?,
        /** spec 03 §18.6: the hash of the newest answer's commit value. */
        val commitHash: String? = null,
        /** When the account's owner cancelled this request before its code was entered ([cancelPending]); null otherwise. */
        val cancelledAt: Long? = null,
    ) {
        /** The account of a request past verification; only a real request ever gets there. */
        val account: String get() = userId ?: error("a decoy recovery request has no account")
    }

    fun row(c: Connection, requestId: String): Row? = c.queryOne("SELECT * FROM recovery_requests WHERE requestId=?", requestId) { rs ->
        Row(
            rs.getString("requestId"), rs.getString("userId"), rs.getString("emailHash"), rs.getString("rPub"), rs.getString("pollHash"),
            rs.getString("platform"), rs.getString("codeMac"), rs.longOrNull("codeExpiresAt"), rs.getInt("attempts"), rs.getString("state"),
            rs.getLong("createdAt"), rs.longOrNull("verifiedAt"), rs.longOrNull("holdEndsAt"), rs.getString("sealed"),
            rs.getString("commitHash"), rs.longOrNull("cancelledAt"),
        )
    }

    /**
     * The served state of a stored request (spec 03 §18.4) at [nowMs]. A verified request, fulfilled or not,
     * expires 30 days after its hold ended (exclusive: dead at `now = holdEndsAt + 30 d`); that is decided here,
     * at every read and at the commit, never only by the janitor's daily sweep.
     */
    fun stateOf(r: Row, nowMs: Long): String = when (r.state) {
        "vetoed" -> RecoveryRequestState.VETOED
        "fulfilled" -> if (nowMs >= r.holdEndsAt!! + AFTER_HOLD_TTL_MS) RecoveryRequestState.EXPIRED else RecoveryRequestState.READY
        "unverified" -> if (nowMs >= r.createdAt + UNVERIFIED_TTL_MS) RecoveryRequestState.EXPIRED else RecoveryRequestState.UNVERIFIED
        else -> when {
            nowMs >= r.holdEndsAt!! + AFTER_HOLD_TTL_MS -> RecoveryRequestState.EXPIRED
            nowMs < r.holdEndsAt -> RecoveryRequestState.HOLDING
            else -> RecoveryRequestState.AWAITING_OPERATOR
        }
    }

    /** States in which a request is shown to the account's devices and may be vetoed (spec 03 §18.3). */
    private val PENDING = setOf(RecoveryRequestState.HOLDING, RecoveryRequestState.AWAITING_OPERATOR, RecoveryRequestState.READY)

    /**
     * Pending: verified and not yet committed, vetoed or expired — `holding`, `awaiting_operator`, and also
     * `ready` once the operator fulfilled it. Every such request is listed to the account's signed-in devices,
     * counted by `/sync`, and vetoable, so an answer the operator gave to someone holding only the inbox can
     * still be stopped before it is committed.
     */
    fun pending(r: Row, nowMs: Long): Boolean = stateOf(r, nowMs) in PENDING

    /** The account's pending requests, oldest first: one source for the list (row 29) and `/sync`'s count. */
    fun pendingOf(c: Connection, userId: String, nowMs: Long): List<Row> =
        c.queryAll("SELECT requestId FROM recovery_requests WHERE userId=? ORDER BY createdAt", userId) { it.getString(1) }
            .mapNotNull { row(c, it) }
            .filter { pending(it, nowMs) }

    /**
     * Cancel every request of [userId] not yet committed. Run inside the transaction of each event that makes an
     * earlier request meaningless or dangerous: the posture switched to private, a kit-recovery or assisted-recovery
     * commit, a password change.
     *
     * - A request past its mailed code (verified or fulfilled) becomes `vetoed`, its sealed answer dropped: whoever
     *   opened it has shown that they read the mailbox, and its poll says so.
     * - A request whose code was not entered stays `unverified`, its code still checkable, and only [cancelledAt] is
     *   set (decided on 2026-11-17). Its poll then answers exactly as before the owner acted, as a decoy's does, so
     *   that whoever opened a request for an address cannot learn from its poll that the address has an account whose
     *   owner just acted. The cancel is told at the code step: the right code is answered `409 request_state` and the
     *   request becomes `vetoed`; a wrong one is the uniform `400 bad_code`.
     */
    fun cancelPending(c: Connection, userId: String, nowMs: Long): Int =
        c.exec("UPDATE recovery_requests SET state='vetoed', codeMac=NULL, sealed=NULL, commitHash=NULL WHERE userId=? AND state IN ('verified','fulfilled')", userId) +
            c.exec("UPDATE recovery_requests SET cancelledAt=COALESCE(cancelledAt,?) WHERE userId=? AND state='unverified'", nowMs, userId)

    /**
     * The start-up's step for answers of the old form (spec 02 §5.1): a request a database already
     * holds as answered without a commit hash was answered before the answer carried one (every upload since stores
     * it), so its answer is of the old form, which no device takes, and no commit value can ever match it. It goes
     * back to verified and waiting for the operator, its stored answer dropped, so the operator's console lists it as
     * to be answered again. Run at every start inside the start-up's transaction; a current database has none. Returns
     * the phrase for the start's log line, naming how many, or nothing.
     */
    fun returnOldFormAnswers(c: Connection): List<String> {
        val n = c.exec("UPDATE recovery_requests SET state='verified', sealed=NULL WHERE state='fulfilled' AND commitHash IS NULL")
        return if (n == 0) emptyList()
        else listOf("returned $n answered recovery request${if (n == 1) "" else "s"} of the old form to waiting for the operator, the stored answer dropped")
    }

    /** spec 03 §18.5: the commit hash of a presented `b64_32` commit value, or null when it is not one. */
    fun commitHashOf(commitB64: String): String? = io.silencelen.andvari.core.trust.AssistedRecovery.commitHashOf(crypto, commitB64)

    /** The presented value's hash against the stored one, in constant time; no stored hash matches nothing. */
    fun commitMatches(presentedHash: String, stored: String?): Boolean =
        stored != null && MessageDigest.isEqual(presentedHash.encodeToByteArray(), stored.encodeToByteArray())

    /**
     * spec 03 §18.6: the one size of a sealed version-3 answer for the account of [emailNorm] (the address the request
     * was made for): `525 + E`, `E` the length of the address's unpadded base64url.
     */
    fun answerBytes(emailNorm: String): Int = io.silencelen.andvari.core.trust.AnswerToken.sealedBytes(emailNorm)

    fun pathId(raw: String): String = raw.takeIf { WireGrammar.isB64_16(it) } ?: notFound(WireErrors.REQUEST_UNKNOWN)

    /** The request whose poll secret is [pollSecret], or `404 request_unknown`. */
    fun byPoll(c: Connection, requestId: String, pollSecret: String): Row {
        val r = row(c, requestId) ?: notFound(WireErrors.REQUEST_UNKNOWN)
        val bytes = Grammar.b64Bytes(pollSecret, 32, 32) ?: notFound(WireErrors.REQUEST_UNKNOWN)
        if (!MessageDigest.isEqual(sha256Hex(bytes).encodeToByteArray(), r.pollHash.encodeToByteArray())) notFound(WireErrors.REQUEST_UNKNOWN)
        return r
    }
}

/** What the verify's transaction returns for the right code of a request its owner cancelled before the code step. */
private const val CANCELLED_AT_CODE = -1L

fun Route.assistedRecoveryRoutes(s: Services) {
    /**
     * `POST /recovery/requests` (spec 03 §18.1), **R**: the per-IP bucket; `400 invalid_email`; a stalled
     * outbox (`503`, for every address alike). Otherwise always `202 {requestId}` and always a stored row: an
     * operator-posture account gets a real request and `recovery_request_code`; a private-posture one a decoy
     * and `recovery_request_private`; an unknown address a decoy and nothing else. Every request, real or decoy,
     * is audited `recovery_request_create` with one row of one shape (no device, the caller's address, no meta),
     * naming the account only for a real request (before 2026-11-17 only a real request wrote one).
     *
     * The per-address bucket (design §9.3: 5 a day, keyed on the address hash, for known and unknown
     * addresses alike) stands in front of both mail outcomes. Over it, the route sends nothing and stores a
     * decoy, so the answer, the poll, the verify and the commit stay uniform (spec 05 T11): anyone
     * can call this route, and it must not be a way to fill a member's mailbox or to learn an account's posture.
     *
     * **The mailbox value** (decided on 2026-11-17): every code mail carries one beside the code, so that a person whose
     * five requests of the day someone else spent can still open one. A request that names a value of its address,
     * unused and unexpired, of an account in the operator posture, is taken past the address's five; it uses the value up
     * and draws on a ceiling of its own ([Assisted.MAILBOX_BUCKET], 5 per window per address). Each of the two counts in
     * a window of 24 hours that starts at the first request it counts, and the two windows start independently: within
     * one window of each an address receives at most five code mails of plain requests and five of requests taken by a
     * value, and across the windows' edges more than ten can fall inside 24 hours, all past ten through requests that
     * name values, which only a reader of the mailbox can send. Within
     * the address's five a value is not needed and is left as it is. A wrong, used, expired or foreign value changes
     * nothing, and there is no limit on wrong values: 80 bits make guessing pointless, and a limit would let anyone
     * spend the way out again. The answer is the same whatever was given, and the work before it is too: the presented
     * value (or none) is hashed and looked up in every case, and a fresh value is made and hashed for every request,
     * stored only beside a real request's code. The audit row's meta says when the request named a value
     * (`mailbox=used` when it took the request past the cap, `mailbox=not_used` otherwise).
     */
    api(WireRoute.RECOVERY_REQUEST_CREATE, s, Bucket.ipPerHour("recovery_request", 5)) {
        // `mailboxValue` is read from the tree: absent or null is none, a string of at most 64 characters is a value as
        // typed, anything else is `400 bad_mailbox_value`. The rest decodes as the route's body.
        val tree = jsonBody() as? kotlinx.serialization.json.JsonObject ?: badRequest(WireErrors.BAD_REQUEST)
        val typedValue = when (val v = tree["mailboxValue"]) {
            null, kotlinx.serialization.json.JsonNull -> null
            is kotlinx.serialization.json.JsonPrimitive -> v.takeIf { it.isString && it.content.length <= Assisted.MAILBOX_FIELD_MAX }?.content
                ?: badRequest(WireErrors.badField("mailboxValue"))
            else -> badRequest(WireErrors.badField("mailboxValue"))
        }
        val req = try {
            io.silencelen.andvari.core.model.wire.WireJson.json.decodeFromJsonElement(RecoveryRequestCreate.serializer(), kotlinx.serialization.json.JsonObject(tree - "mailboxValue"))
        } catch (_: Throwable) {
            badRequest(WireErrors.BAD_REQUEST)
        }
        val email = Grammar.requireEmail(req.email)
        Grammar.requireB64_32(req.rPub, "rPub")
        Grammar.requireHex64(req.pollHash, "pollHash")
        Grammar.requirePlatform(req.platform)
        if (s.db.read { c -> s.mail.stalled(c) }) unavailable(WireErrors.MAIL_UNAVAILABLE)
        val requestId = Bytes.toB64(createCryptoProvider().randomBytes(16))
        val addressBucket = Assisted.ADDRESS_BUCKET
        // The plain hash keys the in-memory allowances only; every row keeps the keyed one ([Config.addressHash]).
        val emailHash = Grammar.emailHash(email)
        val recordHash = s.config.addressHash(email)
        // The presented value's hash, made in every case (for none, or one not of the value's form, as for a value no
        // mail carries), and the next mail's value with its hash, made for every request. A value mailed before
        // 2026-11-18 was stored with the plain hash inside its own; it is looked for too, until it expires (seven days).
        val presented = Assisted.mailboxValueOf(typedValue)
        val presentedHash = Assisted.mailboxHash(s, recordHash, presented)
        val presentedHashBefore = Assisted.mailboxHash(s, emailHash, presented)
        val nextValue = Assisted.newMailboxValue()
        val nextHash = Assisted.mailboxHash(s, recordHash, nextValue)
        s.db.tx { c ->
            // One reading of the clock for the whole request, taken inside the transaction: the address's bucket, the
            // value's ceiling, the code mail's per-recipient cap and every time the request stores. The address's window
            // and the code mails' window start at the same reading, so they lapse together, and a request inside a fresh
            // window of the address never finds the mail cap's window still full of the one before.
            val at = now
            // A request whose transaction fails gives its draws back (decided on 2026-11-17): it stored nothing and mailed
            // nothing, so it must not spend one of its address's five, nor a place under the value's ceiling (the code
            // mail's cap gives its own back in Mail.enqueue).
            fun draw(b: Bucket): Boolean {
                val admitted = s.limiter.draw("${b.name}:$emailHash", b.limit, b.windowMs, at).admitted ?: return false
                onRollback(c) { s.limiter.refund(admitted) }
                return true
            }
            val underAddressCap = draw(addressBucket)
            // The same work for every kind of request: the presented value is looked up, the address's account row is
            // read (over the address's cap too), a code and its MAC are made, one request row is inserted with the same
            // columns, and one audit row of one shape is written, naming the account only for a real request (for a
            // decoy the lookup the audit makes for a named account is made here instead). Only a real request stores
            // the MAC and the next value's hash and mails the code with the value; a decoy (no account, no code, so
            // never verifiable) stores nothing more than its row and its audit row. A private-posture account is told
            // by its own mail, as before.
            val valueRow = c.queryOne(
                "SELECT valueHash,expiresAt FROM recovery_mailbox_values WHERE valueHash IN (?,?) ORDER BY expiresAt DESC LIMIT 1",
                presentedHash, presentedHashBefore,
            ) { it.getString(1) to it.getLong(2) }
            val valueExpiresAt = valueRow?.second
            val valueRight = presented != null && valueExpiresAt != null && valueExpiresAt > at
            val found = c.queryOne("SELECT userId,recovery,status,identityPub FROM users WHERE email=?", email) { listOf(it.getString(1), it.getString(2), it.getString(3), it.getString(4)) }
            // Past the address's five, a right value takes the request when the value ceiling has room, and only for an
            // account in the operator posture: the way out exists for requests the operator can take, and in the private
            // posture there are none, so there a value is never used and the ceiling never drawn. The value is used up at
            // once. Every write runs under the database's one lock, so the value this transaction found unused is still
            // there when it is deleted: two requests that name the same value at the same moment run one after the
            // other, and the second finds nothing.
            val byValue = !underAddressCap && valueRight && found?.get(1) == RecoveryPosture.OPERATOR && draw(Assisted.MAILBOX_BUCKET)
            if (byValue) c.exec("DELETE FROM recovery_mailbox_values WHERE valueHash=?", valueRow!!.first)
            val acct = found?.takeIf { underAddressCap || byValue }
            val real = acct != null && acct[1] == RecoveryPosture.OPERATOR
            val code = Signup.newCode()
            val mac = Assisted.codeMac(s, requestId, code)
            c.exec(
                """INSERT INTO recovery_requests(requestId,userId,emailHash,rPub,pollHash,platform,codeMac,codeExpiresAt,attempts,state,createdAt)
                   VALUES(?,?,?,?,?,?,?,?,0,'unverified',?)""",
                requestId, if (real) acct!![0] else null, recordHash, req.rPub, req.pollHash, req.platform, if (real) mac else null, at + Assisted.CODE_TTL_MS, at,
            )
            if (real) {
                // No account ID in this mail (MailTemplates.carriesAccountId). A request taken by a
                // value has a per-recipient mail cap of its own, as it has a ceiling of its own. The next value is stored
                // only when its mail is queued: a value no mail carries could never be used.
                val queued = s.mail.enqueue(
                    c, "recovery_request_code", email,
                    Mail.Ctx(null, at, mapOf("code" to code, "mailboxValue" to Assisted.mailboxDisplay(nextValue))), codeExpiresAt = at + Assisted.CODE_TTL_MS,
                    capClass = if (byValue) Mail.CapClass.MAILBOX_CODE else null, at = at,
                )
                if (queued) c.exec("INSERT INTO recovery_mailbox_values(valueHash,emailHash,expiresAt) VALUES(?,?,?)", nextHash, recordHash, at + Assisted.MAILBOX_TTL_MS)
                else c.queryOne("SELECT 1 FROM recovery_mailbox_values WHERE valueHash=?", nextHash) { 1 }
            } else {
                c.queryOne("SELECT 1 FROM recovery_mailbox_values WHERE valueHash=?", nextHash) { 1 }
                c.queryOne("SELECT 1 FROM users WHERE userId=?", Assisted.NO_REQUEST) { 1 }
                if (acct != null) notify(s, c, acct[0], "recovery_request_private")
            }
            val meta = when {
                typedValue == null -> null
                byValue -> "mailbox=used"
                else -> "mailbox=not_used"
            }
            s.audit.on(c, "recovery_request_create", if (real) acct!![0] else null, null, ip, meta)
        }
        respond(RecoveryRequestCreated(requestId))
    }

    /**
     * `POST /recovery/requests/{requestId}/verify` (spec 03 §18.2), **R**: a uniform `400 bad_code` for a
     * wrong, expired or used-up code, for a decoy and for an unknown request; 5 attempts per request. There is
     * no per-address cap on attempts: a stranger's wrong codes on a request of their own must not
     * use up the owner's, and guesses stay bounded because opening requests is capped per address and day.
     * The right code of a request the account's owner cancelled before the code was entered ([Assisted.cancelPending])
     * is `409 request_state`: the request becomes `vetoed` (its poll says so from then on), audited
     * `recovery_request_verify` with meta `cancelled`, and nothing is mailed or rung.
     * On success the 7-day hold starts, every signed-in device of the account gets a bell, and
     * `recovery_request_open` goes out. Audited `recovery_request_verify`.
     *
     * The route has a bucket per caller address ([Assisted.VERIFY_BUCKET], as the sign-up code's route has), and every
     * refused code is recorded as `recovery_request_verify_fail`, naming the account only when the request is real. A
     * refusal does the same work whatever it refuses (a real request, a decoy, an unknown or malformed requestId): the
     * code's MAC is computed and compared, one attempts update is run (it matches no row for a decoy or an unknown
     * id) and one audit row is written with the same columns, so a decoy answers
     * exactly like a real request in body, status, timing class and audit shape.
     */
    api(WireRoute.RECOVERY_REQUEST_VERIFY, s, Assisted.VERIFY_BUCKET) {
        val rawId = param("requestId")
        val req = body<RecoveryRequestVerify>()
        val requestId = rawId.takeIf { WireGrammar.isB64_16(it) }
        val ok = req.code.length == 6 && req.code.all { it in '0'..'9' }
        val candidate = Assisted.codeMac(s, requestId ?: Assisted.NO_REQUEST, if (ok) req.code else "000000")
        val result = s.db.tx { c ->
            val r = requestId?.let { Assisted.row(c, it) }
            val usable = r?.userId != null && r.state == "unverified" && r.codeMac != null && (r.codeExpiresAt ?: 0) > now && r.attempts < Assisted.ATTEMPTS
            val stored = r?.codeMac?.takeIf { usable } ?: Assisted.NO_MAC
            val match = MessageDigest.isEqual(candidate.encodeToByteArray(), stored.encodeToByteArray()) && usable && ok
            if (!match) {
                c.exec("UPDATE recovery_requests SET attempts=attempts+1 WHERE requestId=? AND userId IS NOT NULL AND state='unverified'", requestId ?: Assisted.NO_REQUEST)
                s.audit.on(c, "recovery_request_verify_fail", r?.userId, null, ip)
                return@tx null
            }
            val real = checkNotNull(r) // a match needs a usable row
            if (real.cancelledAt != null) {
                // The owner cancelled it before the code was entered: told now, to whoever shows they read the mailbox.
                c.exec("UPDATE recovery_requests SET state='vetoed', codeMac=NULL WHERE requestId=?", real.requestId)
                s.audit.on(c, "recovery_request_verify", real.account, null, ip, "cancelled")
                return@tx CANCELLED_AT_CODE
            }
            val holdEnds = now + Assisted.HOLD_MS
            c.exec("UPDATE recovery_requests SET state='verified', codeMac=NULL, verifiedAt=?, holdEndsAt=? WHERE requestId=?", now, holdEnds, real.requestId)
            s.audit.on(c, "recovery_request_verify", real.account, null, ip)
            notify(s, c, real.account, "recovery_request_open", vars = mapOf("platform" to real.platform))
            bellUser(s, c, real.account)
            holdEnds
        } ?: badRequest(WireErrors.BAD_CODE)
        if (result == CANCELLED_AT_CODE) conflict(WireErrors.REQUEST_STATE)
        respond(RecoveryRequestVerified(RecoveryRequestState.HOLDING, result))
    }

    /**
     * `POST /recovery/requests/{requestId}/veto` (spec 03 §18.3), **R**, with the device's session: a pending
     * request of the session's account, `ready` included (`404 request_unknown`), then the 0x0A statement (`bad_frame`,
     * `non_canonical`, `bad_statement`, `bad_signer`, `bad_signature`). The request dies and a sealed answer
     * the operator already stored is discarded; the cancellation is emailed naming the device. Audited `recovery_request_veto`.
     */
    api(WireRoute.RECOVERY_REQUEST_VETO, s) {
        val requestId = Assisted.pathId(param("requestId"))
        val req = body<RecoveryVetoRequest>()
        val principal = p
        s.db.tx { c ->
            val r = Assisted.row(c, requestId)?.takeIf { it.userId == principal.userId && Assisted.pending(it, now) } ?: notFound(WireErrors.REQUEST_UNKNOWN)
            val frame = frameBytes(req.statement, WireErrors.BAD_FRAME)
            val identityPub = c.queryOne("SELECT identityPub FROM users WHERE userId=?", principal.userId) { Bytes.fromB64(it.getString(1)) }!!
            s.trust.checkVeto(frame, identityPub, principal.userId, requestId)?.let { badRequest(it) }
            c.exec("UPDATE recovery_requests SET state='vetoed', sealed=NULL, commitHash=NULL WHERE requestId=?", r.requestId)
            s.audit.on(c, "recovery_request_veto", principal.userId, principal.deviceId, ip)
            notify(s, c, principal.userId, "recovery_request_cancelled", MailDevices.of(c, principal.deviceId))
        }
        ok()
    }

    /**
     * `POST /recovery/requests/{requestId}/poll` (spec 03 §18.4), **R**: the state, or the sealed answer once fulfilled.
     * A `ready` answer also carries the stored `commitHash` (additive), so that the device can
     * tell, before it asks its person for anything, that the answer on the server is not the one it opened. It is
     * served only past the poll secret, like `sealed`.
     */
    api(WireRoute.RECOVERY_REQUEST_POLL, s, Bucket.ipPerMinute("recovery_poll", 60)) {
        val requestId = Assisted.pathId(param("requestId"))
        val req = body<RecoveryPollRequest>()
        val (resp, commitHash) = s.db.read { c ->
            val r = Assisted.byPoll(c, requestId, req.pollSecret)
            when (val st = Assisted.stateOf(r, now)) {
                RecoveryRequestState.READY -> c.queryOne("SELECT encryptedIdentitySeed,identityPub FROM users WHERE userId=?", r.account) {
                    RecoveryPollResponse(st, null, r.sealed, it.getString(1), it.getString(2)) to r.commitHash
                }!!
                RecoveryRequestState.HOLDING, RecoveryRequestState.AWAITING_OPERATOR -> RecoveryPollResponse(st, r.holdEndsAt) to null
                else -> RecoveryPollResponse(st) to null
            }
        }
        if (commitHash == null) return@api respond(resp)
        val tree = io.silencelen.andvari.core.model.wire.WireJson.json.encodeToJsonElement(RecoveryPollResponse.serializer(), resp) as kotlinx.serialization.json.JsonObject
        respondJsonText(kotlinx.serialization.json.JsonObject(tree + ("commitHash" to kotlinx.serialization.json.JsonPrimitive(commitHash))).toString())
    }

    /**
     * `POST /recovery/requests/{requestId}/commit` (spec 03 §18.5), **R**: the poll secret (`404`); fulfilled,
     * not vetoed and not expired, the expiry checked here at commit time (`409 request_state`); the KDF and kit checks; then the kit commit's transaction with
     * `how = recovered`, and the request deleted. Audited `recovery_request_commit`.
     */
    api(WireRoute.RECOVERY_REQUEST_COMMIT, s, SharedBuckets.RECOVERY_COMMIT) {
        val requestId = Assisted.pathId(param("requestId"))
        // `commit` is read from the tree, so absent, null, a number or another non-string is `bad_commit`;
        // the rest decodes as the route's body.
        val tree = jsonBody() as? kotlinx.serialization.json.JsonObject ?: badRequest(WireErrors.BAD_REQUEST)
        val commitText = (tree["commit"] as? kotlinx.serialization.json.JsonPrimitive)?.takeIf { it.isString }?.content
        val req = try {
            io.silencelen.andvari.core.model.wire.WireJson.json.decodeFromJsonElement(RecoveryRequestCommit.serializer(), kotlinx.serialization.json.JsonObject(tree - "commit"))
        } catch (_: Throwable) {
            badRequest(WireErrors.BAD_REQUEST)
        }
        val r0 = s.db.read { c -> Assisted.byPoll(c, requestId, req.pollSecret) }
        if (Assisted.stateOf(r0, now) != RecoveryRequestState.READY) conflict(WireErrors.REQUEST_STATE)
        // spec 03 §18.5: only a device that opened the answer holds its commit value. A wrong value
        // is audited and changes nothing else: the value is 32 random bytes, so no count of tries
        // protects anything, and a count let a damaged or replaced upload, or a poll secret seen in transit, cancel a
        // request that took seven days. The route's own rate limit stays.
        val presented = commitText?.let { Assisted.commitHashOf(it) } ?: badRequest(WireErrors.BAD_COMMIT)
        if (!Assisted.commitMatches(presented, r0.commitHash)) {
            s.db.tx { c -> s.audit.on(c, "recovery_request_commit_mismatch", r0.account, null, ip, "at=check") }
            forbidden(WireErrors.COMMIT_MISMATCH)
        }
        // As the kit commit (spec 03 §12, §18.5): a disabled account is re-enabled by the operator first.
        val active = s.db.read { c -> c.queryOne("SELECT status FROM users WHERE userId=?", r0.account) { it.getString(1) } } == "active"
        if (!active) badRequest(WireErrors.RECOVERY_ACCOUNT_NOT_ACTIVE)
        val (kit, secretHash) = checkResetBody(s, req.newAuthKey, req.newKdfSalt, req.newKdfParams, req.newWrappedUvk, req.newMemberRecovery, req.device)
        val clientVersion = call.declaredClientVersion()
        s.raceHook?.invoke("assistedCommit.afterCheck")
        val resp = s.db.tx { c ->
            val r = Assisted.row(c, requestId)?.takeIf { Assisted.stateOf(it, now) == RecoveryRequestState.READY } ?: conflict(WireErrors.REQUEST_STATE)
            // Again inside the transaction: an upload that replaced the answer meanwhile refuses the older answer's value.
            // The refusal leaves this transaction with nothing written, so its audit row is written after it (below).
            if (!Assisted.commitMatches(presented, r.commitHash)) return@tx null
            val out = commitRecovery(s, c, r.account, req.newAuthKey, req.newKdfSalt, req.newKdfParams, req.newWrappedUvk, kit, req.device, secretHash,
                headerPlatform ?: req.device.platform, clientVersion, MailTemplates.HOW_ASSISTED)
            c.exec("DELETE FROM recovery_requests WHERE requestId=?", requestId)
            s.audit.on(c, "recovery_request_commit", r.account, out.deviceId, ip)
            out
        }
        if (resp == null) {
            // §18.5: each wrong value is audited, this one too (a mismatch found inside the transaction).
            s.db.tx { c -> s.audit.on(c, "recovery_request_commit_mismatch", r0.account, null, ip, "at=commit") }
            forbidden(WireErrors.COMMIT_MISMATCH)
        }
        respond(SessionResponse.serializer(), resp)
    }

    /** `GET /account/recovery-requests` (spec 03 §18.3), **R**: the account's pending requests, `ready` included. */
    api(WireRoute.ACCOUNT_RECOVERY_REQUESTS, s) {
        val principal = p
        val rows = s.db.read { c ->
            Assisted.pendingOf(c, principal.userId, now)
                .map { RecoveryRequestSummary(it.requestId, Assisted.stateOf(it, now), it.createdAt, it.verifiedAt!!, it.holdEndsAt!!, it.platform) }
        }
        respondList(RecoveryRequestSummary.serializer(), rows)
    }
}
