package io.silencelen.andvari.server

import io.ktor.server.routing.Route
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.SignupMode
import io.silencelen.andvari.core.model.wire.SignupStartRequest
import io.silencelen.andvari.core.model.wire.SignupStartResponse
import io.silencelen.andvari.core.model.wire.SignupVerifyRequest
import io.silencelen.andvari.core.model.wire.SignupVerifyResponse
import io.silencelen.andvari.core.model.wire.WireErrors
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.SignupCode
import io.silencelen.andvari.core.trust.SignupPow
import java.security.MessageDigest
import java.security.SecureRandom

/** Email-verified sign-up (spec 03 §14.1, §14.2; design §7.2). */
object Signup {
    const val CODE_TTL_MS = 15 * 60_000L
    const val TICKET_TTL_MS = 30 * 60_000L
    const val MAX_ATTEMPTS = 5

    private val crypto = createCryptoProvider()
    private val rng = SecureRandom()

    /** A uniformly random 6-digit code, as typed (leading zeros kept). */
    fun newCode(): String = rng.nextInt(1_000_000).toString().padStart(6, '0')

    fun codeMac(secret: ByteArray, emailNorm: String, code: String): String = Bytes.toHexLower(SignupCode.mac(crypto, secret, emailNorm, code))

    /** The proof of work (§14.1): today's or yesterday's UTC date, `powBits` leading zero bits. */
    fun powAccepted(emailNorm: String, date: String, nonce: Long, powBits: Int, nowMs: Long): Boolean {
        if (!SignupPow.isUtcDate(date) || nonce !in 0 until (1L shl 53)) return false
        val today = Clock.utcDate(nowMs)
        val yesterday = Clock.utcDate(nowMs - Clock.DAY_MS)
        if (date != today && date != yesterday) return false
        return SignupPow.accepts(crypto, emailNorm, date, nonce, powBits)
    }

    /**
     * Register step 3 for a ticket (spec 03 §14.3): bound to the address it was earned with (the stored [emailHash]
     * equal to [registerHash], the register address's hash as the server stores it: [Config.addressHash]), unused, and
     * in time — expiry is exclusive: valid while `now < expiresAt`. Tickets are stored as the SHA-256 of their ASCII
     * text as sent ([ServerCrypto.hashToken]), like a register token.
     */
    fun ticketOk(emailHash: String, expiresAt: Long, used: Boolean, registerHash: String, nowMs: Long): Boolean =
        emailHash == registerHash && nowMs < expiresAt && !used

    /** The domain an address belongs to, for the blocklist (§14.1). */
    fun domainOf(emailNorm: String): String = emailNorm.substringAfter('@')
}

/** `POST /signup/start`'s buckets per caller's address (spec 03 §0.2): 3 an hour and 10 a day. */
internal val SIGNUP_START_HOUR = Bucket.ipPerHour("signup_start", 3)
internal val SIGNUP_START_DAY = Bucket.ipPerDay("signup_start_day", 10)

/**
 * The ceiling in front of the sign-up start per address, never given back (decided on 2026-11-17): the start gives its
 * hourly and daily draws back when no mail can be sent, so that an operator's mail fault does not lock an honest person
 * out, and without this a caller had no limit at all while mail was down. Thirty an hour is ten times the hourly
 * allowance, so an honest person's tries during an outage still pass.
 */
internal val SIGNUP_START_CEILING = Bucket.ipPerHour("signup_start_ceiling", 30)

/** The limiter key prefix of an existing account's notice, at most one a day per address (with its hash after it). */
internal const val SIGNUP_EXISTING_KEY = "signup_existing:"

fun Route.signupRoutes(s: Services) {
    /**
     * `POST /signup/start` (spec 03 §14.1). Checks, in order: the per-IP bucket (3/h and 10/day); the
     * effective mode is `open` (`403 signup_closed`); the cap (`403 signup_full`); `emailNorm`
     * (`400 invalid_email`); the domain blocklist, before any account lookup (`400 email_domain_blocked`);
     * age confirmation; the proof of work (`400 pow_required`, `400 bad_pow`); the per-address bucket
     * (5/day); a stalled outbox (`503 mail_unavailable`, for every address alike). Otherwise always
     * `202 {"status":"sent"}`: an existing account gets `signup_existing` (at most once a day), anyone
     * else a fresh code (`signup_code`), which replaces the previous one.
     *
     * **A start refused because no mail can be sent costs the caller nothing** (decided on 2026-11-17): the outbox is
     * checked before the address's draw, and the caller's two draws are given back with `503 mail_unavailable`; a
     * refusal of the day's draw gives the hour's back. The draw for an existing account's notice, made inside the
     * transaction, comes back when the transaction fails. Before, a stalled outbox spent the caller's three an hour and
     * the address's five a day on starts that sent nothing. In front of both stands [SIGNUP_START_CEILING], thirty an hour
     * per address, which is never given back: a give-back never removes every limit.
     */
    api(WireRoute.SIGNUP_START, s, bucket = null) {
        take(SIGNUP_START_CEILING)
        val hour = takeHeldAddress(SIGNUP_START_HOUR)
        val day = try { takeHeldAddress(SIGNUP_START_DAY) } catch (e: ApiException) { s.limiter.refund(hour); throw e }
        val req = body<SignupStartRequest>()
        val policy = s.policy.get()
        if (s.policy.effectiveMode(policy) != SignupMode.OPEN) forbidden(WireErrors.SIGNUP_CLOSED)
        if (s.db.read { c -> s.policy.signupFull(c, policy) }) forbidden(WireErrors.SIGNUP_FULL)
        val email = Grammar.requireEmail(req.email)
        if (Signup.domainOf(email) in s.config.signupBlocklist) badRequest(WireErrors.EMAIL_DOMAIN_BLOCKED)
        if (s.config.requireAgeConfirm && !req.ageConfirmed) badRequest(WireErrors.AGE_CONFIRM_REQUIRED)
        if (s.config.signupPowBits > 0) {
            val pow = req.pow ?: badRequest(WireErrors.POW_REQUIRED)
            if (!Signup.powAccepted(email, pow.date, pow.nonce, s.config.signupPowBits, now)) badRequest(WireErrors.BAD_POW)
        }
        val emailHash = Grammar.emailHash(email)
        // What the code row, the audit row and the journal keep of the address: its keyed hash, never the plain one.
        val recordHash = s.config.addressHash(email)
        // No mail can be sent: found before the address's draw, and the caller's draws are given back.
        val secret = s.config.signupSecret
        if (secret == null || s.db.read { c -> s.mail.stalled(c) }) {
            s.limiter.refund(hour); s.limiter.refund(day)
            unavailable(WireErrors.MAIL_UNAVAILABLE)
        }
        take(Bucket.givenPerDay("signup_start_address", 5), keySuffix = emailHash)
        s.db.tx { c ->
            val existing = c.queryOne("SELECT userId,identityPub FROM users WHERE email=?", email) { it.getString(1) to it.getString(2) }
            if (existing != null) {
                val notice = s.limiter.draw("$SIGNUP_EXISTING_KEY$emailHash", 1, Clock.DAY_MS).admitted
                if (notice != null) {
                    // A transaction that fails sends nothing, so the day's one notice is not spent by it.
                    onRollback(c) { s.limiter.refund(notice) }
                    s.mail.enqueue(c, "signup_existing", email, Mail.Ctx(Mail.accountId(existing.second), now))
                }
            } else {
                val code = Signup.newCode()
                val expiresAt = now + Signup.CODE_TTL_MS
                c.exec(
                    """INSERT INTO signup_codes(emailHash,codeMac,expiresAt,attempts) VALUES(?,?,?,0)
                       ON CONFLICT(emailHash) DO UPDATE SET codeMac=excluded.codeMac, expiresAt=excluded.expiresAt, attempts=0""",
                    recordHash, Signup.codeMac(secret, email, code), expiresAt,
                )
                s.mail.enqueue(c, "signup_code", email, Mail.Ctx(null, now, mapOf("code" to code)), codeExpiresAt = expiresAt)
            }
            s.audit.on(c, "signup_start", null, null, ip, "addr=${recordHash.take(8)}")
        }
        respond(SignupStartResponse(SignupStartResponse.SENT))
    }

    /**
     * `POST /signup/verify` (spec 03 §14.2): a uniform `400 bad_code` for no code, a wrong code, an expired
     * one, or attempts used up. Each wrong code counts; at 5 the code is dead. On success the code is
     * consumed and a 256-bit ticket is minted, stored as its SHA-256, bound to the address, valid 30
     * minutes, single use.
     */
    api(WireRoute.SIGNUP_VERIFY, s, Bucket.ipPerHour("signup_verify", 20)) {
        val req = body<SignupVerifyRequest>()
        val email = Grammar.emailOrNull(req.email) ?: badRequest(WireErrors.BAD_CODE)
        val secret = s.config.signupSecret ?: badRequest(WireErrors.BAD_CODE)
        val codeOk = req.code.length == 6 && req.code.all { it in '0'..'9' }
        val emailHash = s.config.addressHash(email)
        val candidate = if (codeOk) Signup.codeMac(secret, email, req.code) else "x"
        val ticket = s.db.tx { c ->
            val row = c.queryOne("SELECT codeMac,expiresAt,attempts FROM signup_codes WHERE emailHash=?", emailHash) {
                Triple(it.getString(1), it.getLong(2), it.getInt(3))
            }
            val live = row != null && row.second > now && row.third < Signup.MAX_ATTEMPTS
            val match = live && MessageDigest.isEqual(row!!.first.encodeToByteArray(), candidate.encodeToByteArray())
            if (!match) {
                if (live) c.exec("UPDATE signup_codes SET attempts=attempts+1 WHERE emailHash=?", emailHash)
                s.audit.on(c, "signup_verify_fail", null, null, ip, "addr=${emailHash.take(8)}")
                return@tx null
            }
            c.exec("DELETE FROM signup_codes WHERE emailHash=?", emailHash)
            val t = ServerCrypto.newToken()
            c.exec("INSERT INTO signup_tickets(ticketHash,emailHash,expiresAt) VALUES(?,?,?)", ServerCrypto.hashToken(t), emailHash, now + Signup.TICKET_TTL_MS)
            t
        } ?: badRequest(WireErrors.BAD_CODE)
        respond(SignupVerifyResponse(ticket, now + Signup.TICKET_TTL_MS))
    }
}
