package io.silencelen.andvari.server

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.model.wire.AdminPolicy
import io.silencelen.andvari.core.model.wire.AdminSignupPolicy
import io.silencelen.andvari.core.model.wire.ClientPolicy
import io.silencelen.andvari.core.model.wire.Quota
import io.silencelen.andvari.core.model.wire.SignupMode
import io.silencelen.andvari.core.model.wire.SignupPolicy
import io.silencelen.andvari.core.model.wire.WireErrors
import io.silencelen.andvari.core.model.wire.WireJson
import java.sql.Connection

/**
 * The three limits a hashing-cost floor (`ANDVARI_MIN_KDF_OPS`, `ANDVARI_MIN_KDF_MEM`) must stay within, said in one place
 * (spec 03 §1.1, decided on 2026-11-17). A floor outside any of them is a floor the operator set and the server cannot
 * apply, and the server refuses to start with it ([Config]) rather than take something else in its place:
 *  1. [CONFIG_OPS], [CONFIG_MEM_BYTES]: what the configuration reads as a number at all (before 2026-11-17 a value outside
 *     this range, or one that is not a whole number, was replaced by the default, which LOWERED the floor);
 *  2. [SERVER_MAX_OPS], [SERVER_MAX_MEM_BYTES]: the server's own upper limit for a stored cost ([PolicyStore.requireKdfFloor]):
 *     above it the served cost is one the server itself refuses at every commit;
 *  3. [CLIENT_MAX_OPS], [CLIENT_MAX_MEM_BYTES]: the most every client accepts. The figure is the shared code's client-side
 *     sanity bound (spec 01 §7, `KdfUpgrade.MAX_OPS` and `MAX_MEM_BYTES` in core), read from there and not copied; the
 *     web client keeps the same figures as `KDF_MAX_OPS` and `KDF_MAX_MEM_BYTES` in `web/src/crypto/keys.ts`. Above it
 *     every client refuses the served cost (`kdf_above_ceiling`), and nobody can register, recover or change a password.
 * The memory floor is compared after the rounding up to a whole KiB that [PolicyStore.servedKdf] applies.
 */
object KdfLimits {
    val CONFIG_OPS: LongRange = 0L..1_000_000L
    val CONFIG_MEM_BYTES: LongRange = 0L..(1L shl 40)
    const val SERVER_MAX_OPS: Long = 64L
    const val SERVER_MAX_MEM_BYTES: Long = 4L shl 30
    const val CLIENT_MAX_OPS: Long = io.silencelen.andvari.core.client.KdfUpgrade.MAX_OPS
    const val CLIENT_MAX_MEM_BYTES: Long = io.silencelen.andvari.core.client.KdfUpgrade.MAX_MEM_BYTES

    /** The memory floor as it is served: rounded up to a whole KiB. */
    fun servedMem(floorBytes: Long): Long = (floorBytes + 1023) / 1024 * 1024

    /** Why the floor [name] = [value] cannot be applied, in one line naming the value and the range; null when it can. */
    fun problem(name: String, value: Long, unit: String): String? {
        val ops = name == "ANDVARI_MIN_KDF_OPS"
        val config = if (ops) CONFIG_OPS else CONFIG_MEM_BYTES
        if (value !in config) {
            return "$name=$value is outside the range the configuration accepts (${config.first}..${config.last} $unit); the server would otherwise take the default in its place, which is a different floor"
        }
        return aboveLimits(name, value, if (ops) value else servedMem(value), ops, unit)
    }

    /**
     * The second and third limits, in the same lines for a floor and for a policy the operator writes later
     * ([policyProblem]): [served] is the figure as it would be served, [value] the one the line names.
     */
    private fun aboveLimits(name: String, value: Long, served: Long, ops: Boolean, unit: String): String? {
        val serverMax = if (ops) SERVER_MAX_OPS else SERVER_MAX_MEM_BYTES
        val clientMax = if (ops) CLIENT_MAX_OPS else CLIENT_MAX_MEM_BYTES
        return when {
            served > serverMax ->
                "$name=$value is above the server's own upper limit for a stored hashing cost ($serverMax $unit): every commit at the served cost would be refused"
            served > clientMax ->
                "$name=$value is above what the clients accept (at most $clientMax $unit, spec 01 §7): every client would refuse the served cost"
            else -> null
        }
    }

    /**
     * Why the hashing cost of a policy the operator writes (`PUT /admin/policy`, spec 03 §7.2) cannot be served, in the
     * floor's own lines (decided on 2026-11-17: a policy written later is held to the same limits as the floor); null when
     * it can. Before, the write was held to the server's own limit only, so an operator could store a cost every client
     * refuses, and then nobody could register, recover or change a password.
     */
    fun policyProblem(ops: Long, memBytes: Long): String? =
        aboveLimits("kdfParams.ops", ops, ops, true, "passes") ?: aboveLimits("kdfParams.memBytes", memBytes, memBytes, false, "bytes")
}

/**
 * The operator policy (spec 03 §7.2) and everything derived from it: the effective sign-up stance
 * (§14.4) and the client policy (§1.1).
 *
 * The environment is the source of truth for the sign-up stance; the stored `signup {mode, cap}` can
 * only TIGHTEN it (§7.2): the effective mode is the stricter of the two, the effective cap the smaller.
 */
class PolicyStore(private val config: Config, private val db: Db) {
    @Volatile private var cached: AdminPolicy? = null

    fun defaults(): AdminPolicy = AdminPolicy(
        minVersion = emptyMap(),
        kdfParams = KdfParams.DEFAULT,
        autoLockSeconds = 300,
        clipboardClearSeconds = 30,
        offlineCacheAllowed = true,
        sessionAccessTtlSeconds = 3_600,
        sessionRefreshTtlDays = 30,
        attachmentMaxBytes = minOf(25L * 1024 * 1024, config.quotaAccountBytes),
        itemAttachmentsMaxBytes = minOf(100L * 1024 * 1024, config.quotaAccountBytes),
        quotaDefaults = Quota(config.quotaAccountBytes, config.quotaItems, config.quotaOwnedSharedVaults, config.quotaOpenLinks),
        signup = AdminSignupPolicy(null, null),
    )

    /** The stored policy, or the defaults when none is stored. */
    fun get(): AdminPolicy = cached ?: db.read { load(it) }.also { cached = it }

    fun load(c: Connection): AdminPolicy =
        c.queryOne("SELECT json FROM policies WHERE id=1") { it.getString(1) }
            ?.let { WireJson.json.decodeFromString(AdminPolicy.serializer(), it) }
            ?: defaults()

    fun storeOn(c: Connection, p: AdminPolicy) {
        c.exec(
            "INSERT INTO policies(id,json) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET json=excluded.json",
            WireJson.json.encodeToString(AdminPolicy.serializer(), p),
        )
        cached = null
    }

    fun invalidate() { cached = null }

    /** `closed` is stricter than `links`, stricter than `open` (spec 03 §1.1). */
    private fun strictness(mode: String): Int = when (mode) {
        SignupMode.OPEN -> 0
        SignupMode.LINKS -> 1
        else -> 2
    }

    fun stricterMode(a: String, b: String?): String = if (b == null || strictness(a) >= strictness(b)) a else b

    /** The effective mode: the stricter of `ANDVARI_SIGNUP_MODE` and the stored value (§14.4). */
    fun effectiveMode(p: AdminPolicy = get()): String = stricterMode(config.signupMode, p.signup.mode)

    /** The effective cap: `min(ANDVARI_SIGNUP_CAP, stored cap)` (§14.4). */
    fun effectiveCap(p: AdminPolicy = get()): Long = p.signup.cap?.let { minOf(it, config.signupCap) } ?: config.signupCap

    /** Accounts the cap counts: `role = member` and `status = active` (§14.4). */
    fun activeMembers(c: Connection): Long = c.count("SELECT COUNT(*) FROM users WHERE role='member' AND status='active'")

    fun signupFull(c: Connection, p: AdminPolicy = get()): Boolean = activeMembers(c) >= effectiveCap(p)

    /** The account's effective quota: its overrides, else the policy's defaults (§14.4, §7.1). */
    fun quotaOf(c: Connection, userId: String, p: AdminPolicy = get()): Quota =
        c.queryOne("SELECT quotaAccountBytes,quotaItems,quotaOwnedSharedVaults,quotaOpenLinks FROM users WHERE userId=?", userId) { rs ->
            Quota(
                rs.longOrNull("quotaAccountBytes") ?: p.quotaDefaults.accountBytes,
                rs.longOrNull("quotaItems") ?: p.quotaDefaults.items,
                rs.longOrNull("quotaOwnedSharedVaults") ?: p.quotaDefaults.ownedSharedVaults,
                rs.longOrNull("quotaOpenLinks") ?: p.quotaDefaults.openLinks,
            )
        } ?: p.quotaDefaults

    /** `GET /client-policy` (spec 03 §1.1). */
    fun clientPolicy(nowMs: Long): ClientPolicy {
        val p = get()
        val full = db.read { signupFull(it, p) }
        return ClientPolicy(
            minVersion = p.minVersion,
            kdfParams = servedKdf(p),
            autoLockSeconds = p.autoLockSeconds,
            clipboardClearSeconds = p.clipboardClearSeconds,
            // The env floor is ANDed over the operator's value (§1.1): it can forbid, never force-allow.
            offlineCacheAllowed = p.offlineCacheAllowed && config.offlineCacheAllowedFloor,
            sessionAccessTtlSeconds = p.sessionAccessTtlSeconds,
            sessionRefreshTtlDays = p.sessionRefreshTtlDays,
            attachmentMaxBytes = p.attachmentMaxBytes,
            itemAttachmentsMaxBytes = p.itemAttachmentsMaxBytes,
            serverTime = nowMs,
            signup = SignupPolicy(effectiveMode(p), full, config.requireAgeConfirm, config.signupPowBits),
            totpRequired = config.totpRequired,
            instanceName = config.instanceName,
            canonicalOrigin = config.canonicalOrigin,
            selfHostDocsUrl = config.selfHostDocsUrl ?: "${config.canonicalOrigin}/selfhost",
        )
    }

    // ---- KDF rules (spec 03 §7.2) ----

    /**
     * The hashing cost the server serves wherever it names one that is not an account's own: the client policy
     * (`GET /client-policy`), the first exchange of a sign-in for an address that has no account (`POST /auth/prelogin`),
     * and the operator's view of the policy (`GET /admin/policy`). It is the stored policy's cost (or the default when none
     * is stored), raised on each figure to the floor ([Config.minKdfOps], [Config.minKdfMemBytes], the memory floor
     * rounded up to a whole KiB, the only memory cost the server takes). So a client that follows what it is served is
     * never refused as `kdf_too_weak`, whenever the floor was raised: before 2026-11-17 the stored or default cost was
     * served as it was, and on a server whose floor sat above it every recovery that followed the policy was refused,
     * with nothing the person could do. Every commit is still checked against the floor ([requireKdfFloor]).
     */
    fun servedKdf(p: AdminPolicy = get()): KdfParams {
        val k = p.kdfParams
        val floorMem = KdfLimits.servedMem(config.minKdfMemBytes)
        val ops = maxOf(k.ops, config.minKdfOps)
        val mem = maxOf(k.memBytes, floorMem)
        return if (ops == k.ops && mem == k.memBytes) k else k.copy(ops = ops, memBytes = mem)
    }

    /** The production floor (spec 01 §9, spec 05 T8): `400 kdf_too_weak`. */
    fun requireKdfFloor(k: KdfParams) {
        if (k.memBytes < config.minKdfMemBytes || k.ops < config.minKdfOps) badRequest(WireErrors.KDF_TOO_WEAK)
        // An absurd value would stall every unlock of the account (and the server never runs it).
        if (k.memBytes > KdfLimits.SERVER_MAX_MEM_BYTES || k.ops > KdfLimits.SERVER_MAX_OPS || k.memBytes < 8 * 1024 || k.ops < 1) badRequest(WireErrors.KDF_TOO_WEAK)
    }

    /** `memBytes % 1024 == 0` (spec 03 §7.2): `400 kdf_mem_not_kib_multiple`, distinct from the strength floor. */
    fun requireKdfShape(k: KdfParams) {
        if (k.memBytes % 1024 != 0L) badRequest(WireErrors.KDF_MEM_NOT_KIB_MULTIPLE)
    }

    /** Both KDF checks, in the order the routes list them. */
    fun requireKdf(k: KdfParams) { requireKdfFloor(k); requireKdfShape(k) }

    /**
     * The checks of a cost a NEW WRAP is made at (a registration, a password change or quiet re-key, both recoveries'
     * commits): [requireKdf], and then each figure by itself at least the cost the server serves ([servedKdf]: the
     * policy's, raised to the floor), `400 kdf_too_weak` with a line that names the figure (decided on 2026-11-17). Before,
     * a new wrap was held only to the environment's floor ([requireKdfFloor]), so after the operator raised the policy's
     * memory figure a password change at the account's old memory figure was still stored below the policy. The policy
     * itself is not held to this (the operator may lower it), only to [requireKdf].
     */
    fun requireWrapKdf(k: KdfParams) {
        requireKdf(k)
        val served = servedKdf()
        if (k.ops < served.ops) throw ApiException(400, WireErrors.KDF_TOO_WEAK, "kdfParams.ops=${k.ops} is below the cost this server serves (${served.ops} passes)")
        if (k.memBytes < served.memBytes) throw ApiException(400, WireErrors.KDF_TOO_WEAK, "kdfParams.memBytes=${k.memBytes} is below the cost this server serves (${served.memBytes} bytes)")
    }

    /** The salt bound: base64url of 16..64 bytes (`400 bad_kdf_salt`). */
    fun requireKdfSalt(salt: String) {
        val bytes = runCatching { Bytes.fromB64(salt) }.getOrNull()
        if (bytes == null || bytes.size < KdfParams.SALT_BYTES || bytes.size > 64 || Bytes.toB64(bytes) != salt) badRequest(WireErrors.BAD_KDF_SALT)
    }
}
