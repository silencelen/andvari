package io.silencelen.andvari.core.app.fake

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.DisableWhy
import io.silencelen.andvari.core.app.JoinMode
import io.silencelen.andvari.core.app.OperatorApi
import io.silencelen.andvari.core.app.OperatorConsole
import io.silencelen.andvari.core.app.OperatorHelpStage
import io.silencelen.andvari.core.app.OperatorResult
import io.silencelen.andvari.core.app.QuotaLimits
import io.silencelen.andvari.core.app.RoleInVault
import io.silencelen.andvari.core.app.ServerKind
import io.silencelen.andvari.core.app.Subscription
import io.silencelen.andvari.core.app.WhoCanRecover
import io.silencelen.andvari.core.client.pin.PinRoot
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.model.wire.AccountSummary
import io.silencelen.andvari.core.model.wire.AdminEscrowResponse
import io.silencelen.andvari.core.model.wire.AdminMailStatus
import io.silencelen.andvari.core.model.wire.AdminPolicy
import io.silencelen.andvari.core.model.wire.AdminRecoveryRequest
import io.silencelen.andvari.core.model.wire.AdminSignupPolicy
import io.silencelen.andvari.core.model.wire.AdminSignupStatus
import io.silencelen.andvari.core.model.wire.AdminStatus
import io.silencelen.andvari.core.model.wire.AuditRow
import io.silencelen.andvari.core.model.wire.Device
import io.silencelen.andvari.core.model.wire.Quota
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** The operator views of the fake: only [FakeDesktopAppApi] has one. Its lists are the fake server's own word. */
internal class FakeOperator(private val app: FakeAppApi) : OperatorApi {
    private val flow = MutableStateFlow<OperatorConsole?>(null)
    private val listeners = ArrayList<(OperatorConsole?) -> Unit>()
    private var open = false
    private var devicesOf: String? = null
    private var auditShown: List<AuditRow> = emptyList()
    private val auditLog = ArrayList<AuditRow>()
    private var escrow: AdminEscrowResponse? = null
    private val quotas = HashMap<String, QuotaLimits>()
    private var policy = AdminPolicy(
        minVersion = emptyMap(),
        kdfParams = KdfParams(),
        autoLockSeconds = 300,
        clipboardClearSeconds = 30,
        offlineCacheAllowed = true,
        sessionAccessTtlSeconds = 3600,
        sessionRefreshTtlDays = 30,
        attachmentMaxBytes = 26_214_400,
        itemAttachmentsMaxBytes = 67_108_864,
        quotaDefaults = Quota(104_857_600, 5000, 50, 20),
        signup = AdminSignupPolicy(null, null),
    )

    init {
        // The console shows the world as it is at every publish.
        app.afterPublish = ::rebuild
    }

    override val console: OperatorConsole? get() = flow.value
    override val consoles: StateFlow<OperatorConsole?> get() = flow

    override fun observeConsole(listener: (OperatorConsole?) -> Unit): Subscription {
        listeners += listener
        listener(flow.value)
        return object : Subscription {
            override fun close() {
                listeners -= listener
            }
        }
    }

    private fun rebuild() {
        val s = app.session
        val next = if (!open || s == null || app.phase != AppPhase.UNLOCKED || !s.account.isOperator) null else build(s)
        if (next == null) open = false
        flow.value = next
        for (l in listeners.toList()) l(next)
    }

    private fun build(s: FakeSession): OperatorConsole {
        val server = s.server
        val accounts = server.accounts.values.map { a ->
            AccountSummary(
                userId = a.userId,
                email = a.email,
                displayName = a.email.substringBefore('@'),
                role = if (a.isOperator) "operator" else "member",
                status = if (a.disabled) "disabled" else "active",
                createdAt = 0L,
                lastSeenAt = a.devices.maxOfOrNull { it.lastSeenAtMs },
                disabledAt = if (a.disabled) a.disabledAtMs else null,
                recovery = if (a.whoCanRecover == WhoCanRecover.ME_OR_OPERATOR) "operator" else "private",
                usedBytes = a.vaults.sumOf { it.itemCount.toLong() } * 2048,
                itemCount = a.vaults.sumOf { it.itemCount.toLong() },
                ownedVaultCount = a.vaults.count { it.role == RoleInVault.OWNER }.toLong(),
                liveDeviceCount = a.devices.count { it.live }.toLong(),
            )
        }
        val members = server.accounts.values.count { !it.isOperator && !it.disabled }.toLong()
        val status = AdminStatus(
            serverVersion = "1.0.0",
            serverTime = app.nowMs,
            userCount = server.accounts.size.toLong() + server.userCountOffBy,
            itemCount = accounts.sumOf { it.itemCount },
            attachmentCount = 0,
            attachmentBytes = 0,
            dbBytes = 1_048_576,
            totpEnrolledCount = server.accounts.values.count { it.twoStepCode != null }.toLong(),
            downloadsManifest = false,
            emailConfigured = true,
            instanceKind = if (server.kind == ServerKind.PUBLIC_SERVER) "public" else "private",
            signup = AdminSignupStatus(mode(server.mode), 200, members, server.full),
            mail = AdminMailStatus(server.mailStalled, if (server.mailStalled) app.nowMs - 11 * FakeScript.MINUTE else null),
        )
        val shown = devicesOf?.let { id -> server.accounts.values.firstOrNull { it.userId == id } }
        val requests = server.accounts.values.flatMap { a ->
            a.helpRequests.filter { it.stage == OperatorHelpStage.HOLDING || it.stage == OperatorHelpStage.AWAITING_OPERATOR }.map { r ->
                // Never the request code: the operator gets it from the person (T2-R-c).
                // The id and key in the wire's grammar (b64_16, b64_32), derived from the fake's own, as the shared reader of an answer needs.
                AdminRecoveryRequest(wireId(r.requestId), a.userId, a.email, a.accountId, wireKey(r.requestId), r.platform.wireName, r.createdAtMs, r.verifiedAtMs, r.holdEndsAtMs)
            }
        }
        return OperatorConsole(
            instance = app.label(server),
            details = app.details(server),
            setupUnfinished = !server.hasCard,
            status = status,
            accounts = accounts,
            devicesOfUserId = shown?.userId,
            devices = shown?.devices.orEmpty().map { d ->
                Device(d.deviceId, d.platform.wireName, d.name, d.clientVersion, d.addedAtMs, d.lastSeenAtMs, d.live, d.how.name.lowercase(), d.linkedFrom.ifEmpty { null }, false)
            },
            recoveryRequests = requests,
            policy = policy,
            audit = auditShown,
            countsDisagree = status.userCount != accounts.size.toLong(),
            policyRefusal = policyRefusal,
        )
    }

    /** [OperatorConsole.policyRefusal], as the engine keeps it. */
    private var policyRefusal: io.silencelen.andvari.core.app.CopyLine? = null

    private fun mode(m: JoinMode): String = when (m) {
        JoinMode.ANYONE -> "open"
        JoinMode.INVITATION_ONLY -> "links"
        else -> "closed"
    }

    private fun strictness(mode: String?): Int = when (mode) {
        "open" -> 0
        "links" -> 1
        "closed" -> 2
        else -> -1
    }

    private fun note(type: String, userId: String?) {
        auditLog += AuditRow(id = auditLog.size + 1L, at = app.nowMs, type = type, userId = userId)
    }

    /** The checks every operator intent starts with; [password] null for a route that needs no fresh proof. */
    private suspend inline fun asOperator(password: String?, body: (FakeSession) -> OperatorResult): OperatorResult = app.act { s ->
        if (!s.account.isOperator) return OperatorResult.NOT_THE_OPERATOR
        if (password != null && password != s.account.password) return OperatorResult.WRONG_PASSWORD
        if (password != null) app.script.proofRefusal(OperatorResult.KEYS_NOT_KNOWN_HERE, OperatorResult.PROOF_REFUSED)?.let { return it }
        val result = body(s)
        app.publish()
        result
    }

    private fun account(s: FakeSession, userId: String): FakeAccount? = s.server.accounts.values.firstOrNull { it.userId == userId }

    override suspend fun openConsole(): OperatorResult = asOperator(null) {
        open = true
        OperatorResult.DONE
    }

    override fun closeConsole() {
        open = false
        devicesOf = null
        app.publish()
    }

    override suspend fun refreshConsole(): OperatorResult = asOperator(null) { if (open) OperatorResult.DONE else OperatorResult.STALE }

    override suspend fun finishServerSetup(password: String): OperatorResult = asOperator(password) { s ->
        if (s.server.hasCard) return@asOperator OperatorResult.SETUP_ALREADY_DONE
        // Card 0 from the offer this device kept, or from what `andvari setup` wrote; the server binds it to the operator.
        s.server.hasCard = true
        app.signedCard0 += s.server.origin
        app.pin(s.server, PinRoot.SETUP, s.account.email)
        note("instance_card_update", s.account.userId)
        OperatorResult.DONE
    }

    override suspend fun disableAccount(userId: String, why: DisableWhy, password: String): OperatorResult = asOperator(password) { s ->
        val target = account(s, userId) ?: return@asOperator OperatorResult.NO_SUCH_ACCOUNT
        if (target === s.account) return@asOperator OperatorResult.CANNOT_TARGET_SELF
        if (!target.disabled) {
            target.disabled = true
            target.disabledAtMs = app.nowMs
            target.devices.forEach { it.live = false }
        }
        note("operator_disable", target.userId)
        OperatorResult.DONE
    }

    override suspend fun enableAccount(userId: String, password: String): OperatorResult = asOperator(password) { s ->
        val target = account(s, userId) ?: return@asOperator OperatorResult.NO_SUCH_ACCOUNT
        // Re-enabling does not check the cap (S3-Q7).
        target.disabled = false
        target.disabledAtMs = 0L
        note("operator_enable", target.userId)
        OperatorResult.DONE
    }

    override suspend fun deleteAccount(userId: String, password: String): OperatorResult =
        deleteAccountFor(userId, io.silencelen.andvari.core.app.OperatorDeleteWhy.DISABLED_30_DAYS, password)

    override suspend fun deleteAccountFor(userId: String, why: io.silencelen.andvari.core.app.OperatorDeleteWhy, password: String): OperatorResult = asOperator(password) { s ->
        val target = account(s, userId) ?: return@asOperator OperatorResult.NO_SUCH_ACCOUNT
        if (target === s.account) return@asOperator OperatorResult.CANNOT_TARGET_SELF
        // "Under the minimum age" lifts the 30 days and nothing else: the account must still be disabled.
        val waited = why == io.silencelen.andvari.core.app.OperatorDeleteWhy.UNDER_MINIMUM_AGE || app.nowMs - target.disabledAtMs >= 30 * FakeScript.DAY
        if (!target.disabled || !waited) return@asOperator OperatorResult.NOT_DISABLED_LONG_ENOUGH
        val blocked = target.vaults.any { v -> v.role == RoleInVault.OWNER && v.members.any { it.userId != target.userId } }
        if (blocked) return@asOperator OperatorResult.BLOCKED_BY_SHARED_VAULT
        // No leaves: the person is not there to sign. They stay in each vault's history until its owner removes them.
        s.server.accounts.remove(target.email)
        s.server.accounts.values.forEach { a -> a.vaults.forEach { v -> v.members.filter { it.userId == target.userId }.forEach { it.deletedByOperator = true } } }
        note("operator_delete", null)
        OperatorResult.DONE
    }

    override suspend fun openAccountDevices(userId: String): OperatorResult = asOperator(null) { s ->
        val target = account(s, userId) ?: return@asOperator OperatorResult.NO_SUCH_ACCOUNT
        devicesOf = target.userId
        OperatorResult.DONE
    }

    override fun closeAccountDevices() {
        devicesOf = null
        app.publish()
    }

    override suspend fun revokeAccountDevice(deviceId: String, password: String): OperatorResult = asOperator(password) { s ->
        for (a in s.server.accounts.values) {
            val device = a.devices.firstOrNull { it.deviceId == deviceId } ?: continue
            device.live = false
            a.knownDevices -= deviceId
            note("operator_device_revoke", a.userId)
            return@asOperator OperatorResult.DONE
        }
        OperatorResult.NO_SUCH_DEVICE
    }

    override suspend fun setAccountQuota(userId: String, limits: QuotaLimits, password: String): OperatorResult = asOperator(password) { s ->
        val target = account(s, userId) ?: return@asOperator OperatorResult.NO_SUCH_ACCOUNT
        quotas[target.userId] = limits
        note("operator_quota", target.userId)
        OperatorResult.DONE
    }

    override suspend fun savePolicy(policy: AdminPolicy, password: String): OperatorResult = asOperator(password) { s ->
        // As the engine: the operator is told why ([OperatorConsole.policyRefusal]).
        if (policy.kdfParams.memBytes % 1024 != 0L) {
            policyRefusal = io.silencelen.andvari.core.app.CopyLine.of(io.silencelen.andvari.core.app.CopyKey.OPERATOR_POLICY_KDF_MEM_NOT_KIB)
            return@asOperator OperatorResult.BAD_POLICY
        }
        if (policy.kdfParams.memBytes < 8192) {
            policyRefusal = io.silencelen.andvari.core.app.CopyLine.of(io.silencelen.andvari.core.app.CopyKey.OPERATOR_POLICY_KDF_TOO_WEAK)
            return@asOperator OperatorResult.BAD_POLICY
        }
        policyRefusal = null
        // The panel can only tighten sign-up; loosening is done on the host (R7).
        val asked = strictness(policy.signup.mode)
        if (policy.signup.mode != null && asked < strictness(mode(s.server.mode))) return@asOperator OperatorResult.NOT_TIGHTER
        if ((policy.signup.cap ?: 0L) > 200L) return@asOperator OperatorResult.NOT_TIGHTER
        when (asked) {
            1 -> s.server.mode = JoinMode.INVITATION_ONLY
            2 -> s.server.mode = JoinMode.CLOSED
        }
        this.policy = policy
        note("operator_policy", s.account.userId)
        OperatorResult.DONE
    }

    override suspend fun loadAudit(sinceMs: Long, type: String?, userId: String?): OperatorResult = asOperator(null) {
        auditShown = auditLog.filter { it.at >= sinceMs && (type == null || it.type == type) && (userId == null || it.userId == userId) }
        OperatorResult.DONE
    }

    override suspend fun downloadEscrow(userId: String, password: String): OperatorResult = asOperator(password) { s ->
        val target = account(s, userId) ?: return@asOperator OperatorResult.NO_SUCH_ACCOUNT
        if (target.whoCanRecover != WhoCanRecover.ME_OR_OPERATOR || !s.server.offersOperatorRecovery) return@asOperator OperatorResult.NO_ESCROW
        escrow = AdminEscrowResponse(target.userId, "sealed-${target.userId}", "seed-${target.userId}", FakeText.hex32("identity:${target.userId}"))
        note("operator_escrow_read", target.userId)
        OperatorResult.DONE
    }

    override fun takeEscrow(): AdminEscrowResponse? = escrow.also { escrow = null }

    /** The fake request's id as the console lists it: 16 bytes of base64url derived from the fake's own id. */
    private fun wireId(fakeId: String): String = io.silencelen.andvari.core.crypto.Bytes.toB64(io.silencelen.andvari.core.crypto.Bytes.fromHexLower(FakeText.hex32("rid:$fakeId"))!!)

    /** The fake request's key as the console lists it: 32 bytes of base64url derived from the fake's own id. */
    private fun wireKey(fakeId: String): String = io.silencelen.andvari.core.crypto.Bytes.toB64(FakeText.hex32("rpub:$fakeId").encodeToByteArray())

    override suspend fun fulfilRecovery(requestId: String, sealedAnswer: String, password: String): OperatorResult {
        // In step with the engine: the one shared reader, against the listed request, before the password (spec 04 §7 step 3).
        val listed = console?.recoveryRequests?.firstOrNull { it.requestId == requestId }
        if (listed != null) {
            val read = io.silencelen.andvari.core.trust.AnswerToken.read(sealedAnswer, listed.requestId, listed.rPub, listed.email)
            if (read is io.silencelen.andvari.core.trust.AnswerRead.Refused) return OperatorResult.of(read.refusal)
        }
        return fulfilChecked(requestId, password)
    }

    private suspend fun fulfilChecked(requestId: String, password: String): OperatorResult = asOperator(password) { s ->
        val request = s.server.accounts.values.flatMap { it.helpRequests }.firstOrNull { wireId(it.requestId) == requestId }
        // The server refuses before the hold has passed, and after a veto.
        if (request == null || request.stage != OperatorHelpStage.AWAITING_OPERATOR) return@asOperator OperatorResult.REQUEST_NOT_READY
        request.fulfilled = true
        note("operator_recovery_fulfil", s.server.accounts[request.email]?.userId)
        OperatorResult.DONE
    }

    override suspend fun renameInstance(name: String, password: String): OperatorResult = asOperator(password) { s ->
        s.server.name = name
        note("instance_card_update", s.account.userId)
        OperatorResult.DONE
    }

    override suspend fun moveInstance(origin: String, password: String): OperatorResult = asOperator(password) { s ->
        val to = FakeText.origin(origin) ?: return@asOperator OperatorResult.NOT_AN_ADDRESS
        val pins = app.pins.remove(s.server.origin)
        app.servers.remove(s.server.origin)
        s.server.origin = to
        app.servers[to] = s.server
        if (pins != null) app.pins[to] = pins.map { it.copy(origin = to) }.toMutableList()
        note("instance_card_update", s.account.userId)
        OperatorResult.DONE
    }

    override suspend fun changeRecoveryKey(recoveryFingerprint: String, rotationStatement: String?, password: String): OperatorResult = asOperator(password) { s ->
        // Under variant R a public card never names a recovery key.
        if (s.server.kind == ServerKind.PUBLIC_SERVER) return@asOperator OperatorResult.CARD_REFUSED
        if (rotationStatement != null && !rotationStatement.startsWith("rotation:")) return@asOperator OperatorResult.ROTATION_REFUSED
        val had = s.server.recoveryKey
        s.server.recoveryKey = true
        if (had && rotationStatement == null) {
            // An unsigned change: everyone who chose operator recovery is asked, with turning it off as the default.
            s.server.unsignedRecoveryKeyChange = true
            s.server.accounts.values.filter { it.whoCanRecover == WhoCanRecover.ME_OR_OPERATOR }.forEach { it.recoveryKeyChangedUnsigned = true }
        }
        note(if (rotationStatement != null) "recovery_rotation_stored" else "instance_card_update", s.account.userId)
        OperatorResult.DONE
    }

    override suspend fun removeRecoveryKey(password: String): OperatorResult = asOperator(password) { s ->
        s.server.recoveryKey = false
        note("instance_card_update", s.account.userId)
        OperatorResult.DONE
    }
}
