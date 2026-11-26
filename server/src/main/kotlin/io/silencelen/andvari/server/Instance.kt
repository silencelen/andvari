package io.silencelen.andvari.server

import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.request.header
import io.ktor.server.response.respond
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.AccountRole
import io.silencelen.andvari.core.model.wire.InstanceCardPut
import io.silencelen.andvari.core.model.wire.InstanceCardPutResponse
import io.silencelen.andvari.core.model.wire.InstanceResponse
import io.silencelen.andvari.core.model.wire.InstanceRotationPut
import io.silencelen.andvari.core.model.wire.InstanceSetup
import io.silencelen.andvari.core.model.wire.RecoveryPosture
import io.silencelen.andvari.core.model.wire.WireErrors
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import java.sql.Connection

/** The values `andvari setup` wrote (spec 03 §17.1): the instance id and the setup `name`. */
data class InstanceSetupRow(val instanceId: String, val name: String)

/** The newest stored card's mirrored fields (spec 03 §17). */
data class CardHead(val seq: Long, val hash: String, val operatorId: String, val recoveryFp: String)

/**
 * The instance card chain (spec 03 §17, design §4). The server stores and serves the chain; it never
 * signs a card.
 */
class InstanceStore(private val config: Config, private val db: Db, private val clock: Clock) {

    /**
     * The setup row; created on first boot when `andvari setup` has not written one (a fresh instance id
     * and the `name` of `ANDVARI_INSTANCE_NAME`, else the origin's host).
     */
    fun ensureSetup(): InstanceSetupRow = db.tx { c ->
        setupOn(c) ?: run {
            val row = InstanceSetupRow(uuid(), defaultName(config))
            c.exec("INSERT INTO instance_setup(id,instanceId,name) VALUES(1,?,?)", row.instanceId, row.name)
            row
        }
    }

    fun setupOn(c: Connection): InstanceSetupRow? =
        c.queryOne("SELECT instanceId,name FROM instance_setup WHERE id=1") { InstanceSetupRow(it.getString(1), it.getString(2)) }

    fun instanceId(c: Connection): String = setupOn(c)?.instanceId ?: error("instance setup row missing")

    fun head(c: Connection): CardHead? =
        c.queryOne("SELECT seq,hash,operatorId,recoveryFp FROM instance_cards ORDER BY seq DESC LIMIT 1") {
            CardHead(it.getLong(1), it.getString(2), it.getString(3), it.getString(4))
        }

    /** The display name for notices (spec 03 §14.5): the newest card's, else the setup name; decoded text. */
    fun displayName(c: Connection): String {
        val b64 = c.queryOne("SELECT name FROM instance_cards ORDER BY seq DESC LIMIT 1") { it.getString(1) } ?: setupOn(c)?.name
        return b64?.let { io.silencelen.andvari.core.trust.TrustGrammar.decodeName(it) } ?: "andvari"
    }

    /** True once card 0 is stored (spec 03 §14.3 step 2: every registration but setup waits for it). */
    fun hasCard(c: Connection): Boolean = head(c) != null

    /** card 0's hash, for the enrol offers (`cardHash`) the host mints. */
    fun card0Hash(c: Connection): String? = c.queryOne("SELECT hash FROM instance_cards WHERE seq=0") { it.getString(1) }

    /** The newest card's `recoveryFp`, or null before card 0 (spec 03 §3.1, §14.3 step 8). */
    fun recoveryFp(c: Connection): String? = head(c)?.recoveryFp

    /** `GET /instance`'s body and its ETag (spec 03 §17.1). */
    fun served(c: Connection): Pair<String, String> {
        val cards = c.queryAll("SELECT frame FROM instance_cards ORDER BY seq") { it.getString(1) }
        val body = if (cards.isEmpty()) {
            val setup = setupOn(c) ?: error("instance setup row missing")
            InstanceResponse(cards = emptyList(), setup = InstanceSetup(setup.instanceId, config.canonicalOrigin, setup.name, config.instanceKind, config.recoveryFpOrNone))
        } else {
            InstanceResponse(cards = cards, rotations = c.queryAll("SELECT frame FROM recovery_rotations ORDER BY id") { it.getString(1) })
        }
        val text = WireJson.json.encodeToString(InstanceResponse.serializer(), body)
        return text to "\"${sha256Hex(text).take(32)}\""
    }

    /**
     * `andvari admin reset-instance-identity` (spec 03 §17.5), in ONE transaction: demote the operator,
     * delete the stored cards and rotations, and mint a new setup link for the same instance id.
     */
    fun resetIdentity(c: Connection, audit: Audit): HostLinks.Minted {
        val nowMs = clock.now()
        c.exec("UPDATE users SET role='member' WHERE role='operator'")
        c.exec("DELETE FROM instance_cards")
        c.exec("DELETE FROM recovery_rotations")
        val minted = HostLinks.mintSetup(c, config, setupOn(c) ?: error("instance setup row missing"), nowMs)
        audit.on(c, "instance_identity_reset", null, null, null)
        return minted
    }

    companion object {
        fun defaultName(config: Config): String =
            config.instanceName?.let { Grammar.nameOf(it) }
                ?: Grammar.nameOf(config.canonicalOrigin.substringAfter("://").substringBefore(':'))
                ?: Grammar.nameOf("andvari")!!
    }
}

/** Card frames travel as `frame` (unpadded base64url of the frame bytes) and are at most 1,125 bytes. */
private const val FRAME_MAX_BYTES = 1125

/** Decode a `frame` field, or throw [code]. */
fun frameBytes(b64: String?, code: String): ByteArray = frameBytesOrNull(b64) ?: badRequest(code)

/** Decode a `frame` field, or null when it is not one. */
fun frameBytesOrNull(b64: String?): ByteArray? = b64?.let { Grammar.b64Bytes(it, 4, FRAME_MAX_BYTES) }

fun Route.instanceRoutes(s: Services) {
    /** `GET /instance` (spec 03 §17.1): the chain, or the setup block before card 0; ETag honoured. */
    api(WireRoute.INSTANCE, s, Bucket.ipPerMinute("instance", 60)) {
        val (text, etag) = s.db.read { c -> s.instance.served(c) }
        call.response.headers.append(HttpHeaders.ETag, etag, false)
        call.response.headers.append(HttpHeaders.CacheControl, "no-cache", false)
        val inm = call.request.header(HttpHeaders.IfNoneMatch)
        if (inm != null && inm.split(',').any { it.trim() == etag || it.trim() == "*" }) {
            call.respond(HttpStatusCode.NotModified)
        } else {
            respondJsonText(text)
        }
    }

    /**
     * `GET /recovery-pubkey` (spec 03 §17.4), **R**: the configured key as bare base64url, only while the
     * newest card's `recoveryFp` names that very key; `404 not_found` otherwise.
     */
    api(WireRoute.RECOVERY_PUBKEY, s, Bucket.ipPerMinute("recovery_pubkey", 60)) {
        val fp = s.db.read { c -> s.instance.recoveryFp(c) }
        if (!s.config.recoveryConfigured || (fp != null && fp != s.config.recoveryFingerprint) || fp == "none") notFound()
        call.respondText(Bytes.toB64(s.config.recoveryPublicKey), ContentType.Text.Plain)
    }

    /**
     * `PUT /instance/card` (spec 03 §17.2), operator†. Checks, in order: the operator (generic); the
     * password proof; the strict parse (`400 bad_card`); the position (`409 card_head_moved {seq, hash}`,
     * or `400 bad_card` for anything but card 0 on an empty chain); the chain, signature and fields
     * (`400 bad_card`); the handover target (`409 handover_target_invalid`). Then, in one transaction, the
     * card is stored and, on a handover, the operator role switches atomically. Audited `instance_card_update`.
     */
    api(WireRoute.INSTANCE_CARD_PUT, s) {
        val req = body<InstanceCardPut>()
        reauth(req.currentAuthKey)
        val frame = frameBytes(req.card, WireErrors.BAD_CARD)
        val card = s.trust.parseCard(frame) ?: badRequest(WireErrors.BAD_CARD)
        val caller = p
        val stored = s.db.tx { c ->
            val head = s.instance.head(c)
            if (head == null) {
                if (card.seq != 0L) badRequest(WireErrors.BAD_CARD)
            } else if (card.seq != head.seq + 1 || card.prev != head.hash) {
                cardHeadMoved(head.seq, head.hash)
            }
            val previous = head?.let { h ->
                val prevFrame = c.queryOne("SELECT frame FROM instance_cards WHERE seq=?", h.seq) { Bytes.fromB64(it.getString(1)) }!!
                s.trust.parseCard(prevFrame) ?: error("stored card does not parse")
            }
            val setup = s.instance.setupOn(c) ?: error("instance setup row missing")
            // An account's Ed25519 signing key: the signer of its stored genesis (spec 03 §17.2).
            val signKeyOf = { id: String ->
                c.queryOne("SELECT genesis FROM users WHERE userId=?", id) { it.getString(1) }?.let { frameBytesOrNull(it) }?.let { s.trust.genesisSigner(it) }
            }
            if (!s.trust.verifyCardStep(previous, card, setup.instanceId, s.instance.card0Hash(c), signKeyOf)) badRequest(WireErrors.BAD_CARD)
            if (card.instanceId != setup.instanceId) badRequest(WireErrors.BAD_CARD)
            // Variant R (§18.6): a public card never names a recovery key.
            if (s.config.isPublic && card.recoveryFp != "none") badRequest(WireErrors.BAD_CARD)
            if (previous == null) {
                // Card 0 equals what `andvari setup` wrote, and names the caller (§17.2).
                if (card.origin != s.config.canonicalOrigin || card.kind != s.config.instanceKind ||
                    card.recoveryFp != s.config.recoveryFpOrNone || card.operator != caller.userId
                ) badRequest(WireErrors.BAD_CARD)
            }
            // The operator key is byte-equal to the Ed25519 key that signed the named account's genesis (§17.2):
            // never a comparison through the X25519 image, which a key and its negation share.
            // core checked this already; the route keeps its own check so no verifier wiring can drop it.
            val targetStatus = c.queryOne("SELECT status FROM users WHERE userId=?", card.operator) { it.getString(1) }
                ?: badRequest(WireErrors.BAD_CARD)
            val genesisSigner = signKeyOf(card.operator)
            if (genesisSigner == null || !java.security.MessageDigest.isEqual(genesisSigner, card.operatorSignKey)) badRequest(WireErrors.BAD_CARD)
            if (card.operator != caller.userId) {
                // Handover (§17.2): the target is active, has no operator recovery (the operator
                // would hold the sheet that opens its own account's escrow), and on a public instance owns no
                // shared vault.
                if (targetStatus != "active") conflict(WireErrors.HANDOVER_TARGET_INVALID)
                val targetRecovery = c.queryOne("SELECT recovery FROM users WHERE userId=?", card.operator) { it.getString(1) }
                if (targetRecovery != RecoveryPosture.PRIVATE) conflict(WireErrors.HANDOVER_TARGET_INVALID)
                if (s.config.isPublic) {
                    val owns = c.count(
                        "SELECT COUNT(*) FROM grants g JOIN vaults v ON v.vaultId=g.vaultId WHERE g.userId=? AND g.role='owner' AND v.type='shared' AND g.revokedAt IS NULL",
                        card.operator,
                    )
                    if (owns > 0) conflict(WireErrors.HANDOVER_TARGET_INVALID)
                }
                c.exec("UPDATE users SET role='member' WHERE role='operator'")
                c.exec("UPDATE users SET role=? WHERE userId=?", AccountRole.OPERATOR, card.operator)
            }
            c.exec(
                "INSERT INTO instance_cards(seq,hash,frame,operatorId,name,recoveryFp,storedAt) VALUES(?,?,?,?,?,?,?)",
                card.seq, card.hash, req.card, card.operator, card.name, card.recoveryFp, now,
            )
            s.audit.on(c, "instance_card_update", caller.userId, caller.deviceId, ip, "seq=${card.seq}")
            // The card bell (spec 03 §6): every open socket learns at once to look at the chain again, so a
            // client that must not hold the new operator account (a handover) signs it out at once.
            ringCardBell(c, s, setup.instanceId, now)
            card
        }
        respond(InstanceCardPutResponse(stored.seq, stored.hash))
    }

    /**
     * `PUT /instance/rotation` (spec 03 §17.3), operator†, **R**. Stored only when it verifies against the
     * current recovery key: `instanceId` this instance's, `fromFp` the newest card's `recoveryFp` or the
     * newest stored rotation's `toFp`, signed by the key `fromFp` names; otherwise `400 bad_rotation`. A
     * byte-identical stored statement answers `ok`. Audited `recovery_rotation_stored`.
     */
    api(WireRoute.INSTANCE_ROTATION_PUT, s) {
        val req = body<InstanceRotationPut>()
        reauth(req.currentAuthKey)
        val frame = frameBytes(req.statement, WireErrors.BAD_ROTATION)
        val caller = p
        s.db.tx { c ->
            if (c.queryOne("SELECT 1 FROM recovery_rotations WHERE frame=?", req.statement) { 1 } != null) return@tx
            val cardFp = s.instance.recoveryFp(c) ?: badRequest(WireErrors.BAD_ROTATION)
            val currentFp = c.queryOne("SELECT toFp FROM recovery_rotations ORDER BY id DESC LIMIT 1") { it.getString(1) } ?: cardFp
            val instanceId = s.instance.instanceId(c)
            // fromFp may be the newest card's recoveryFp or the newest stored rotation's toFp (§17.3).
            val rot = (listOf(currentFp, cardFp).distinct() - "none").firstNotNullOfOrNull { s.trust.verifyRotation(frame, instanceId, it) }
                ?: badRequest(WireErrors.BAD_ROTATION)
            c.exec(
                "INSERT INTO recovery_rotations(hash,frame,fromFp,toFp,storedAt) VALUES(?,?,?,?,?)",
                rot.hash, req.statement, rot.fromFp, rot.toFp, now,
            )
            s.audit.on(c, "recovery_rotation_stored", caller.userId, caller.deviceId, ip)
            ringCardBell(c, s, instanceId, now)
        }
        ok()
    }
}

/**
 * The card bell (spec 03 §6): whenever `GET /instance` starts serving another chain (a card or a rotation
 * statement stored), the store takes a fresh global rev and, after the commit, every open events socket of
 * every account gets the ordinary `{"type":"rev","rev":N}`. It carries nothing about the card; a client only
 * pulls, and its own card check at that pull decides what changed.
 */
private fun ringCardBell(c: Connection, s: Services, instanceId: String, nowMs: Long) {
    val rev = nextRev(c, "instance", instanceId, null, nowMs)
    afterCommit(c) { s.notifier.notifyEveryone(rev) }
}
