package io.silencelen.andvari.core.client.link

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.pin.CardTrust
import io.silencelen.andvari.core.client.state.AccountDocument
import io.silencelen.andvari.core.client.state.AccountStateRead
import io.silencelen.andvari.core.client.state.AccountStateStore
import io.silencelen.andvari.core.client.state.AccountStateWrite
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.KeyPairBytes
import io.silencelen.andvari.core.model.wire.LinkAnswerRequest
import io.silencelen.andvari.core.model.wire.LinkCreateRequest
import io.silencelen.andvari.core.model.wire.LinkCreatedResponse
import io.silencelen.andvari.core.model.wire.LinkFetchResponse
import io.silencelen.andvari.core.model.wire.LinkRevealRequest
import io.silencelen.andvari.core.model.wire.RegisterAuth
import io.silencelen.andvari.core.model.wire.RegisterRequest
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.Links
import kotlinx.serialization.builtins.ListSerializer
import io.silencelen.andvari.core.model.wire.LinkAnswer as ServedAnswer

/** An in-memory account state: what the engine reads and writes, with a switch to refuse writes. */
class MemoryAccountState(var doc: AccountDocument = AccountDocument.EMPTY) : AccountStateStore {
    var refuse: String? = null
    override fun local(): AccountDocument = doc
    override suspend fun read(): AccountStateRead = AccountStateRead.Ok(doc, emptyList())
    override suspend fun update(change: (AccountDocument) -> AccountDocument): AccountStateWrite {
        refuse?.let { return AccountStateWrite.Refused(it) }
        val next = change(doc)
        if (next == doc) return AccountStateWrite.Unchanged(doc)
        doc = next.copy(seq = doc.seq + 1)
        return AccountStateWrite.Written(doc)
    }
}

/**
 * The link routes of spec 03 §15 as an honest server answers them, over a [FakeInstance] that serves the card chain,
 * the client policy and registration. [client] gives one caller's view (a session for that userId, or none).
 */
class LinkServer(val crypto: CryptoProvider, val instance: FakeInstance = FakeInstance(crypto)) {
    class Row(val linkId: String, val kind: String, val offer: String, val expiresAt: Long, val creator: String?, val creatorKey: String?, val tokenHash: String?) {
        var state = "open"
        var answer: String? = null
        var answerer: String? = null
        var delivered = false
        var reveal: String? = null
    }

    val rows = HashMap<String, Row>()
    val keys = HashMap<String, String>()
    val calls = ArrayList<WireRoute>()
    val override = HashMap<WireRoute, WireResult<String>>()

    /** What [GET /links/{id}] answers with instead of the honest reveal (a lying server). */
    var revealOverride: String? = null

    private fun refuse(status: Int, code: String): WireResult<Nothing> = WireResult.Refused(status, WireError(code, code))

    /** Routes whose request the server processes but whose reply is lost on the way back (the caller sees no answer). */
    val loseReply = HashSet<WireRoute>()

    fun client(caller: String?): WireClient = object : WireClient {
        override val origin: String = instance.origin
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            val r = handle(caller, route, pathParams, query, bodyJson, authenticated, decode)
            return if (route in loseReply) WireResult.NoAnswer(NoAnswerKind.TIMEOUT) else r
        }
    }

    @Suppress("UNCHECKED_CAST")
    private suspend fun <T> handle(caller: String?, route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
        calls += route
        override[route]?.let { o -> return if (o is WireResult.Ok) WireResult.Ok(decode(o.value), o.status) else o as WireResult<T> }
        val now = instance.now
        fun <R> ok(text: String): WireResult<R> = WireResult.Ok(decode(text) as R, 200)
        val id = pathParams["linkId"]
        return when (route) {
            WireRoute.LINK_CREATE -> {
                val c = caller ?: return refuse(401, "unauthenticated")
                val b = WireJson.json.decodeFromString(LinkCreateRequest.serializer(), bodyJson!!)
                if (b.linkId in rows) return refuse(409, "link_id_taken")
                rows[b.linkId] = Row(b.linkId, b.kind, b.offer, b.expiresAt, c, keys[c], b.tokenHash)
                WireResult.Ok(decode(WireJson.json.encodeToString(LinkCreatedResponse.serializer(), LinkCreatedResponse(b.expiresAt, b.expiresAt - now))), 201)
            }
            WireRoute.LINK_FETCH -> {
                val r = rows[id] ?: return refuse(404, "link_unknown")
                when {
                    r.state == "revoked" -> refuse(404, "link_unknown")
                    r.state == "open" && now >= r.expiresAt -> refuse(410, "link_expired")
                    r.state == "open" -> ok(LinkFetchResponse.open(r.kind, r.offer, r.expiresAt, r.creator, r.creatorKey).toJsonObject().toString())
                    else -> ok(LinkFetchResponse.answered(r.kind, revealOverride ?: r.reveal).toJsonObject().toString())
                }
            }
            WireRoute.LINK_ANSWER -> {
                val c = caller ?: return refuse(401, "unauthenticated")
                val r = rows[id]?.takeIf { it.state != "revoked" } ?: return refuse(404, "link_unknown")
                if (r.kind != "connect") return refuse(409, "kind_mismatch")
                if (now >= r.expiresAt) return refuse(410, "link_expired")
                if (r.state != "open") return refuse(409, "link_used")
                if (r.creator == c) return refuse(400, "cannot_target_self")
                r.answer = WireJson.json.decodeFromString(LinkAnswerRequest.serializer(), bodyJson!!).answer
                r.answerer = c
                r.state = "answered"
                ok("{}")
            }
            WireRoute.LINK_REVEAL -> {
                val r = rows[id]?.takeIf { it.creator == caller } ?: return refuse(404, "link_unknown")
                if (r.state != "answered" || r.reveal != null) return refuse(409, "link_state")
                r.reveal = WireJson.json.decodeFromString(LinkRevealRequest.serializer(), bodyJson!!).nonce
                ok("{}")
            }
            WireRoute.LINK_ANSWERS -> {
                val list = rows.values.filter { it.creator == caller && it.state == "answered" && !it.delivered }
                    .map { ServedAnswer(it.linkId, it.answer!!, it.answerer!!, now) }
                ok(WireJson.json.encodeToString(ListSerializer(ServedAnswer.serializer()), list))
            }
            WireRoute.LINK_ACK -> {
                val r = rows[id]?.takeIf { it.creator == caller } ?: return refuse(404, "link_unknown")
                if (r.state != "answered") return refuse(409, "link_state")
                r.delivered = true
                ok("{}")
            }
            WireRoute.LINK_REVOKE -> {
                val r = rows[id]?.takeIf { it.creator == caller } ?: return refuse(404, "link_unknown")
                if (r.state != "open") return refuse(409, "link_state")
                r.state = "revoked"
                ok("{}")
            }
            WireRoute.REGISTER -> {
                val b = WireJson.json.decodeFromString(RegisterRequest.serializer(), bodyJson!!)
                val auth = b.auth
                val row = when (auth) {
                    is RegisterAuth.Link -> rows[auth.linkId]?.takeIf { it.kind == "register" } ?: return refuse(409, "kind_mismatch")
                    else -> null
                }
                if (row != null) {
                    auth as RegisterAuth.Link
                    if (row.tokenHash != Links.tokenHash(crypto, auth.registerToken) || row.state != "open" || now >= row.expiresAt) return refuse(409, "link_used")
                }
                val r = instance.call(route, pathParams, query, bodyJson, authenticated, decode)
                if (r is WireResult.Ok && row != null) {
                    row.answer = (auth as RegisterAuth.Link).answer
                    row.answerer = b.userId
                    row.state = "answered"
                    keys[b.userId] = b.identityPub
                }
                r
            }
            else -> if (route.name.startsWith("LINK")) WireResult.NoAnswer(NoAnswerKind.TRANSPORT) else instance.call(route, pathParams, query, bodyJson, authenticated, decode)
        }
    }
}

/** One person of a link test: an account at the server's origin, with its own device state and pins. */
class LinkPerson(val crypto: CryptoProvider, val server: LinkServer, seedByte: Int, val userId: String, val name: String) {
    val seed = ByteArray(32) { seedByte.toByte() }
    val identity: KeyPairBytes = crypto.boxKeypairFromSeed(seed)
    val signing: KeyPairBytes = crypto.signKeypairFromSeed(seed)
    val store = MemoryAccountState()
    val state = MemoryDeviceState()
    lateinit var trust: CardTrust
    var signedIn = true
    val releases = ArrayList<Triple<String, LinkShare, Boolean>>()

    val account = LinkAccount(server.instance.origin, "$name@example.com".lowercase(), userId, "dddddddd-dddd-4ddd-8ddd-00000000000$seedByte", name,
        ByteArray(32) { (seedByte + 100).toByte() }, identity, signing, store)

    val identityPubB64: String get() = Bytes.toB64(identity.publicKey)

    lateinit var flows: WireLinkFlows

    suspend fun start(setupAllowed: Boolean = true): LinkPerson {
        server.keys[userId] = identityPubB64
        trust = server.instance.pinnedTrust(state)
        flows = WireLinkFlows({ server.client(if (signedIn) userId else null) }, trust, state, crypto, { server.instance.now }, { if (signedIn) account else null },
            setupAllowed, LinkShareRelease { contact, share, uncompared -> releases += Triple(contact, share, uncompared); true })
        return this
    }
}
