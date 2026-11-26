package io.silencelen.andvari.cli

import io.silencelen.andvari.core.client.account.ReauthKey
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.pin.CardStatus
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.InstanceCardPut
import io.silencelen.andvari.core.model.wire.InstanceCardPutResponse
import io.silencelen.andvari.core.model.wire.InstanceRotationPut
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.CardFields
import io.silencelen.andvari.core.trust.InstanceKind
import io.silencelen.andvari.core.trust.SignedFrame

/** What a card or rotation write came to. */
sealed class CardWrite {
    data class Stored(val seq: Long, val hash: String) : CardWrite()
    data class Refused(val code: String) : CardWrite()
}

/**
 * A RAW card signer for the journeys and the hostile-server bench, never shipped: it signs whatever card it is asked for
 * with the operator account's key (several fields at once, a change from one recovery key to another with no rotation,
 * a rotation statement uploaded unchecked), as anyone holding that key could with code of their own (design R30). The
 * bench uses it to play the key thief. The tool's own commands sign through the shared code's path instead
 * ([Host.operatorCards], [CardChanges]), which refuses all of that; this class was the tool's
 * `card sign` and `card rotation` until then.
 */
class CardOps(private val host: Host, private val held: HeldSession) {
    private val origin get() = held.origin

    private suspend fun currentKey(password: CharArray): Pair<String?, String> =
        when (val k = host.reauth(held).currentAuthKey(password)) {
            is ReauthKey.Key -> k.currentAuthKey to ""
            ReauthKey.WrongPassword -> null to WRONG_PASSWORD
            else -> null to REAUTH_REFUSED
        }

    companion object {
        const val WRONG_PASSWORD = "wrong_password"
        const val REAUTH_REFUSED = "reauth_unavailable"
    }

    /** Sign and store the next card. [name], [newOrigin] and [recoveryFp] (`"none"` for none) default to the pinned card's. */
    suspend fun sign(password: CharArray, name: String? = null, newOrigin: String? = null, recoveryFp: String? = null): CardWrite {
        val (key, why) = currentKey(password)
        if (key == null) return CardWrite.Refused(why)
        val status = host.trust.refresh(origin)
        val pin = (status as? CardStatus.Ok)?.pin ?: return CardWrite.Refused("pin_not_ok: $status")
        if (pin.operator != held.userId) return CardWrite.Refused("not_operator")
        val kind = InstanceKind.fromLiteral(pin.kind) ?: return CardWrite.Refused("bad_kind")
        val fp = (recoveryFp ?: pin.recoveryFp).takeIf { it != "none" }
        val fields = CardFields(
            pin.instanceId, pin.seq + 1, pin.hash, newOrigin ?: pin.origin, name ?: pin.name, kind, held.userId,
            held.session.account.signingKeyB64(), fp, host.clock(),
        )
        val frame = try {
            held.session.account.signInstanceCard(host.crypto, fields)
        } catch (e: IllegalArgumentException) {
            return CardWrite.Refused("bad_card_fields")
        }
        val body = WireJson.json.encodeToString(InstanceCardPut.serializer(), InstanceCardPut(Bytes.toB64(frame), key))
        return when (val r = host.client(origin).call(WireRoute.INSTANCE_CARD_PUT, bodyJson = body, decode = { WireJson.json.decodeFromString(InstanceCardPutResponse.serializer(), it) })) {
            is WireResult.Ok -> {
                if (r.value.hash != SignedFrame.hash(host.crypto, frame)) return CardWrite.Refused("bad_response")
                host.trust.refresh(origin)
                CardWrite.Stored(r.value.seq, r.value.hash)
            }
            is WireResult.Refused -> CardWrite.Refused(r.code)
            is WireResult.NoAnswer -> CardWrite.Refused("unreachable")
        }
    }

    /** Store a 0x08 rotation statement, unchecked here (the server and every reader check it). */
    suspend fun storeRotation(statementB64: String, password: CharArray): CardWrite {
        val (key, why) = currentKey(password)
        if (key == null) return CardWrite.Refused(why)
        val body = WireJson.json.encodeToString(InstanceRotationPut.serializer(), InstanceRotationPut(statementB64.trim(), key))
        return when (val r = host.client(origin).call(WireRoute.INSTANCE_ROTATION_PUT, bodyJson = body, decode = { })) {
            is WireResult.Ok -> CardWrite.Stored(-1, "")
            is WireResult.Refused -> CardWrite.Refused(r.code)
            is WireResult.NoAnswer -> CardWrite.Refused("unreachable")
        }
    }
}
