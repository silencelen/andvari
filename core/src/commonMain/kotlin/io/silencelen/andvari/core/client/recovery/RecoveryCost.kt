package io.silencelen.andvari.core.client.recovery

import io.silencelen.andvari.core.client.KdfUpgrade
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.KeptAccountKeys
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.model.wire.ClientPolicy
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute

/**
 * The hashing cost a server serves to whoever makes a new wrap there (`GET /client-policy`, spec 03 §1.1): the policy's
 * cost raised to the server's floor. Null when it cannot be read; a new wrap is then made at the cost without it, and the
 * server's own floor refuses a commit below it with nothing changed. What is served is never followed outside the fence:
 * [KdfUpgrade.wrapCost] leaves such a cost out.
 */
internal object ServedCost {
    suspend fun read(client: WireClient): KdfParams? =
        when (val r = client.call(WireRoute.CLIENT_POLICY, decode = { WireJson.json.decodeFromString(ClientPolicy.serializer(), it) })) {
            is WireResult.Ok -> r.value.kdfParams
            else -> null
        }
}

/**
 * The cost a recovery derives the new master password at (spec 01 §7: no new wrap at a cost lower than the account
 * already has; never below what the server serves).
 *
 * A recovering device cannot know the account's own cost from the account: the person has lost the password, so no wrap
 * the server holds is opened, and the server's word on the cost is no evidence (the prelogin answers alike for every
 * address). What it can know is: the cost the caller names ([base], the client's own default unless the host says more),
 * the cost of this device's own copy of the account when it keeps one (its own wrap and a pending one: the cost the
 * account had when this device last opened it), and the cost the pinned server serves during the flow. The new wrap is
 * made, figure by figure, at the highest of them, inside the fence ([KdfUpgrade.wrapCost]): so an account that stands
 * above the served cost on one figure and below it on the other recovers at a cost the server takes, and keeps the
 * higher figure. A served cost outside the fence is not followed, and one that cannot be read raises nothing.
 */
internal object RecoveryCost {
    suspend fun of(client: WireClient, base: KdfParams, kept: KeptAccountKeys?, userId: String): KdfParams {
        val own = kept?.takeIf { it.userId == userId }
        return KdfUpgrade.wrapCost(ServedCost.read(client), base, own?.own?.kdfParams, own?.pending?.kdfParams)
    }
}
