package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.client.pin.CardStatus
import io.silencelen.andvari.core.client.pin.InstanceTrust
import io.silencelen.andvari.core.client.pin.PinState

/**
 * Whether the origin [ItemEngine] talks to may still be talked to (design §4.4). The item engine decides nothing
 * about an instance's identity; it asks here, twice:
 *
 * - **[judge] at the start of every sync.** "On every policy probe or sync the client fetches the chain and verifies
 *   forward from the pinned card": a fork, a move, a kind change or a withheld card is then noticed by ordinary use,
 *   not only when some flow happens to refresh the card.
 * - **[stopped] before anything else it would send or write.** A local read; nothing is fetched.
 *
 * Once either answers true the engine is halted for good: it sends nothing, accepts nothing served and writes
 * nothing, and what its cache holds stays readable ("a fork stops traffic, not reading"). The transport's own guard
 * (the one place that dials refuses a forked or damaged origin) stands behind this; the engine does not rely on it.
 */
interface OriginGate {
    /** True when this device's pin for the origin is forked, damaged or gone. Nothing is fetched. */
    fun stopped(): Boolean

    /**
     * Fetch the origin's card chain and verify it forward from the pin; true when the origin is stopped after that.
     * A chain that could not be fetched, a withheld card, a move or a kind change awaiting the person's answer stop
     * nothing here: the pin stays in force and the host shows them.
     */
    suspend fun judge(): Boolean
}

/**
 * [OriginGate] over the pin package: [InstanceTrust.refresh] on every sync, [InstanceTrust.pinState] in between.
 * [onStatus] receives every refresh's [CardStatus], so the host can show "older version", a move or a kind change.
 */
class PinnedOriginGate(
    private val trust: InstanceTrust,
    private val origin: String,
    private val onStatus: (CardStatus) -> Unit = {},
) : OriginGate {
    /** What the last [judge] found; null before the first. */
    var lastStatus: CardStatus? = null
        private set

    override fun stopped(): Boolean = trust.pinState(origin) !is PinState.Pinned

    override suspend fun judge(): Boolean {
        val status = trust.refresh(origin)
        lastStatus = status
        onStatus(status)
        return status is CardStatus.Fork || stopped()
    }
}
