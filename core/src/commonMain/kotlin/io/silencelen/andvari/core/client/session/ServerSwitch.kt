package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.OriginCanon
import io.silencelen.andvari.core.model.ClientPolicy
import kotlinx.coroutines.CancellationException

/** What an address typed into the server field means (design 2026-07-15 §4.4; review 2026-07-16). */
sealed interface ServerAddress {
    /**
     * Not a bare http(s) origin: a userinfo, a path, a query. Refused before anything is shown or dialed:
     * `https://real.host@evil.example` would let the gate show a reassuring host while the client dials
     * another, and the next sign-in would hand that host an offline-crackable authKey.
     */
    data object Invalid : ServerAddress

    /** The origin the client already dials, spelled differently: applied without the gate, nothing dropped. */
    data class Current(val origin: String) : ServerAddress

    /** A real change: show the Trust Gate with [render]; its Connect calls [ServerSwitch.connect]. */
    data class NeedsGate(val origin: String, val render: TrustGateRender) : ServerAddress
}

/** What Connect on the manual switch did (audit F27). */
sealed interface SwitchResult {
    /** The target answered (any answer) and the client now dials it. A real change ended the old session. */
    data class Switched(val origin: String, val droppedSession: Boolean) : SwitchResult

    /** The target never answered: nothing changed. The session, the unlock state and the origin are intact. */
    data class Unreachable(val cause: Throwable) : SwitchResult
}

/** One policy probe of the origin the client dials. */
sealed interface PolicyProbe {
    /** The policy is this client's current one; mirrors and the live auto-lock window are written. */
    data class Applied(val policy: ClientPolicy) : PolicyProbe

    /** The client moved to another origin, or another visit, while it ran: it wrote nothing. */
    data object Stale : PolicyProbe

    /** No answer, or a refusal. [current] says whether the client still dials the probed origin in the same visit. */
    data class Failed(val cause: Throwable, val current: Boolean) : PolicyProbe

    /** No origin is chosen yet (iOS first launch): there is nothing to probe. */
    data object NoOrigin : PolicyProbe
}

/**
 * The manual server switch (design 2026-07-15 §4, Wave 3) and the policy probe of the origin the client
 * dials. The invite-driven pending switch is not here: a foreign invite goes through the manual gate first.
 */
class ServerSwitch(
    private val store: SessionPersistence,
    private val session: VaultSession,
    private val coordinator: PolicyCoordinator,
    private val clients: SessionClients,
    /** The hosts this platform permits cleartext http to ([trustGateRender]). */
    private val cleartextExemptHosts: Set<String>,
) {
    /**
     * §4.4 requirement 3: what [input] means. A userinfo- or path-bearing string is [ServerAddress.Invalid]
     * ([OriginCanon.canonicalServerOrigin] returns the bare canonical origin the gate shows AND dials); the
     * current origin re-typed needs no gate; anything else needs the raw-origin Trust Gate.
     */
    fun prepare(input: String): ServerAddress {
        val target = OriginCanon.canonicalServerOrigin(input) ?: return ServerAddress.Invalid
        val current = store.baseUrl
        if (current != null && !switchDropsSession(current, target)) return ServerAddress.Current(target)
        return ServerAddress.NeedsGate(target, trustGateRender(target, cleartextExemptHosts))
    }

    /**
     * Audit F27: the Trust Gate's Connect, which commits only after proving the target answers.
     *
     * A real switch is destructive — it ends the session ([moveTo]) — and it used to do that first and
     * discover the address was unusable second. So the probe runs here, against [target], with NO tokens
     * (nothing may carry a bearer across an origin change, the probe included), and nothing changes until
     * it comes back: a target the client can never dial — a platform's cleartext ban, a typo'd host, a
     * server that is down — now costs the user nothing at all. Any answer, a refusal included, is a real
     * endpoint ([switchProbeReachable]): those are verdicts the user needs to see AT that origin.
     */
    suspend fun connect(target: String): SwitchResult {
        val probe = clients.probe(target)
        // try/catch rather than runCatching: a cancelled caller (the screen going away mid-probe) must NOT
        // read as a probe verdict and commit a switch on the way out.
        val failure = try {
            coordinator.boundedPolicy(probe)
            null
        } catch (c: CancellationException) {
            throw c
        } catch (t: Throwable) {
            t
        } finally {
            probe.close()
        }
        if (!switchProbeReachable(failure)) return SwitchResult.Unreachable(failure!!)
        return SwitchResult.Switched(target, moveTo(target))
    }

    /**
     * §4.1 rule 1 (B1-5 — HARD MUST): point the client at [newOrigin]. A real origin change ends the old
     * session first: the live session locks (its api and engine close before anything reaches the new
     * origin), and the stored tokens are dropped BEFORE the origin moves (F8), so a crash between the two
     * leaves the old origin with no tokens, never a stored session paired with the new origin. A canonical
     * no-op (a re-typed spelling of your own server) keeps the session. Per-origin material survives either
     * way (§4.2/B2-7: a switch is not a wipe). Every policy probe started before this is stale from here on,
     * and the live policy, which belonged to the old origin, is forgotten. Returns whether it dropped the session.
     */
    fun moveTo(newOrigin: String): Boolean {
        val current = store.baseUrl
        val drop = current != null && switchDropsSession(current, newOrigin)
        if (drop) {
            session.lock()
            store.clearSessionTokens()
        }
        store.moveOrigin(newOrigin)
        coordinator.originChanged()
        return drop
    }

    /**
     * Probe the policy of the origin the client dials (tokenless, bounded) and apply it where it is enforced.
     * A12 (row 80): the probe is tagged before it is sent, so an answer that lands after the client moved
     * writes nothing. A forbidding answer purges the stored session's namespace at THAT origin (§4.2), so a
     * probe of server B can never touch server A's data.
     */
    suspend fun probePolicy(): PolicyProbe {
        val origin = store.baseUrl ?: return PolicyProbe.NoOrigin
        val originKey = OriginCanon.originKey(origin)
        val tag = coordinator.tag(originKey)
        val probe = clients.probe(origin)
        try {
            val p = try {
                coordinator.boundedPolicy(probe)
            } catch (c: CancellationException) {
                throw c
            } catch (t: Throwable) {
                val current = coordinator.probeIsCurrent(tag)
                // The client no longer knows this origin's policy: what it enforces comes from the persisted mirror.
                if (current) coordinator.forgetLivePolicy()
                return PolicyProbe.Failed(t, current)
            }
            if (!coordinator.applyPolicy(p, tag)) return PolicyProbe.Stale
            // Spec 02 §8: a forbidding server purges ITS OWN namespace for the stored session's user.
            if (!p.offlineCacheAllowed) store.load()?.let { coordinator.purgeForbidden(originKey, it.userId) }
            return PolicyProbe.Applied(p)
        } finally {
            probe.close()
        }
    }
}
