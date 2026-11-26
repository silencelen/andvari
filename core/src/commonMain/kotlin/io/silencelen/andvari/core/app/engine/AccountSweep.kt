package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.client.CoreLog
import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.pin.PinStore
import io.silencelen.andvari.core.client.session.SessionKeeper
import io.silencelen.andvari.core.client.session.SessionRecordReadability
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.trust.TrustGrammar
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * The sweep (decided on 2026-11-21): every record kept by the id of an account this device no longer knows anywhere goes,
 * whatever the tie between servers said when something ended. The records are those of [PinStore.ACCOUNT_KEYED]: the
 * identity record, the state copy and its marks, the vault logs, the item engine's records, the recovery mirror and the
 * escrow mark. It only ever removes.
 *
 * An account is known where at least one of these is so:
 * - a session is kept for it: the one this process's keeper holds, or the one the secure store holds now (another process
 *   over the same stores may have taken one since this process started);
 * - a copy is held for it at any address ([EngineAppApi.HELD_KEY]);
 * - an address record at any server names it ([SessionKeeper.EMAIL_BINDING_PREFIX]);
 * - something of it is in flight: an end of the person's own not settled yet ([SessionKeeper.OWN_ENDS_KEY]), a forgetting
 *   not finished ([EngineAppApi.FORGETTING_KEY]), a deletion whose outcome is not known
 *   ([EngineAccountSettings.OUTCOME_UNKNOWN_KEY]), a deletion begun and not finished ([EngineAccountSettings.DELETION_KEY]:
 *   a start finishes it, by its own steps, before this sweep runs).
 * The record a forgetting keeps of an earlier account at its server ([SessionKeeper.EARLIER_IDENTITY_PREFIX]) is that
 * server's, not kept by the id alone: it stays, and it does not make the account known.
 *
 * A take never leaves a moment in which such a record exists and nothing names the account: its first write is the address
 * record ([SessionKeeper.establish]), and every other such record is written while a session is kept, or (a registration the
 * keeper refused) is a record whose absence makes the device ask rather than act.
 *
 * Where the store cannot list its keys, or any record above cannot be read (it throws, or does not parse as its form), the
 * sweep removes nothing and says so in the diagnostic log; so too while the secure store says it holds a session record it
 * cannot read now ([SessionRecordReadability]): that record, like an address record that cannot be read, could name an
 * account the device must keep. The engine's own readers of the copies held, of the forgettings begun and of the marks of a
 * deletion of unknown outcome drop exactly the lines this sweep cannot read, so that the next rewrite of such a record (or
 * the start, for the last two) clears them and the sweep runs again. A removal the store refuses stops it there, said in the
 * log; the next sweep goes on from what is left, so a sweep cut at any of its writes and followed by a start ends as the
 * uncut one. The identity record of an account goes after its other records. Run again over what is left, it removes
 * nothing more.
 *
 * Where something ends, what is kept by the account's id stays while the account is known by this same rule apart from what
 * that end removes ([knownApartFrom]), read before anything of the end is removed: the tie of an end and this sweep agree.
 */
internal object AccountSweep {
    /** What a sweep came to. */
    sealed class Outcome {
        /** Every record kept by the id of an account not known went: [removed] records of [accounts] (none: nothing to do). */
        class Swept(val accounts: Set<String>, val removed: Int) : Outcome()

        /** Nothing was removed: the keys could not be listed, or [record] could not be read. */
        class HeldBack(val record: String) : Outcome()

        /** The store refused the removal of [record]; what came before it went. */
        class Stopped(val record: String) : Outcome()
    }

    /** [HeldBack.record] when the store cannot list its keys. */
    const val KEYS = "the store's keys"

    private class Unreadable(val record: String) : Exception()

    /**
     * The sweep over the device's [state] and [secure] stores. [keptHere]: the user id of the session this process's keeper
     * holds, if any. [log] gets one line when nothing could be decided or a removal was refused.
     */
    fun run(state: DeviceState, secure: DeviceState, keptHere: String?, log: CoreLog): Outcome {
        val keys = try { state.keys() } catch (e: Exception) { null }
            ?: return heldBack(log, KEYS)
        val known = try {
            sightings(state, secure, keys, keptHere?.let { Sighting(it, Kind.SESSION, null) }).map { it.id }.toSet()
        } catch (e: Unreadable) {
            return heldBack(log, e.record)
        }
        val gone = keys.mapNotNull { k ->
            val prefix = PinStore.ACCOUNT_KEYED.firstOrNull { k.startsWith(it) } ?: return@mapNotNull null
            val id = k.removePrefix(prefix).substringBefore('|')
            if (TrustGrammar.isUuid(id) && id !in known) Triple(k, id, prefix == IDENTITY) else null
        }.sortedWith(compareBy({ it.third }, { it.first }))
        var removed = 0
        for ((k, _, _) in gone) {
            try {
                state.set(k, null)
            } catch (e: Exception) {
                log.warn(CoreLog.EVENT_ACCOUNT_SWEEP_STOPPED, "the sweep of accounts this device no longer knows stopped: the store refused to remove $k")
                return Outcome.Stopped(k)
            }
            removed++
        }
        return Outcome.Swept(gone.map { it.second }.toSet(), removed)
    }

    /**
     * The accounts this rule knows apart from what an end at [origin] removes, read before anything of the end is removed:
     * the session kept at [origin] (this process's [kept], as (origin, user id), or the secure store's), the copies held
     * at the addresses [heldThere] names, the address record of [address] there ([address] null: every address record
     * there, as "Forget this server" removes them), and what is in flight of an end there. Everything else that makes an
     * account known counts. Where a record cannot be read, every account the device keeps records of by its id is
     * counted (it could be any of them); where the keys cannot be listed, none (the tie itself then keeps everything).
     */
    fun knownApartFrom(
        state: DeviceState, secure: DeviceState, kept: Pair<String, String>?, origin: String, address: String?, heldThere: (String) -> Boolean,
    ): Set<String> {
        val keys = try { state.keys() } catch (e: Exception) { null } ?: return emptySet()
        val seen = try {
            // An address record at [origin] itself that cannot be read is the end's own, as the tie reads it: no account.
            sightings(state, secure, keys, kept?.let { Sighting(it.second, Kind.SESSION, it.first) }) { at -> at == origin }
        } catch (e: Unreadable) {
            return keys.mapNotNull { k ->
                PinStore.ACCOUNT_KEYED.firstOrNull { k.startsWith(it) }?.let { k.removePrefix(it).substringBefore('|') }?.takeIf { TrustGrammar.isUuid(it) }
            }.toSet()
        }
        return seen.filterNot { s ->
            when (s.kind) {
                Kind.SESSION -> s.origin == origin
                Kind.HELD -> s.origin != null && heldThere(s.origin)
                Kind.ADDRESS, Kind.FORGETTING -> s.origin == origin && (address == null || s.address == address)
                Kind.OWN_END, Kind.OUTCOME_UNKNOWN, Kind.DELETION -> s.origin == origin
            }
        }.map { it.id }.toSet()
    }

    private const val IDENTITY = "ovh.identity|"

    private fun heldBack(log: CoreLog, record: String): Outcome {
        log.warn(CoreLog.EVENT_ACCOUNT_SWEEP_HELD_BACK, "the sweep of accounts this device no longer knows removed nothing: $record could not be read")
        return Outcome.HeldBack(record)
    }

    /** What makes an account known. */
    private enum class Kind { SESSION, HELD, ADDRESS, OWN_END, FORGETTING, OUTCOME_UNKNOWN, DELETION }

    /** Account [id] is known by a record of [kind], at [origin] (null: not told), for [address] where the record has one. */
    private class Sighting(val id: String, val kind: Kind, val origin: String?, val address: String? = null)

    /**
     * Every record that makes an account known, with [kept] (this process's session) first; throws [Unreadable], except for
     * an address record at a server [passOver] names, which then names no account.
     */
    private fun sightings(state: DeviceState, secure: DeviceState, keys: Set<String>, kept: Sighting?, passOver: (String) -> Boolean = { false }): List<Sighting> {
        val out = ArrayList<Sighting>()
        kept?.let { out += it }
        fun read(store: DeviceState, key: String): String? = try { store.get(key) } catch (e: Exception) { throw Unreadable(key) }
        fun uuid(id: String?, key: String): String = id?.takeIf { TrustGrammar.isUuid(it) } ?: throw Unreadable(key)
        // The session the secure store holds now; a store that says it holds one it cannot read now names no one it can tell.
        val session = read(secure, SessionKeeper.KEY)
        if ((secure as? SessionRecordReadability)?.sessionRecordUnreadable == true) throw Unreadable(SessionKeeper.KEY)
        session?.let { text ->
            val json = runCatching { WireJson.json.parseToJsonElement(text) }.getOrNull() as? JsonObject
            val id = uuid((json?.get("userId") as? JsonPrimitive)?.takeIf { it.isString }?.content, SessionKeeper.KEY)
            out += Sighting(id, Kind.SESSION, (json?.get("origin") as? JsonPrimitive)?.takeIf { it.isString }?.content)
        }
        // The copies held: `origin|userId` per line, read as the engine reads them.
        read(state, EngineAppApi.HELD_KEY)?.split('\n')?.filter { it.isNotEmpty() }?.forEach { line ->
            val (o, u) = EngineAppApi.heldLine(line) ?: throw Unreadable(EngineAppApi.HELD_KEY)
            out += Sighting(u, Kind.HELD, o)
        }
        // The address records, at every server: `<prefix><origin>|<address>` → `<userId>|<identity key>`.
        for (k in keys) if (k.startsWith(SessionKeeper.EMAIL_BINDING_PREFIX)) {
            val at = k.removePrefix(SessionKeeper.EMAIL_BINDING_PREFIX)
            val server = at.substringBeforeLast('|')
            val v = try { state.get(k) } catch (e: Exception) { if (passOver(server)) continue else throw Unreadable(k) } ?: continue
            val id = v.substringBefore('|').takeIf { TrustGrammar.isUuid(it) } ?: if (passOver(server)) continue else throw Unreadable(k)
            out += Sighting(id, Kind.ADDRESS, server, at.substringAfterLast('|'))
        }
        // The person's own ends not settled: `origin|userId[|why]` per line.
        read(state, SessionKeeper.OWN_ENDS_KEY)?.split('\n')?.filter { it.isNotEmpty() }?.forEach { line ->
            val f = line.split('|')
            out += Sighting(uuid(f.getOrNull(1)?.takeIf { f.size in 2..3 && f.none(String::isEmpty) }, SessionKeeper.OWN_ENDS_KEY), Kind.OWN_END, f[0])
        }
        // The forgettings begun, read as the engine reads them: none of them while one entry does not read.
        read(state, EngineAppApi.FORGETTING_KEY)?.let { text ->
            val all = EngineAppApi.forgettingEntries(text) ?: throw Unreadable(EngineAppApi.FORGETTING_KEY)
            for (m in all) {
                m ?: throw Unreadable(EngineAppApi.FORGETTING_KEY)
                out += Sighting(m.userId, Kind.FORGETTING, m.origin, m.emailNorm)
            }
        }
        // The deletions whose outcome is not known: `<prefix><origin>|<userId>`.
        for (k in keys) if (k.startsWith(EngineAccountSettings.OUTCOME_UNKNOWN_KEY)) {
            val (o, u) = EngineAccountSettings.outcomeUnknownOf(k) ?: throw Unreadable(k)
            out += Sighting(u, Kind.OUTCOME_UNKNOWN, o)
        }
        // The deletions begun and not finished: none of them while one does not read.
        read(state, EngineAccountSettings.DELETION_KEY)?.let { text ->
            val all = EngineAccountSettings.deletionEntries(text) ?: throw Unreadable(EngineAccountSettings.DELETION_KEY)
            for (m in all) {
                m ?: throw Unreadable(EngineAccountSettings.DELETION_KEY)
                out += Sighting(m.userId, Kind.DELETION, m.origin, m.emailNorm)
            }
        }
        return out
    }
}
