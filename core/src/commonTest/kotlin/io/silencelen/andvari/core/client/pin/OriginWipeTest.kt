package io.silencelen.andvari.core.client.pin

import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull

/**
 * "Forget this server" in full ([CardTrust.forgetServer], [PinStore.wipeOrigin]): the pin, every per-origin record and
 * the records of the accounts kept under the origin go, their identity records among them; another origin and another
 * account stay.
 * It works under a fork, a damaged pin and with no session, and nothing is dialed.
 */
class OriginWipeTest {
    private val home = "https://home.example"
    private val other = "https://other.example"
    private val alice = "22222222-2222-4222-8222-222222222222"
    private val kept = "33333333-3333-4333-8333-333333333333"
    private val bob = "44444444-4444-4444-8444-444444444444"

    private fun pin(o: String = home) = CardPin("0b6f3c2e-4d5a-4b7c-8d9e-0f1a2b3c4d5e", 1, "a".repeat(64), o, "Home", "private",
        "1c7f4d3e-5e6b-4c8d-9e0f-1a2b3c4d5e6f", "A".repeat(43), "none", PinRoot.TRUST_GATE, null, "b".repeat(64))

    private fun trust(state: DeviceState) = CardTrust(PinStore(state), { _, _ -> error("no chain is verified") },
        { o -> error("nothing is dialed: $o") }, createCryptoProvider(), null, false)

    /** Records for [home] (alice found through them, [kept] only through the caller), [other] and bob. */
    private fun seeded(state: MemoryDeviceState): Map<String, Boolean> {
        val gone = listOf(
            "ovh.links|$home|$alice", "ovh.links.dropped|$home|$alice", "ovh.codes|$home|$alice", "ovh.current|$home|$alice",
            "ovh.onetap|$home|$alice", "ovh.bundlevaults|$home|$alice", "ovh.setup|$home", "ovh.assist|$home", "ovh.dev|$home|a@x.example",
            "ovh.notused|$home|$alice", "ovh.quick.offer|$home|$alice", "ovhtest.wiped|$home|$alice",
            "ovh.acct|$alice|sealed", "ovh.acct|$alice|hw", "ovh.log|$alice|v1|hashes", "ovh.log|$alice|pending-index", "ovh.rmirror|$alice",
            "ovh.escrowfp|$alice", "ovh.items|$alice|lost", "ovh.acct|$kept|sealed", "ovh.log|$kept|v1|state",
            // The accounts there: their identity records go with the server (no address at another server names them).
            "ovh.identity|$alice", "ovh.identity|$kept",
        )
        val stay = listOf(
            "ovh.identity|$bob", "ovh.links|$other|$bob", "ovh.dev|$other|b@x.example", "ovh.acct|$bob|sealed",
            "ovh.log|$bob|v1|hashes", "ovh.dev|$home.evil|a@x.example", "ovh.session",
        )
        (gone + stay).forEach { state.set(it, "v") }
        return gone.associateWith { false } + stay.associateWith { true }
    }

    private fun assertWiped(state: MemoryDeviceState, expect: Map<String, Boolean>) {
        for ((k, stays) in expect) if (stays) assertEquals("v", state.get(k), "$k stays") else assertNull(state.get(k), "$k is deleted")
    }

    @Test fun forgetTheServerRemovesThePinItsRecordsAndItsAccountsRecordsUnderAForkOrADamagedPin() {
        PinStore.carryWithMoves("ovhtest.wiped|")
        for (how in listOf("forked", "damaged", "in force", "none")) {
            val state = MemoryDeviceState()
            val store = PinStore(state)
            store.put(pin())
            store.put(pin(other))
            when (how) {
                "forked" -> store.markForked(pin())
                "damaged" -> state.set(PinStore.KEY_PREFIX + home, "{damaged")
                "none" -> store.remove(home)
            }
            state.set(PinStore.MOVE_PREFIX + home, "{not a mark")
            val expect = seeded(state)
            val t = trust(state)
            assertEquals(ServerForgotten.Done, t.forgetServer(home, listOf(kept)), how)
            assertEquals(PinState.None, t.pinState(home), how)
            assertEquals(OriginAccess.OPEN, t.access(home), "$how: the move mark went with it")
            assertIs<PinState.Pinned>(t.pinState(other), "$how: another origin is untouched")
            assertEquals(listOf(other), store.origins())
            assertWiped(state, expect)
        }
    }

    /**
     * A followed move carries the session keeper's records of which account an address is, as it carries the server's
     * other records: under the new address they still hold the address to its account. The record of each account's
     * identity key is kept by account and stays in force. Before, the address's record stayed under the old address, and
     * the new address held none.
     */
    @Test fun aFollowedMoveCarriesTheAddressRecordsAndLeavesTheIdentityRecordInForce() {
        val state = MemoryDeviceState()
        val store = PinStore(state)
        val moved = "https://moved.example"
        store.put(pin())
        val prefix = io.silencelen.andvari.core.client.session.SessionKeeper.EMAIL_BINDING_PREFIX
        val earlier = io.silencelen.andvari.core.client.session.SessionKeeper.EARLIER_IDENTITY_PREFIX
        // As the keeper registers it at its start.
        PinStore.carryWithMoves(earlier)
        state.set("$prefix$home|a@x.example", "$alice|key")
        state.set("ovh.identity|$alice", "key")
        state.set("$earlier$home|$kept", "key of the earlier account")
        state.set("ovh.links|$home|$alice", "v")
        assertEquals(PinStore.MoveOutcome.MOVED, store.move(pin(), pin(moved)))
        assertNull(state.get("$prefix$home|a@x.example"), "nothing of the server stays under the old address")
        assertEquals("$alice|key", state.get("$prefix$moved|a@x.example"), "the address's record is carried")
        assertEquals("key of the earlier account", state.get("$earlier$moved|$kept"), "the record a forgetting keeps is carried")
        assertEquals("key", state.get("ovh.identity|$alice"), "the identity record stays in force")
        assertEquals("v", state.get("ovh.links|$moved|$alice"))
    }

    private val addressPrefix = io.silencelen.andvari.core.client.session.SessionKeeper.EMAIL_BINDING_PREFIX
    private val earlierPrefix = io.silencelen.andvari.core.client.session.SessionKeeper.EARLIER_IDENTITY_PREFIX

    /** [home] pinned, with an address record there naming [alice] and records of [home] that always go; [other] pinned. */
    private fun parked(state: DeviceState): List<String> {
        val store = PinStore(state)
        store.put(pin())
        store.put(pin(other))
        state.set("$addressPrefix$home|a@x.example", "$alice|key")
        state.set("ovh.identity|$alice", "key")
        val gone = listOf("$addressPrefix$home|a@x.example", "ovh.links|$home|$alice", "ovh.dev|$home|a@x.example", "ovh.setup|$home")
        gone.drop(1).forEach { state.set(it, "v") }
        return gone
    }

    /**
     * The check's p2: an older build followed a move from [home] to [other] and left the address record under [home], while
     * the account lives at [other] (its records there, no address record there). Another server's move to [home] is refused
     * for that record, and the person forgets the server at [home]: the identity record of the account at [other] stays,
     * and everything of [home] still goes.
     */
    @Test fun anAddressRecordParkedUnderAnOldAddressDoesNotTakeTheIdentityOfAnAccountThatLivesElsewhere() {
        PinStore.carryWithMoves(earlierPrefix)
        val state = MemoryDeviceState()
        val gone = parked(state)
        val there = listOf("ovh.links|$other|$alice", "ovh.current|$other|$alice", "ovh.dev|$other|a@x.example")
        there.forEach { state.set(it, "v") }
        assertEquals(ServerForgotten.Done, trust(state).forgetServer(home))
        assertEquals("key", state.get("ovh.identity|$alice"), "the account at the new address keeps its identity record")
        for (k in gone) assertNull(state.get(k), "$k goes")
        assertEquals(PinState.None, PinStore(state).state(home))
        for (k in there) assertEquals("v", state.get(k), "$k stays")
        assertIs<PinState.Pinned>(PinStore(state).state(other))
    }

    /**
     * Each tie at another origin, alone, keeps the identity record of the account an address's record at the forgotten
     * origin names, and everything of that origin still goes; with none of them, the identity record goes. Records there
     * for the same address tie unless that origin's address record for it names ANOTHER account: then the address there is
     * someone else's (the same email address used for another account at an unrelated server), and they do not.
     */
    @Test fun eachTieAtAnotherOriginAloneKeepsTheIdentityRecord() {
        PinStore.carryWithMoves(earlierPrefix)
        val sameAddressThere = "$addressPrefix$other|a@x.example"
        // What is written at the other origin, and whether it ties the account.
        val cases = listOf(
            Triple("an address record there naming the account", mapOf("$addressPrefix$other|b@x.example" to "$alice|key"), true),
            Triple("a record there keyed by the account's id", mapOf("ovh.links|$other|$alice" to "v"), true),
            Triple("the key a forgetting kept there of the account", mapOf("$earlierPrefix$other|$alice" to "key"), true),
            Triple("a device's record there of the same address", mapOf("ovh.dev|$other|a@x.example" to """{"deviceSecret":"BwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSY","deviceId":"55555555-5555-4555-8555-555555555555"}"""), true),
            Triple("a device's record there of the same address holding no device id (only an attempt was made there)",
                mapOf("ovh.dev|$other|a@x.example" to """{"deviceSecret":"BwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSY"}"""), false),
            Triple("a device's record there of the same address that cannot be read as one", mapOf("ovh.dev|$other|a@x.example" to "{damaged"), true),
            Triple("an address record there of the same address, naming the same account", mapOf(sameAddressThere to "$alice|key"), true),
            Triple("an address record there of the same address, naming no account it can tell", mapOf(sameAddressThere to "not an id"), true),
            Triple("an address record there of the same address, naming another account", mapOf(sameAddressThere to "$bob|key2"), false),
            Triple("a device's record there of the same address, whose record there names another account",
                mapOf("ovh.dev|$other|a@x.example" to """{"deviceSecret":"BwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSY","deviceId":"55555555-5555-4555-8555-555555555555"}""", sameAddressThere to "$bob|key2"), false),
            Triple("a record there keyed by the account's id, beside an address record there naming another account",
                mapOf("ovh.links|$other|$alice" to "v", sameAddressThere to "$bob|key2"), true),
            Triple("none", emptyMap(), false),
        )
        for ((what, there, ties) in cases) {
            val state = MemoryDeviceState()
            val gone = parked(state)
            there.forEach { (k, v) -> state.set(k, v) }
            assertEquals(ServerForgotten.Done, trust(state).forgetServer(home), what)
            if (!ties) assertNull(state.get("ovh.identity|$alice"), "$what: nothing ties it elsewhere, so it goes")
            else assertEquals("key", state.get("ovh.identity|$alice"), "$what: the identity record stays")
            for (k in gone) assertNull(state.get(k), "$what: $k goes")
            there.forEach { (k, v) -> assertEquals(v, state.get(k), "$what: the record at the other origin stays") }
            assertEquals(PinState.None, PinStore(state).state(home), what)
        }
    }

    /**
     * The check's p3: an address record that cannot be read, at another origin or at the forgotten one, does not stop the
     * forgetting. It names every account: every identity record stays, everything else of the server goes, the pin goes,
     * and the answer says that it was done in part.
     */
    @Test fun anAddressRecordThatCannotBeReadKeepsEveryIdentityRecordAndTheRestGoes() {
        for (where in listOf(other, home)) {
            val inner = MemoryDeviceState()
            val damaged = "$addressPrefix$where|c@x.example"
            val state = object : DeviceState {
                override fun get(key: String) = if (key == damaged) error("cannot read") else inner.get(key)
                override fun set(key: String, value: String?) = inner.set(key, value)
                override fun keys() = inner.keys()
            }
            val gone = parked(state)
            inner.set(damaged, "$bob|key")
            inner.set("ovh.identity|$bob", "key")
            inner.set("ovh.acct|$alice|sealed", "v")
            assertEquals(ServerForgotten.Partly(ServerForgotten.CANNOT_READ), trust(state).forgetServer(home), where)
            assertEquals("key", inner.get("ovh.identity|$alice"), "$where: every identity record stays")
            assertEquals("key", inner.get("ovh.identity|$bob"), "$where: every identity record stays")
            for (k in gone) assertNull(inner.get(k), "$where: $k goes")
            // Kept by the account's id alone: an unreadable record at another origin may name it there, so it stays.
            if (where == other) assertEquals("v", inner.get("ovh.acct|$alice|sealed"), "$where: what another server may serve stays")
            else assertNull(inner.get("ovh.acct|$alice|sealed"), "$where: the account's other records go")
            assertEquals(PinState.None, PinStore(state).state(home), where)
            assertIs<PinState.Pinned>(PinStore(state).state(other), where)
        }
    }

    /**
     * The check's p1: one account id known at two addresses (a server that moved and whose move was not followed, or a
     * server that serves a copy of another's accounts): each address has a record naming it. "Forget this server" at the
     * first keeps everything kept by the account's id alone (the account state with its marks against an older state, the
     * vault logs' hashes and checkpoints, the item engine's records, the recovery mirror, the escrow mark) and its identity
     * record, so the second's next read is no first sight; everything of the first server still goes. With nothing at the
     * second, those records go as before.
     */
    @Test fun oneAccountIdAtTwoAddressesKeepsWhatIsKeptByItsIdAloneAtTheFirstsForgetting() {
        val byId = listOf("ovh.acct|$alice|sealed", "ovh.acct|$alice|hw", "ovh.log|$alice|v1|hashes", "ovh.log|$alice|v1|checkpoint",
            "ovh.items|$alice|x", "ovh.rmirror|$alice", "ovh.escrowfp|$alice")
        for (twice in listOf(true, false)) {
            val state = MemoryDeviceState()
            val gone = parked(state)
            byId.forEach { state.set(it, "v") }
            if (twice) state.set("$addressPrefix$other|a@x.example", "$alice|key")
            assertEquals(ServerForgotten.Done, trust(state).forgetServer(home), "twice: $twice")
            for (k in gone) assertNull(state.get(k), "twice: $twice: $k goes")
            assertEquals(PinState.None, PinStore(state).state(home))
            if (twice) {
                for (k in byId) assertEquals("v", state.get(k), "$k stays: the other address serves that account")
                assertEquals("key", state.get("ovh.identity|$alice"))
                assertEquals("$alice|key", state.get("$addressPrefix$other|a@x.example"))
            } else {
                for (k in byId) assertNull(state.get(k), "$k goes: nothing else serves that account")
                assertNull(state.get("ovh.identity|$alice"))
            }
        }
    }

    @Test fun aStoreThatCannotListItsRecordsStillLosesThePinAndSaysSo() {
        val inner = MemoryDeviceState()
        val unlisted = object : DeviceState {
            override fun get(key: String) = inner.get(key)
            override fun set(key: String, value: String?) = inner.set(key, value)
        }
        PinStore(unlisted).put(pin())
        inner.set("ovh.links|$home|$alice", "v")
        assertEquals(ServerForgotten.Partly(ServerForgotten.CANNOT_LIST), trust(unlisted).forgetServer(home))
        assertEquals(PinState.None, PinStore(unlisted).state(home))
        assertEquals("v", inner.get("ovh.links|$home|$alice"), "what it cannot list it cannot delete; it is read under no pin")
    }

    @Test fun aRecordThatCannotBeDeletedIsReportedAndTheRestGoes() {
        val inner = MemoryDeviceState()
        val stuck = "ovh.codes|$home|$alice"
        val state = object : DeviceState {
            override fun get(key: String) = inner.get(key)
            override fun set(key: String, value: String?) { if (key == stuck) error("locked"); inner.set(key, value) }
            override fun keys() = inner.keys()
        }
        PinStore(state).put(pin())
        inner.set(stuck, "v")
        inner.set("ovh.links|$home|$alice", "v")
        inner.set("ovh.acct|$alice|sealed", "v")
        assertEquals(ServerForgotten.Partly(ServerForgotten.CANNOT_DELETE), trust(state).forgetServer(home))
        assertEquals(PinState.None, PinStore(state).state(home))
        assertNull(inner.get("ovh.links|$home|$alice"))
        assertNull(inner.get("ovh.acct|$alice|sealed"))
        assertEquals("v", inner.get(stuck))
    }
}
