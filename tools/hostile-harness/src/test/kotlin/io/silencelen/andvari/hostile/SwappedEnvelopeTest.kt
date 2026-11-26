package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.AccountSession
import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.accept
import io.silencelen.andvari.cli.e2e.connect
import io.silencelen.andvari.cli.e2e.doc
import io.silencelen.andvari.cli.e2e.ok
import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.core.client.log.Adoption
import io.silencelen.andvari.core.client.log.AdoptionRefusal
import io.silencelen.andvari.core.client.log.AppendOutcome
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.log.VaultLogStatus
import io.silencelen.andvari.core.client.onboard.SignIn
import io.silencelen.andvari.core.client.state.AccountStateRead
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.AccountGenesis
import io.silencelen.andvari.core.trust.LogEntry
import io.silencelen.andvari.core.trust.MemberRole
import io.silencelen.andvari.hostile.proxy.Frames
import io.silencelen.andvari.hostile.proxy.arr
import io.silencelen.andvari.hostile.proxy.edit
import io.silencelen.andvari.hostile.proxy.editAnswer
import io.silencelen.andvari.hostile.proxy.editEach
import io.silencelen.andvari.hostile.proxy.fullSyncPage
import io.silencelen.andvari.hostile.proxy.serveVaultRows
import io.silencelen.andvari.hostile.proxy.withRowsFrom
import io.silencelen.andvari.hostile.proxy.withVaultRowsFrom
import io.silencelen.andvari.hostile.proxy.obj
import io.silencelen.andvari.hostile.proxy.remove
import io.silencelen.andvari.hostile.proxy.serveLog
import io.silencelen.andvari.hostile.proxy.set
import io.silencelen.andvari.hostile.proxy.setNull
import io.silencelen.andvari.hostile.proxy.str
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Swapped envelopes and server-chosen values (spec 05 T1: "swap ciphertexts between slots — blocked by AD binding";
 * design G1: "No trust decision rests on a value only the server vouches for"). Everything the server stores for one
 * slot is served in another's place, and every identity value it could choose is chosen by it.
 */
class SwappedEnvelopeTest {
    private val password get() = Steps.PASSWORD.toCharArray()

    /** The `grant` Alice's device posted with her `add` of [member] to [vaultId], as the server recorded it. */
    private fun World.grantOf(vaultId: String, member: String): String = proxy.requests(WireRoute.LOG_APPEND, "alice")
        .filter { it.param("vaultId") == vaultId }
        .last { Frames.statement(it.json!!.str("entry")!!).let { s -> s.str("kind") == "add" && s.str("member") == member } }
        .json!!.str("grant")!!

    /**
     * The device [tag]'s own grant row of [vaultId], changed by [change], in every `/sync` answer: put in when the
     * delta would not carry it (it carries only rows changed since the cursor), so the device is shown the lie.
     */
    private fun World.swapGrantRow(tag: String, vaultId: String, change: (JsonObject) -> JsonObject) =
        proxy.on(WireRoute.SYNC, tag, name = "swapGrantRow $vaultId@$tag") { x ->
            val real = x.forward()
            val full = x.fullSyncPage()
            if (!real.ok || full == null) real
            else real.withJson { body ->
                body.withRowsFrom(full, "grants", { it.str("vaultId") }, { it.str("vaultId") == vaultId })
                    .editEach("grants") { g -> if (g.str("vaultId") == vaultId) change(g) else g }
            }
        }

    /**
     * §3.5: a grant is refused unless it is addressed to this account (`misaddressed`, or `unopenable` when sealed to
     * another key), names the row's vault (`vault_mismatch`) and is bound to this account's LATEST `add` (`no_add_entry`:
     * "Otherwise a server could put an old grant back on the row and the accept prompt would name whoever owned the
     * vault at the earlier `add`"). A refused grant never becomes a prompt, and nothing is decrypted.
     */
    @Test fun aGrantFromAnotherVaultForAnotherAccountOrOfAnEarlierAddIsRefusedAndNeverBecomesAPrompt() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val ch = member("carol")
        val a = account(ah)
        val b = account(bh)
        val c = account(ch)
        connect(ah, bh, origin)
        connect(ah, ch, origin)
        a.synced()
        val one = a.ok(null, LogAction.Create("One"))
        val two = a.ok(null, LogAction.Create("Two"))
        a.ok(one, LogAction.Add(b.userId, "writer"))
        val earlier = grantOf(one, b.userId)
        a.ok(one, LogAction.Remove(b.userId))
        a.ok(one, LogAction.Add(b.userId, "writer")) // the add that counts
        a.ok(two, LogAction.Add(b.userId, "writer"))
        a.ok(one, LogAction.Add(c.userId, "reader"))

        val swaps = listOf(
            "the grant of another vault" to grantOf(two, b.userId),
            "the grant made for another member" to grantOf(one, c.userId),
            "the grant of an earlier add of this account" to earlier,
        )
        for ((what, grant) in swaps) {
            val rule = swapGrantRow("bob", one) { it.set("signedGrant", grant) }
            b.synced()
            assertEquals(grant, b.grant(one)?.signedGrant, "$what: the device was served the swapped row")
            assertEquals(Adoption.Refused(one, AdoptionRefusal.GRANT_REFUSED), b.logs.adoption(one), what)
            assertNull(b.logs.keyFor(one), "$what: no key is in use")
            rule.remove()
        }
        // The genuine row, served again: the person is asked, naming the owner, and only then is the key used.
        proxy.serveVaultRows("bob", one)
        b.synced()
        val ask = assertIs<Adoption.AskAccept>(b.logs.adoption(one))
        assertEquals(a.userId, ask.owner)
        assertEquals("One", ask.vaultName)
    }

    /**
     * §3.6 (d), §2.3 (T-B3): an account's own wrap opens only "with the AD that names this log's genesis hash". The wrap
     * of another vault, or another account's wrap of the same vault, served on a fresh device of the account opens
     * nothing: the vault is not adopted through it.
     */
    @Test fun aWrappedVaultKeyOfAnotherVaultOrAnotherAccountOpensNothingOnAFreshDevice() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val ch = member("carol")
        val a = account(ah)
        val b = account(bh)
        val c = account(ch)
        val one = sharedVault(ah, bh, "One")
        val two = a.ok(null, LogAction.Create("Two"))
        a.ok(two, LogAction.Add(b.userId, "writer"))
        accept(b, two, "Two")
        connect(ah, ch, origin)
        a.ok(one, LogAction.Add(c.userId, "writer"))
        accept(c, one, "One")
        // What the server holds: each member's own wrap of each vault, posted by their devices.
        fun wrap(tag: String, vaultId: String) = proxy.requests(WireRoute.VAULT_SELF_WRAP, tag).last { it.param("vaultId") == vaultId }.json!!.str("wrappedVk")!!
        val bobsTwo = wrap("bob", two)
        val carolsOne = wrap("carol", one)

        for ((i, case) in listOf("the account's wrap of another vault" to bobsTwo, "another account's wrap of this vault" to carolsOne).withIndex()) {
            val (what, served) = case
            val tag = "bob-fresh$i"
            // The row carries only the swapped wrap: the grant is gone, as it is once a server decides to drop it.
            swapGrantRow(tag, one) { it.set("wrappedVk", served).setNull("signedGrant") }
            val fresh = account(passwordDevice(tag, "bob@example.org"))
            assertIs<AccountStateRead.Ok>(fresh.store.read())
            fresh.synced()
            assertIs<VaultLogStatus.Verified>(fresh.logs.status(one), "the log itself is genuine")
            val adoption = fresh.logs.adoption(one)
            assertFalse(adoption is Adoption.Adopted || adoption is Adoption.AskAccept, "$what: $adoption")
            assertNull(fresh.logs.keyFor(one), "$what: no key is in use")
            assertFalse(fresh.writeAllowed(one))
        }
        // The genuine row on a fresh device adopts through the account's own wrap.
        val honest = account(passwordDevice("bob-honest", "bob@example.org"))
        assertIs<AccountStateRead.Ok>(honest.store.read())
        honest.synced()
        assertIs<Adoption.Adopted>(honest.logs.adoption(one))
    }

    private fun names(s: AccountSession, v: String) = s.items(v).map { it.doc["name"]!!.jsonPrimitive.content }.toSet()

    /**
     * Spec 05 T1: "swap ciphertexts between slots — blocked by AD binding". An item blob served under another item's id,
     * or in another vault, and a vault's name served on another vault, open nowhere: nothing is shown in the wrong place.
     */
    @Test fun anItemBlobOrVaultNameServedInAnotherSlotIsNeverShownThere() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val a = account(ah)
        val b = account(bh)
        val one = sharedVault(ah, bh, "One")
        val two = a.ok(null, LogAction.Create("Two"))
        a.ok(two, LogAction.Add(b.userId, "writer"))
        accept(b, two, "Two")
        a.synced()
        for (n in listOf("first", "second")) assertEquals(null, a.putItem(one, doc(n)).second)
        assertEquals(null, a.putItem(two, doc("other vault")).second)
        b.synced()
        assertEquals(setOf("first", "second"), names(b, one))
        assertEquals("One", b.vaultName(one))
        val genuine = b.items(one).associate { it.itemId to it.doc["name"]!!.jsonPrimitive.content }

        // The device's cursor is past every row now, so an honest delta carries none: the server puts the rows it
        // lies about into the page (their revs unchanged), as it would to make the device take them.
        fun rows(body: JsonObject, key: String) = body.arr(key)!!.map { it as JsonObject }
        var swapped = 0

        // Within one vault: each item's blob under the other's id.
        var rule = proxy.on(WireRoute.SYNC, "bob", name = "swap blobs within $one") { x ->
            val full = assertNotNull(x.fullSyncPage())
            x.forward().withJson { delta ->
                val body = delta.withVaultRowsFrom(full, one, items = true)
                val blobs = rows(body, "items").filter { it.str("vaultId") == one }.map { it.str("blob")!! }
                var i = 0
                body.editEach("items") { item -> if (item.str("vaultId") == one) item.set("blob", blobs[blobs.size - 1 - i++]).also { swapped++ } else item }
            }
        }
        b.synced()
        assertEquals(2, swapped, "both of the vault's item rows reached the device with the other's blob")
        assertTrue(names(b, one).isEmpty(), "a blob under another item's id opens nowhere: ${names(b, one)}")
        rule.remove()

        // Across vaults: the other vault's item blob in this vault's slots, and the other vault's name on this vault.
        swapped = 0
        rule = proxy.on(WireRoute.SYNC, "bob", name = "swap blobs and name across vaults") { x ->
            val full = assertNotNull(x.fullSyncPage())
            val foreign = rows(full, "items").first { it.str("vaultId") == two }.str("blob")!!
            val otherName = rows(full, "vaults").first { it.str("vaultId") == two }.str("metaBlob")!!
            x.forward().withJson { delta ->
                delta.withVaultRowsFrom(full, one, items = true)
                    .editEach("items") { item -> if (item.str("vaultId") == one) item.set("blob", foreign).also { swapped++ } else item }
                    .editEach("vaults") { v -> if (v.str("vaultId") == one) v.set("metaBlob", otherName).also { swapped++ } else v }
            }
        }
        b.synced()
        assertEquals(3, swapped, "both item rows and the vault row reached the device with the other vault's ciphertext")
        assertTrue(names(b, one).isEmpty(), "another vault's item opens nowhere here: ${names(b, one)}")
        // A name that does not open under this vault's key is shown as the engine's placeholder, never as what it says.
        assertEquals("Shared", b.vaultName(one), "another vault's name is not shown on this vault")
        rule.remove()

        // Served the genuine rows again, each item opens under its own id, and nowhere else.
        proxy.serveVaultRows("bob", one, items = true)
        b.synced()
        assertEquals(genuine, b.items(one).associate { it.itemId to it.doc["name"]!!.jsonPrimitive.content })
        assertEquals("One", b.vaultName(one))
    }

    /**
     * §3.3, §3.9, design G2: "Only a vault's owner can change who holds that vault's key … an M+T1 coalition can forge
     * none of them." A grant row's role is the server's word and decides nothing; and an entry a member signs with its
     * own key that the log does not authorise is `not_authorized` for every other member, whatever the server stores.
     */
    @Test fun aRoleTheServerReportsOrAnEntryAColludingMemberSignsNeverChangesWhoOwnsOrHoldsAVault() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val ch = member("carol")
        val a = account(ah)
        val b = account(bh)
        val c = account(ch)
        val v = sharedVault(ah, bh, role = "reader")
        connect(ah, ch, origin)
        a.ok(v, LogAction.Add(c.userId, "writer")) // seq 2
        accept(c, v)

        // The server tells Bob's device he owns the vault.
        val lie = swapGrantRow("bob", v) { it.set("role", "owner") }
        b.synced()
        val state = assertIs<VaultLogStatus.Verified>(b.logs.status(v)).state
        assertEquals(a.userId, state.owner, "the owner is who the log says")
        assertEquals("reader", state.members.getValue(b.userId).role)
        val mark = proxy.mark()
        assertEquals(AppendOutcome.NotAllowed("not_authorized"), b.logs.append(v, LogAction.Remove(c.userId)), "the engine signs nothing its own verified log does not allow")
        assertTrue(sent(bh, WireRoute.LOG_APPEND, mark).isEmpty())
        lie.remove()

        // Bob, working with the server, signs the removal anyway with his own key; the server serves it to Carol.
        val head = assertIs<VaultLogStatus.Verified>(c.logs.status(v)).state
        val forged = Adversary.signEntry(bh, origin, LogEntry.Remove(v, head.headSeq + 1, head.headHash, b.userId, server.now(), c.userId))
        val serving = proxy.serveLog("carol", v) { genuine -> genuine + forged }
        c.synced()
        val failed = assertIs<VaultLogStatus.Failed>(c.logs.status(v), "a member's signature on an owner's entry fails the log: ${c.logs.status(v)}")
        assertEquals("not_authorized", failed.verdict)
        assertEquals(head, failed.lastGood, "Carol is still a member of the last good state")
        // The same for an add that would let an outsider in.
        serving.remove()
        val grantId = Bytes.toB64(ByteArray(16) { 5 })
        val added = Adversary.signEntry(bh, origin, LogEntry.Add(v, head.headSeq + 1, head.headHash, b.userId, server.now(), "9f0c8e6a-1b2d-4c3e-8f4a-5b6c7d8e9f01", state.ownerKey, MemberRole.WRITER, grantId))
        proxy.serveLog("carol", v) { genuine -> genuine + added }
        c.logs.refresh(v, null, null, force = true)
        assertEquals("not_authorized", assertIs<VaultLogStatus.Failed>(c.logs.status(v)).verdict)
        assertEquals(head.members.keys, assertIs<VaultLogStatus.Failed>(c.logs.status(v)).lastGood!!.members.keys, "nobody was let in")
    }

    /**
     * §5.2, §5.3, §2.4 "Account genesis": at every unlock the genesis must be signed by the seed-derived key and name
     * this account, this instance and the served personal wrap's vault. The server choosing any of them is the identity
     * fault, and no session is opened; a withheld or unopenable personal wrap is only "no personal vault".
     */
    @Test fun aSubstitutedIdentityKeyGenesisOrPersonalWrapIsTheIdentityFaultAtSignIn() = world {
        operator()
        val ah = member("alice")
        member("bob")
        val alices = proxy.last(WireRoute.REGISTER, "alice")!!.upstream!!.json!!.obj("accountKeys")!!
        val bobs = proxy.last(WireRoute.REGISTER, "bob")!!.upstream!!.json!!.obj("accountKeys")!!
        // What only Alice's own key could sign: her genesis for another instance, and for another user id.
        val signing = ah.session(origin)!!.session.account.signing
        val fields = ah.session(origin)!!.session.account.genesis.fields
        val otherInstance = Bytes.toB64(signing.use { AccountGenesis.sign(ah.crypto, it, fields.copy(instanceId = "0b6d7c1e-52aa-4f0e-9d3b-7a1c2e3f4a5b")) })
        val otherUser = Bytes.toB64(signing.use { AccountGenesis.sign(ah.crypto, it, fields.copy(userId = "0b6d7c1e-52aa-4f0e-9d3b-7a1c2e3f4a5c")) })

        val faults: List<Triple<String, String, (JsonObject) -> JsonObject>> = listOf(
            Triple("another account's identity key", "identity_mismatch", { k -> k.set("identityPub", bobs.str("identityPub")!!) }),
            Triple("another account's genesis", "signer_not_pinned_key", { k -> k.set("genesis", bobs.str("genesis")!!) }),
            Triple("no genesis", "no_genesis", { k -> k.setNull("genesis") }),
            Triple("a genesis nobody signed", "bad_signature", { k -> k.set("genesis", Frames.withBrokenSignature(alices.str("genesis")!!)) }),
            Triple("the account's genesis for another instance", "instance_mismatch", { k -> k.set("genesis", otherInstance) }),
            Triple("the account's genesis for another user id", "user_mismatch", { k -> k.set("genesis", otherUser) }),
            Triple("another account's personal wrap", "personal_vault_mismatch", { k -> k.set("personalWrap", bobs.obj("personalWrap")!!) }),
            Triple("a personal wrap naming another vault", "personal_vault_mismatch", { k -> k.edit("personalWrap") { it.set("vaultId", bobs.obj("personalWrap")!!.str("vaultId")!!) } }),
        )
        // Each lie meets a device of its own (the server limits prelogins per address).
        for ((i, fault) in faults.withIndex()) {
            val (what, verdict, change) = fault
            val d = pinnedDevice("fault$i")
            proxy.on(WireRoute.LOGIN, "fault$i", handler = editAnswer { it.edit("accountKeys", change) })
            assertEquals(SignIn.IdentityFault(verdict), d.onboarding(origin).signIn("alice@example.org", password), what)
            assertNull(d.session(origin), "$what: no session is opened")
        }
        // Not identity faults: the wrap withheld, or the right vault's wrap replaced by one that does not open.
        val anomalies = listOf<Pair<String, (JsonObject) -> JsonObject>>(
            "the personal wrap withheld" to { k -> k.setNull("personalWrap") },
            "another account's key under the right vault id" to { k -> k.edit("personalWrap") { it.set("wrappedVk", bobs.obj("personalWrap")!!.str("wrappedVk")!!) } },
        )
        for ((i, anomaly) in anomalies.withIndex()) {
            val d = pinnedDevice("anomaly$i")
            proxy.on(WireRoute.LOGIN, "anomaly$i", handler = editAnswer { it.edit("accountKeys", anomaly.second) })
            val signedIn = d.onboarding(origin).signIn("alice@example.org", password)
            assertIs<SignIn.SignedIn>(signedIn, "${anomaly.first}: $signedIn")
            assertNull(account(d).personalVaultId, "${anomaly.first}: no personal vault is in force, and nothing else is used in its place")
        }
        assertEquals(fields.personalVaultId, account(passwordDevice("honest", "alice@example.org")).personalVaultId)
    }
}
