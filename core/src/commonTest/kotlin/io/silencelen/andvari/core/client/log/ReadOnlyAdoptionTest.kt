package io.silencelen.andvari.core.client.log

import io.silencelen.andvari.core.client.state.AcceptedRecord
import io.silencelen.andvari.core.client.state.VaultRecord
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.readVector
import io.silencelen.andvari.core.trust.AddRecord
import io.silencelen.andvari.core.trust.KnownHashes
import io.silencelen.andvari.core.trust.OpenedGrant
import io.silencelen.andvari.core.trust.VaultLog
import io.silencelen.andvari.core.trust.VaultState
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Design §3.6 (e) as decided on 23 November 2026: a record ahead of the served chain (the log withheld) or beside it (the
 * log frozen after the genesis) gives the key read-only when every other condition holds; in every other way (e) fails,
 * and whenever another condition fails, nothing is taken. Graded on every `adopt` row of `spec/test-vectors/wrapad.json`
 * whose log verifies, with the row's own record replaced by one the case chooses.
 */
class ReadOnlyAdoptionTest {
    private val crypto = createCryptoProvider()

    private fun JsonObject.s(k: String) = getValue(k).jsonPrimitive.content

    private class Row(
        val name: String, val me: String, val uvk: ByteArray, val state: VaultState, val served: List<String>,
        val wrap: String, val accepted: AcceptedRecord?, val vaultId: String,
    )

    private fun rows(): List<Row> {
        val doc = Json.parseToJsonElement(readVector("wrapad.json")).jsonObject
        val vaultId = doc.s("vaultId")
        val accounts = doc.getValue("accounts").jsonObject
        val logs = doc.getValue("logs").jsonObject
        return doc.getValue("adopt").jsonArray.map { it.jsonObject }.mapNotNull { row ->
            val frames = (row["frames"] ?: logs.getValue(row.s("log")).jsonObject.getValue("frames")).jsonArray.map { Bytes.fromB64(it.jsonPrimitive.content) }
            val replay = VaultLog.replay(crypto, vaultId, frames, from = null, known = KnownHashes.NONE_HELD)
            val state = (if (replay.verdict == null) replay.state else null) ?: return@mapNotNull null
            val acc = row.getValue("accountState").jsonObject["accepted"]?.jsonObject?.get(vaultId)?.jsonObject
                ?.let { AcceptedRecord(vaultId, it.s("owner"), it.s("addSeq").toLong(), it.s("at").toLong(), it.s("decision")) }
            Row(row.s("name"), accounts.getValue(row.s("me")).jsonObject.s("userId"), Bytes.fromB64(row.s("uvkB64")), state,
                AdoptionRules.hashes(crypto, frames), row.s("wrappedVkB64"), acc, vaultId)
        }
    }

    private fun view(s: VaultState) = VerifiedVaultState(s.vaultId, s.head.seq, s.head.hash, s.at, s.genesisHash, s.owner, s.ownerKey, s.vkCommit, emptyMap(), null, null)

    private fun withheld(s: VaultState) = VaultLogStatus.Withheld(s.vaultId, view(s), s.head.seq)
    private fun frozen(s: VaultState, at: Long) = VaultLogStatus.Frozen(s.vaultId, view(s), at)
    private fun verified(s: VaultState) = VaultLogStatus.Verified(s.vaultId, view(s), false)

    private val otherHash = "ab".repeat(32)

    /** The record one place above the served head, naming the served chain's genesis. */
    private fun ahead(r: Row) = VaultRecord(r.vaultId, r.state.genesisHash, r.state.head.seq + 1, otherHash)

    private fun check(r: Row, record: VaultRecord?, log: VaultLogStatus?, served: List<String> = r.served) =
        AdoptionRules.checkWrap(crypto, r.me, r.uvk, r.state, served, r.wrap, record, r.accepted, log)

    /** The conditions other than (e) that fail for the row, judged with no record. */
    private fun others(r: Row): Set<AdoptCondition> = when (val c = check(r, null, null)) {
        is AdoptCheck.Adopt -> emptySet<AdoptCondition>().also { c.vk.fill(0) }
        is AdoptCheck.Refuse -> c.failed
    }

    private fun assertRefusedWithRecord(r: Row, got: AdoptCheck, case: String) {
        val refused = assertIs<AdoptCheck.Refuse>(got, "${r.name}: $case")
        assertEquals(others(r) + AdoptCondition.RECORD, refused.failed, "${r.name}: $case")
    }

    @Test fun aRecordAheadOfAWithheldLogGivesTheKeyReadOnlyOnlyWhenEveryOtherConditionHolds() {
        val all = rows()
        assertTrue(all.any { others(it).isEmpty() } && all.any { others(it).isNotEmpty() }, "the vectors hold rows of both kinds")
        for (r in all) {
            val got = check(r, ahead(r), withheld(r.state))
            if (others(r).isEmpty()) {
                val ok = assertIs<AdoptCheck.Adopt>(got, "${r.name}: every other condition holds")
                assertEquals(RecordStanding.AHEAD, ok.readOnly, r.name)
                ok.vk.fill(0)
            } else {
                assertRefusedWithRecord(r, got, "another condition fails although the record is ahead")
            }
        }
    }

    @Test fun aRecordBesideAFrozenLogGivesTheKeyReadOnlyOnlyWhenEveryOtherConditionHolds() {
        for (r in rows()) {
            val got = check(r, ahead(r), frozen(r.state, r.state.head.seq + 1))
            if (others(r).isEmpty()) {
                assertEquals(RecordStanding.FORK, assertIs<AdoptCheck.Adopt>(got, r.name).also { it.vk.fill(0) }.readOnly, r.name)
            } else {
                assertRefusedWithRecord(r, got, "another condition fails although the log is frozen")
            }
        }
    }

    @Test fun everyOtherWayTheRecordCanFailStillRefuses() {
        for (r in rows()) {
            val st = r.state
            // The log is not withheld or frozen (a verified log, or no status given): as before.
            assertRefusedWithRecord(r, check(r, ahead(r), verified(st)), "a verified log")
            assertRefusedWithRecord(r, check(r, ahead(r), null), "no status")
            // Another beginning: the record names another genesis.
            val otherGenesis = VaultRecord(r.vaultId, otherHash, st.head.seq + 1, otherHash)
            assertRefusedWithRecord(r, check(r, otherGenesis, withheld(st)), "the record names another genesis")
            assertRefusedWithRecord(r, check(r, otherGenesis, frozen(st, st.head.seq + 1)), "another genesis, frozen")
            // A served chain whose first entry is not the verified genesis.
            assertRefusedWithRecord(r, check(r, ahead(r), withheld(st), listOf(otherHash) + r.served.drop(1)), "another first entry")
            // Frozen at the genesis: another chain under the same id.
            assertRefusedWithRecord(r, check(r, ahead(r), frozen(st, 0)), "frozen at the genesis")
            // Frozen at a place the verified state already holds.
            assertRefusedWithRecord(r, check(r, ahead(r), frozen(st, st.head.seq)), "frozen at the verified head")
            // A record of another vault's status.
            val elsewhere = VaultLogStatus.Withheld("00000000-0000-4000-8000-000000000001", view(st), st.head.seq)
            assertRefusedWithRecord(r, check(r, ahead(r), elsewhere), "the status of another vault")
        }
    }

    /**
     * A withheld log alone gives nothing: a record that stands beside the verified chain (another hash at a place at or
     * below the verified head, which the device's own hashes kept over the record's) is refused, with no key, although
     * the log engine calls the vault withheld. Only a record above the served head is "ahead".
     */
    @Test fun aRecordBesideTheVerifiedChainIsRefusedAlthoughTheLogIsWithheld() {
        val all = rows()
        assertTrue(all.any { others(it).isEmpty() }, "the vectors hold a row whose other conditions all hold")
        for (r in all) {
            val st = r.state
            for (place in 0..st.head.seq) {
                val beside = VaultRecord(r.vaultId, st.genesisHash, place, otherHash)
                assertRefusedWithRecord(r, check(r, beside, withheld(st)), "beside the chain at $place while withheld")
            }
        }
    }

    /** The rows whose account holds an `add` of its own and whose every other condition holds: the grant road's cases. */
    private fun grantRows(): List<Pair<Row, AddRecord>> = rows().mapNotNull { r ->
        val add = r.state.latestAdd(r.me) ?: return@mapNotNull null
        if (others(r).isNotEmpty()) null else r to add
    }

    /** A grant from [add]'s actor of the row's own key, as the shared verifiers open one. */
    private fun grant(r: Row, add: AddRecord): OpenedGrant {
        val vk = Envelope.openB64(crypto, r.uvk, r.wrap, Ad.vkShared(r.state.vaultId, r.me, r.state.genesisHash))
        return try { OpenedGrant(vk, add.actor, "grant-1", 0L, add) } finally { vk.fill(0) }
    }

    private fun checkGrant(r: Row, add: AddRecord, record: VaultRecord, log: VaultLogStatus, current: Boolean = true, accepted: AcceptedRecord? = r.accepted): AdoptCheck {
        val g = grant(r, add)
        return try {
            AdoptionRules.checkGrant(crypto, r.me, r.state, r.served, g, current, record, accepted, log)
        } finally {
            g.wipe()
        }
    }

    /**
     * The grant road holds the same rule as the wrap road: with the record ahead and the vault withheld, and with the
     * record beside and the vault frozen, a grant gives the key read-only when every other condition holds; when its
     * actor is not a current contact, or the account's answer names an older `add`, it is refused, with no key.
     */
    @Test fun aGrantGivesTheKeyReadOnlyOnlyWhenEveryOtherConditionHolds() {
        val all = grantRows()
        assertTrue(all.isNotEmpty(), "the vectors hold a member's row whose other conditions all hold")
        for ((r, add) in all) {
            val st = r.state
            for ((standing, log) in listOf(RecordStanding.AHEAD to withheld(st), RecordStanding.FORK to frozen(st, st.head.seq + 1))) {
                val ok = assertIs<AdoptCheck.Adopt>(checkGrant(r, add, ahead(r), log), "${r.name}, $standing: every other condition holds")
                assertEquals(standing, ok.readOnly, "${r.name}, $standing")
                assertEquals(KeySource.GRANT, ok.source, "${r.name}, $standing")
                ok.vk.fill(0)

                val notCurrent = assertIs<AdoptCheck.Refuse>(checkGrant(r, add, ahead(r), log, current = false), "${r.name}, $standing: the actor is not a current contact")
                assertEquals(setOf(AdoptCondition.SOURCE, AdoptCondition.RECORD), notCurrent.failed, "${r.name}, $standing: the actor is not a current contact")

                val older = AcceptedRecord(r.vaultId, r.accepted?.owner ?: add.actor, add.seq - 1, r.accepted?.at ?: 0L, AcceptedRecord.ACCEPT)
                val oldAnswer = assertIs<AdoptCheck.Refuse>(checkGrant(r, add, ahead(r), log, accepted = older), "${r.name}, $standing: the answer names an older add")
                assertEquals(setOf(AdoptCondition.SOURCE, AdoptCondition.RECORD), oldAnswer.failed, "${r.name}, $standing: the answer names an older add")
            }
        }
    }

    @Test fun aRecordOnTheServedChainIsJudgedAsBefore() {
        for (r in rows()) {
            val on = VaultRecord(r.vaultId, r.state.genesisHash, r.state.head.seq, r.state.head.hash)
            for (log in listOf(null, verified(r.state), withheld(r.state))) {
                when (val got = check(r, on, log)) {
                    is AdoptCheck.Adopt -> {
                        assertTrue(others(r).isEmpty(), r.name)
                        assertNull(got.readOnly, "${r.name}: a record that agrees takes the key as before")
                        got.vk.fill(0)
                    }
                    is AdoptCheck.Refuse -> assertEquals(others(r), got.failed, r.name)
                }
            }
        }
    }

    @Test fun aRefusalOfTheRecordSaysHowItFailed() {
        val r = rows().first()
        val st = r.state
        assertEquals(AdoptionRefusal.RECORD_AHEAD, AdoptionRules.recordRefusal(st, r.served, ahead(r), verified(st)))
        assertEquals(AdoptionRefusal.RECORD_FORK, AdoptionRules.recordRefusal(st, r.served, ahead(r), frozen(st, st.head.seq + 1)))
        val beside = VaultRecord(r.vaultId, st.genesisHash, st.head.seq, otherHash)
        assertEquals(AdoptionRefusal.RECORD_FORK, AdoptionRules.recordRefusal(st, r.served, beside, verified(st)))
        assertEquals(AdoptionRefusal.RECORD_GENESIS_MISMATCH, AdoptionRules.recordRefusal(st, r.served, ahead(r), frozen(st, 0)))
        val otherGenesis = VaultRecord(r.vaultId, otherHash, st.head.seq + 1, otherHash)
        assertEquals(AdoptionRefusal.RECORD_GENESIS_MISMATCH, AdoptionRules.recordRefusal(st, r.served, otherGenesis, withheld(st)))
    }
}
