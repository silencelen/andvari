package io.silencelen.andvari.cli.e2e

import io.silencelen.andvari.cli.AccountSession
import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.SyncOutcome
import io.silencelen.andvari.core.client.link.CompareResult
import io.silencelen.andvari.core.client.link.CreateOutcome
import io.silencelen.andvari.core.client.link.CreatorStep
import io.silencelen.andvari.core.client.link.RecipientStep
import io.silencelen.andvari.core.client.log.Adoption
import io.silencelen.andvari.core.client.log.AppendOutcome
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.pin.GateEntry
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** Contacts, vault-log actions and items, as the journeys after 4 use them. */

suspend fun AccountSession.synced() = assertIs<SyncOutcome.Synced>(sync(), "sync")

suspend fun AccountSession.ok(vaultId: String?, action: LogAction): String {
    val r = logs.append(vaultId, action)
    return assertIs<AppendOutcome.Appended>(r, "$action: $r").state.vaultId
}

/** [b] syncs, is asked to accept [vaultId] named [name], and accepts. */
suspend fun accept(b: AccountSession, vaultId: String, name: String = "Family") {
    b.synced()
    val ask = assertIs<Adoption.AskAccept>(b.logs.adoption(vaultId), "the added member is asked to accept")
    assertEquals(name, ask.vaultName)
    assertIs<Adoption.Adopted>(b.logs.answerIncoming(ask, accept = true))
}

fun doc(name: String) = buildJsonObject {
    put("type", JsonPrimitive("login")); put("name", JsonPrimitive(name))
    put("login", buildJsonObject { put("username", JsonPrimitive("u")); put("password", JsonPrimitive("p-$name")) })
}

/** Connect [ah]'s and [bh]'s accounts through a connect link [ah] creates; both type the other side's code. */
suspend fun connect(ah: Host, bh: Host, origin: String) {
    val a = ah.account(origin)!!
    val b = bh.account(origin)!!
    val created = assertIs<CreateOutcome.Created>(ah.links.create("connect", 86_400_000L, emptyList()), "connect link")
    val confirm = assertIs<RecipientStep.Confirm>(bh.links.open(created.link.url, GateEntry.PASTE_INVITE), "the recipient's confirm step")
    assertEquals(false, confirm.needsAccount)
    val answered = assertIs<RecipientStep.Answered>(bh.links.confirm(confirm), "the answer is posted")
    val processed = ah.links.processAnswers()
    assertIs<CreatorStep.Processed>(processed.single(), "the creator processes the answer: $processed")
    assertIs<RecipientStep.CodeReady>(bh.links.awaitReveal(answered), "the reveal opens the commitment")
    val codeA = assertNotNull(ah.links.code(b.userId), "the creator's code")
    val codeB = assertNotNull(bh.links.code(a.userId), "the recipient's code")
    // Each side has its own code (design §6.11): the two screens differ, and typing one's own code is refused.
    kotlin.test.assertNotEquals(codeA, codeB, "the creator and the answerer show different codes")
    assertEquals(CompareResult.Mismatch, ah.links.typeCode(b.userId, codeA), "the creator typing its own code")
    assertEquals(CompareResult.Mismatch, bh.links.typeCode(a.userId, codeB), "the answerer typing its own code")
    assertEquals(CompareResult.Matched, ah.links.typeCode(b.userId, codeB))
    assertEquals(CompareResult.Matched, bh.links.typeCode(a.userId, codeA))
    assertTrue(a.store.local().contacts.getValue(b.userId).compared)
    assertTrue(b.store.local().contacts.getValue(a.userId).compared)
}
