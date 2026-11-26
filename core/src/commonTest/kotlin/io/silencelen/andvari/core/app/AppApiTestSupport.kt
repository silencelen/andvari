package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.runBlocking
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull

// What the IF-3 tests share. They drive the fake as a UI would: through the intents and the snapshot.

internal const val PW: String = FakeScenes.PASSWORD
internal const val ADA: String = FakeScenes.EMAIL
internal const val FAMILY: String = FakeScenes.FAMILY_ORIGIN
internal const val MINUTE: Long = 60_000L
internal const val DAY: Long = 24 * 60 * MINUTE

/** Run one `suspend` intent to its end, as a UI's coroutine would. */
internal fun <T> await(block: suspend () -> T): T = runBlocking { block() }

/** The signed-out screen on show, which must be an [S]. */
internal inline fun <reified S : EntryScreen> FakeAppApi.on(): S =
    assertIs<S>(snapshot.entry, "on ${snapshot.entry?.let { it::class.simpleName }} in ${snapshot.phase}")

/** The signed-in account. */
internal val FakeAppApi.account: AccountSnapshot get() = assertNotNull(snapshot.account, "not signed in: ${snapshot.phase}")

/** The first prompt of kind [P]. */
internal inline fun <reified P : AccountPrompt> FakeAppApi.prompt(): P =
    assertNotNull(account.prompts.filterIsInstance<P>().firstOrNull(), "no ${P::class.simpleName} among ${account.prompts.map { it::class.simpleName }}")

internal inline fun <reified P : AccountPrompt> FakeAppApi.hasPrompt(): Boolean = account.prompts.any { it is P }

/** The kit on show, in the signed-out journey or in Settings. */
internal fun FakeAppApi.kitOnShow(): KitScreen = (snapshot.entry as? EntryScreen.Kit)?.kit ?: assertNotNull(snapshot.account?.kit, "no kit on show")

/** Read the kit on show, then type back the groups it asks for. */
internal fun FakeAppApi.saveKit() {
    val reveal = kitOnShow()
    assertEquals(KitStep.REVEAL, reveal.step)
    val groups = assertNotNull(kit.kitDocument(reveal)).groups
    kit.proceedToConfirm(reveal)
    val confirm = kitOnShow()
    assertEquals(KitStep.CONFIRM, confirm.step)
    assertEquals(KitConfirmResult.DONE, await { kit.confirmKit(confirm, confirm.groupsToType.map { groups[it - 1] }) })
}

internal fun SharedVaultRow.named(): String = assertNotNull(name)

internal fun FakeAppApi.vault(name: String): SharedVaultRow = account.vaults.first { it.name == name }

internal fun FakeAppApi.contact(label: String): ContactRow {
    if (account.contacts == null) assertEquals(PlainResult.DONE, await { contacts.openContacts() })
    return assertNotNull(account.contacts).contacts.first { it.label == label }
}
