package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.engine.AppEngine
import io.silencelen.andvari.core.app.engine.EngineDesktopAppApi
import io.silencelen.andvari.core.client.JsonDeviceState
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.model.wire.MutationResult
import io.silencelen.andvari.core.model.wire.MutationStatus
import io.silencelen.andvari.core.model.wire.PushRequest
import io.silencelen.andvari.core.model.wire.PushResponse
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull

/**
 * The day a vault's line names as the day this computer saw its restore finished: a run that ended with items the server
 * refused writes the vault's end, and a later run that stores the vault's last refused item moves the end to the time it
 * stored it; a run that stores one refused item while another is still refused leaves the end where it was. Each drawn
 * through the real flow over the real shared restore, with the clock moved by whole days so that the days differ in every
 * zone.
 */
internal class RestoreFinishedDayTest : RestoreTestKit() {
    private val day = 86_400_000L

    @Test
    fun aVaultThatEndedWithARefusedItemIsFinishedOnTheDayTryAgainStoresIt() {
        val w = world("finished-day-try-again")
        val bytes = backup(201)
        // The first run ends with "A" refused: the vault's end is written all the same, and "A" is still to restore.
        w.server.rejectFirst = true
        val f = flow(w, bytes)
        open(f)
        runBlocking { f.confirm() }
        assertEquals(RestoreFlow.Stage.ENDED, f.views.value.stage)
        assertEquals(200, personalItems(w))
        val firstDay = w.instance.now
        // Days later, Try again stores "A".
        w.instance.now += 3 * day
        w.server.rejectFirst = false
        runBlocking { f.tryAgain() }
        assertEquals(201, personalItems(w))
        val storedAt = w.instance.now
        assertNotEquals(RestoreFlow.dayText(firstDay), RestoreFlow.dayText(storedAt))
        // A page days after that: the day is the one on which "A" was stored, not the first run's, nor this look's.
        w.instance.now += 2 * day
        val g = flow(w, bytes)
        open(g)
        val v = assertNotNull(g.views.value.preview).vaults.first { it.personal }
        println("FINISHEDDAY|try-again restoredAt=${v.restoredAt} first=$firstDay stored=$storedAt")
        assertEquals(storedAt, v.restoredAt)
        has(page(w, g), ph(Placeholder.RESTORE_RESTORED_AT, "Personal vault: 201 items.", RestoreFlow.dayText(storedAt)))
    }

    @Test
    fun aRunThatStoresOneOfTwoRefusedItemsKeepsTheVaultsDayAndTheRunThatStoresTheLastMovesIt() {
        val (w, front) = refusingWorld("finished-day-two-refused")
        val bytes = backup(201, familyItems = 0)
        // The first run: "A" and "Item 2" refused; the vault's end is written all the same.
        front.pick = { push, ids -> if (push == 1) ids.take(2) else emptyList() }
        val f = flow(w, bytes)
        open(f)
        runBlocking { f.confirm() }
        front.pick = null
        assertEquals(RestoreFlow.Stage.ENDED, f.views.value.stage)
        assertEquals(199, personalItems(w))
        val firstDay = w.instance.now
        val (aId, _) = front.refuse.toList()
        // Days later, Try again: "A" is stored, "Item 2" is refused again.
        front.refuse.remove(aId)
        w.instance.now += 3 * day
        runBlocking { f.tryAgain() }
        assertEquals(RestoreFlow.Stage.ENDED, f.views.value.stage)
        assertEquals(200, personalItems(w))
        val g = flow(w, bytes)
        open(g)
        val p = assertNotNull(g.views.value.preview)
        val v = p.vaults.first { it.personal }
        val mid = page(w, g)
        println("FINISHEDDAY|two-refused-mid refused=${p.refused.map { it.name }} restoredAt=${v.restoredAt} first=$firstDay left=${v.left}")
        assertEquals(listOf("Item 2"), p.refused.map { it.name })
        assertEquals(firstDay, v.restoredAt, "an item of the vault is still refused: its day does not move")
        assertEquals(1, v.left)
        has(mid, ph(Placeholder.RESTORE_VAULT_LEFT, "Personal vault: 201 items.", "1"))
        // Days later, the next page's restore stores "Item 2": the day moves to that run's.
        front.refuse.clear()
        w.instance.now += 3 * day
        val lastStoredAt = w.instance.now
        runBlocking { g.confirm() }
        assertEquals(RestoreFlow.Stage.ENDED, g.views.value.stage)
        assertEquals(201, personalItems(w))
        w.instance.now += 2 * day
        val h = flow(w, bytes)
        open(h)
        val q = assertNotNull(h.views.value.preview)
        val u = q.vaults.first { it.personal }
        println("FINISHEDDAY|two-refused-end refused=${q.refused.map { it.name }} restoredAt=${u.restoredAt} stored=$lastStoredAt")
        assertEquals(emptyList(), q.refused.map { it.name })
        assertEquals(lastStoredAt, u.restoredAt)
        has(page(w, h), ph(Placeholder.RESTORE_RESTORED_AT, "Personal vault: 201 items.", RestoreFlow.dayText(lastStoredAt)))
    }

    /**
     * In front of the kit's server: each change whose id is in [refuse] is refused for good (`item_too_large`) and never
     * reaches the server; [pick] chooses, per push (numbered from 1) and its change ids in order, more ids to refuse.
     */
    private class RefusingFront(private val inner: KitServer) : WireClient {
        override val origin: String get() = inner.origin
        val refuse = LinkedHashSet<String>()
        var pick: ((Int, List<String>) -> List<String>)? = null
        private var pushes = 0

        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            if (route != WireRoute.PUSH || bodyJson == null) return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
            val request = WireJson.json.decodeFromString(PushRequest.serializer(), bodyJson)
            pushes++
            pick?.let { refuse += it(pushes, request.mutations.map { m -> m.mutationId }) }
            if (request.mutations.none { it.mutationId in refuse }) return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
            val kept = request.mutations.filter { it.mutationId !in refuse }
            val r = inner.call(route, pathParams, query, WireJson.json.encodeToString(PushRequest.serializer(), PushRequest(kept)), authenticated) { it }
            if (r !is WireResult.Ok) {
                @Suppress("UNCHECKED_CAST")
                return r as WireResult<T>
            }
            val answer = WireJson.json.decodeFromString(PushResponse.serializer(), r.value)
            val byId = answer.results.associateBy { it.mutationId }
            val results = request.mutations.map { m -> byId[m.mutationId] ?: MutationResult(m.mutationId, MutationStatus.REJECTED, reason = "item_too_large") }
            return WireResult.Ok(decode(WireJson.json.encodeToString(PushResponse.serializer(), PushResponse(answer.rev, results))), r.status)
        }

        override suspend fun <T> callBytes(route: WireRoute, pathParams: Map<String, String>, query: String?, body: ByteArray, authenticated: Boolean, decode: (String) -> T): WireResult<T> =
            inner.callBytes(route, pathParams, query, body, authenticated, decode)
    }

    /** As the kit's world, with a [RefusingFront] in front of its server. */
    private fun refusingWorld(name: String): Pair<World, RefusingFront> {
        val instance = FakeInstance(crypto)
        val server = KitServer(instance)
        val front = RefusingFront(server)
        val dir = newDir(name)
        val home = DesktopHome(dir, NoKeyStore, log = {}, keyStorePause = {})
        val api = EngineDesktopAppApi(
            AppEngine(
                platform = TrustSeam.desktopPlatform(), deviceName = "test", transport = BearerTransport(mapOf(instance.origin to front)),
                state = JsonDeviceState(home.stateFile()), secure = JsonDeviceState(home.secureFile), requestStore = JsonDeviceState(home.requestFile),
                crypto = crypto, clock = { instance.now }, baked = null, storeBuild = false, stores = null,
                main = Dispatchers.Unconfined, work = Dispatchers.Unconfined,
                cacheFiles = home.cacheFiles, contentStores = home.content.stores, keepsAtRest = home::keepsAtRest,
            ),
        )
        home.consentWithdrawn = api::atRestConsentChanged
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L }, HomeSignInKeeping(home), faultLog = {})
        m.start()
        m.onSnapshot(api.snapshot)
        val w = World(server, api, m, home, dir, instance)
        runBlocking { signUp(w.api, instance) }
        w.m.onSnapshot(w.api.snapshot)
        return w to front
    }
}
