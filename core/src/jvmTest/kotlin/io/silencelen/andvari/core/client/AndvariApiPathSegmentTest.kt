package io.silencelen.andvari.core.client

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.silencelen.andvari.core.model.ItemUpload
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Security review 2026-10 (root cause D): `purgeItem` joined a co-member-chosen itemId into its
 * path unencoded, and request() attached the victim's bearer token — OkHttp resolves `..`, so a
 * planted `../admin/users/<id>/disable#` turned "Delete forever" into an admin action. Every id
 * that reaches a path now passes [AndvariApi.pathSeg]: a non-id is refused BEFORE any request,
 * and an accepted one is percent-encoded. (Encoding alone is not a fix — `%2e%2e` is still `..`
 * to a WHATWG parser.) Twin of web client.pathseg.test.ts.
 */
class AndvariApiPathSegmentTest {
    private val seen = mutableListOf<String>()

    private fun api(): AndvariApi {
        val engine = MockEngine { req ->
            seen += req.url.encodedPath
            respond("""{"rev":1,"versions":[]}""", HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/json"))
        }
        return AndvariApi("http://fake", HttpClient(engine), Tokens("at", "rt"))
    }

    private val hostile = listOf(
        "../admin/users/0f8e2c1a-3b4d-4e5f-8a9b-0c1d2e3f4a5b/disable#",
        "../admin/users/x/escrow",
        "..", ".", "%2e%2e", "a/b", "a\\b", "a?b", "a#b", "",
    )

    @Test
    fun itemAndAttachmentRoutes_refuseAPlantedId_beforeAnyRequest() = runBlocking {
        val a = api()
        for (id in hostile) {
            assertFailsWith<IllegalArgumentException>("purge $id") { a.purgeItem(id) }
            assertFailsWith<IllegalArgumentException>("restore $id") { a.restoreItem(id, ItemUpload(1, emptyList(), "x")) }
            assertFailsWith<IllegalArgumentException>("versions $id") { a.itemVersions(id) }
            assertFailsWith<IllegalArgumentException>("download $id") { a.downloadAttachment(id) }
            assertFailsWith<IllegalArgumentException>("leave $id") { a.leaveVault(id) }
        }
        assertTrue(seen.isEmpty(), "no request may leave for a refused id: $seen")
    }

    @Test
    fun aRealId_reachesExactlyItsOwnRoute() = runBlocking {
        val a = api()
        val id = "0f8e2c1a-3b4d-4e5f-8a9b-0c1d2e3f4a5b"
        a.purgeItem(id)
        assertEquals(listOf("/api/v1/items/$id/purge"), seen)
    }
}
