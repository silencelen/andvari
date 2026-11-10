package io.silencelen.andvari.core.client.session

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.request.get
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.runBlocking
import kotlinx.io.IOException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** The transport rule of a client with no cleartext of its own (iOS): https only, loopback excepted. */
class HttpsOnlyTest {
    private val sent = mutableListOf<String>()
    private val client = HttpClient(MockEngine { request -> sent += request.url.toString(); respond("ok", HttpStatusCode.OK) }).httpsOnly(setOf("127.0.0.1"))

    @Test
    fun httpsGoesThrough() = runBlocking<Unit> {
        client.get("https://vault.example/x")
        assertEquals(listOf("https://vault.example/x"), sent)
    }

    @Test
    fun plainHttpToAnotherHostFailsBeforeAnythingIsSent() = runBlocking<Unit> {
        assertFailsWith<IOException> { client.get("http://192.168.1.9:8080/x") }
        assertFailsWith<IOException> { client.get("http://vault.example/x") }
        assertTrue(sent.isEmpty(), "and it reads as unreachable wherever a client branches on IOException")
    }

    @Test
    fun plainHttpToLoopbackIsAllowed() = runBlocking<Unit> {
        client.get("http://127.0.0.1:8080/x")
        assertEquals(1, sent.size)
    }
}
