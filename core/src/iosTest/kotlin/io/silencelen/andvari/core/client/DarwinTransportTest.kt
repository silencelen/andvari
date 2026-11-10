package io.silencelen.andvari.core.client

import io.ktor.client.HttpClient
import io.ktor.client.engine.darwin.Darwin
import io.ktor.client.request.get
import kotlinx.coroutines.runBlocking
import kotlinx.io.IOException
import kotlin.test.Test
import kotlin.test.fail

/**
 * Offline unlock and the switch probe both branch on IOException, so a Darwin transport failure
 * must be one. If it were not, an unreachable server would look like one that answered.
 */
class DarwinTransportTest {
    @Test fun aRefusedConnectionIsAnIOException() = runBlocking {
        val client = HttpClient(Darwin)
        try {
            client.get("https://127.0.0.1:9/")
            fail("the request should not have succeeded")
        } catch (e: IOException) {
            // expected
        } catch (e: AssertionError) {
            throw e
        } catch (e: Throwable) {
            fail("expected an IOException, got ${e::class.qualifiedName}: ${e.message}")
        } finally {
            client.close()
        }
    }
}
