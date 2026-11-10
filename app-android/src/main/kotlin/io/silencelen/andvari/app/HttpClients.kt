package io.silencelen.andvari.app

import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp
import io.silencelen.andvari.core.client.session.BoundedOps
import io.silencelen.andvari.core.client.session.HttpClients
import java.util.concurrent.TimeUnit

/** Android's [HttpClients]: OkHttp, the "android" wire tag, and the device model as its name. */
object AndroidHttpClients : HttpClients {
    override fun create(): HttpClient = androidHttpClient()
    override val wirePlatform: String = "android"
    override val deviceName: String get() = android.os.Build.MODEL ?: "android"
}

/**
 * The HTTP client behind every Android [io.silencelen.andvari.core.client.AndvariApi].
 *
 * OkHttp's defaults bound each connect and read, not the call, so a server that keeps answering
 * slowly can hold one open indefinitely. Ops bound themselves ([BoundedOps]), and a token refresh,
 * which no caller may cancel, carries its own request timeout. This call timeout is the belt under
 * both: it sits at the longest bound any op may legitimately run (an attachment at the size
 * ceiling), so it never severs a transfer an op still allows, and no call outlives every op.
 */
internal fun androidHttpClient(): HttpClient = HttpClient(OkHttp) {
    engine {
        config {
            callTimeout(BoundedOps.attachmentMs(BoundedOps.ATTACHMENT_CEILING_BYTES), TimeUnit.MILLISECONDS)
        }
    }
}
