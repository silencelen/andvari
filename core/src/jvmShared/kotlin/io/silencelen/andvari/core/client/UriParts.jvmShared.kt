package io.silencelen.andvari.core.client

import java.net.URI

internal actual fun parseUriParts(input: String): UriParts? =
    runCatching { URI(input) }.getOrNull()?.let {
        UriParts(it.scheme, it.rawUserInfo, it.host, it.port, it.rawPath, it.rawQuery, it.rawFragment)
    }
