package io.silencelen.andvari.core.client

internal actual fun parseUriParts(input: String): UriParts? = parseUriRfc2396(input)
