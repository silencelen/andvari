package io.silencelen.andvari.core

/** The text of a file in spec/test-vectors. Each platform finds the directory its own way. */
expect fun readVector(name: String): String
