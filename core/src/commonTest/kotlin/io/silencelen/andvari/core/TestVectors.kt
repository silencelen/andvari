package io.silencelen.andvari.core

/** The text of a file in spec/test-vectors. Each platform finds the directory its own way. */
expect fun readVector(name: String): String

/** A new empty directory for one test, as an absolute path. */
expect fun newTempDir(prefix: String): String

expect fun deleteDir(path: String)

fun testNowMs(): Long = kotlinx.datetime.Clock.System.now().toEpochMilliseconds()
