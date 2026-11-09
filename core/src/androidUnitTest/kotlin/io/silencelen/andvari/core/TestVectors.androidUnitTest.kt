package io.silencelen.andvari.core

import java.io.File

actual fun readVector(name: String): String =
    File(System.getProperty("andvari.vectors.dir") ?: error("andvari.vectors.dir not set"), name).readText()

actual fun newTempDir(prefix: String): String = java.nio.file.Files.createTempDirectory(prefix).toFile().absolutePath

actual fun deleteDir(path: String) {
    File(path).deleteRecursively()
}
