package io.silencelen.andvari.core

import java.io.File

actual fun readVector(name: String): String =
    File(System.getProperty("andvari.vectors.dir") ?: error("andvari.vectors.dir not set"), name).readText()
