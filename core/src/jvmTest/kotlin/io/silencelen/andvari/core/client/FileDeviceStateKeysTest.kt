package io.silencelen.andvari.core.client

import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals

/** [FileDeviceState] lists its keys, so a namespace stored in it can follow a move (design §4.4). */
class FileDeviceStateKeysTest {
    private val dir = Files.createTempDirectory("andvari-device-state").toFile()

    @AfterTest fun cleanup() { dir.deleteRecursively() }

    @Test fun theStoreListsItsKeysAcrossInstances() {
        FileDeviceState(dir).set("ovh.pin|https://a.example", "p")
        FileDeviceState(dir).set("ovh.links|https://a.example|x", "l")
        assertEquals(setOf("ovh.pin|https://a.example", "ovh.links|https://a.example|x"), FileDeviceState(dir).keys())
        FileDeviceState(dir).set("ovh.pin|https://a.example", null)
        assertEquals(setOf("ovh.links|https://a.example|x"), FileDeviceState(dir).keys())
        assertEquals(emptySet(), FileDeviceState(dir.resolve("none")).keys(), "no file yet: an empty store, listable")
    }
}
