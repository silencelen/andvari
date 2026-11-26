package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.deleteDir
import io.silencelen.andvari.core.newTempDir
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class FileDeviceStateIosTest {
    private val root = newTempDir("andvari-device-state")
    private val dir = "$root/ns/user"

    @AfterTest fun cleanup() = deleteDir(root)

    @Test fun valuesSurviveANewInstanceInANewDirectory() {
        fileDeviceState(dir).set("personal.last", "v1")
        assertEquals("v1", fileDeviceState(dir).get("personal.last"))
        fileDeviceState(dir).set("personal.last", null)
        assertNull(fileDeviceState(dir).get("personal.last"))
    }

    /** Following a move needs the store to list its keys (design §4.4); null would refuse the move. */
    @Test fun theStoreListsItsKeys() {
        fileDeviceState(dir).set("ovh.pin|https://a.example", "p")
        fileDeviceState(dir).set("ovh.links|https://a.example|x", "l")
        assertEquals(setOf("ovh.pin|https://a.example", "ovh.links|https://a.example|x"), fileDeviceState(dir).keys())
        fileDeviceState(dir).set("ovh.pin|https://a.example", null)
        assertEquals(setOf("ovh.links|https://a.example|x"), fileDeviceState(dir).keys())
    }
}
