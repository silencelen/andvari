package io.silencelen.andvari.desktop.trust

import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Everything the desktop creates under its home (`~/.andvari-desktop`) is owner-only: every file `rw-------`, every
 * directory `rwx------`. The run found the vault cache's SQLite files (made by core's driver) and the instance lock
 * created `rw-r--r--` inside an owner-only directory.
 */
class OwnerOnlyFilesTest {
    private fun mode(f: File): String = PosixFilePermissions.toString(Files.getPosixFilePermissions(f.toPath()))

    private fun notOwnerOnly(root: File): List<String> = root.walkTopDown().filter { it != root }.mapNotNull { f ->
        val want = if (f.isDirectory) "rwx------" else "rw-------"
        mode(f).takeIf { it != want }?.let { "${f.relativeTo(root)} $it" }
    }.toList()

    @Test
    fun aKeptSignInsFilesTheCacheAndTheLockAreAllOwnerOnly() {
        val root = Files.createTempDirectory("andvari-modes").toFile().also { it.deleteOnExit() }
        if (!posix(root)) return
        val gate = SingleInstance.acquire(SingleInstance.fileIn(root))
        try {
            val home = DesktopHome(root, TestKeyStore(), log = {})
            home.setKeepSignIn(true, "acct-1")
            home.secureFile.replace("""{"session":"kept"}""")
            home.stateFile().replace("""{"pins":{}}""")
            assertTrue(home.content.storage.record("kept-abc").write(byteArrayOf(1)))
            assertTrue(home.content.storage.blobs("held").put("0a1b2c3d-0000-4000-8000-000000000001", byteArrayOf(2)))
            // The vault cache as core opens it: the SQLite driver makes the database, then its WAL files.
            home.cacheFiles.open("vault-abc.db", "user-1")
            assertTrue(File(home.cacheDir, "vault-abc.db").exists())
            assertEquals(emptyList(), notOwnerOnly(root))
        } finally {
            (gate as? SingleInstance.Gate.Acquired)?.instance?.release()
        }
    }

    @Test
    fun filesAnEarlierBuildLeftReadableAreMadeOwnerOnly() {
        val root = Files.createTempDirectory("andvari-modes").toFile().also { it.deleteOnExit() }
        if (!posix(root)) return
        val v2 = File(root, DesktopHome.NEW_DIR).apply { mkdirs() }
        val readable = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-r--r--"))
        val lock = Files.createFile(File(v2, SingleInstance.FILE_NAME).toPath(), readable).toFile()
        val cache = File(v2, "vault-cache").apply { mkdirs() }
        val db = Files.createFile(File(cache, "vault-old.db").toPath(), readable).toFile()
        val wal = Files.createFile(File(cache, "vault-old.db-wal").toPath(), readable).toFile()

        val gate = SingleInstance.acquire(SingleInstance.fileIn(root))
        try {
            assertEquals("rw-------", mode(lock))
            val home = DesktopHome(root, TestKeyStore(), log = {})
            home.setKeepSignIn(true, "acct-1")
            home.cacheFiles.open("vault-old.db", "user-1")
            assertEquals("rw-------", mode(db))
            assertEquals("rw-------", mode(wal))
        } finally {
            (gate as? SingleInstance.Gate.Acquired)?.instance?.release()
        }
    }

    @Test
    fun aDirectoryMadeWithItsParentsMakesThemAllOwnerOnly() {
        val root = Files.createTempDirectory("andvari-modes").toFile().also { it.deleteOnExit() }
        if (!posix(root)) return
        val deep = File(root, "a/b/c")
        ownerOnlyDir(deep)
        assertEquals(listOf("rwx------", "rwx------", "rwx------"), listOf(File(root, "a"), File(root, "a/b"), deep).map(::mode))
    }
}
