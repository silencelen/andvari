package io.silencelen.andvari.desktop.trust

import java.io.File
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes

/**
 * Deletes that never follow a link. The first-launch wipe followed a link planted at
 * `ns/<origin>/self-identity-by-email` into a Documents folder and emptied it, and `deleteRecursively()` follows links
 * through whole trees.
 *
 * - **No-follow.** Every entry is looked at with [LinkOption.NOFOLLOW_LINKS]. A symbolic link, and anything the file
 *   system reports as neither a plain file nor a plain directory (a Windows junction or other reparse point), is
 *   removed as itself; nothing is ever deleted through it.
 * - **Inside the app's directory.** Before a directory is entered, its real path must lie inside [within]'s real path
 *   (`~/.andvari-desktop`); otherwise it is left as it is and the delete answers false.
 */
internal object SafeDelete {
    private val NOFOLLOW = arrayOf(LinkOption.NOFOLLOW_LINKS)

    private fun attrs(p: Path): BasicFileAttributes? =
        runCatching { Files.readAttributes(p, BasicFileAttributes::class.java, *NOFOLLOW) }.getOrNull()

    /** A plain directory: not a link, not a junction. */
    fun isRealDir(f: File): Boolean = attrs(f.toPath())?.let { it.isDirectory && !it.isSymbolicLink && !it.isOther } ?: false

    /** A plain file: not a link. */
    fun isRealFile(f: File): Boolean = attrs(f.toPath())?.let { it.isRegularFile && !it.isSymbolicLink } ?: false

    /** Something is at [f], a dangling link included. */
    fun exists(f: File): Boolean = attrs(f.toPath()) != null

    /** [dir]'s entries, without following [dir] itself when it is a link: empty for anything but a plain directory. */
    fun entries(dir: File): List<File> = if (isRealDir(dir)) dir.listFiles()?.toList().orEmpty() else emptyList()

    /**
     * Deletes one entry the wipe found by name: a file or a link (itself), or an empty plain directory. A plain
     * directory still holding something, sitting where a file was expected, is left as it is and the delete answers
     * false, so the wipe never empties a directory it did not expect.
     */
    fun entry(target: File, within: File): Boolean {
        if (isRealDir(target) && entries(target).isNotEmpty()) return false
        return tree(target, within)
    }

    /**
     * Deletes [target]: a file, a link (itself), or a plain directory and everything in it, never through a link and
     * never outside [within]. True when nothing is left at [target].
     */
    fun tree(target: File, within: File): Boolean {
        val root = runCatching { within.toPath().toRealPath() }.getOrNull() ?: return !exists(target)
        return delete(target.toPath().toAbsolutePath(), root)
    }

    private fun delete(p: Path, root: Path): Boolean {
        val a = attrs(p) ?: return true
        // The entry itself must sit in a directory inside the app's own.
        val parent = runCatching { p.parent.toRealPath() }.getOrNull() ?: return false
        if (!parent.startsWith(root)) return false
        if (a.isDirectory && !a.isSymbolicLink && !a.isOther) {
            val real = runCatching { p.toRealPath() }.getOrNull() ?: return false
            if (!real.startsWith(root)) return false
            var ok = true
            runCatching { Files.newDirectoryStream(p).use { s -> for (c in s) ok = delete(c, root) && ok } }.onFailure { ok = false }
            if (!ok) return false
        }
        // A link or a junction goes as itself: Files.delete never follows one.
        return runCatching { Files.delete(p) }.isSuccess || attrs(p) == null
    }
}
