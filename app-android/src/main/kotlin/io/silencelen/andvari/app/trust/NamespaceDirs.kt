package io.silencelen.andvari.app.trust

import io.silencelen.andvari.app.OriginNamespace
import io.silencelen.andvari.core.client.pin.NamespaceMover
import java.io.File

/**
 * The new path's per-(server, account) directories: `<base>/ns/<originKey>/<userId>/` ([OriginNamespace.dir]), where
 * `base` is the new path's own no-backup folder (`ovh`). Everything this app keeps for one account on one server and
 * not inside core's device state lives there (the vault content's kept records, when they land).
 */
internal object NamespaceDirs {
    fun originDir(base: File, origin: String): File = File(File(base, "ns"), OriginNamespace.pathSafe(OriginNamespace.originKey(origin)))

    fun accountDir(base: File, origin: String, userId: String): File =
        OriginNamespace.dir(base, OriginNamespace.originKey(origin), userId)
}

/**
 * The host's side of a followed server move (design §4.4, [NamespaceMover]): after the pin and core's records moved,
 * the engine calls [onMoved] and keeps [to] closed (nothing sent, nothing written) until it returns true.
 *
 * Every account directory under the old address's folder is renamed into the new address's folder (a rename on one
 * file system: each one is moved whole or not at all), then the emptied old folder goes. It is called again after a
 * crash or a failure, so:
 * - nothing left at the old address (moved already, or never anything there) is success;
 * - a part-done move (some accounts moved, the app stopped) is finished from where it stopped;
 * - an account directory that exists at BOTH addresses is never merged and never overwritten: that is a failure, the
 *   new address stays closed, and only "Forget this server" or a person's look settles it (the safer reading: two
 *   copies of one account's records are never mixed).
 * An exception (a file system that refuses) is the engine's failure too; it is not swallowed here.
 */
internal class AndroidNamespaceMover(private val base: File) : NamespaceMover {
    override fun onMoved(from: String, to: String): Boolean {
        val old = NamespaceDirs.originDir(base, from)
        val new = NamespaceDirs.originDir(base, to)
        if (old.canonicalPath == new.canonicalPath) return true
        if (!old.exists()) return true
        if (!old.isDirectory) return false
        if (new.exists() && !new.isDirectory) return false
        // The usual case: nothing at the new address yet, and the whole folder moves in one rename.
        if (!new.exists() && old.renameTo(new)) return true
        if (!new.isDirectory && !new.mkdirs() && !new.isDirectory) return false
        val children = old.listFiles() ?: return false
        for (child in children) {
            val target = File(new, child.name)
            if (target.exists()) return false
            if (!child.renameTo(target)) return false
        }
        // Everything moved: the old folder must be gone for the move to count (a later call then sees nothing there).
        return old.delete() || !old.exists()
    }
}
