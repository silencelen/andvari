package io.silencelen.andvari.cli

import io.silencelen.andvari.core.client.DeviceStateFile
import io.silencelen.andvari.core.client.JsonDeviceState
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions

/**
 * One owner-only file, replaced atomically, for [JsonDeviceState] and for every file the tool writes that holds a secret
 * (`--kit-out`, `operator escrow --out`, a restore's plan). The device state holds only public ids and UVK-sealed blobs;
 * the secure store ([secureState]) holds the assisted-recovery request secrets.
 *
 * The text goes into a temporary file in the same directory with an unpredictable name ([Files.createTempFile]: a
 * random part from a secure generator, created so that it fails when the name exists and never through a link), readable
 * by the owner only from the moment it exists, written and forced to the disk, then renamed over [f] in one step. A
 * failure removes it. Nothing at a predictable name is ever deleted or written (the old
 * `<name>.tmp` let anyone who can write the directory aim the write).
 */
class OwnerOnlyFile(private val f: File) : DeviceStateFile {
    override fun read(): String? = if (f.isFile) f.readText() else null

    override fun replace(text: String) {
        val dir = (f.absoluteFile.parentFile ?: File(".").absoluteFile).also { it.mkdirs() }.toPath()
        val posix = runCatching { Files.getFileStore(dir).supportsFileAttributeView("posix") }.getOrDefault(false)
        val tmp = if (posix) {
            Files.createTempFile(dir, ".${f.name}.", ".part", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
        } else {
            Files.createTempFile(dir, ".${f.name}.", ".part").also { p ->
                val t = p.toFile()
                t.setReadable(false, false); t.setReadable(true, true); t.setWritable(false, false); t.setWritable(true, true)
            }
        }
        try {
            java.nio.channels.FileChannel.open(tmp, java.nio.file.StandardOpenOption.WRITE, java.nio.file.StandardOpenOption.TRUNCATE_EXISTING).use { ch ->
                val buf = java.nio.ByteBuffer.wrap(text.encodeToByteArray())
                while (buf.hasRemaining()) ch.write(buf)
                ch.force(true)
            }
            Files.move(tmp, f.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } catch (e: Exception) {
            runCatching { Files.deleteIfExists(tmp) }
            throw e
        }
    }
}

/** The CLI's home: one directory per device (`--home`, `ANDVARI_CLI_HOME`, or `~/.andvari-cli`). */
class CliHome(val dir: File) {
    init {
        dir.mkdirs()
        runCatching { Files.setPosixFilePermissions(dir.toPath(), PosixFilePermissions.fromString("rwx------")) }
    }

    fun deviceState() = JsonDeviceState(OwnerOnlyFile(File(dir, JsonDeviceState.FILE_NAME)))
    fun secureState() = JsonDeviceState(OwnerOnlyFile(File(dir, "secure-state.json")))
}

/**
 * Where a secret comes from: never the command line (design §12; every other user of the host can read it). In order:
 * `--<name>-file PATH` (its first line), the environment variable `--<name>-env NAME` names (or the default one), then a
 * prompt on the console without echo, then one line of standard input when it is not a terminal.
 */
class Secrets(private val opts: Map<String, String>, private val env: (String) -> String? = System::getenv, private val stdin: () -> String? = { readlnOrNull() }) {
    fun read(name: String, defaultEnv: String, prompt: String): CharArray {
        opts["$name-file"]?.let { path ->
            val f = File(path)
            if (!f.isFile) throw CliError("--$name-file: $path is not a readable file")
            return (f.readLines().firstOrNull() ?: "").toCharArray()
        }
        (env(opts["$name-env"] ?: defaultEnv))?.takeIf { it.isNotEmpty() }?.let { return it.toCharArray() }
        Term.console()?.let { c -> return Term.readPassword(c, prompt) ?: throw CliError("no input") }
        Term.prompt(prompt)
        return (stdin() ?: throw CliError("no $name given (use --$name-file or \$$defaultEnv)")).toCharArray()
    }

    /** [name] when it was given, as `--<name>-file PATH` or in the environment ([read]'s first two), else null: no prompt, no standard input. */
    fun given(name: String, defaultEnv: String): CharArray? {
        opts["$name-file"]?.let { path ->
            val f = File(path)
            if (!f.isFile) throw CliError("--$name-file: $path is not a readable file")
            return (f.readLines().firstOrNull() ?: "").toCharArray()
        }
        return env(opts["$name-env"] ?: defaultEnv)?.takeIf { it.isNotEmpty() }?.toCharArray()
    }
}

/**
 * A command stopped: [message] for the person, the exit [code], and for a fault a script may tell apart, its message [key].
 * The message is printed as one line, every character a terminal would act on escaped ([Shown.text]), so a server's
 * words inside it cannot start a line of their own. A message of several lines is [lines], each built by this tool.
 */

open class CliError(message: String, val code: Int = 1, val key: String? = null, val lines: List<String> = listOf(message)) : Exception(message) {
    companion object {
        /** A message of several lines, each printed on its own line. */
        fun lines(lines: List<String>, code: Int = 1, key: String? = null) = CliError(lines.joinToString(" "), code, key, lines)
    }
}
