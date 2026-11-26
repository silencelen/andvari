package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.client.restore.BackupRestore
import io.silencelen.andvari.core.client.restore.RestoreChoice
import io.silencelen.andvari.core.client.restore.RestoreEvent
import io.silencelen.andvari.core.client.restore.RestoreFile
import io.silencelen.andvari.core.client.restore.RestoreOpening
import io.silencelen.andvari.core.client.restore.RestorePreview
import io.silencelen.andvari.core.client.restore.RestoreResult

/**
 * "Restore a backup" (decided on 21 and 22 November 2026, for the desktop app only): the shared restore ([BackupRestore])
 * over the vault open on this device, as the command-line tool runs it. Only [DesktopAppApi] hands it out; the phone and
 * the web app have no restore.
 *
 * The file is opened on this device and nothing is sent before [restore]. The records that make a stopped restore
 * continue live in the account's kept records on this device and go with them at a sign-out; a policy that forbids an
 * offline copy moves them into this process's memory.
 */
interface BackupRestoreApi {
    /**
     * Open [bytes] under [passphrase], on this device (the passphrase's characters are zeroed). Off the caller's thread:
     * the key derivation takes seconds.
     */
    suspend fun open(passphrase: CharArray, bytes: ByteArray): RestoreOpening

    /** What [file] holds and what of it this account already has; nothing is written. Null when no vault is open. */
    suspend fun preview(file: RestoreFile): RestorePreview?

    /**
     * Restore what [choice] names, made on a preview of [file] ([RestorePreview.choose]): what that preview said is left
     * of each vault chosen, or nothing ([RestoreResult.Changed]) when that is no longer so. Null when no vault is open
     * (nothing was sent).
     */
    suspend fun restore(file: RestoreFile, choice: RestoreChoice, events: (RestoreEvent) -> Unit): RestoreResult?

    /**
     * Try again after a stop or an end with items the server refused: the vaults [vaults] of the run before, as the
     * description at this run's start chooses them (those with something left to store). Null when no vault is open.
     * Additive.
     */
    suspend fun restoreAgain(file: RestoreFile, vaults: Set<String>, events: (RestoreEvent) -> Unit): RestoreResult?

    /**
     * True when a restore's record lives in this process's memory only, as the account's kept records do while the
     * server's policy forbids an offline copy or this device keeps nothing at rest (the desktop: "Keep me signed in on
     * this computer" off): a restore stopped there continues after a lock, but once the app is closed the same file
     * finds no record and starts again from the beginning, storing again what was stored. False while the record is a
     * file of this device. Null when no vault is open. Asked when it is to be said: a switch turned or a policy that
     * arrives later changes the answer.
     */
    fun recordInMemoryOnly(): Boolean?

    /**
     * True while a restore into the account signed in on this device has not finished here ([BackupRestore.unfinished]:
     * a ticked vault not wholly stored, or items the server refused left), as the question before a sign-out or "Forget
     * this server" says, since those delete the record and the same file chosen again afterwards stores a second time
     * what was stored. Read without the account's keys, so also while locked. False with no account signed in. Additive.
     */
    fun unfinishedRestore(): Boolean
}
