package io.silencelen.andvari.app

import android.content.Context
import androidx.fragment.app.FragmentActivity
import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.VaultCache
import io.silencelen.andvari.core.client.session.BiometricHost
import io.silencelen.andvari.core.client.session.NamespaceStorage
import io.silencelen.andvari.core.client.session.QuickEnroll
import io.silencelen.andvari.core.client.session.QuickRecover
import io.silencelen.andvari.core.client.session.QuickUnlockKeys
import io.silencelen.andvari.core.client.sqliteVaultCache
import java.io.File

/** The activity a BiometricPrompt rides on (core [BiometricHost]). */
class ActivityHost(val activity: FragmentActivity) : BiometricHost

/**
 * [QuickUnlock] behind core's [QuickUnlockKeys] seam: the Keystore-wrapped UVK in the namespaces under
 * [noBackupDir]. [context] is the application context, used only for the BiometricManager availability check.
 */
class AndroidQuickUnlockKeys(private val context: Context, private val noBackupDir: File) : QuickUnlockKeys {
    override fun hasStrongBiometric(): Boolean = QuickUnlock.hasStrongBiometric(context)

    override fun isEnrolled(originKey: String, userId: String): Boolean = QuickUnlock.isEnrolled(noBackupDir, originKey, userId)

    override suspend fun recover(host: BiometricHost, originKey: String, userId: String): QuickRecover {
        val activity = requireNotNull((host as? ActivityHost)?.activity) { "BiometricPrompt needs the activity it shows over" }
        return when (val r = QuickUnlock.recoverUvk(activity, noBackupDir, originKey, userId)) {
            is QuickUnlock.Recover.Ok -> QuickRecover.Ok(r.uvk)
            is QuickUnlock.Recover.Fallback -> QuickRecover.Fallback(r.reason)
            is QuickUnlock.Recover.Wiped -> QuickRecover.Wiped(r.reason)
        }
    }

    override suspend fun enroll(host: BiometricHost, originKey: String, userId: String, account: Account): QuickEnroll {
        val activity = requireNotNull((host as? ActivityHost)?.activity) { "BiometricPrompt needs the activity it shows over" }
        return when (val r = QuickUnlock.enroll(activity, noBackupDir, originKey, userId, account)) {
            QuickUnlock.Enroll.Ok -> QuickEnroll.Ok
            QuickUnlock.Enroll.Cancelled -> QuickEnroll.Cancelled
            is QuickUnlock.Enroll.Failed -> QuickEnroll.Failed(r.reason)
        }
    }

    override fun wipe(originKey: String, userId: String) = QuickUnlock.wipe(noBackupDir, originKey, userId)
}

/**
 * The §4.2 namespace layout under [noBackupDir], behind core's [NamespaceStorage] seam:
 * `<noBackup>/ns/<originKey>/<userId>/vault-<userId>.db` (the userId fragment path-safe-laundered: it is
 * server-supplied) beside the device state ([PersonalDeviceState]), which no purge removes.
 */
class AndroidNamespaceStorage(private val noBackupDir: File) : NamespaceStorage {
    override fun openVaultCache(originKey: String, userId: String): VaultCache {
        val dir = OriginNamespace.dir(noBackupDir, originKey, userId).apply { mkdirs() }
        return sqliteVaultCache(File(dir, "vault-${OriginNamespace.pathSafe(userId)}.db").absolutePath, userId)
    }

    override fun deviceState(originKey: String, userId: String): DeviceState = PersonalDeviceState.open(noBackupDir, originKey, userId)

    override fun deleteVaultCache(originKey: String, userId: String) = OfflineData.deleteVaultCache(noBackupDir, originKey, userId)
}
