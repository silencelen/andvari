package io.silencelen.andvari.app

import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.FileDeviceState
import java.io.File

/**
 * Security review 2026-10, root cause A, A5b (M-1): where the phone keeps the personal wrap it last
 * authenticated (UVK-sealed) and the vault id it pinned: `<noBackup>/ns/<originKey>/<userId>/device-state.json`.
 * The phone may run an in-memory offline cache (org-forbid policy) and [OfflineData]'s purges delete the
 * durable one (a policy flip, a revocation); none of them removes this file, so after a restart a server
 * that withholds the wrap is still the WITHHELD anomaly, not a "new device" that asks again. Used by every
 * engine the app builds: the main app and the autofill-only process.
 */
object PersonalDeviceState {
    fun open(noBackupDir: File, originKey: String, userId: String): DeviceState =
        FileDeviceState(OriginNamespace.dir(noBackupDir, originKey, userId))
}
