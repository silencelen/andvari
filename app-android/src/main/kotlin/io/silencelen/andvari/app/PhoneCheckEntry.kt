package io.silencelen.andvari.app

import androidx.compose.runtime.Composable

/**
 * A screen only the test build has: the check of the phone's own crypto against the specification's test vectors,
 * reached from Settings. `phoneCheck` is defined once per build type: the test build's (src/debug) runs the check, the
 * release build's (src/release) is null, so the release build has no such screen and no vector files.
 */
internal class PhoneCheckEntry(val screen: @Composable (onClose: () -> Unit) -> Unit)
