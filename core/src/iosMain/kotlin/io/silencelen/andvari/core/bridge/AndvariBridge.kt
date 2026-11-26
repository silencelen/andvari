package io.silencelen.andvari.core.bridge

import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.client.ANDVARI_CLIENT_VERSION
import io.silencelen.andvari.core.crypto.GeneratorOptions
import io.silencelen.andvari.core.crypto.PasswordGenerator
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlin.experimental.ExperimentalNativeApi

/** The surface Swift calls. Keys stay on the Kotlin side; Swift only receives what it displays. */
object AndvariBridge {
    fun coreVersion(): String = ANDVARI_CLIENT_VERSION

    fun generatePassword(length: Int): String =
        PasswordGenerator.generate(createCryptoProvider(), GeneratorOptions(length = length))

    /**
     * A fake app (IF-3, [io.silencelen.andvari.core.app.AppApi]) standing at [scene]: for SwiftUI previews and UI
     * tests. It lives in memory: no network, no keys, nothing stored, and every call gives a fresh one. Its `script`
     * sets up its world and says what happens next.
     *
     * **Nil outside a debug binary.** The fake accepts scripted passwords and verifies nothing, so no release build
     * may hand one to a screen. The binary itself knows which it is: Kotlin/Native compiles
     * `Platform.isDebugBinary` into the framework, true for the debug framework Xcode's Debug configuration links
     * and false for the release framework its Release and Archive configurations link. So there is nothing for a
     * release build to fall back to, and Swift has no `?? fakeApp(…)` to write: the engine-backed API is
     * [io.silencelen.andvari.core.ios.AndvariBridgeApp.app].
     *
     * Note (census, "the fake is never available in the app"): `app-ios/scripts/prepare.sh` links the RELEASE framework
     * for every Xcode configuration, so this answers nil in Debug, previews and UI tests too; it fails safe. To build
     * screens against the fake, Debug must link `linkDebugFramework…` with its own search path.
     */
    @OptIn(ExperimentalNativeApi::class)
    fun fakeApp(scene: FakeScene): FakeAppApi? = if (Platform.isDebugBinary) FakeScenes.at(scene) else null
}
