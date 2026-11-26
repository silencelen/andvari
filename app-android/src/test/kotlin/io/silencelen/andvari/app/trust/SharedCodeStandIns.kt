package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppApi
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CopyLine
import io.silencelen.andvari.core.app.EntryApi
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitWipedNotice
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.flow.StateFlow
import java.lang.reflect.Modifier

/**
 * The notice that a kit shown with a refusal is gone ([AppSnapshot.kitWiped]), as the shared code's fake makes it: the
 * fake plays the engine's lock (the kit is wiped and the notice follows, with its reason line and its way out), so the
 * notice is walked to, never built by hand. Each walk ends at the first screen with the notice on [fake]'s snapshot.
 */
internal object FakeKitNotices {
    private const val NEW_PASSWORD = "a brand new master password"

    /** A phone whose account's session its server ended: the first screen, with that account kept signed out. */
    fun keptSignedOut(): FakeAppApi = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.VAULTS).also {
        it.script.sessionEndedByServer()
        it.signInAgain(requireNotNull(it.snapshot.locked))
        requireNotNull(it.snapshot.keptSignedOut)
    }

    /**
     * On [fake] with an account kept signed out ([keptSignedOut]): a recovery with that account's kit whose commit the
     * server took while this device refused the session for the account kept here; a lock wipes its kit while the kept
     * account still stands. The notice says the kit is gone and why, and names the kept account's sign-out as its way out.
     * [refusal]: the keeper's reason instead (one of the engine's, as `FakeScript.refusedAfterCommit` takes it).
     */
    fun afterRecoveryWhileKept(fake: FakeAppApi = keptSignedOut(), refusal: String? = null): KitWipedNotice = runBlocking {
        val e = fake.entry
        e.openSignIn(entry(fake))
        e.openForgot(entry(fake))
        e.openKitEntry(entry(fake))
        e.submitKit(entry(fake), fake.script.kitOf(fake.script.publicInstance.accounts.values.first()), PayloadSource.SCANNED)
        e.confirmKitRecovery(entry(fake))
        refuse(fake, refusal)
        e.chooseReplacementPassword(entry(fake), NEW_PASSWORD)
        lockedAway(fake)
    }

    /**
     * A recovery's commit refused for another account taken meanwhile (or for the keeper's [refusal]), nothing kept here
     * at the lock: for another account, the plain line.
     */
    fun afterRecovery(
        fake: FakeAppApi = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.REPLACE_PASSWORD),
        refusal: String? = null,
    ): KitWipedNotice = runBlocking {
        refuse(fake, refusal)
        fake.entry.chooseReplacementPassword(entry(fake), NEW_PASSWORD)
        lockedAway(fake)
    }

    private fun refuse(fake: FakeAppApi, refusal: String?) {
        if (refusal == null) fake.script.anotherAccountTakenDuringCommit = true else fake.script.refusedAfterCommit = refusal
    }

    /** A registration's first kit, refused for another account taken meanwhile, nothing kept here at the lock: the plain line. */
    fun afterRegistration(fake: FakeAppApi = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.CREATE_ACCOUNT)): KitWipedNotice = runBlocking {
        fake.script.anotherAccountTakenDuringCommit = true
        fake.entry.createAccount(entry(fake), NewAccountInput("", "Ada", NEW_PASSWORD, true))
        lockedAway(fake)
    }

    private inline fun <reified T : EntryScreen> entry(fake: FakeAppApi): T =
        fake.snapshot.entry as? T ?: error("expected ${T::class.simpleName}, on ${fake.snapshot.entry}")

    private fun lockedAway(fake: FakeAppApi): KitWipedNotice {
        requireNotNull(entry<EntryScreen.Kit>(fake).kit.notKeptLine) { "the kit is shown with its refusal" }
        fake.lock()
        return requireNotNull(fake.snapshot.kitWiped) { "the fake's lock wiped the kit and says so" }
    }
}

/**
 * Stand-ins for what the shared code's fake cannot play yet, for the tests and the drawings only: it has no road for a
 * recovery's commit that did not open ([io.silencelen.andvari.core.app.ReplacePasswordResult.COMMITTED_NOT_OPENED]),
 * and its "Move everything" notice never counts kept deletions. The shared code's objects have internal constructors,
 * so these are rebuilt through their own primary constructor, every other field copied as it is.
 */
internal object StandIns {
    /**
     * A copy of [obj] made through its primary constructor, the fields named in [changes] replaced. The primary
     * constructor's parameters are the class's own instance fields, in their order (each is checked by its type).
     */
    fun <T : Any> rebuilt(obj: T, vararg changes: Pair<String, Any?>): T {
        val c = obj.javaClass
        val fields = c.declaredFields.filter { !Modifier.isStatic(it.modifiers) && !it.isSynthetic }
        val ctor = c.declaredConstructors.single { k ->
            k.parameterTypes.toList() == fields.map { it.type }
        }
        ctor.isAccessible = true
        val asked = changes.toMap()
        require(asked.keys.all { name -> fields.any { it.name == name } }) { "no such field among ${fields.map { it.name }}" }
        val args = fields.map { f ->
            if (f.name in asked) asked[f.name] else f.also { it.isAccessible = true }.get(obj)
        }
        @Suppress("UNCHECKED_CAST")
        return ctor.newInstance(*args.toTypedArray()) as T
    }

    /** A line of the shared code with its values, as only the shared code makes one. */
    fun line(key: CopyKey, vararg values: String): CopyLine {
        val ctor = CopyLine::class.java.getDeclaredConstructor(CopyKey::class.java, List::class.java)
        ctor.isAccessible = true
        return ctor.newInstance(key, values.toList())
    }
}

/**
 * The shared code as the engine behaves, with a notice of another walk ([FakeKitNotices]) carried into a scene the walk
 * does not end in: [inner] (the fake) with [kitWiped] laid over every snapshot,
 * in every phase, until [dismissKitWiped] is called with that very notice (the engine's rule: nothing else takes it), and
 * an [entry] that can be replaced for one intent. It also counts the app's calls of [lock] and of [dismissKitWiped].
 */
internal class EngineLike(private val inner: AppApi) : AppApi by inner {
    var kitWiped: KitWipedNotice? = null
        set(value) {
            field = value
            refresh()
        }

    var locks = 0
        private set

    val dismissed = mutableListOf<KitWipedNotice>()

    /** In place of the fake's entry intents, where a road of the engine is played by hand. */
    var entryOverride: EntryApi? = null

    private val flow = MutableStateFlow(over(inner.snapshot))

    init {
        inner.observe { refresh() }
    }

    private fun over(s: AppSnapshot): AppSnapshot = kitWiped?.let { StandIns.rebuilt(s, "kitWiped" to it) } ?: s

    fun refresh() {
        flow.value = over(inner.snapshot)
    }

    override val snapshot: AppSnapshot get() = over(inner.snapshot)

    override val snapshots: StateFlow<AppSnapshot> get() = flow

    override val entry: EntryApi get() = entryOverride ?: inner.entry

    override fun lock() {
        locks++
        inner.lock()
        refresh()
    }

    override fun dismissKitWiped(notice: KitWipedNotice) {
        dismissed += notice
        if (kitWiped === notice) kitWiped = null
        inner.dismissKitWiped(notice)
    }
}
