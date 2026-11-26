package io.silencelen.andvari.desktop.trust

import androidx.compose.runtime.Composable
import androidx.compose.runtime.ProvidableCompositionLocal
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.staticCompositionLocalOf
import io.silencelen.andvari.core.crypto.KeysGoneException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

/**
 * Work a lock overtook (the key fix in the shared code): once a lock or the end of the session wipes the account's
 * keys, the shared code refuses anything more built from them. Its intents answer that as STALE and the vault's content
 * as "not done"; on a few paths it still throws [KeysGoneException]. A throw that reaches the desktop is not a crash,
 * not a failure and never a wrong password: it is the lock. Each place where the desktop launches such work catches it
 * here, logs nothing (not even the exception's class: the kind of work would say what the person was doing), and
 * treats it as the lock ([TrustModel.lockOvertook]).
 *
 * Anything else the shared code throws (once, a vault whose name was the text of its own key made
 * it throw at every sync, redraw and unlock) is a fault ([FaultSink]): caught at the place that started the work, said
 * there as "something went wrong" (naming the vault, for work on one vault), with the exception's class name at most
 * and nothing of its message, shown or logged ([TrustModel.faulted]). Every other vault, the lock and the rest of the
 * app go on. A cancellation is neither: it is passed on, as before.
 */
internal object Overtaken {
    /** Whether [t], or one of its causes, is the shared code's "the keys are gone". */
    fun isLock(t: Throwable): Boolean {
        var c: Throwable? = t
        var depth = 0
        while (c != null && depth++ < 8) {
            if (c is KeysGoneException) return true
            c = c.cause
        }
        return false
    }

    /** [block]'s value, or [locked]'s when a lock overtook it. Anything else is not swallowed. */
    inline fun <T> orLocked(locked: () -> T, block: () -> T): T = try {
        block()
    } catch (t: Throwable) {
        if (!isLock(t)) throw t
        locked()
    }

    /**
     * What [t] is to the place that caught it: the lock ([onLock]), a cancellation (thrown on), or a fault ([onFault],
     * with [vault] when the work was on one vault).
     */
    fun handle(t: Throwable, onLock: () -> Unit, onFault: FaultSink, vault: String?) {
        when {
            isLock(t) -> onLock()
            t is CancellationException -> throw t
            else -> onFault.fault(t, vault)
        }
    }

    /** A person's act (a click, a key, a field's change) that calls the shared code at once: as [handle]. */
    inline fun act(noinline onLock: () -> Unit, onFault: FaultSink, vault: String? = null, block: () -> Unit) {
        try {
            block()
        } catch (t: Throwable) {
            handle(t, onLock, onFault, vault)
        }
    }

    /**
     * A read of the shared code while a screen is drawn: its value, or [fallback] when it threw. A fault is said
     * ([onFault]); the lock is not acted on here (a screen being drawn starts nothing), its own snapshot follows.
     */
    inline fun <T> read(onFault: FaultSink, vault: String?, fallback: T, block: () -> T): T = try {
        block()
    } catch (t: Throwable) {
        if (t is CancellationException) throw t
        if (!isLock(t)) onFault.fault(t, vault)
        fallback
    }
}

/**
 * Where an unexpected exception from the shared code goes: [TrustModel.faulted] in the app. [vault] names the vault
 * whose work it was, or null.
 */
internal fun interface FaultSink {
    fun fault(t: Throwable, vault: String?)
}

/**
 * As [launch], for work a lock can overtake: a [KeysGoneException] ends [block] and runs [onLock] instead of crashing
 * the app; any other exception but a cancellation goes to [onFault] ([vault] names the vault it was for).
 */
internal fun CoroutineScope.launchOvertakable(onLock: () -> Unit, onFault: FaultSink, vault: String? = null, block: suspend CoroutineScope.() -> Unit): Job =
    launch {
        try {
            block()
        } catch (t: Throwable) {
            Overtaken.handle(t, onLock, onFault, vault)
        }
    }

/**
 * The scope the vault's screens launch their work in: a composition's scope whose every [launch] is
 * [launchOvertakable], with the app's way of saying a lock ([TrustModel.lockOvertook], through [LocalLockOvertook]) and
 * a fault ([TrustModel.faulted], through [LocalFault]). The vault screens hold no other scope, so no work of theirs can
 * reach the window as a crash.
 */
internal class WorkScope(private val scope: CoroutineScope, private val onLock: () -> Unit, private val onFault: FaultSink) {
    /** [vault]: the name of the vault the work is on, which a fault names. */
    fun launch(vault: String? = null, block: suspend CoroutineScope.() -> Unit): Job = scope.launchOvertakable(onLock, onFault, vault, block)
}

/** What a screen calls when a lock overtook its work; [TrustApp] provides [TrustModel.lockOvertook]. */
internal val LocalLockOvertook: ProvidableCompositionLocal<() -> Unit> = staticCompositionLocalOf { {} }

/**
 * What a screen calls when the shared code threw something unexpected; [TrustApp] provides [TrustModel.faulted].
 * Outside it (previews, the blocking screens) the exception goes on as before, to the window's failure card.
 */
internal val LocalFault: ProvidableCompositionLocal<FaultSink> = staticCompositionLocalOf { FaultSink { t, _ -> throw t } }

/** A [WorkScope] for this composition: cancelled when the screen leaves, as [rememberCoroutineScope]'s is. */
@Composable
internal fun rememberWorkScope(): WorkScope {
    val scope = rememberCoroutineScope()
    val onLock = LocalLockOvertook.current
    val onFault = LocalFault.current
    return remember(scope, onLock, onFault) { WorkScope(scope, onLock, onFault) }
}

/** [onClick], guarded: what the shared code throws in it is the lock or a fault ([Overtaken.act]), never a crash. */
@Composable
internal fun guarded(vault: String? = null, onClick: () -> Unit): () -> Unit {
    val onLock = LocalLockOvertook.current
    val onFault = LocalFault.current
    return { Overtaken.act(onLock, onFault, vault) { onClick() } }
}

/** As [guarded], for a change that carries a value (a field's text, a tick). */
@Composable
internal fun <T> guardedChange(vault: String? = null, onChange: (T) -> Unit): (T) -> Unit {
    val onLock = LocalLockOvertook.current
    val onFault = LocalFault.current
    return { v -> Overtaken.act(onLock, onFault, vault) { onChange(v) } }
}

/** A read of the shared code while drawing ([Overtaken.read]): [fallback] when it threw, and a fault said for [vault]. */
@Composable
internal fun <T> guardedRead(vault: String?, fallback: T, read: () -> T): T = Overtaken.read(LocalFault.current, vault, fallback, read)
