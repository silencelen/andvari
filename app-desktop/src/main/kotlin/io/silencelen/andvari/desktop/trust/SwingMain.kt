package io.silencelen.andvari.desktop.trust

import kotlinx.coroutines.CoroutineDispatcher
import java.awt.EventQueue
import kotlin.coroutines.CoroutineContext

/**
 * The desktop's main dispatcher: the AWT event dispatch thread, where Compose for Desktop draws and handles input.
 *
 * `Dispatchers.Main` does not exist in this app. It needs `kotlinx-coroutines-swing`, which Compose 1.7.3 does not
 * bring and which is not a dependency here, so the first intent the window launched on it threw "Module with the Main
 * dispatcher is missing" (found by the first run of the new path under a virtual display). The engine and the model
 * run here instead.
 */
internal object SwingMain : CoroutineDispatcher() {
    override fun isDispatchNeeded(context: CoroutineContext): Boolean = !EventQueue.isDispatchThread()

    override fun dispatch(context: CoroutineContext, block: Runnable) = EventQueue.invokeLater(block)

    override fun toString(): String = "SwingMain"
}
