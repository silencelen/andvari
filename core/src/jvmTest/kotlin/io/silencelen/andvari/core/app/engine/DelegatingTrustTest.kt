package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.client.pin.InstanceTrust
import java.lang.reflect.Modifier
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * The binding hands the engine's flows a [DelegatingTrust] over the device's `CardTrust`. A member of [InstanceTrust]
 * with a default body that it does not forward answers the default instead of the device's trust: `isBakedOrigin`
 * said false at the baked origin and `setupVerdictAtBaked` said `no_baked_instance`. Every member must be forwarded,
 * including the ones the engine adds later with a default.
 */
class DelegatingTrustTest {
    @Test fun everyMemberOfInstanceTrustIsForwarded() {
        val missing = InstanceTrust::class.java.methods
            .filter { !Modifier.isStatic(it.modifiers) && it.declaringClass == InstanceTrust::class.java }
            .filter { m ->
                runCatching { DelegatingTrust::class.java.getDeclaredMethod(m.name, *m.parameterTypes) }.isFailure
            }
            .map { it.name }
        assertTrue(missing.isEmpty(), "DelegatingTrust does not forward: $missing")
    }
}
