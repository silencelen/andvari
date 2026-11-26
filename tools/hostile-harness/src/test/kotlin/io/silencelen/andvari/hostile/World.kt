package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.AccountSession
import io.silencelen.andvari.cli.HeldSession
import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.cli.e2e.accept
import io.silencelen.andvari.cli.e2e.connect
import io.silencelen.andvari.cli.e2e.ok
import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.core.client.items.ItemFailure
import io.silencelen.andvari.core.client.items.ItemRefusal
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.onboard.Registration
import io.silencelen.andvari.core.client.onboard.SignIn
import io.silencelen.andvari.core.client.pin.FirstPin
import io.silencelen.andvari.core.client.pin.TrustGateWording
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.hostile.proxy.HostileBell
import io.silencelen.andvari.hostile.proxy.HostileProxy
import kotlinx.coroutines.runBlocking
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * One scenario's world: the REAL server in its test mode, the hostile proxy in front of it, and devices that each dial
 * the proxy through a listener of their own (their tag). The instance's origin names a port that answers nothing (each
 * connection is closed) unless a test asks the proxy to ([originListener]); every device reaches the server only through the proxy, so the recording
 * is complete: what is not in [proxy]'s log never left a device.
 *
 * A device is the CLI's [Host]: the engine of `:core` over the JVM's HTTP client, with its own device state.
 */
class World(
    kind: String = "private",
    mode: String? = null,
    extraSetup: List<String> = emptyList(),
    extraEnv: Map<String, String> = emptyMap(),
) : AutoCloseable {
    // A scenario signs one account in many times from one address (each a different lie); the per-address login limit
    // of a real deployment (5 a minute, by the server's clock, which a test holds still) would cut that short.
    //
    // No port is picked first and bound later: the origin's port is the test server's relay, bound to port 0 at its
    // construction and held to the end; the server's own listener and every listener of the proxy bind port 0 too. The
    // relay is pointed at nothing (`interpose(0)`: it closes each connection), so a device that dials the origin itself
    // reaches nothing unless a test routes the origin to the proxy ([originListener]).
    val server = TestServer(kind, mode, extraSetup, mapOf("ANDVARI_LOGIN_RATE_PER_MIN" to "100000") + extraEnv).also { it.interpose(0) }
    val origin: String get() = server.origin
    val proxy = HostileProxy({ server.serverAddress }, server.origin.substringAfter("://"))

    private val tagOf = HashMap<Host, String>()

    /**
     * A fresh device that dials the proxy as [tag]. With a [bell], its event socket goes to that hostile bell instead
     * (the proxy cannot upgrade a socket); everything else still goes through the proxy.
     */
    fun device(tag: String, name: String = tag, bell: HostileBell? = null): Host =
        (if (bell == null) server.device(name, dial = proxy.dial(tag))
        else Host(MemoryDeviceState(), MemoryDeviceState(), server::now, http = bell.clientFor(origin, proxy.dial(tag)), deviceName = name))
            .also { tagOf[it] = tag }

    fun tag(h: Host): String = tagOf.getValue(h)

    /**
     * The same device after a restart: new engine objects over the SAME durable device state, and the sessions it held
     * (the CLI persists those through `Host.onSession`; a test device hands them over here). Nothing kept only in
     * memory survives, which is the point: whatever must outlive a restart has to be in the device state.
     */
    fun restarted(h: Host): Host {
        val tag = tag(h)
        val next = Host(h.state, h.secure, server::now, http = server.httpFor(proxy.dial(tag)), deviceName = h.deviceName)
        h.session(origin)?.let { next.adopt(HeldSession(it.session, it.accessToken, it.refreshToken)) }
        tagOf[next] = tag
        return next
    }

    /**
     * The proxy also answers at the origin's own port, as [tag]: for a device that dials the origin directly. The proxy's
     * listener for [tag] binds port 0 and the test server's relay on the origin's port hands it every connection
     * ([TestServer.interpose]). Answers the origin.
     */
    fun originListener(tag: String = "origin"): String {
        server.interpose(proxy.dial(tag).substringAfterLast(':').toInt())
        return origin
    }

    private val registrations = HashMap<Host, Registration.Registered>()

    /** What [h]'s registration answered: its user id and the recovery kit it revealed (the kit's text outlives the confirmation). */
    fun registration(h: Host): Registration.Registered = registrations.getValue(h)

    /** The operator registers through the setup link, signs card 0 and pins it. */
    suspend fun operator(tag: String = "op"): Host =
        device(tag).also { registrations[it] = Steps.registerThrough(it, origin, server.setupLink, "$tag@example.org") }

    /** A member registers through an enrol link (its Trust Gate confirmed). */
    suspend fun member(tag: String, email: String = "$tag@example.org", bell: HostileBell? = null): Host =
        device(tag, bell = bell).also { registrations[it] = Steps.registerThrough(it, origin, Steps.enrolLink(server), email, trustGate = true) }

    /** The requests of [tag] since [mark] on a route that carries a value derived from an account's secrets (design §4.4's password rule). */
    fun secretSends(tag: String, mark: Int = 0) = proxy.requests(tag = tag, since = mark).filter { it.route in SECRET_ROUTES }

    /** A fresh device whose person typed the address and confirmed the Trust Gate: it holds a password pin and no account. */
    suspend fun pinnedDevice(tag: String): Host = device(tag).also { d ->
        val gate = assertIs<FirstPin.NeedsTrustGate>(d.trust.beginTrustGate(origin, TrustGateWording.TYPED_ADDRESS), "the typed address shows the Trust Gate")
        assertIs<FirstPin.Pinned>(d.trust.confirmTrustGate(gate.confirm))
    }

    /** A second device of [email]'s account: the typed address through the Trust Gate, then the password (design §8.5). */
    suspend fun passwordDevice(tag: String, email: String): Host = pinnedDevice(tag).also { d ->
        val signedIn = d.onboarding(origin).signIn(email, Steps.PASSWORD.toCharArray())
        assertIs<SignIn.SignedIn>(signedIn, "password sign-in of $email on $tag: $signedIn")
    }

    fun account(h: Host): AccountSession = h.account(origin) ?: error("${tagOf[h]} is not signed in")

    /**
     * [owner] and [member] connect (both type the other's code); [owner] creates a shared vault, adds [member] as
     * [role], and [member] accepts. Answers the vault id; its log is then `genesis` (0), `add` (1).
     */
    suspend fun sharedVault(owner: Host, member: Host, name: String = "Family", role: String = "writer"): String {
        connect(owner, member, origin)
        val a = account(owner)
        val b = account(member)
        a.synced()
        val v = a.ok(null, LogAction.Create(name))
        a.ok(v, LogAction.Add(b.userId, role))
        accept(b, v, name)
        return v
    }

    /** The requests [h] sent on [route] since [mark]. */
    fun sent(h: Host, route: WireRoute, mark: Int = 0) = proxy.requests(route, tag(h), mark)

    /** Run a scenario; a failure carries the end of the proxy's recording, and a rule that threw fails the test. */
    fun <T> run(block: suspend World.() -> T): T = runBlocking {
        val result = try {
            block()
        } catch (e: Throwable) {
            throw AssertionError("${e.message}\n--- the proxy's recording ends:\n${proxy.tail()}", e)
        }
        assertTrue(proxy.failures.isEmpty(), "a proxy rule failed: ${proxy.failures.joinToString("\n")}")
        result
    }

    private val others = ArrayList<World>()

    /**
     * A second instance beside this one, for **A** lies that need another instance's real answers: its own real server,
     * proxy and devices, closed with this world. Its devices never dial this world's proxy, and this world's devices never
     * reach it; a rule here serves one of its recorded answers ([realAnswer]) for one of this world's routes.
     */
    fun another(kind: String = "private", extraSetup: List<String> = emptyList(), mode: String? = null, extraEnv: Map<String, String> = emptyMap()): World =
        World(kind, mode, extraSetup, extraEnv).also { synchronized(others) { others += it } }

    /** What this world's real server answered to [tag]'s latest request on [route] (the recording's upstream answer). */
    fun realAnswer(route: WireRoute, tag: String): io.silencelen.andvari.hostile.proxy.Resp =
        proxy.last(route, tag)?.upstream ?: error("$tag sent no $route that reached the real server")

    override fun close() {
        synchronized(others) { others.toList() }.forEach { runCatching { it.close() } }
        proxy.close()
        server.close()
    }

    companion object {
        /**
         * The routes whose request carries a secret-derived value of an EXISTING account (design §4.4: prelogin for its
         * email, `authKey`, `currentAuthKey`, `recoveryAuthKey`, a two-step code), or a device-link step that leads to
         * one (§8.2 step 0: no prelogin, claim or pickup before the pin), or an assisted-recovery request for it.
         * `register` is not here: creating an account sends nothing of an existing one. Every route spec 03 §0.2 marks
         * † (session† and operator†: a `currentAuthKey` in the body) is here; [SecretRoutesTest] holds the list to that.
         */
        val SECRET_ROUTES: Set<WireRoute> = setOf(
            WireRoute.PRELOGIN, WireRoute.LOGIN,
            WireRoute.DEVICE_LINK_CLAIM, WireRoute.DEVICE_LINK_POLL, WireRoute.DEVICE_LINK_REVEAL, WireRoute.DEVICE_LINK_PICKUP,
            WireRoute.RECOVERY_SELF_VERIFY, WireRoute.RECOVERY_SELF_COMMIT,
            WireRoute.RECOVERY_REQUEST_CREATE, WireRoute.RECOVERY_REQUEST_VERIFY, WireRoute.RECOVERY_REQUEST_POLL, WireRoute.RECOVERY_REQUEST_COMMIT,
            WireRoute.PASSWORD_CHANGE, WireRoute.ACCOUNT_RECOVERY_PUT, WireRoute.RECOVERY_SELF_SETUP, WireRoute.DEVICE_REVOKE, WireRoute.REQUIRE_LINK,
            WireRoute.ACCOUNT_DELETE,
            // Two-step sign-in: setting it up carries a password proof (`currentAuthKey`, when already enrolled) and a code.
            WireRoute.TOTP_SETUP, WireRoute.TOTP_CONFIRM, WireRoute.TOTP_DISABLE,
            // The operator's † routes, each with the operator's `currentAuthKey`.
            WireRoute.INSTANCE_CARD_PUT, WireRoute.INSTANCE_ROTATION_PUT,
            WireRoute.ADMIN_ACCOUNT_DISABLE, WireRoute.ADMIN_ACCOUNT_ENABLE, WireRoute.ADMIN_ACCOUNT_DELETE, WireRoute.ADMIN_DEVICE_REVOKE,
            WireRoute.ADMIN_QUOTA, WireRoute.ADMIN_POLICY_PUT, WireRoute.ADMIN_ESCROW, WireRoute.ADMIN_RECOVERY_FULFIL,
        )
    }
}

/**
 * The item engine's refusal of a write under a vault whose log does not let this device write (design §3.6: frozen,
 * failed, withheld, or a reader), as the headless host words it. Nothing was sent.
 */
val READ_ONLY: String = AccountSession.code(ItemFailure.NotAllowed(ItemRefusal.VAULT_READ_ONLY))

/** A scenario in a world of its own. It answers nothing, so `@Test fun x() = world { … }` is a test method. */
fun world(
    kind: String = "private",
    mode: String? = null,
    extraSetup: List<String> = emptyList(),
    extraEnv: Map<String, String> = emptyMap(),
    block: suspend World.() -> Unit,
) {
    World(kind, mode, extraSetup, extraEnv).use { it.run(block) }
}
