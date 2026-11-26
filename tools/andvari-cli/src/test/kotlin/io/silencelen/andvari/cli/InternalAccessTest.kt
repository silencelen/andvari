package io.silencelen.andvari.cli

import java.io.DataInputStream
import java.io.File
import java.util.zip.ZipFile
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The tool takes everything from the shared code's public calls: the module is no friend of :core, so the compiler stops
 * any reach into its internals. This test pins that on what ships, the tool's own compiled classes, in case a friend
 * arrangement ever comes back:
 * - no internal member of :core is named (the compiler gives each one a mangled name, `name$andvari_core`);
 * - none of the constructors the shared code keeps internal is called (those carry no mangled name, so they are listed:
 *   a session, its token pair, a proven key, an opened account and the results that carry one, a password change's new
 *   wrap, the key-taking stores), and none of its internal classes is named;
 * - the module's build script passes the compiler no friend paths;
 * - a session's tokens are taken in one place (the host's session sink) and a session is rebuilt only through the
 *   shared code's public factory.
 */
class InternalAccessTest {
    private data class Ref(val owner: String, val name: String, val descriptor: String)

    /** Every class, field and method reference in one class file's constant pool. */
    private fun refs(f: String, bytes: ByteArray): List<Ref> = DataInputStream(bytes.inputStream()).use { d ->
        require(d.readInt() == 0xCAFEBABE.toInt()) { "$f is not a class file" }
        d.readUnsignedShort(); d.readUnsignedShort()
        val n = d.readUnsignedShort()
        val utf = HashMap<Int, String>()
        val cls = HashMap<Int, Int>()
        val nat = HashMap<Int, Pair<Int, Int>>()
        val members = ArrayList<Pair<Int, Int>>()
        var i = 1
        while (i < n) {
            when (val tag = d.readUnsignedByte()) {
                1 -> utf[i] = d.readUTF()
                3, 4 -> d.readInt()
                5, 6 -> { d.readLong(); i++ }
                7 -> cls[i] = d.readUnsignedShort()
                8, 16, 19, 20 -> d.readUnsignedShort()
                9, 10, 11 -> members += d.readUnsignedShort() to d.readUnsignedShort()
                12 -> nat[i] = d.readUnsignedShort() to d.readUnsignedShort()
                15 -> { d.readUnsignedByte(); d.readUnsignedShort() }
                17, 18 -> { d.readUnsignedShort(); d.readUnsignedShort() }
                else -> error("$f: constant tag $tag")
            }
            i++
        }
        members.map { (c, t) -> val (nm, ds) = nat.getValue(t); Ref(utf.getValue(cls.getValue(c)), utf.getValue(nm), utf.getValue(ds)) } +
            cls.values.map { Ref(utf.getValue(it), "", "") }
    }

    private val classes: Map<String, List<Ref>> by lazy {
        // The tool's main classes, as a directory or as the jar the test fixtures put on the classpath.
        val root = File(Host::class.java.protectionDomain.codeSource.location.toURI())
        if (root.isDirectory) {
            root.walk().filter { it.isFile && it.name.endsWith(".class") }.associate { it.relativeTo(root).path to refs(it.path, it.readBytes()) }
        } else {
            ZipFile(root).use { z ->
                z.entries().asSequence().filter { it.name.endsWith(".class") }.associate { e -> e.name to refs(e.name, z.getInputStream(e).use { it.readBytes() }) }
            }
        }
    }

    private val all: List<Pair<String, Ref>> by lazy { classes.flatMap { (file, rs) -> rs.map { file to it } } }

    private val core = "io/silencelen/andvari/core/"
    private val cli = "io/silencelen/andvari/cli/"

    /** The files (outer class names) that reference [pick]. */
    private fun users(pick: (Ref) -> Boolean): Set<String> =
        all.filter { pick(it.second) }.map { it.first.substringBefore('$').removeSuffix(".class") }.toSet()

    @Test
    fun theToolsShippedClassesReachNothingInternalOfTheSharedCode() {
        assertTrue(classes.keys.any { it.startsWith("${cli}Host") } && classes.size > 20, "the shipped classes were found: ${classes.keys}")

        val mangled = all.filter { (_, r) -> r.name.contains("\$andvari_core") }
        assertEquals(emptyList(), mangled, "an internal member of the shared code is named")

        val internalConstructors = setOf(
            "client/onboard/EstablishedSession", "client/onboard/SessionTokens", "client/account/ReauthKey\$Key",
            "client/onboard/OpenedAccount", "client/onboard/PasswordOpen\$Opened", "client/onboard/AccountOpenResult\$Opened",
            "client/account/WireAccountSettings\$NewWrap", "client/log/StoredVaultLogs", "client/state/StoredAccountState",
        ).map { core + it }.toSet()
        val built = all.filter { (_, r) -> r.name == "<init>" && r.owner in internalConstructors } +
            all.filter { (_, r) -> r.name == "<init>" && r.owner == "${core}client/deletion/WireAccountDeletion" && r.descriptor.contains("KeyPairBytes") }
        assertEquals(emptyList(), built, "a constructor the shared code keeps internal is called")

        val internalClasses = setOf("client/recovery/AssistRequests", "client/onboard/SessionOpener").map { core + it }.toSet()
        val named = all.filter { (_, r) -> r.owner in internalClasses }
        assertEquals(emptyList(), named, "an internal class of the shared code is named")

        // The tests run in the module's own directory: its build script is here, and gives the compiler no friend of :core.
        val script = File("build.gradle.kts")
        assertTrue(script.isFile && script.readText().contains("io.silencelen.andvari.cli.MainKt"), "the module's build script is ${script.absolutePath}")
        assertTrue("-Xfriend-paths" !in script.readText(), "the module's build script passes the compiler friend paths")
    }

    /**
     * The token handover (the shared code's `takeTokens`, once per session) is taken only at the host's session sink, and a
     * session is rebuilt only through the public factory (`EstablishedSession.reopened`): from a saved session, and over the
     * wrap of a password change made in this run.
     */
    @Test
    fun aSessionsTokensAreTakenOnlyAtTheSinkAndASessionIsRebuiltOnlyThroughThePublicFactory() {
        val session = "${core}client/onboard/EstablishedSession"
        assertEquals(setOf("${cli}Host"), users { it.owner == session && it.name == "takeTokens" }, "who takes a session's tokens")
        assertEquals(setOf("${cli}Host", "${cli}SavedSessions"), users { it.owner == "$session\$Companion" && it.name == "reopened" }, "who rebuilds a session")
        assertEquals(setOf("${cli}Host"), users { it.owner == session && it.name == "proveAuthKey" }, "who proves a password against a session's wrap")
    }

    /**
     * Spec 01 §7 in the tool: every re-authentication it builds is [Host.reauth], whose session proves the password on this
     * device first (LocalProofTest). So the engine's `Reauth` is constructed, and its `ReauthSession` implemented, in
     * `Host` alone; every command reaches a re-authentication through `Host.reauth` (directly, or through the engine
     * objects `Host` builds with it: settings, recovery settings, operator routes, `AccountSession.deletion`, `CardOps`).
     */
    @Test
    fun everyReauthenticationTheToolBuildsIsTheHostsLocalProof() {
        val reauthInit = classes.filter { (_, rs) -> rs.any { it.owner == "${core}client/account/Reauth" && it.name == "<init>" } }.keys
        assertEquals(setOf("${cli}Host.class"), reauthInit, "Reauth is built outside Host.reauth")
        val sessions = classes.filter { (_, rs) -> rs.any { it.owner == "${core}client/account/ReauthSession" && it.name == "" } }.keys
        assertTrue(sessions.isNotEmpty() && sessions.all { it.startsWith("${cli}Host") }, "a ReauthSession outside Host: $sessions")
        assertEquals(setOf("${cli}Host", "${cli}AccountSession"), users { it.owner == "${cli}Host" && it.name == "reauth" }, "the callers of Host.reauth")
        // The operator's card changes are the shared code's own path, built in Host alone: nothing else
        // in what ships builds a card, signs one or uploads one or a rotation.
        assertEquals(setOf("${cli}Host"), users { it.owner == "${core}client/account/WireOperatorCards" && it.name == "<init>" }, "who builds the card path")
        assertEquals(emptySet(), users { it.name == "signInstanceCard" || (it.owner == "${core}model/wire/InstanceCardPut" && it.name == "<init>") ||
            (it.owner == "${core}model/wire/InstanceRotationPut" && it.name == "<init>") }, "a card signed or uploaded outside the shared path")
    }

    @Test
    fun noneOfTheInternalsTheEngineReplacedWithPublicCallsIsReachedAnyMore() {
        val retired = all.filter { (_, r) ->
            val name = r.name.substringBefore('$')
            (r.owner.startsWith(core) && name in setOf("getCandidate", "getSigning", "getUvk", "getIdentity", "getWrapKey")) ||
                (r.owner == "${core}client/onboard/EstablishedSession" && name in setOf("getAccessToken", "getRefreshToken", "getAccountKeys"))
        }
        assertEquals(emptyList(), retired, "a retired engine internal is still reached")
    }
}
