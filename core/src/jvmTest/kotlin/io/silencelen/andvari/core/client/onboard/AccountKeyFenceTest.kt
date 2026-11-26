package io.silencelen.andvari.core.client.onboard

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Source checks of the rule a lock depends on: no code outside the opened account holds one of its key
 * arrays, and every key is read inside its guard ([GuardedKey.use], [GuardedKeyPair.use], the vault-key lend
 * `withKey`), where a wipe cannot cut in and a wiped account refuses. The guard's block cannot suspend (the compiler
 * refuses a wait inside it), and the guard refuses at run time a block that answers the key ([KeyEscape]); these checks
 * hold the rest: the account's key fields stay guarded, and no guarded lend in shipped source hands the key itself, a
 * copy or its text out of the guard, by its answer or by an assignment.
 *
 * What this is: a net for the commonest slips, not a proof. It reads source with patterns and
 * a brace counter, not a compiler: a key passed to a helper that keeps it, stored in an object of the block's own
 * making, or carried out by a shape not listed in [AccountKeyFence] passes it. `KeyEscapesTest` lists the
 * nine escapes and which of the two halves (this check, or the guard at run time) stops each.
 */
class AccountKeyFenceTest {
    private val repo = File(System.getProperty("andvari.vectors.dir") ?: error("andvari.vectors.dir not set")).resolve("../..").canonicalFile

    /** Every Kotlin source that ships, and the tools that are friends of `:core`. */
    private val roots = listOf("core/src/commonMain", "core/src/jvmMain", "core/src/jvmShared", "core/src/androidMain", "core/src/iosMain", "tools/andvari-cli/src/main")

    private fun sources(): List<File> = roots.map { repo.resolve(it) }.filter { it.isDirectory }
        .flatMap { root -> root.walkTopDown().filter { it.isFile && it.extension == "kt" }.toList() }

    private fun rel(f: File) = f.relativeTo(repo).path

    @Test fun theOpenedAccountsKeyFieldsAreGuarded() {
        val text = repo.resolve("core/src/commonMain/kotlin/io/silencelen/andvari/core/client/onboard/AccountOpen.kt").readText()
        val body = text.substringAfter("class OpenedAccount internal constructor(").substringBefore("\n/** What [AccountOpen.openWithPassword]")
        for (name in listOf("uvk", "identity", "signing", "personalVk")) {
            val decl = Regex("""(?m)^\s*(?:internal |private |public )?(?:val|var) $name\b[^\n]*""").findAll(body).map { it.value.trim() }.toList()
            assertEquals(1, decl.size, "one declaration of $name in OpenedAccount: $decl")
            assertTrue("Guarded" in decl.single(), "OpenedAccount.$name is a guarded key, never a bare array: ${decl.single()}")
        }
        val header = body.substringBefore(") {")
        assertTrue(Regex("""(?:val|var)\s+(uvk|identity|signing|personalVk)\s*:""").find(header) == null,
            "the constructor takes the arrays but keeps none as a property: $header")
    }

    @Test fun theGuardedKeyArraysAreReadOnlyInsideTheirGuard() {
        val text = repo.resolve("core/src/commonMain/kotlin/io/silencelen/andvari/core/client/onboard/GuardedKeys.kt").readText()
        // `key` and `pair` are private and read only in the wipe hook, in `use` (with its escape check) and in `copyOut`.
        fun code(s: String) = s.lines().filterNot { it.trim().let { l -> l.startsWith("*") || l.startsWith("/**") || l.startsWith("//") } }.joinToString("\n")
        val keyReads = Regex("""\bkey\b(?!:)""").findAll(code(text.substringAfter("class GuardedKey internal constructor").substringBefore("companion object"))).count()
        val pairReads = Regex("""\bpair\b(?!:)""").findAll(code(text.substringAfter("class GuardedKeyPair internal constructor").substringBefore("companion object"))).count()
        assertTrue(Regex("""private val key: ByteArray""").containsMatchIn(text) && Regex("""private val pair: KeyPairBytes""").containsMatchIn(text))
        assertTrue(keyReads <= 3, "GuardedKey reads its array only in its wipe hook and its use ($keyReads reads)")
        assertTrue(pairReads <= 5, "GuardedKeyPair reads its pair only in its wipe hook, its public key and its use ($pairReads reads)")
    }

    /**
     * The floor tests a signing secret's seed half in place (a copy of it would be the
     * identity seed, outliving the lock), and the guard's escape check decodes an answer instead of encoding the key, so
     * no text form of a key is ever built.
     */
    @Test fun theFloorAndTheEscapeCheckCopyNoKeyAndBuildNoTextOfOne() {
        fun code(s: String) = s.lines().filterNot { it.trim().let { l -> l.startsWith("*") || l.startsWith("/**") || l.startsWith("//") } }
            .joinToString("\n") { it.substringBefore(" // ") }
        val floor = code(repo.resolve("core/src/commonMain/kotlin/io/silencelen/andvari/core/crypto/KeysGone.kt").readText())
        assertTrue(Regex("""\.copyOf(Range)?\(""").find(floor) == null, "the floor copies no key")
        val escape = code(repo.resolve("core/src/commonMain/kotlin/io/silencelen/andvari/core/client/onboard/GuardedKeys.kt").readText()
            .substringAfter("internal object KeyEscape"))
        for (built in listOf("Base64.", "toHex", "toB64", ".copyOf", ".encode(", "String(", "textForms")) {
            assertTrue(built !in escape, "the escape check builds no copy or text of a key: found $built")
        }
    }

    /**
     * No guarded lend in shipped source answers the key, a copy or its text, or assigns it to anything, on one line or
     * many ([AccountKeyFence] lists the shapes). No copy leaves at all.
     */
    @Test fun noGuardedLendHandsTheKeyOutOfTheGuard() {
        val found = ArrayList<String>()
        for (f in sources()) found += AccountKeyFence.scan(f.readText()).map { "${rel(f)}:$it" }
        assertEquals(emptyList(), found, "a guarded lend hands the key out of the guard")
    }

    /**
     * No copy of a key leaves the guard in shipped source: quick unlock's enrolment, the last
     * caller of the old `copyOut()`, now asks the person's consent first and seals inside the guarded use after the
     * prompt, so `GuardedKey` has no way to hand out a copy, and nothing calls one. Tests take theirs through their own
     * holder (`KeyCopies.kt`).
     */
    @Test fun noKeyIsCopiedOutOfTheGuard() {
        val found = ArrayList<String>()
        for (f in sources()) f.readLines().forEachIndexed { i, line -> if (Regex("""\bcopyOut\s*\(""").containsMatchIn(line)) found += "${rel(f)}:${i + 1}: ${line.trim()}" }
        assertEquals(emptyList(), found, "a copy of a key out of the guard in shipped source")
    }

    /**
     * Quick unlock's confirmation of presence (`QuickUnlockKeeper.confirmPresence`) opens a sealed copy of the account's
     * key: from the moment it is opened until it is wiped it stays in the guard. The opened array is taken from the
     * platform's answer once; outside its wipes it is read only as the second argument of the constant-time comparison,
     * inside the account key's guarded use, which also wipes it; an outer `finally` wipes it on every other path. Nothing
     * in the call keeps, copies, encodes, stores, sends or unlocks with it.
     */
    @Test fun quickUnlocksPresenceCheckKeepsTheOpenedKeyInTheGuard() {
        fun code(s: String) = s.lines().filterNot { it.trim().let { l -> l.startsWith("*") || l.startsWith("/**") || l.startsWith("//") } }
            .joinToString("\n") { it.substringBefore(" // ") }
        val text = repo.resolve("core/src/commonMain/kotlin/io/silencelen/andvari/core/client/session/QuickUnlockKeeper.kt").readText()
        assertTrue("suspend fun confirmPresence(" in text, "the call is where this check reads it")
        val body = code(text.substringAfter("suspend fun confirmPresence(").substringBefore("private var presenceUp"))
        assertEquals(1, Regex("""\br\.secret\b""").findAll(body).count(), "the opened array is taken from the answer once")
        assertTrue(Regex("""val opened = r\.secret\s*\n""").containsMatchIn(body), "into one local, and nothing else")
        val reads = Regex("""\bopened\b(\s*\.\s*\w+\s*\([^()]*\))?""").findAll(body).map { it.value.replace(Regex("""\s"""), "") }.toList()
        val other = reads.filterNot { it == "opened" || it == "opened.fill(0)" }
        assertEquals(emptyList(), other, "the opened array is only compared and wiped")
        assertEquals(1, Regex("""Bytes\.ctEquals\(key, opened\)""").findAll(body).count(), "compared once, in constant time, with the guard's key")
        // The bare `opened` reads: its declaration and the comparison's argument, nothing else.
        assertEquals(2, reads.count { it == "opened" }, "declared once and compared once: $reads")
        val lend = body.substringAfter("open.account.uvk.use { key ->")
        assertTrue(body.contains("open.account.uvk.use { key ->"), "the comparison is inside the account key's guarded use")
        val inside = lend.substringBefore("catch (e: io.silencelen.andvari.core.crypto.KeysGoneException)")
        assertTrue("Bytes.ctEquals(key, opened)" in inside && "opened.fill(0)" in inside, "compared and wiped inside the use")
        assertTrue(Regex("""opened\.fill\(0\)""").findAll(body).count() >= 2, "wiped inside the use and again on every other path")
        assertTrue(Regex("""}\s*finally\s*\{\s*opened\.fill\(0\)\s*}""").containsMatchIn(body), "the outer finally wipes it")
        for (gone in listOf("copyOf", "toB64", "toHex", "encode", "secure.set", "state.set", ".call(", "unlockWithUvk", "passwordUsed", "clientFor", "transport")) {
            assertTrue(gone !in body, "the presence check does not use $gone")
        }
    }
}

/**
 * The pattern half of the fence, also run by `KeyEscapesTest` on its escapes. A lend is `.use {`, `.use(`,
 * `?.use {` or `withKey(…) {`; its body is found by counting braces, so a body that starts on the next line is read.
 * Flagged in a body whose parameter is `p` (`it` when it names none):
 * - an answer (its last statement) that is `p`, or `p` followed only by `.privateKey`, `.copyOf(…)`, `.copyOfRange(…)`,
 *   `.clone()`, `.toList()`, `.also {…}`, `.apply {…}` or `.let { it }`;
 * - an answer that is the text of `p`: `toB64`, `toB64Bytes`, `toHexLower`, `toHexUpper` or `encode` of `p` or of
 *   `p.privateKey`;
 * - an assignment, `+=`, `add(…)` or `put(…)` of `p` or of one of the shapes above, anywhere in the body;
 * - a lend of a function reference that copies (`use(ByteArray::copyOf)`).
 * Not flagged: a key handed to a function that keeps it, or wrapped in an object; a shape not listed here.
 */
internal object AccountKeyFence {
    private val lend = Regex("""(?:\?\.|\.)use\s*\{|\bwithKey\s*\(""")
    private val methodRef = Regex("""(?:\.use\s*\(|\bwithKey\s*\([^()]*,)\s*ByteArray::(copyOf|copyOfRange|clone)""")

    /** "line: snippet" for every escape in [text]. */
    fun scan(text: String): List<String> {
        val out = ArrayList<String>()
        fun lineOf(at: Int) = text.substring(0, at).count { it == '\n' } + 1
        fun snippet(at: Int) = text.substring(at).lineSequence().first().trim()
        methodRef.findAll(text).forEach { out += "${lineOf(it.range.first)}: ${snippet(it.range.first)}" }
        for (m in lend.findAll(text)) {
            val open = if (m.value.endsWith("{")) m.range.last else lambdaAfterCall(text, m.range.last) ?: continue
            val body = bodyAt(text, open) ?: continue
            if (escapes(body)) out += "${lineOf(m.range.first)}: ${snippet(m.range.first)}"
        }
        return out.distinct()
    }

    /** The `{` of the trailing lambda after the call whose `(` is at [paren], or null (a lend given a reference). */
    private fun lambdaAfterCall(text: String, paren: Int): Int? {
        var depth = 0
        var i = paren
        while (i < text.length) {
            when (text[i]) {
                '(' -> depth++
                ')' -> { depth--; if (depth == 0) break }
            }
            i++
        }
        var j = i + 1
        while (j < text.length && text[j].isWhitespace()) j++
        return if (j < text.length && text[j] == '{') j else null
    }

    /** The text between the `{` at [open] and its matching `}`. */
    private fun bodyAt(text: String, open: Int): String? {
        var depth = 0
        for (i in open until text.length) {
            when (text[i]) {
                '{' -> depth++
                '}' -> { depth--; if (depth == 0) return text.substring(open + 1, i) }
            }
        }
        return null
    }

    private fun escapes(rawBody: String): Boolean {
        val header = Regex("""^\s*(\w+)\s*->""").find(rawBody)
        val p = header?.groupValues?.get(1) ?: "it"
        val body = if (header != null) rawBody.substring(header.range.last + 1) else rawBody
        val q = Regex.escape(p)
        val chain = """(?:\s*\.\s*(?:privateKey|copyOf\([^()]*\)|copyOfRange\([^()]*\)|clone\(\)|toList\(\)|also\s*\{[^{}]*}|apply\s*\{[^{}]*}|let\s*\{\s*(?:\w+\s*->\s*\w+|it)\s*}))*"""
        val key = """$q\b$chain"""
        val text = """(?:\w+\.)?(?:toB64|toB64Bytes|toHexLower|toHexUpper|encode)\(\s*$q(?:\s*\.\s*privateKey)?\s*\)"""
        val answer = Regex("""^\s*(?:$key|$text)\s*$""")
        val assign = Regex("""(?:[^=!<>]=|\+=)\s*(?:$key|$text)\s*(?:$|[;\n}])|\b(?:add|put)\s*\([^()]*?\b$key\s*\)""")
        return answer.matches(lastStatement(body)) || assign.containsMatchIn(body)
    }

    /** The body's last top-level statement (split at depth-0 newlines and semicolons). */
    private fun lastStatement(body: String): String {
        var depth = 0
        var start = 0
        var last = ""
        for (i in body.indices) {
            when (body[i]) {
                '(', '{', '[' -> depth++
                ')', '}', ']' -> depth--
                '\n', ';' -> if (depth == 0) {
                    body.substring(start, i).takeIf { it.isNotBlank() }?.let { last = it }
                    start = i + 1
                }
            }
        }
        body.substring(start).takeIf { it.isNotBlank() }?.let { last = it }
        return last
    }
}
