package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.TestServer
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The name an account goes by in its links, on a home where the account was not made: the server keeps none, so the
 * tool asks for it at a terminal, takes it as `--name` without one, keeps it for that account, and never makes it up
 * from the address. Against the real server: a second home of each of two accounts makes a link and answers one, each
 * after giving the name; without a name and without a terminal, exit 2 with the sentence and nothing of the link sent.
 */
class LinkNameTest {
    private val ada = "ada@example.org"
    private val bo = "bo@example.org"

    /** What [p] passed since [mark] that touches a link: the requests a stop for the name must not make. */
    private fun linkRequests(p: LyingProxy, mark: Int) = p.seen.drop(mark).filter { it.contains("/api/v1/links") }

    @Test fun aSecondHomeMakesALinkAndAnswersOneEachAfterGivingTheName() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val ada1 = w.account(ada)
                w.account(bo)
                // The same two accounts signed in on homes where they were not made.
                val ada2 = File(w.tmp, "ada-second")
                val bo2 = File(w.tmp, "bo-second")
                w.run(ada2, "sign-in", "--email", ada, "--trust-card", w.card0, dial = p.address).ok()
                w.run(bo2, "sign-in", "--email", bo, "--trust-card", w.card0, dial = p.address).ok()

                // No name and no terminal: exit 2, the sentence, and nothing of a link sent.
                var mark = p.seen.size
                val noName = w.run(ada2, "link", "create", dial = p.address)
                assertEquals(2, noName.code, noName.out + noName.err)
                assertTrue(noName.err.contains("[${LinkName.KEY_NEEDED}]: " + fill(LinkName.NEEDED, ada)), noName.err)
                assertEquals(emptyList(), linkRequests(p, mark), "nothing of a link was sent")

                // Something that cannot be a name: exit 2, nothing sent, nothing kept.
                mark = p.seen.size
                val notAName = w.run(ada2, "link", "create", "--name", " Ada", dial = p.address)
                assertEquals(2, notAName.code, notAName.out + notAName.err)
                assertTrue(notAName.err.contains(LinkName.NOT_A_NAME), notAName.err)
                assertEquals(emptyList(), linkRequests(p, mark))
                assertEquals(2, w.run(ada2, "link", "create", dial = p.address).code, "nothing was kept")

                // With the name: the link is made, and the name is kept for the account on this home.
                val url = w.run(ada2, "link", "create", "--name", "Ada L", dial = p.address).ok().lines().last { it.contains("://") }.trim()
                assertTrue(w.run(ada2, "link", "create", dial = p.address).ok().contains("://"), "the name was kept: nothing asked again")

                // The other side answers on its second home: first without a name (nothing of the link sent), then with one.
                val linkFile = File(w.tmp, "ada-link.txt").also { it.writeText(url) }
                mark = p.seen.size
                val unnamed = w.run(bo2, "link", "open", "--link-file", linkFile.path, dial = p.address)
                assertEquals(2, unnamed.code, unnamed.out + unnamed.err)
                assertTrue(unnamed.err.contains(fill(LinkName.NEEDED, bo)), unnamed.err)
                assertEquals(emptyList(), linkRequests(p, mark), "the link was not even read")
                val answered = w.run(bo2, "link", "open", "--link-file", linkFile.path, "--name", "Bo B", dial = p.address)
                assertEquals(0, answered.code, answered.out + answered.err)
                assertTrue(answered.err.contains("“Ada L”"), "the creator's chosen name: ${answered.err}")
                assertTrue(answered.out.contains("answered: contact"), answered.out)

                // The creator processes the answer and sees the other side's chosen name, never an address's first part.
                val answers = w.run(ada2, "link", "answers", dial = p.address).ok()
                assertTrue(answers.contains("“Bo B”"), answers)
                assertFalse(answers.contains("“bo”"), answers)

                // The home where the account was made keeps the name it registered with, and asks nothing.
                assertTrue(w.run(ada1, "link", "create").ok().contains("://"))
            }
        }
    }

    /** At a terminal the name is asked for once; given, nothing is asked; without a terminal there is none. */
    @Test fun theNameIsAskedForAtATerminalOnly() {
        val asked = ArrayList<String>()
        val ask = { answer: String? -> { q: String -> asked += q; answer } }
        assertNull(LinkName.read(null, null, ada), "no terminal: none, nothing asked")
        assertEquals("Ada L", LinkName.read(null, ask("  Ada L "), ada), "the answer, without the spaces around it")
        assertEquals(listOf(fill(LinkName.PROMPT, ada)), asked)
        asked.clear()
        assertEquals("Given", LinkName.read("Given", ask("asked"), ada))
        assertEquals(emptyList(), asked)
        assertFalse(LinkName.isName(" Ada") || LinkName.isName("") || LinkName.isName("a".repeat(65)))
        assertTrue(LinkName.isName("Ada L"))
    }
}
