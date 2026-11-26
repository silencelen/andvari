package io.silencelen.andvari.cli.e2e

import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.core.client.link.RecipientStep
import io.silencelen.andvari.core.client.onboard.KitConfirm
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.onboard.Registration
import io.silencelen.andvari.core.client.onboard.RegistrationAuth
import io.silencelen.andvari.core.client.onboard.RegistrationForm
import io.silencelen.andvari.core.client.onboard.RevealedKit
import io.silencelen.andvari.core.client.onboard.WireOnboarding
import io.silencelen.andvari.core.client.pin.GateEntry
import kotlin.test.assertEquals
import kotlin.test.assertIs

/** Steps the journeys share. Every assertion names what the engine and the server must agree on. */
object Steps {
    const val PASSWORD = "correct horse Battery 9 staple"

    fun form(email: String, name: String = email.substringBefore('@'), password: String = PASSWORD, recovery: RecoveryChoiceKind = RecoveryChoiceKind.PRIVATE) =
        RegistrationForm(email, name, password.toCharArray(), true, recovery, "cli", "cli")

    /** Type back the three groups the engine asks for; the server records the confirmation. */
    suspend fun confirmKit(o: WireOnboarding, kit: RevealedKit) {
        val asked = o.kitChallenge(kit)
        val typed = asked.associateWith { kit.groups[it - 1] }
        assertEquals(KitConfirm.Confirmed, o.confirmKit(kit, typed), "the kit confirmation is recorded")
    }

    /** Open [link] on [d] and register [email] through it: setup, enrol or register, whichever the link is. */
    suspend fun registerThrough(d: Host, origin: String, link: String, email: String, trustGate: Boolean = false): Registration.Registered {
        var step = d.links.open(link, GateEntry.PASTE_INVITE)
        if (trustGate) {
            assertIs<RecipientStep.TrustGate>(step, "an enrol link asks for the Trust Gate first: $step")
            step = d.links.proceed(step)
        }
        val confirm = assertIs<RecipientStep.Confirm>(step, "the link opens to its sign-up form: $step")
        val auth = when (confirm.offer.kind) {
            "setup" -> RegistrationAuth.SetupLink(confirm)
            "enrol" -> RegistrationAuth.EnrolLink(confirm)
            else -> RegistrationAuth.RegisterLink(confirm)
        }
        val o = d.onboarding(origin)
        val f = form(email)
        val reg = o.register(auth, f)
        val ok = assertIs<Registration.Registered>(reg, "registration through the ${confirm.offer.kind} link: $reg")
        d.rememberName(origin, ok.userId, f.displayName)
        confirmKit(o, ok.kit)
        return ok
    }

    private fun sent(s: TestServer, to: String, template: String) =
        s.mail().filter { it["to"]?.toString()?.trim('"') == to && it["template"]?.toString()?.trim('"') == template }

    /**
     * How many [template] mails to [to] the server has sent, once every one it has queued so far is in the sink: the
     * server's sender worker writes a mail some seconds after the request that queued it, so a count taken at once could
     * miss one still on its way. That makes it a sound baseline for [awaitMail]'s `seen` (no earlier mail arrives after
     * it and passes for the next one) and a sound "none was sent" (none is queued either). Waits at most [timeoutMs].
     */
    fun mailCount(s: TestServer, to: String, template: String, timeoutMs: Long = Await.DEFAULT_MS): Int {
        Await.until("the server's outbox to hand every queued $template mail to $to to the sink", timeoutMs, { s.mailSinkText() }) {
            if (s.queuedMail(to, template) == 0L) Unit else null
        }
        return sent(s, to, template).size
    }

    /**
     * The newest [template] mail to [to], once more than [seen] of them are in the sink, each written whole. The mail
     * comes after the request that queued it ([Await]); after [timeoutMs] the failure says what was awaited and what the
     * sink and the outbox held instead.
     */
    fun awaitMail(s: TestServer, to: String, template: String, seen: Int = 0, timeoutMs: Long = Await.DEFAULT_MS): kotlinx.serialization.json.JsonObject =
        Await.until("$template mail number ${seen + 1} to $to", timeoutMs, { s.mailSinkText() }) {
            sent(s, to, template).takeIf { it.size > seen }?.last()
        }

    /** The six-digit code of the newest [template] mail to [to], once more than [seen] of them came ([awaitMail]). */
    fun awaitCode(s: TestServer, to: String, template: String = "signup_code", seen: Int = 0, timeoutMs: Long = Await.DEFAULT_MS): String {
        val text = awaitMail(s, to, template, seen, timeoutMs)["text"].toString()
        return Regex("(?<![0-9])([0-9]{6})(?![0-9])").find(text)?.groupValues?.get(1) ?: throw AssertionError("no six-digit code in the $template mail to $to: $text")
    }

    /** `andvari admin enrol-link` printed one link per line. */
    fun enrolLink(s: TestServer, email: String? = null): String =
        s.admin(*(listOf("enrol-link") + (email?.let { listOf("--email", it) } ?: emptyList())).toTypedArray()).trim().lines().last()
}
