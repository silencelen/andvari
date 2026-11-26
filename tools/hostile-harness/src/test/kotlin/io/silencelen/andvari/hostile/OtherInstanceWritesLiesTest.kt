package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.core.client.account.Fetched
import io.silencelen.andvari.core.client.account.OperatorDelete
import io.silencelen.andvari.core.client.account.Reauthed
import io.silencelen.andvari.core.client.account.TwoStepAnswer
import io.silencelen.andvari.core.client.account.TwoStepSetup
import io.silencelen.andvari.core.client.account.TwoStepStatus
import io.silencelen.andvari.core.client.account.WireOperatorRoutes
import io.silencelen.andvari.core.client.account.WireTwoStep
import io.silencelen.andvari.core.client.deletion.DeletionOutcome
import io.silencelen.andvari.core.model.wire.AccountSummary
import io.silencelen.andvari.core.model.wire.AdminPolicy
import io.silencelen.andvari.core.model.wire.AdminSignupPolicy
import io.silencelen.andvari.core.model.wire.DeletedAtResponse
import io.silencelen.andvari.core.model.wire.DisableReason
import io.silencelen.andvari.core.model.wire.OperatorDeleteReason
import io.silencelen.andvari.core.model.wire.Quota
import io.silencelen.andvari.core.model.wire.TotpSetupResponse
import io.silencelen.andvari.core.model.wire.TotpStatus
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.hostile.proxy.Handler
import io.silencelen.andvari.hostile.proxy.Resp
import io.silencelen.andvari.hostile.proxy.answer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * **A** lies on the write routes that need a second instance ([World.another]): another instance's real answer, as its
 * own account or operator got it, served for this instance's route. Most dangerous first: an account's deletion, two-step
 * sign-in's status and setup, then the operator's quota and policy changes and an account's deletion by the operator.
 *
 * None of these answers names the instance or the account (a time, two flags, limits, a policy), so a device cannot tell
 * them from this server's own: the stated limit, as for the operator's reads. The one that does, two-step setup's (its
 * `otpauth` label names the account), is compared with the account and refused. Each scenario says what the
 * device did with the answer, that the server here still holds what it held, and that nothing reached the other
 * instance: every request of this world went to this world's server only, the secrets among them included.
 */
class OtherInstanceWritesLiesTest {
    private val password get() = Steps.PASSWORD.toCharArray()

    private fun World.twoStep(h: Host): WireTwoStep = h.session(origin)!!.let { WireTwoStep(h.client(origin), h.reauth(it)) }

    private fun World.ops(op: Host): WireOperatorRoutes = op.operator(op.session(origin)!!)

    /** Nothing at all reached [other]'s server after [mark]: this world's devices dial their own server only. */
    private fun nothingReached(other: World, mark: Int, what: String) {
        assertEquals(emptyList(), other.proxy.requests(since = mark).map { "${it.tag} ${it.route}" }, "$what: nothing reached the other instance")
    }

    private inline fun <reified T> Resp.decoded(s: kotlinx.serialization.KSerializer<T>): T = WireJson.json.decodeFromString(s, text)

    /**
     * `POST /account/delete` (row 31) answered with the other instance's real answer to its own member's deletion, the
     * request never passed on (A). The answer is `{deletedAt}`, which names no account: the device reports the deletion
     * at the other instance's time, the stated limit (a server can always claim, or refuse, a deletion). The account
     * still stands on this server, the proof of the password went to this server alone, and nothing reached the other.
     */
    @Test fun anotherInstancesDeletionAnswerIsTakenAsServedAndTheAccountStandsHere() = world {
        val op = operator()
        val ah = member("alice")
        val alice = account(ah)

        val other = another()
        other.operator()
        val bh = other.member("bob")
        assertIs<DeletionOutcome.Deleted>(other.account(bh).deletion {}.delete("bob@example.org", password, null))
        val theirs = other.realAnswer(WireRoute.ACCOUNT_DELETE, "bob")
        assertTrue(theirs.ok, "the other instance deleted its own member: $theirs")
        val theirAt = theirs.decoded(DeletedAtResponse.serializer()).deletedAt
        val otherMark = other.proxy.mark()

        val mark = proxy.mark()
        val lie = proxy.on(WireRoute.ACCOUNT_DELETE, "alice", handler = answer { theirs })
        val got = alice.deletion {}.delete("alice@example.org", password, null)
        lie.remove()
        assertEquals(DeletionOutcome.Deleted(theirAt), got, "taken as served: nothing in the answer names the account")
        assertEquals(1, sent(ah, WireRoute.ACCOUNT_DELETE, mark).size, "one deletion, sent here")
        assertTrue(secretSends("alice", mark).all { it.route == WireRoute.PRELOGIN || it.route == WireRoute.ACCOUNT_DELETE },
            "the proof went with the deletion, to this server: ${secretSends("alice", mark).map { it.route }}")
        val accounts = assertIs<Fetched.Ok<List<AccountSummary>>>(ops(op).accounts()).value
        assertTrue(accounts.any { it.userId == alice.userId }, "the account still stands on this server")
        nothingReached(other, otherMark, "a deletion")
    }

    /**
     * `GET /account/totp` and `POST /account/totp/setup` (rows 13, 14) answered with the other instance's real answers to
     * its own member's first setup (A), the setup never passed on. The status is shown as served (two flags, no account
     * named). The setup is refused: its `otpauth` label names the other account (`andvari:bob@…`), so it is the server's
     * fault and no screen is given its secret. Nothing is turned on: a code is refused by this server, which has no setup
     * waiting, and two-step sign-in stays off here. The proof of the password went to this server alone, and nothing
     * reached the other. This server's own answer, named for this account, is still a setup.
     */
    @Test fun anotherInstancesTwoStepSetupIsRefusedAndTurnsNothingOn() = world {
        operator()
        val ah = member("alice")
        val ours = twoStep(ah)

        val other = another()
        other.operator()
        val bh = other.member("bob")
        val bobs = other.twoStep(bh)
        val bobSecret = assertIs<TwoStepSetup.Ready>(bobs.setup(password)).secret
        assertIs<Fetched.Ok<TwoStepStatus>>(bobs.status())
        val theirSetup = other.realAnswer(WireRoute.TOTP_SETUP, "bob")
        val theirStatus = other.realAnswer(WireRoute.TOTP_STATUS, "bob")
        assertEquals(TotpStatus(enrolled = false, pendingSetup = true), theirStatus.decoded(TotpStatus.serializer()))
        assertTrue("bob@example.org" in theirSetup.decoded(TotpSetupResponse.serializer()).otpauthUri)
        val otherMark = other.proxy.mark()

        val mark = proxy.mark()
        val rules = listOf(
            proxy.on(WireRoute.TOTP_STATUS, "alice", handler = answer { theirStatus }),
            proxy.on(WireRoute.TOTP_SETUP, "alice", handler = answer { theirSetup }),
        )
        val shown = assertIs<Fetched.Ok<TwoStepStatus>>(ours.status()).value
        assertEquals(TwoStepStatus(false, true), shown, "the other account's flags, shown as served")
        assertEquals(TwoStepSetup.Refused(WireTwoStep.LABEL_NOT_THIS_ACCOUNT), ours.setup(password), "another account's setup is refused, its secret shown to no screen")
        assertTrue(bobSecret.secretBase32.isNotEmpty())
        rules.forEach { it.remove() }

        assertEquals(TwoStepAnswer.NoPendingSetup, ours.confirm("123456"), "this server has no setup waiting: nothing is turned on")
        assertEquals(TwoStepStatus(false, false), assertIs<Fetched.Ok<TwoStepStatus>>(ours.status()).value, "two-step sign-in is off here")
        assertTrue(sent(ah, WireRoute.TOTP_SETUP, mark).size == 1, "one setup, sent here")
        nothingReached(other, otherMark, "two-step sign-in")
        // This server's own answer names this account: it is a setup.
        assertIs<TwoStepSetup.Ready>(ours.setup(password), "this account's own setup")
    }

    /**
     * `PUT /admin/accounts/{id}/quota` (row 79) answered with the other instance's real answer to its own operator's quota
     * change (A), stored here first. The answer is four limits and names no account: the operator's device shows them as
     * served (the stated limit). The server here holds what this operator asked for, and nothing reached the other.
     */
    @Test fun anotherInstancesQuotaAnswerIsShownAsServedAndTheStoredQuotaIsOurs() = world {
        val op = operator()
        val alice = account(member("alice"))

        val other = another()
        val ob = other.operator()
        val bob = other.account(other.member("bob"))
        val theirQuota = assertIs<Reauthed.Done<Quota>>(other.ops(ob).setQuota(bob.userId, 7_000_000, 70, 7, 7, password)).value
        val theirs = other.realAnswer(WireRoute.ADMIN_QUOTA, "op")
        val otherMark = other.proxy.mark()

        val ops = ops(op)
        val mark = proxy.mark()
        val lie = proxy.on(WireRoute.ADMIN_QUOTA, "op", handler = Handler { x -> x.forward(); theirs })
        val shown = assertIs<Reauthed.Done<Quota>>(ops.setQuota(alice.userId, 3_000_000, 30, 3, 3, password), "taken as served").value
        lie.remove()
        assertEquals(theirQuota, shown, "the other instance's limits, shown as served")
        assertEquals(1, sent(op, WireRoute.ADMIN_QUOTA, mark).size)
        // What this server stored is what this operator asked for: the same change again answers the same limits.
        assertEquals(Quota(3_000_000, 30, 3, 3), assertIs<Reauthed.Done<Quota>>(ops.setQuota(alice.userId, 3_000_000, 30, 3, 3, password)).value)
        nothingReached(other, otherMark, "a quota change")
    }

    /**
     * `PUT /admin/policy` (row 81) answered with the other instance's real answer to its own operator's policy change
     * (A), the request never passed on. The operator's device shows the other instance's policy as served (the stated
     * limit); it keeps nothing of it: the next read of this server's policy shows what this server holds, unchanged, and
     * nothing reached the other.
     */
    @Test fun anotherInstancesPolicyAnswerIsShownAsServedAndChangesNothingHere() = world {
        val op = operator()

        val other = another()
        val ob = other.operator()
        val bops = other.ops(ob)
        val before = assertIs<Fetched.Ok<AdminPolicy>>(bops.policy()).value
        val theirPolicy = assertIs<Reauthed.Done<AdminPolicy>>(
            bops.setPolicy(before.copy(autoLockSeconds = 120, signup = AdminSignupPolicy(null, null)), password)).value
        val theirs = other.realAnswer(WireRoute.ADMIN_POLICY_PUT, "op")
        val otherMark = other.proxy.mark()

        val ops = ops(op)
        val held = assertIs<Fetched.Ok<AdminPolicy>>(ops.policy()).value
        val mark = proxy.mark()
        val lie = proxy.on(WireRoute.ADMIN_POLICY_PUT, "op", handler = answer { theirs })
        val shown = assertIs<Reauthed.Done<AdminPolicy>>(
            ops.setPolicy(held.copy(autoLockSeconds = 240, signup = AdminSignupPolicy(null, null)), password), "taken as served").value
        lie.remove()
        assertEquals(theirPolicy, shown, "the other instance's policy, shown as served")
        assertEquals(1, sent(op, WireRoute.ADMIN_POLICY_PUT, mark).size)
        assertEquals(held, assertIs<Fetched.Ok<AdminPolicy>>(ops.policy()).value, "this server's policy is unchanged: the change never reached it")
        nothingReached(other, otherMark, "a policy change")
    }

    /**
     * `POST /admin/accounts/{id}/delete` (row 76) answered with the other instance's real answer to its own operator's
     * deletion of a disabled account (A), the request never passed on. The answer is `{deletedAt}`: the operator's
     * device reports the deletion at the other instance's time (the stated limit), the account still stands on this
     * server, and nothing reached the other.
     */
    @Test fun anotherInstancesOperatorDeletionAnswerIsTakenAsServedAndTheAccountStandsHere() = world {
        val op = operator()
        val alice = account(member("alice"))

        val other = another()
        val ob = other.operator()
        val bob = other.account(other.member("bob"))
        val bops = other.ops(ob)
        assertIs<Reauthed.Done<Unit>>(bops.disable(bob.userId, DisableReason.REQUEST, password))
        val theirDeletion = assertIs<OperatorDelete.Deleted>(bops.deleteChecked(bob.userId, password, OperatorDeleteReason.UNDER_MINIMUM_AGE))
        val theirs = other.realAnswer(WireRoute.ADMIN_ACCOUNT_DELETE, "op")
        val otherMark = other.proxy.mark()

        val ops = ops(op)
        val mark = proxy.mark()
        val lie = proxy.on(WireRoute.ADMIN_ACCOUNT_DELETE, "op", handler = answer { theirs })
        val got = ops.deleteChecked(alice.userId, password, OperatorDeleteReason.UNDER_MINIMUM_AGE)
        lie.remove()
        assertEquals(OperatorDelete.Deleted(theirDeletion.deletedAt), got, "taken as served: nothing in the answer names the account")
        assertEquals(1, sent(op, WireRoute.ADMIN_ACCOUNT_DELETE, mark).size)
        val accounts = assertIs<Fetched.Ok<List<AccountSummary>>>(ops.accounts()).value
        assertNotNull(accounts.firstOrNull { it.userId == alice.userId }, "the account still stands on this server")
        nothingReached(other, otherMark, "an operator's deletion")
    }
}
