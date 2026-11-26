package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.CliError
import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.SavedSessions
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.core.client.account.Reauthed
import io.silencelen.andvari.core.client.devicelink.DeviceLinkStop
import io.silencelen.andvari.core.client.devicelink.ExistingStep
import io.silencelen.andvari.core.client.devicelink.NewStep
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.AccountOpen
import io.silencelen.andvari.core.client.onboard.PasswordOpen
import io.silencelen.andvari.core.client.onboard.SignIn
import io.silencelen.andvari.core.client.pin.GateEntry
import io.silencelen.andvari.core.client.recovery.KitRecoveryStep
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.RecoveryKit
import io.silencelen.andvari.hostile.proxy.Ctx
import io.silencelen.andvari.hostile.proxy.Handler
import io.silencelen.andvari.hostile.proxy.Resp
import io.silencelen.andvari.hostile.proxy.edit
import io.silencelen.andvari.hostile.proxy.long
import io.silencelen.andvari.hostile.proxy.obj
import io.silencelen.andvari.hostile.proxy.set
import io.silencelen.andvari.hostile.proxy.str
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Lies about key material (spec 05 T1; design §2.4 "Account keys at sign-in, unlock, kit recovery and device-link
 * pickup", §5.2, §8.2 step 8, §10): on the routes whose answers carry or decide an account's keys (sign-in and its code
 * step, the account's keys, the kit's verify and commit, a device link's poll and pickup), the server answers with a
 * replay of an earlier honest exchange (the same account before its password or kit changed), with another account's
 * valid answer, or with the right answer and one field taken from another account's or an earlier one. Three properties:
 * no key of another account is ever taken as this account's; a replayed answer never rolls the account back to keys or a
 * password it has left (what the device keeps for its next unlock opens with the password the person now has); nothing
 * is kept, and the person is never told "wrong password" (or "wrong kit") for a lie.
 */
class KeyMaterialTest {
    private val password get() = Steps.PASSWORD.toCharArray()
    private val newPassword get() = NEW_PASSWORD.toCharArray()

    /** What the device keeps, but for its own device secret (made before the first send, by design, and never a key). */
    private fun kept(h: Host): Map<String, String?> =
        h.state.keys()!!.filter { !it.startsWith("ovh.dev|") }.associateWith { h.state.get(it) } +
            h.secure.keys()!!.associate { "secure:$it" to h.secure.get(it) }

    private fun World.answerOf(route: WireRoute, tag: String): JsonObject = assertNotNull(proxy.last(route, tag)?.upstream?.json, "$route of $tag was answered")

    private suspend fun World.changePassword(h: Host) =
        assertIs<Reauthed.Done<Unit>>(h.settings(h.session(origin)!!).change(password, newPassword), "the password change of ${tag(h)}")

    /** The request as the device sent it, without a two-step code (the account has none), to the real server. */
    private fun honestly(x: Ctx): Resp =
        if (x.req.json == null) x.forward() else x.forward(x.req.withJson { it.set("totp", null as JsonElement?) })

    private fun swapped(edit: (JsonObject) -> JsonObject) = Handler { x -> honestly(x).let { if (it.ok) it.withJson(edit) else it } }

    private fun whole(answer: JsonObject) = Handler { _ -> Resp.json(200, answer) }

    /**
     * If a lie was taken, the keys this device now keeps for the account must still open with the password the person
     * has (the kept session unlocks with them, `SessionKeeper.unlockOnce`): anything else is a later "wrong password".
     */
    private fun World.keptKeysOpen(h: Host, pw: String, what: String) {
        val s = h.session(origin)?.session ?: return
        val pin = h.trust.pinFor(origin)!!
        val o = AccountOpen.openWithPassword(h.crypto, s.userId, pw.toCharArray(), s.accountKeys, pin.instanceId)
        if (o !is PasswordOpen.Opened) fail("$what: the device took the lie, and the keys it keeps for its next unlock do not open with the person's password ($o)")
        o.account.wipe()
    }

    /**
     * Sign-in and its code step. Alice changes her password; a new device signs in with the new one, and the server
     * answers the login (or, after it asked for a code, the login with the code) with: Bob's login answer; Alice's own
     * login answer from before the change; the right answer with her salt from before, with Bob's salt, with other KDF
     * parameters, with Bob's user id, or with her wrapped key from before. None signs in, none keeps anything or a device
     * row, none is "wrong password"; the honest sign-in then works.
     */
    @Test fun aSignInAnswerReplayedOrOfAnotherAccountOrWithOneFieldSwappedIsNeverTaken() = world {
        operator()
        val ah = member("alice")
        member("bob")
        passwordDevice("bob-login", "bob@example.org")
        val bobs = answerOf(WireRoute.LOGIN, "bob-login")
        passwordDevice("alice-before", "alice@example.org")
        val before = answerOf(WireRoute.LOGIN, "alice-before")
        changePassword(ah)
        val lies = listOf<Pair<String, Handler>>(
            "another account's login answer" to whole(bobs),
            "the account's own login answer from before its password changed" to whole(before),
            "the right answer with the account's salt from before" to swapped { it.edit("accountKeys") { k -> k.set("kdfSalt", before.obj("accountKeys")!!.str("kdfSalt")!!) } },
            "the right answer with another account's salt" to swapped { it.edit("accountKeys") { k -> k.set("kdfSalt", bobs.obj("accountKeys")!!.str("kdfSalt")!!) } },
            "the right answer with other KDF parameters" to swapped { it.edit("accountKeys") { k -> k.edit("kdfParams") { p -> p.set("ops", p.long("ops")!! + 1) } } },
            "the right answer with another account's user id" to swapped { it.set("userId", bobs.str("userId")!!) },
            "the right answer with the account's wrapped key from before" to swapped { it.edit("accountKeys") { k -> k.set("wrappedUvk", before.obj("accountKeys")!!.str("wrappedUvk")!!) } },
        )
        for (codeStep in listOf(false, true)) for ((i, lie) in lies.withIndex()) {
            val what = lie.first + if (codeStep) ", at the code step" else ""
            val tag = "d${if (codeStep) "c" else ""}$i"
            val d = pinnedDevice(tag)
            proxy.on(WireRoute.LOGIN, tag, handler = lie.second)
            if (codeStep) proxy.on(WireRoute.LOGIN, tag, times = 1) { _ -> Resp.error(401, "totp_required") }
            val held = kept(d)
            var r = d.onboarding(origin).signIn("alice@example.org", newPassword)
            if (codeStep) r = d.onboarding(origin).signInCode(assertIs<SignIn.TotpRequired>(r, "$what: the code is asked for"), "123456")
            keptKeysOpen(d, NEW_PASSWORD, what)
            assertTrue(r !is SignIn.SignedIn && r != SignIn.InvalidCredentials && r !is SignIn.TotpRequired, "$what: $r")
            assertNull(d.session(origin), "$what: no session")
            assertEquals(held, kept(d), "$what: nothing is kept")
            assertNull(d.devices.deviceId(origin, "alice@example.org"), "$what: no device row is remembered")
        }
        assertIs<SignIn.SignedIn>(pinnedDevice("honest").onboarding(origin).signIn("alice@example.org", newPassword), "the honest sign-in works")
    }

    /**
     * The account's keys (`GET /account/keys`), as the command-line tool's kept session reads them each time it reopens.
     * After Alice's password change, a reopen with the new password is served Bob's keys, her own keys from before the
     * change, or her keys with Bob's salt, identity key or identity seed: none reopens; each is "sign in afresh" or the
     * security fault, never another account's keys and never "wrong password"; the kept session is not deleted, and the
     * honest keys then reopen it.
     */
    @Test fun theAccountsKeysReplayedOrOfAnotherAccountOrWithOneFieldSwappedNeverReopenASession() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        suspend fun keysOf(h: Host): JsonObject =
            Json.parseToJsonElement(assertIs<WireResult.Ok<String>>(h.client(origin).call(WireRoute.ACCOUNT_KEYS, decode = { it })).value).jsonObject
        val bobs = keysOf(bh)
        val before = keysOf(ah)
        changePassword(ah)
        val saved = SavedSessions(ah.secure)
        saved.save(ah.session(origin)!!)
        val email = "alice@example.org"
        val lies = listOf<Pair<String, Handler>>(
            "another account's keys" to whole(bobs),
            "the account's own keys from before its password changed" to whole(before),
            "the account's keys with another account's salt" to swapped { it.set("kdfSalt", bobs.str("kdfSalt")!!) },
            "the account's keys with another account's identity key" to swapped { it.set("identityPub", bobs.str("identityPub")!!) },
            "the account's keys with another account's identity seed" to swapped { it.set("encryptedIdentitySeed", bobs.str("encryptedIdentitySeed")!!) },
        )
        for ((what, lie) in lies) {
            val reopening = Host(ah.state, ah.secure, server::now, http = server.httpFor(proxy.dial("alice")), deviceName = ah.deviceName)
            val rule = proxy.on(WireRoute.ACCOUNT_KEYS, "alice", handler = lie)
            val outcome = try {
                saved.reopen(reopening, origin, email, newPassword).toString()
            } catch (e: CliError) {
                assertTrue(e.message!!.startsWith("SECURITY"), "$what: only the security fault stops it: ${e.message}")
                "security fault"
            }
            rule.remove()
            assertTrue(outcome == SavedSessions.Reopen.None.toString() || outcome == "security fault", "$what: $outcome")
            assertNull(reopening.account(origin), "$what: no account is opened")
            assertTrue(saved.has(origin, email), "$what: the kept session is not deleted")
        }
        val honest = Host(ah.state, ah.secure, server::now, http = server.httpFor(proxy.dial("alice")), deviceName = ah.deviceName)
        assertEquals(SavedSessions.Reopen.Reopened, saved.reopen(honest, origin, email, newPassword), "the honest keys reopen it")
    }

    /**
     * The kit's verify step. Alice rotates her kit; a recovery with the new kit is served Bob's verify answer, her own
     * verify answer from before the rotation, or the right answer with Bob's user id: each stops at `identity_mismatch`
     * before any new password, never "wrong kit" (`Rejected`), commits nothing and keeps no session.
     */
    @Test fun aKitVerifyAnswerReplayedOrOfAnotherAccountStopsBeforeAnyNewPassword() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        suspend fun verified(h: Host, kit: RecoveryKit.Kit, tag: String): JsonObject {
            val d = device(tag)
            val target = assertIs<KitRecoveryStep.ConfirmTarget>(d.kitRecovery.start(kit, GateEntry.KIT_RECOVERY_SCREEN))
            d.kitRecovery.cancel(assertIs<KitRecoveryStep.ChoosePassword>(d.kitRecovery.verify(target), "the honest verify of ${tag(h)}"))
            return answerOf(WireRoute.RECOVERY_SELF_VERIFY, tag)
        }
        val bobs = verified(bh, assertNotNull(RecoveryKit.parseQr(registration(bh).kit.qr)), "bob-verify")
        val before = verified(ah, assertNotNull(RecoveryKit.parseQr(registration(ah).kit.qr)), "alice-verify")
        val rotated = assertIs<Reauthed.Done<io.silencelen.andvari.core.client.onboard.RevealedKit>>(ah.settings(ah.session(origin)!!).rotateKit(password)).value
        val kit = assertNotNull(RecoveryKit.parseQr(rotated.qr))
        val lies = listOf<Pair<String, Handler>>(
            "another account's verify answer" to whole(bobs),
            "the account's own verify answer from before its kit was rotated" to whole(before),
            "the right answer with another account's user id" to swapped { it.set("userId", bobs.str("userId")!!) },
        )
        for ((i, lie) in lies.withIndex()) {
            val tag = "v$i"
            val d = device(tag)
            val target = assertIs<KitRecoveryStep.ConfirmTarget>(d.kitRecovery.start(kit, GateEntry.KIT_RECOVERY_SCREEN))
            proxy.on(WireRoute.RECOVERY_SELF_VERIFY, tag, handler = lie.second)
            val r = d.kitRecovery.verify(target)
            assertEquals(KitRecoveryStep.Stopped("identity_mismatch"), r, lie.first)
            assertTrue(proxy.requests(WireRoute.RECOVERY_SELF_COMMIT, tag).isEmpty(), "${lie.first}: nothing is committed")
            assertNull(d.session(origin), "${lie.first}: no session")
        }
        val d = device("honest")
        val target = assertIs<KitRecoveryStep.ConfirmTarget>(d.kitRecovery.start(kit, GateEntry.KIT_RECOVERY_SCREEN))
        assertIs<KitRecoveryStep.ChoosePassword>(d.kitRecovery.verify(target), "the honest verify works")
    }

    /**
     * The kit's commit step. The recovery commits on the real server, which then answers with Bob's session, Alice's own
     * session from before the recovery (her old salt and wrapped key), or the right session with Bob's salt or with her
     * wrapped key from before. None is taken as the recovered session: a session whose keys do not open with the new
     * password would turn the person's next unlock into "wrong password". Each world is fresh, because a commit replaces
     * the kit.
     */
    @Test fun aKitCommitAnswerReplayedOrOfAnotherAccountOrWithOneFieldSwappedIsNeverTheRecoveredSession() {
        val lies = listOf<Pair<String, (bobs: JsonObject, before: JsonObject) -> Handler>>(
            "another account's session" to { bobs, _ -> Handler { x -> Resp.json(200, bobs.set("recoveryPieceId", x.forward().json!!.str("recoveryPieceId")!!)) } },
            "the account's own session from before the recovery" to { _, before -> Handler { x -> Resp.json(200, before.set("recoveryPieceId", x.forward().json!!.str("recoveryPieceId")!!)) } },
            "the right session with another account's salt" to { bobs, _ -> swapped { it.edit("accountKeys") { k -> k.set("kdfSalt", bobs.obj("accountKeys")!!.str("kdfSalt")!!) } } },
            "the right session with the account's wrapped key from before" to { _, before -> swapped { it.edit("accountKeys") { k -> k.set("wrappedUvk", before.obj("accountKeys")!!.str("wrappedUvk")!!) } } },
        )
        for ((what, lie) in lies) world {
            operator()
            val ah = member("alice")
            member("bob")
            passwordDevice("bob-login", "bob@example.org")
            passwordDevice("alice-before", "alice@example.org")
            val bobs = answerOf(WireRoute.LOGIN, "bob-login")
            val before = answerOf(WireRoute.LOGIN, "alice-before")
            val kit = assertNotNull(RecoveryKit.parseQr(registration(ah).kit.qr))
            val d = device("d")
            val target = assertIs<KitRecoveryStep.ConfirmTarget>(d.kitRecovery.start(kit, GateEntry.KIT_RECOVERY_SCREEN))
            val choose = assertIs<KitRecoveryStep.ChoosePassword>(d.kitRecovery.verify(target))
            proxy.on(WireRoute.RECOVERY_SELF_COMMIT, "d", handler = lie(bobs, before))
            val r = d.kitRecovery.commit(choose, newPassword)
            keptKeysOpen(d, NEW_PASSWORD, what)
            assertTrue(r !is KitRecoveryStep.Recovered && r != KitRecoveryStep.Rejected, "$what: $r")
            assertNull(d.session(origin), "$what: no session")
            assertNull(d.devices.deviceId(origin, "alice@example.org"), "$what: no device row is remembered")
            // The commit did land: the person signs in with the new password.
            assertIs<SignIn.SignedIn>(pinnedDevice("after").onboarding(origin).signIn("alice@example.org", newPassword), "$what: the new password signs in")
        }
    }

    private class Pairing(val nh: Host, val fixed: ExistingStep.ClaimFixed, val code: NewStep.ShowCode)

    /** E shows a link, N claims it (through its Trust Gate), E fixes the claim, N shows its code, E approves the typed code. */
    private suspend fun pairAndApprove(eh: Host, nh: Host): Pairing {
        val shown = assertIs<ExistingStep.Shown>(eh.deviceLinks.create())
        var n = nh.deviceLinks.start(shown.url, GateEntry.LINK_DEVICE_SCREEN)
        if (n is NewStep.TrustGate) n = nh.deviceLinks.afterTrustGate(n, confirmed = true)
        val claimed = assertIs<NewStep.Claimed>(n, "N claims: $n")
        val fixed = assertIs<ExistingStep.ClaimFixed>(eh.deviceLinks.advance(shown))
        val code = assertIs<NewStep.ShowCode>(nh.deviceLinks.advance(claimed))
        val type = assertIs<ExistingStep.TypeDigits>(eh.deviceLinks.advance(fixed))
        val approvable = assertIs<ExistingStep.Approvable>(eh.deviceLinks.typeDigits(type, code.code))
        assertIs<ExistingStep.Approved>(eh.deviceLinks.approve(approvable))
        return Pairing(nh, fixed, code)
    }

    /**
     * A device link's poll and pickup. Alice links a device under her old password, then changes it. A new link's poll
     * is answered with the earlier link's approved poll answer: it stops before any password. Its pickup is answered with
     * the earlier link's whole pickup answer, with that answer's session in this link's answer, or with this link's answer
     * carrying the salt from before the change or other KDF parameters: each stops (never "wrong password", never
     * linked), keeps no session and no device row.
     */
    @Test fun aDeviceLinkPollOrPickupAnswerReplayedOrWithOneFieldSwappedIsNeverTaken() = world {
        operator()
        val eh = member("alice")
        val x = pairAndApprove(eh, device("x"))
        val need = assertIs<NewStep.PasswordNeeded>(x.nh.deviceLinks.advance(x.code))
        assertIs<NewStep.Linked>(x.nh.deviceLinks.pickup(need, password), "the earlier link")
        val earlierPickup = answerOf(WireRoute.DEVICE_LINK_PICKUP, "x")
        val earlierPoll = assertNotNull(proxy.log().lastOrNull { it.req.route == WireRoute.DEVICE_LINK_POLL && it.req.tag == "x" && it.upstream?.json?.str("outer") != null }?.upstream?.json)
        val oldKeys = earlierPickup.obj("session")!!.obj("accountKeys")!!
        changePassword(eh)

        val p = pairAndApprove(eh, device("poll"))
        proxy.on(WireRoute.DEVICE_LINK_POLL, "poll", handler = whole(earlierPoll))
        val mark = proxy.mark()
        val polled = assertIs<NewStep.Stopped>(p.nh.deviceLinks.advance(p.code), "the earlier link's poll answer")
        assertTrue(polled.reason == DeviceLinkStop.BAD_MAC || polled.reason == DeviceLinkStop.NONCE_CHANGED, "the earlier link's poll answer: $polled")
        assertTrue(proxy.requests(tag = "poll", since = mark).none { it.route == WireRoute.PRELOGIN || it.route == WireRoute.DEVICE_LINK_PICKUP }, "no password was asked for")

        val lies = listOf<Pair<String, Handler>>(
            "the earlier link's whole pickup answer" to whole(earlierPickup),
            "this link's answer with the earlier link's session" to swapped { it.set("session", earlierPickup.obj("session")!!) },
            "this link's answer with the salt from before the password change" to swapped { it.edit("session") { s -> s.edit("accountKeys") { k -> k.set("kdfSalt", oldKeys.str("kdfSalt")!!) } } },
            "this link's answer with other KDF parameters" to swapped { it.edit("session") { s -> s.edit("accountKeys") { k -> k.edit("kdfParams") { q -> q.set("ops", q.long("ops")!! + 1) } } } },
        )
        for ((i, lie) in lies.withIndex()) {
            val tag = "n$i"
            val n = pairAndApprove(eh, device(tag))
            val needed = assertIs<NewStep.PasswordNeeded>(n.nh.deviceLinks.advance(n.code))
            proxy.on(WireRoute.DEVICE_LINK_PICKUP, tag, handler = lie.second)
            val r = n.nh.deviceLinks.pickup(needed, newPassword)
            keptKeysOpen(n.nh, NEW_PASSWORD, lie.first)
            assertEquals(NewStep.Stopped(DeviceLinkStop.IDENTITY_MISMATCH), r, lie.first)
            assertNull(n.nh.session(origin), "${lie.first}: no session")
            assertNull(n.nh.devices.deviceId(origin, "alice@example.org"), "${lie.first}: no device row is remembered")
        }
        val honest = pairAndApprove(eh, device("honest"))
        assertIs<NewStep.Linked>(honest.nh.deviceLinks.pickup(assertIs<NewStep.PasswordNeeded>(honest.nh.deviceLinks.advance(honest.code)), newPassword))
    }

    private companion object {
        const val NEW_PASSWORD = "a Different staple 7 horse battery"
    }
}
