package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.CardOps
import io.silencelen.andvari.cli.CardWrite
import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.SyncOutcome
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.doc
import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.account.Reauthed
import io.silencelen.andvari.core.client.devicelink.DeviceLinkStop
import io.silencelen.andvari.core.client.devicelink.ExistingStep
import io.silencelen.andvari.core.client.devicelink.NewStep
import io.silencelen.andvari.core.client.link.CreateOutcome
import io.silencelen.andvari.core.client.link.LinkStop
import io.silencelen.andvari.core.client.link.RecipientStep
import io.silencelen.andvari.core.client.onboard.SignIn
import io.silencelen.andvari.core.client.pin.BakedInstance
import io.silencelen.andvari.core.client.pin.CardStatus
import io.silencelen.andvari.core.client.pin.CardTrust
import io.silencelen.andvari.core.client.pin.PinRoot
import io.silencelen.andvari.core.client.pin.PinStore
import io.silencelen.andvari.core.client.pin.TrustCardChainVerifier
import io.silencelen.andvari.core.client.pin.FirstPin
import io.silencelen.andvari.core.client.pin.GateEntry
import io.silencelen.andvari.core.client.pin.PinState
import io.silencelen.andvari.core.client.pin.TrustGateWording
import io.silencelen.andvari.core.client.recovery.KitRecoveryStep
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.InstanceKind
import io.silencelen.andvari.core.trust.RecoveryKit
import io.silencelen.andvari.hostile.proxy.Frames
import io.silencelen.andvari.hostile.proxy.answer
import io.silencelen.andvari.hostile.proxy.serveCards
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The instance card under a hostile server (design §4.4, §4.6, §2.4 "Pinning"): forks, look-alike addresses, moves and
 * `kind` changes. A fork stops the instance for good; a move and a `kind` change are followed only by the person.
 */
class CardForkTest {
    private val password get() = Steps.PASSWORD.toCharArray()

    /** Alice pins card 1; the operator's key also signed ANOTHER card 1, which the server then serves her. */
    private suspend fun World.forkAtCardOne(): Pair<Host, Host> {
        val oh = operator()
        val ah = member("alice")
        val other = Adversary.signCard(oh, origin, oh.trust.pinFor(origin)!!, server.now()) { it.copy(name = "the other card one") }
        assertIs<CardWrite.Stored>(CardOps(oh, oh.session(origin)!!).sign(password, name = "card one"))
        assertEquals(1L, assertIs<CardStatus.Ok>(ah.trust.refresh(origin)).pin.seq)
        proxy.serveCards("alice") { genuine -> genuine.take(1) + other }
        return oh to ah
    }

    /**
     * §4.4: "Fork. A chain that does not contain the pinned hash at the pinned `seq` makes the client stop using the
     * instance: no sign-in, sync or writes." and "A fork is durable. It is stored with the pin and survives restarts.
     * While it is set, the client refreshes nothing from that origin as trusted, the password rule refuses, and every
     * flow stops. The only way on is 'Forget this server'."
     */
    @Test fun anotherCardAtThePinnedPositionIsAForkThatStopsEveryFlowSurvivesARestartAndOnlyForgettingTheServerGoesOn() = world {
        val (_, ah) = forkAtCardOne()
        val pinned = ah.trust.pinFor(origin)!!
        assertEquals(pinned.hash, assertIs<CardStatus.Fork>(ah.trust.refresh(origin), "another hash at the pinned seq is a fork").pinned.hash)
        assertIs<PinState.Forked>(ah.trust.pinState(origin))

        // Every flow stops, and the forked instance is sent nothing at all. (§4.4 "A fork stops traffic, not reading":
        // what the device already holds stays readable, and nothing here asserts on reading.)
        var mark = proxy.mark()
        assertIs<SignIn.Refused>(ah.onboarding(origin).signIn("alice@example.org", password), "no sign-in")
        assertIs<CreateOutcome.Refused>(ah.links.create("connect", 3_600_000L, emptyList()), "no link")
        assertIs<ExistingStep.Stopped>(ah.deviceLinks.create(), "no device link")
        assertTrue(ah.settings(ah.session(origin)!!).change(password, "another Password 4 the fork".toCharArray()) !is Reauthed.Done<*>, "no password change")
        assertIs<FirstPin.Blocked>(ah.trust.beginTrustGate(origin, TrustGateWording.TYPED_ADDRESS), "no root pins over a fork")
        assertTrue(proxy.requests(tag = "alice", since = mark).isEmpty(), "a forked instance is sent nothing:\n${proxy.since(mark).joinToString("\n")}")

        // The server serving the genuine chain again changes nothing, and the device does not even ask.
        proxy.honest()
        mark = proxy.mark()
        assertIs<CardStatus.Fork>(ah.trust.refresh(origin), "a fork is durable")
        assertTrue(sent(ah, WireRoute.INSTANCE, mark).isEmpty(), "a forked origin is not refreshed")

        // After a restart it is still stopped.
        val again = restarted(ah)
        assertIs<PinState.Forked>(again.trust.pinState(origin), "the fork is stored with the pin")
        mark = proxy.mark()
        assertIs<SignIn.Refused>(again.onboarding(origin).signIn("alice@example.org", password))
        assertIs<CreateOutcome.Refused>(again.links.create("connect", 3_600_000L, emptyList()))
        assertTrue(proxy.requests(tag = "alice", since = mark).isEmpty(), "still nothing is sent after the restart")

        // "Forget this server" is the only way on: then the address is typed again and passes the Trust Gate.
        again.trust.forget(origin)
        assertEquals(PinState.None, again.trust.pinState(origin))
        val gate = assertIs<FirstPin.NeedsTrustGate>(again.trust.beginTrustGate(origin, TrustGateWording.TYPED_ADDRESS))
        assertIs<FirstPin.Pinned>(again.trust.confirmTrustGate(gate.confirm))
        assertIs<SignIn.SignedIn>(again.onboarding(origin).signIn("alice@example.org", password))
    }

    /** §4.4 "Fork … makes the client stop using the instance: no sign-in, sync or writes": the signed-in account's own traffic. */
    @Test fun afterAForkTheSignedInAccountSendsNoSyncAndNoWrite() = world {
        val (_, ah) = forkAtCardOne()
        val a = account(ah)
        assertIs<CardStatus.Fork>(ah.trust.refresh(origin))
        val mark = proxy.mark()
        a.sync()
        a.putItem(a.personalVaultId!!, doc("after the fork"))
        a.logs.append(null, io.silencelen.andvari.core.client.log.LogAction.Create("after the fork"))
        val leaked = proxy.requests(tag = "alice", since = mark)
        assertTrue(leaked.isEmpty(), "a forked instance is sent nothing, but the device sent:\n${leaked.joinToString("\n") { "$it  (session token attached: ${it.bearer != null})" }}")
    }

    /**
     * The item half of the same rule, which the item engine enforces itself (it asks the pin before every send): under a
     * fork the sync and an item write answer `halted`, and nothing goes out on an item route. The log engine's and the
     * account state's traffic under a fork is the rest of H1, above.
     */
    @Test fun afterAForkTheItemEngineSendsNothingOnAnItemRoute() = world {
        val (_, ah) = forkAtCardOne()
        val a = account(ah)
        assertIs<CardStatus.Fork>(ah.trust.refresh(origin))
        val mark = proxy.mark()
        assertEquals(SyncOutcome.Refused("halted"), a.sync())
        assertEquals("halted", a.putItem(a.personalVaultId!!, doc("after the fork")).second)
        assertEquals(SyncOutcome.Refused("halted"), account(restarted(ah)).sync(), "and after a restart")
        val itemRoutes = setOf(WireRoute.SYNC, WireRoute.PUSH, WireRoute.ITEM_VERSIONS, WireRoute.ITEMS_DELETED, WireRoute.ITEM_RESTORE,
            WireRoute.ITEM_PURGE, WireRoute.ATTACHMENT_UPLOAD, WireRoute.ATTACHMENT_GET, WireRoute.VAULTS_DELETED)
        val leaked = proxy.requests(tag = "alice", since = mark).filter { it.route in itemRoutes }
        assertTrue(leaked.isEmpty(), "the item engine sends nothing to a forked instance, but sent:\n${leaked.joinToString("\n")}")
    }

    /**
     * §4.4 "On every policy probe or sync the client fetches the chain … and verifies forward from the pinned card": a
     * fork is found by the device's ordinary traffic, not only when something asks for the card.
     */
    @Test fun anOrdinarySyncNoticesAForkedCardChain() = world {
        val (_, ah) = forkAtCardOne()
        val mark = proxy.mark()
        assertEquals(SyncOutcome.Refused("halted"), account(ah).sync(), "the sync stops at the fork")
        assertIs<PinState.Forked>(ah.trust.pinState(origin), "the sync judged the served chain against the pin")
        assertEquals(listOf(WireRoute.INSTANCE), proxy.requests(tag = "alice", since = mark).map { it.route }.distinct(), "the card chain is all it asked for")
    }

    /**
     * §4.6 step 2, §4.4: after an operator reset the instance serves no card (withheld: the device keeps working), and
     * then a NEW card 0 under the same instance id: "a served chain whose card 0 does not hash to it is a fork at once,
     * however short that chain is".
     */
    @Test fun aNewCardZeroAfterAnOperatorResetIsAForkAndTheEmptyChainBeforeItOnlyWithheld() = world {
        operator()
        val ah = member("alice")
        val pinned = ah.trust.pinFor(origin)!!
        val out = server.admin("reset-instance-identity", "--confirm", pinned.instanceId)
        val setupLink = out.trim().lines().last()
        assertNull(assertIs<CardStatus.Withheld>(ah.trust.refresh(origin), "no card served is withheld, not a fork").servedSeq)
        assertEquals(pinned, ah.trust.pinFor(origin))
        account(ah).synced()

        val op2 = device("op2")
        Steps.registerThrough(op2, origin, setupLink, "op2@example.org")
        val fresh = op2.trust.pinFor(origin)!!
        assertEquals(pinned.instanceId, fresh.instanceId, "the reset keeps the instance id (§4.6)")
        assertTrue(fresh.card0Hash != pinned.card0Hash)
        assertIs<CardStatus.Fork>(ah.trust.refresh(origin), "a different card 0 is a fork at once")
        assertIs<PinState.Forked>(ah.trust.pinState(origin))
        assertIs<SignIn.Refused>(ah.onboarding(origin).signIn("alice@example.org", password))
    }

    /** §2.4: "a pinned card against a chain of another `instanceId` is a `fork` (its card 0 differs)". */
    @Test fun anotherInstancesGenuineChainServedAtAPinnedOriginIsAFork() = world {
        operator()
        val ah = member("alice")
        // A second instance of the attacker's own, with a genuine chain of its own.
        val foreign = World().use { other ->
            other.run {
                val op = operator()
                assertIs<CardStatus.Ok>(op.trust.refresh(origin))
                proxy.last(WireRoute.INSTANCE)!!.upstream!!
            }
        }
        proxy.on(WireRoute.INSTANCE, "alice", handler = answer { foreign })
        assertIs<CardStatus.Fork>(ah.trust.refresh(origin))
        assertIs<PinState.Forked>(ah.trust.pinState(origin))
    }

    /** A device that dials [address] itself, with nothing between it and that address but the proxy listening there. */
    private fun World.directDevice(name: String): Host = Host(MemoryDeviceState(), MemoryDeviceState(), server::now, deviceName = name)

    /**
     * §2.4 "Pinning": "`origin_mismatch` first: the newest verified card's `origin` is not the origin the client dialed.
     * Cards are public, so any server can serve another instance's genuine chain; without this check a look-alike
     * address would pass the Trust Gate, a link offer, a kit or the CLI's `--trust-card` with the real instance's name
     * and key." Nothing is pinned, and nothing secret-derived is sent to the look-alike.
     */
    @Test fun aLookAlikeAddressServingTheGenuineChainIsOriginMismatchForEveryRootAndGetsNoSecret() = world {
        operator()
        val ah = device("alice")
        val reg = Steps.registerThrough(ah, origin, Steps.enrolLink(server), "alice@example.org", trustGate = true)
        // The look-alike: another address, answering with everything the real instance serves.
        val lookalike = proxy.dial("lookalike")
        val d = directDevice("victim")

        // The typed address (the Trust Gate is never shown for it).
        val typed = assertIs<FirstPin.OriginMismatch>(d.trust.beginTrustGate(lookalike, TrustGateWording.TYPED_ADDRESS))
        assertEquals("origin_mismatch", typed.verdict)
        assertEquals(lookalike, typed.dialedOrigin)
        assertEquals(origin, typed.cardOrigin)
        assertEquals(SignIn.TrustGateFirst, d.onboarding(lookalike).signIn("alice@example.org", password))

        // A kit that names the look-alike with the genuine card 0 hash: no recovery proof is sent there.
        val parts = reg.kit.qr.split(':').toMutableList()
        parts[2] = Frames.b64(lookalike.encodeToByteArray())
        val kit = assertNotNull(RecoveryKit.parseQr(parts.joinToString(":")), "a kit text for the look-alike address")
        assertIs<KitRecoveryStep.OriginMismatch>(d.kitRecovery.start(kit, GateEntry.KIT_RECOVERY_SCREEN), "the kit root checks the dialed origin first")

        // A device link that names the look-alike: nothing is claimed.
        val shown = assertIs<ExistingStep.Shown>(ah.deviceLinks.create())
        val dParts = shown.url.substringAfter('#').split('.').toMutableList()
        dParts[1] = Frames.b64(lookalike.encodeToByteArray())
        assertIs<NewStep.OriginMismatch>(d.deviceLinks.start(shown.url.substringBefore('#') + "#" + dParts.joinToString("."), GateEntry.LINK_DEVICE_SCREEN))

        // An invite that names the look-alike: the signed offer names the real origin.
        val link = assertIs<CreateOutcome.Created>(ah.links.create("connect", 3_600_000L, emptyList())).link
        val lParts = link.url.substringAfter('#').split('.').toMutableList()
        lParts[1] = Frames.b64(lookalike.encodeToByteArray())
        assertEquals(RecipientStep.Stopped(LinkStop.ORIGIN_MISMATCH), d.links.open(link.url.substringBefore('#') + "#" + lParts.joinToString("."), GateEntry.PASTE_INVITE))

        assertEquals(PinState.None, d.trust.pinState(lookalike), "nothing was pinned")
        val there = proxy.requests(tag = "lookalike")
        assertTrue(there.isNotEmpty(), "the device did dial the look-alike")
        assertTrue(there.all { it.route == WireRoute.INSTANCE || it.route == WireRoute.LINK_FETCH }, "only public reads reached the look-alike:\n${there.joinToString("\n")}")
    }

    /**
     * §4.4 "A move": the newest verified card names another origin. The pin is not moved by the server: "One tap moves
     * the namespace, with no Trust Gate." Until the tap the device stays where it is and sends the new address nothing.
     */
    @Test fun aSignedMoveIsFollowedOnlyByThePersonsOneTap() = world {
        val oh = operator()
        // These devices dial origins themselves, so that they can reach the new address once the person follows.
        originListener("old")
        val moved = proxy.dial("new")
        val ah = directDevice("alice")
        Steps.registerThrough(ah, origin, Steps.enrolLink(server), "alice@example.org", trustGate = true)
        val before = ah.trust.pinFor(origin)!!
        assertEquals(1L, assertIs<CardWrite.Stored>(CardOps(oh, oh.session(origin)!!).sign(password, newOrigin = moved)).seq)

        val status = assertIs<CardStatus.Moved>(ah.trust.refresh(origin), "a card that names another origin is a move")
        assertEquals(moved, status.newest.origin)
        assertEquals(false, status.storeBuildMustUpdate)
        assertEquals(before, ah.trust.pinFor(origin), "nothing moved without the person")
        assertEquals(PinState.None, ah.trust.pinState(moved))
        assertTrue(proxy.requests(tag = "new").isEmpty(), "the new address was not dialed before the tap")

        // The tap.
        val followed = assertIs<CardStatus.Ok>(ah.trust.followMove(status), "one tap follows the move, with no Trust Gate")
        assertEquals(moved, followed.pin.origin)
        assertEquals(before.root, followed.pin.root, "the pin keeps its root")
        assertEquals(before.card0Hash, followed.pin.card0Hash)
        assertEquals(PinState.None, ah.trust.pinState(origin), "the namespace moved")
        assertEquals(1L, ah.trust.pinFor(moved)!!.seq)
    }

    /**
     * §4.4, §0.3: a store build never follows a move or a `kind` change of the baked instance; it says "Update
     * andvari". The headless host builds its trust with no baked instance, so this device's trust engine is built here
     * as a store build would build it, over the device's own pin store and its dialer through the proxy. The operator's
     * key signs a move, then a `kind` change; the server serves each to the store device. Neither is followed, by any
     * call, and the new address is never dialed.
     */
    @Test fun aStoreBuildNeverFollowsAMoveOrAKindChangeOfTheBakedInstance() = world {
        val oh = operator()
        val base = oh.trust.pinFor(origin)!!
        val sh = device("store")
        val trust = CardTrust(PinStore(sh.state), TrustCardChainVerifier(sh.crypto), sh::client, sh.crypto,
            BakedInstance(origin, base.instanceId, base.card0Hash, base.kind), storeBuild = true)
        assertIs<FirstPin.Pinned>(trust.pinBaked(origin), "the baked root pins the genuine chain")
        assertEquals(PinRoot.BAKED, trust.pinFor(origin)!!.root)
        assertIs<FirstPin.Refused>(trust.pinBaked(proxy.dial("lookalike")), "the baked root pins no other address")
        val pinned = trust.pinFor(origin)!!

        val elsewhere = proxy.dial("elsewhere")
        val move = Adversary.signCard(oh, origin, base, server.now()) { it.copy(origin = elsewhere) }
        var serving = proxy.serveCards("store") { genuine -> genuine + move }
        val moved = assertIs<CardStatus.Moved>(trust.refresh(origin), "a signed move of the baked instance")
        assertTrue(moved.storeBuildMustUpdate, "a store build must update, not follow")
        assertIs<CardStatus.Moved>(trust.followMove(moved), "the tap does nothing in a store build")
        assertEquals(pinned, trust.pinFor(origin))
        assertEquals(PinState.None, trust.pinState(elsewhere))
        assertTrue(proxy.requests(tag = "elsewhere").isEmpty(), "the new address is never dialed")
        serving.remove()

        val toPublic = Adversary.signCard(oh, origin, base, server.now()) { it.copy(kind = InstanceKind.PUBLIC) }
        serving = proxy.serveCards("store") { genuine -> genuine + toPublic }
        val changed = assertIs<CardStatus.KindChanged>(trust.refresh(origin), "a kind change of the baked instance")
        assertTrue(changed.storeBuildMustUpdate)
        assertIs<CardStatus.KindChanged>(trust.acceptKindChange(changed), "no confirmation follows it in a store build")
        assertEquals(pinned, trust.pinFor(origin), "the pin keeps its kind and position")
        serving.remove()
        assertEquals(pinned, assertIs<CardStatus.Ok>(trust.refresh(origin)).pin)
    }

    /**
     * §4.4 "A `kind` change … is never followed silently … the client shows the Trust Gate again, naming the change.
     * Until the person confirms, the client keeps using the old `kind`." And: "A card that changes both `origin` and
     * `kind` is a `kind` change, with its Trust Gate, never a move alone."
     */
    @Test fun aKindChangeIsNeverFollowedSilentlyAndACardThatAlsoMovesIsAKindChangeFirst() = world {
        val oh = operator()
        val ah = member("alice")
        val base = oh.trust.pinFor(origin)!!
        assertEquals("private", base.kind)
        val toPublic = Adversary.signCard(oh, origin, base, server.now()) { it.copy(kind = InstanceKind.PUBLIC) }
        val serving = proxy.serveCards("alice") { genuine -> genuine + toPublic }
        val changed = assertIs<CardStatus.KindChanged>(ah.trust.refresh(origin), "a card that changes kind is never followed silently")
        assertEquals("public", changed.newest.kind)
        assertEquals("private", ah.trust.pinFor(origin)!!.kind, "until the person confirms, the old kind stays")
        assertEquals(0L, ah.trust.pinFor(origin)!!.seq)
        // The person confirms through the Trust Gate that names the change.
        assertEquals("public", assertIs<CardStatus.Ok>(ah.trust.acceptKindChange(changed)).pin.kind)
        assertEquals("public", ah.trust.pinFor(origin)!!.kind)
        serving.remove()

        // A card that changes both: the kind change comes first, never a move alone.
        val bh = member("bob")
        val both = Adversary.signCard(oh, origin, base, server.now()) { it.copy(kind = InstanceKind.PUBLIC, origin = proxy.dial("elsewhere")) }
        proxy.serveCards("bob") { genuine -> genuine + both }
        assertIs<CardStatus.KindChanged>(bh.trust.refresh(origin), "both changed: a kind change, with its Trust Gate")
        assertEquals(base.hash, bh.trust.pinFor(origin)!!.hash)
    }
}
