package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.DeviceLinkHost
import io.silencelen.andvari.core.app.DigitsResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PasswordChangeResult
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ProofResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.app.boundedProbe
import io.silencelen.andvari.core.app.waitFor
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.devicelink.DeviceLinkServer
import io.silencelen.andvari.core.client.devicelink.NewStep
import io.silencelen.andvari.core.client.devicelink.WireDeviceLinks
import io.silencelen.andvari.core.client.items.ItemCodec
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.AccountOpen
import io.silencelen.andvari.core.client.onboard.EstablishedSession
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.onboard.KnownDevices
import io.silencelen.andvari.core.client.onboard.PasswordOpen
import io.silencelen.andvari.core.client.onboard.SessionSink
import io.silencelen.andvari.core.client.pin.GateEntry
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.AttachmentMeta
import io.silencelen.andvari.core.model.wire.ClientPolicy
import io.silencelen.andvari.core.model.wire.Mutation
import io.silencelen.andvari.core.model.wire.MutationOp
import io.silencelen.andvari.core.model.wire.MutationResult
import io.silencelen.andvari.core.model.wire.MutationStatus
import io.silencelen.andvari.core.model.wire.PushRequest
import io.silencelen.andvari.core.model.wire.PushResponse
import io.silencelen.andvari.core.model.wire.SyncItem
import io.silencelen.andvari.core.model.wire.SyncResponse
import io.silencelen.andvari.core.model.wire.SyncVault
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Work that outlives a lock. The rule: after a lock nothing is sealed, wrapped,
 * signed or derived with the account's keys, nothing built from them is sent, and an operation the lock overtook ends
 * with a plain "locked" outcome. Each test holds one request of the app at the server, locks the app while it waits,
 * lets the answer through, and reads what reached the server.
 *
 * The server is [FakeInstance] behind [ProbeServer], which adds the item routes an honest server answers (sync, push,
 * attachment uploads) and records every request with whether the lock had come by then.
 */
class EngineKeysAfterLockTest {
    private val real = createCryptoProvider()

    /** Run once at the end of the [kdfCountdown]-th Argon2id call from now: a lock that lands while the KDF runs. */
    private var duringKdf: (() -> Unit)? = null
    private var kdfCountdown = 0

    /**
     * The real provider, with a seam at the end of every Argon2id: since the master password is proven on the device
     * (spec 01 §7), the KDF is the re-authentication's wait, and a lock on another thread can land in it.
     */
    private val crypto = object : io.silencelen.andvari.core.crypto.CryptoProvider by real {
        override fun argon2id(password: ByteArray, salt: ByteArray, outLen: Int, opsLimit: Long, memLimitBytes: Long): ByteArray {
            val out = real.argon2id(password, salt, outLen, opsLimit, memLimitBytes)
            val f = duringKdf
            if (f != null && --kdfCountdown == 0) {
                duringKdf = null
                f()
            }
            return out
        }
    }

    private fun lockDuringKdf(nth: Int, lock: () -> Unit) {
        kdfCountdown = nth
        duringKdf = lock
    }
    private val strong = "correct horse Battery 9 staple"
    private val email = "alice@example.com"

    /** A request held at the server: [reached] when it arrives, answered once [release] completes. */
    private class Held(val route: WireRoute) {
        val reached = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()

        /** Waits for the request to arrive, within the probe's bound: a probe never hangs. */
        suspend fun arrived() = waitFor("the $route request to reach the server") { reached.await() }
    }

    /** Waits for an intent the probe started to end, within the probe's bound. */
    private suspend fun kotlinx.coroutines.Job.answered(what: String = "the intent to answer after the lock") = waitFor(what) { join() }

    /**
     * [inner] (the onboarding fake, or the device-link server over it) with the item plane of an honest server: the
     * personal vault's row, the items pushed, and attachment uploads. [log] has every request in the order it arrived,
     * with whether [locked] was set then; [pushed] every mutation pushed, likewise.
     */
    private class ProbeServer(private val inner: WireClient, private val instance: FakeInstance) : WireClient {
        override val origin: String get() = inner.origin
        var locked = false
        val log = ArrayList<Pair<WireRoute, Boolean>>()
        val pushed = ArrayList<Pair<Mutation, Boolean>>()
        private var rev = 1L
        private val items = ArrayList<SyncItem>()
        private val holds = HashMap<WireRoute, Held>()
        var usage: String? = null
        var usagePuts = 0

        fun hold(route: WireRoute): Held = Held(route).also { holds[route] = it }

        private suspend fun arrive(route: WireRoute) {
            log += route to locked
            holds.remove(route)?.let {
                it.reached.complete(Unit)
                it.release.await()
            }
        }

        private fun personalVault(): String? = instance.accounts.values.lastOrNull()?.personalWrap?.vaultId

        @Suppress("UNCHECKED_CAST")
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            // What was sent before the lock is "before the lock", however late its answer.
            val lockedWhenSent = locked
            arrive(route)
            return when (route) {
                WireRoute.CLIENT_POLICY -> {
                    // Room for a small file (the onboarding fake allows one byte).
                    val p = WireJson.json.decodeFromString(ClientPolicy.serializer(), (inner.call(route, pathParams, query, bodyJson, authenticated) { it } as WireResult.Ok).value)
                    WireResult.Ok(decode(WireJson.json.encodeToString(ClientPolicy.serializer(), p.copy(attachmentMaxBytes = 1_048_576, itemAttachmentsMaxBytes = 4_194_304))), 200)
                }
                WireRoute.SYNC -> {
                    val since = query?.substringAfter("since=")?.toLongOrNull() ?: 0L
                    val vaults = personalVault()?.let { listOf(SyncVault(it, "personal", 1, "", instance.now)) }.orEmpty()
                    val r = SyncResponse(rev, since == 0L, vaults, emptyList(), items.filter { it.rev > since }, emptyList(), emptyList(), 0, 0)
                    WireResult.Ok(decode(WireJson.json.encodeToString(SyncResponse.serializer(), r)), 200)
                }
                WireRoute.PUSH -> {
                    val b = WireJson.json.decodeFromString(PushRequest.serializer(), bodyJson!!)
                    val results = b.mutations.map { m ->
                        pushed += m to lockedWhenSent
                        rev++
                        items.removeAll { it.itemId == m.itemId }
                        val up = m.item
                        items += SyncItem(m.itemId, m.vaultId, rev, instance.now, instance.now, m.op == MutationOp.DELETE, false,
                            up?.formatVersion ?: 1, up?.attachmentIds.orEmpty(), up?.blob)
                        MutationResult(m.mutationId, MutationStatus.APPLIED, rev)
                    }
                    WireResult.Ok(decode(WireJson.json.encodeToString(PushResponse.serializer(), PushResponse(rev, results))), 200)
                }
                // The usage ledger (spec 02 §8.2): one sealed blob, as stored.
                WireRoute.USAGE_GET -> WireResult.Ok(decode("""{"sealedUsage":${usage?.let { "\"$it\"" } ?: "null"},"updatedAt":0}"""), 200)
                WireRoute.USAGE_PUT -> {
                    usage = WireJson.json.decodeFromString(io.silencelen.andvari.core.model.wire.UsagePut.serializer(), bodyJson!!).sealedUsage
                    usagePuts++
                    WireResult.Ok(decode(""), 200)
                }
                else -> inner.call(route, pathParams, query, bodyJson, authenticated, decode)
            }
        }

        /** Each upload: the bytes as they arrived, and as the server stored them once its answer was let through. */
        val uploads = ArrayList<Pair<ByteArray, ByteArray>>()

        override suspend fun <T> callBytes(route: WireRoute, pathParams: Map<String, String>, query: String?, body: ByteArray, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            val arrived = body.copyOf()
            arrive(route)
            if (route != WireRoute.ATTACHMENT_UPLOAD) return WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
            // A transport still streams the body while the answer is held: what is stored is read after the wait.
            uploads += arrived to body.copyOf()
            val q = query.orEmpty().split('&').associate { it.substringBefore('=') to it.substringAfter('=') }
            val meta = AttachmentMeta(pathParams.getValue("attachmentId"), q["itemId"].orEmpty(), q["vaultId"].orEmpty(), body.size.toLong(),
                Bytes.toHexLower(instance.crypto.sha256(body)), instance.now)
            return WireResult.Ok(decode(WireJson.json.encodeToString(AttachmentMeta.serializer(), meta)), 200)
        }
    }

    private class Env(val instance: FakeInstance, val server: ProbeServer, val app: EngineAppApi, val links: DeviceLinkServer?) {
        /** The lock, as auto-lock or the app going to the background does it; every request from here on is "after the lock". */
        fun lockNow() {
            server.locked = true
            app.lock()
        }

        /** The requests that arrived after the lock. */
        fun sentAfterLock(): List<WireRoute> = server.log.filter { it.second }.map { it.first }
    }

    private fun env(withLinks: Boolean = false): Env {
        val instance = FakeInstance(crypto)
        val links = if (withLinks) DeviceLinkServer(instance) else null
        // The device-link server knows its caller by the account the app registered.
        val inner: WireClient = if (links == null) instance else object : WireClient {
            override val origin: String get() = instance.origin
            override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> =
                links.client(instance.accounts.values.lastOrNull()?.userId).call(route, pathParams, query, bodyJson, authenticated, decode)
        }
        val server = ProbeServer(inner, instance)
        val transport = BearerTransport(mapOf(instance.origin to server))
        val app = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", transport, MemoryDeviceState(), MemoryDeviceState(), crypto,
                { instance.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
        ).also {
            it.linkPollMs = Long.MAX_VALUE
            it.start()
        }
        return Env(instance, server, app, links)
    }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    /** A new account on this device, its kit confirmed: the vault is open on a cache in memory (no policy read yet). */
    private suspend fun open(a: EngineAppApi) {
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), "h.example"))
        assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(a.at()))
        assertEquals(ServerResult.DONE, a.entry.createAccountHere(a.at()))
        assertEquals(SignUpStartResult.DONE, a.entry.startSignUp(a.at(), email, true))
        assertEquals(CodeResult.DONE, a.entry.verifySignUpCode(a.at(), "482915"))
        assertEquals(CreateAccountResult.DONE, a.entry.createAccount(a.at(), NewAccountInput("", "Alice", strong, true)))
        val kit = a.at<EntryScreen.Kit>()
        val doc = assertNotNull(a.kit.kitDocument(kit.kit))
        a.kit.proceedToConfirm(kit.kit)
        val confirm = a.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, a.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
    }

    /** Whether [m]'s item opens under a vault key of 32 zero bytes: what anyone who reads the server's storage could do. */
    private fun opensUnderZeros(m: Mutation): Boolean {
        val up = m.item ?: return false
        // The provider itself, not ItemCodec: the floor refuses an all-zero key at every open of the shared
        // code, so an open through it never succeeded and this detector passed whatever had been sealed under zeros.
        val env = runCatching { Bytes.fromB64(up.blob ?: return false) }.getOrNull() ?: return false
        if (io.silencelen.andvari.core.crypto.Envelope.structuralRefusal(env) != null) return false
        val ad = io.silencelen.andvari.core.crypto.Ad.item(m.vaultId, m.itemId, up.formatVersion)
        return runCatching { crypto.aeadDecrypt(ByteArray(32), env.copyOfRange(2, 26), env.copyOfRange(26, env.size), ad) }.isSuccess
    }

    /** What an intent threw: an intent the lock overtook answers, it never crashes. */
    private val crashes = ArrayList<Throwable>()

    /** Starts the intent [block] now (to its first wait); a throw is recorded in [crashes] rather than failing the test's scope. */
    private fun kotlinx.coroutines.CoroutineScope.intent(block: suspend () -> Unit): kotlinx.coroutines.Job =
        launch(start = CoroutineStart.UNDISPATCHED) {
            try {
                block()
            } catch (c: CancellationException) {
                throw c
            } catch (t: Throwable) {
                crashes += t
            }
        }

    private fun Env.zeroSealed(): List<String> = server.pushed.filter { opensUnderZeros(it.first) }.map { it.first.itemId }

    /**
     * An import of 201 logins on an in-memory cache: the first batch of 200 is on its way when the
     * app locks. Nothing is sealed under an all-zero key, nothing is sealed or sent after the lock, and the import says
     * "not done" (the content closed with the lock).
     */
    @Test fun anImportALockOvertakesSealsNothingUnderZerosAndSendsNothingAfterTheLock() = boundedProbe {
        run {
            val e = env()
            open(e.app)
            val c = assertNotNull(e.app.content)
            val csv = buildString {
                append("name,url,username,password,note\n")
                for (i in 0 until 201) append("site$i,https://s$i.example,user$i,pw-secret-$i,\n")
            }
            assertEquals(ActionResult.Ok, c.importCsv(csv.encodeToByteArray()))
            val held = e.server.hold(WireRoute.PUSH)
            var result: ActionResult? = null
            val job = intent { result = c.confirmImport() }
            held.arrived()
            e.lockNow()
            held.release.complete(Unit)
            job.answered()
            assertEquals(AppPhase.LOCKED, e.app.snapshot.phase)
            assertEquals(200, e.server.pushed.count { !it.second }, "the first batch went before the lock")
            assertEquals(emptyList(), e.zeroSealed(), "nothing is sealed under 32 zero bytes")
            assertEquals(emptyList(), e.sentAfterLock(), "nothing is sent after the lock")
            assertEquals(ActionResult.NotDone(null), result, "the import ends as overtaken by the lock")
        }
    }

    /**
     * A password change with a lock while the re-authentication waits: nothing is sent, the
     * server's wrap is unchanged, a new device still signs in with the password, and the answer is the "locked" outcome
     * (STALE), never DONE. The re-authentication is proven on this device (spec 01 §7) and no prelogin
     * is dialed: its wait is the KDF of that proof (the second Argon2id of the change; the first is the new password's).
     */
    @Test fun aPasswordChangeALockOvertakesSendsNothingAndAnswersStale() = boundedProbe {
        run {
            val e = env()
            open(e.app)
            val acct = e.instance.account(email)
            val before = acct.wrappedUvk
            val sentBefore = e.server.log.size
            lockDuringKdf(2) { e.lockNow() }
            var result: PasswordChangeResult? = null
            val job = intent { result = e.app.settings.changeMasterPassword(strong, "another Strong password 7 horse") }
            job.answered()
            assertEquals(AppPhase.LOCKED, e.app.snapshot.phase, "the lock landed during the proof")
            assertEquals(emptyList(), crashes.map { it.toString() }, "the change answers, it does not crash")
            assertFalse(e.server.log.any { it.first == WireRoute.PASSWORD_CHANGE }, "nothing is sent")
            assertEquals(listOf(WireRoute.CLIENT_POLICY), e.server.log.drop(sentBefore).map { it.first }, "only the read of the served cost, after the proof held")
            assertEquals(before, acct.wrappedUvk, "the server's wrap is unchanged")
            // What a new device does at sign-in: the served keys open with the password, every identity check passing.
            assertIs<PasswordOpen.Opened>(AccountOpen.openWithPassword(crypto, acct.userId, strong.toCharArray(), e.instance.keys(acct), e.instance.instanceId))
            assertEquals(PasswordChangeResult.STALE, result)
            // No pending wrap was kept: only the password in force opens this device, and it is still usable.
            assertEquals(VaultUnlockResult.WRONG_PASSWORD, e.app.unlock(e.app.snapshot.locked!!, "another Strong password 7 horse"))
            assertEquals(VaultUnlockResult.DONE, e.app.unlock(e.app.snapshot.locked!!, strong))
            assertEquals(PasswordChangeResult.DONE, e.app.settings.changeMasterPassword(strong, "another Strong password 7 horse"))
        }
    }

    /**
     * The entry screens: a registration's session is open while its recovery
     * record is written to the account state, and the server holds that answer until the app locks by itself. The write
     * is refused under the wiped key: nothing is sealed or sent after the lock, "Create account" answers STALE (it used
     * to throw the guard's refusal at the screen), the new account stays kept and locked, and its next unlock asks for
     * a kit (none was shown) and then opens the vault.
     */
    @Test fun aRegistrationALockOvertakesWhileItsSessionIsOpenAnswersStaleAndTheAccountOpensAfterTheUnlock() = boundedProbe {
        run {
            val e = env()
            val a = e.app
            a.entry.openOwnServer(a.at())
            assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), "h.example"))
            assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(a.at()))
            assertEquals(ServerResult.DONE, a.entry.createAccountHere(a.at()))
            assertEquals(SignUpStartResult.DONE, a.entry.startSignUp(a.at(), email, true))
            assertEquals(CodeResult.DONE, a.entry.verifySignUpCode(a.at(), "482915"))
            val form = a.at<EntryScreen.CreateAccount>()
            val held = e.server.hold(WireRoute.ACCOUNT_STATE_GET)
            var result: CreateAccountResult? = null
            val job = intent { result = a.entry.createAccount(form, NewAccountInput("", "Alice", strong, true)) }
            held.arrived()
            e.lockNow()
            held.release.complete(Unit)
            job.answered()
            assertEquals(emptyList(), crashes.map { it.toString() }, "the intent answers, it does not crash")
            assertEquals(CreateAccountResult.STALE, result)
            assertEquals(emptyList(), e.sentAfterLock(), "nothing is sent after the lock")
            assertEquals(AppPhase.LOCKED, a.snapshot.phase, "the new account is kept, locked")
            assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
            val kit = a.at<EntryScreen.Kit>()
            val doc = assertNotNull(a.kit.kitDocument(kit.kit))
            a.kit.proceedToConfirm(kit.kit)
            val confirm = a.at<EntryScreen.Kit>().kit
            assertEquals(KitConfirmResult.DONE, a.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
            assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
        }
    }

    /**
     * The usage ledger on the new session (spec 02 §8.2): a fill the content records is batched and
     * sent sealed after the next completed sync; uses recorded and not yet sent when a lock comes are dropped with it,
     * never sealed or sent after the lock.
     */
    @Test fun aRecordedUseIsSentSealedAfterASyncAndNothingAfterALock() = boundedProbe {
        run {
            val e = env()
            open(e.app)
            val c = assertNotNull(e.app.content)
            assertEquals(ActionResult.Ok, c.saveLogin(null, io.silencelen.andvari.core.app.LoginInput("Bank", "me", "pw-secret", listOf("https://bank.test"), "", "", false), null))
            assertEquals(ActionResult.Ok, c.saveLogin(null, io.silencelen.andvari.core.app.LoginInput("Shop", "me", "pw-other", listOf("https://shop.test"), "", "", false), null))
            val bank = c.state.items.single { it.name == "Bank" }.itemId
            val shop = c.state.items.single { it.name == "Shop" }.itemId
            assertNotNull(c.fillCredential(bank))
            assertEquals(0, e.server.usagePuts, "batched, never sent per use")
            e.app.vault!!.afterLogAction()
            assertEquals(1, e.server.usagePuts, "sent after the completed sync")
            val sealed = assertNotNull(e.server.usage)
            assertFalse(sealed.contains(bank), "sealed: the item ids are not readable at the server")

            assertNotNull(c.fillCredential(shop))
            e.lockNow()
            assertEquals(1, e.server.usagePuts, "nothing is sent for the lock")
            assertEquals(emptyList(), e.sentAfterLock())
        }
    }

    /**
     * A use recorded within the debounce before a lock (the phone's commonest
     * use: one fill, then the lock) is sealed at the lock, BEFORE the wipe and without a wait, kept on the device, and
     * sent sealed once, by the next unlock's first completed sync. Before, the lock cleared it. Nothing is sent for the
     * lock itself, and the kept record is gone once it was handed on.
     */
    @Test fun aUseALockOvertakesIsSealedBeforeTheWipeAndSentOnceAfterTheNextUnlocksSync() = boundedProbe {
        run {
            val e = env()
            open(e.app)
            // The second opening has the policy as read: an offline copy is allowed, so this device may keep data at rest.
            e.app.lock()
            assertEquals(VaultUnlockResult.DONE, e.app.unlock(e.app.snapshot.locked!!, strong))
            assertTrue(assertNotNull(e.app.vault).keptAtRest)
            val c = assertNotNull(e.app.content)
            assertEquals(ActionResult.Ok, c.saveLogin(null, io.silencelen.andvari.core.app.LoginInput("Bank", "me", "pw-secret", listOf("https://bank.test"), "", "", false), null))
            val bank = c.state.items.single { it.name == "Bank" }.itemId
            e.app.vault!!.afterLogAction()
            val puts = e.server.usagePuts
            val userId = assertNotNull(e.app.keeper.established).userId
            val key = EngineVault.keptUsesKey(e.instance.origin, userId)

            assertNotNull(c.fillCredential(bank))
            e.lockNow()
            assertEquals(puts, e.server.usagePuts, "nothing is sent for the lock")
            assertEquals(emptyList(), e.sentAfterLock())
            val kept = assertNotNull(e.app.engine.state.get(key), "kept, sealed")
            assertFalse(kept.contains(bank), "sealed: the item id is not readable on the device")

            e.server.locked = false
            assertEquals(VaultUnlockResult.DONE, e.app.unlock(e.app.snapshot.locked!!, strong))
            assertEquals(puts + 1, e.server.usagePuts, "sent by the opening's first completed sync")
            assertNull(e.app.engine.state.get(key), "handed on, so it is sent once")
            val ledger = io.silencelen.andvari.core.client.UsageLedger.parse(e.app.vault!!.openUsage(assertNotNull(e.server.usage)).decodeToString())
            assertEquals(1L, ledger[bank]?.useCount)
            e.app.vault!!.afterLogAction()
            val again = io.silencelen.andvari.core.client.UsageLedger.parse(e.app.vault!!.openUsage(assertNotNull(e.server.usage)).decodeToString())
            assertEquals(1L, again[bank]?.useCount, "once")
        }
    }

    /** The same, on an opening that may keep nothing at rest (no offline copy allowed as read): the use is dropped, nothing is kept or sent. */
    @Test fun aUseALockOvertakesWhereNothingMayBeKeptIsDroppedAndNeverSent() = boundedProbe {
        run {
            val e = env()
            open(e.app)
            assertFalse(assertNotNull(e.app.vault).keptAtRest, "the first opening read no policy: nothing at rest")
            val c = assertNotNull(e.app.content)
            assertEquals(ActionResult.Ok, c.saveLogin(null, io.silencelen.andvari.core.app.LoginInput("Bank", "me", "pw-secret", listOf("https://bank.test"), "", "", false), null))
            val bank = c.state.items.single { it.name == "Bank" }.itemId
            val userId = assertNotNull(e.app.keeper.established).userId
            assertNotNull(c.fillCredential(bank))
            e.lockNow()
            assertEquals(emptyList(), e.sentAfterLock())
            assertNull(e.app.engine.state.get(EngineVault.keptUsesKey(e.instance.origin, userId)), "nothing is kept")
            e.server.locked = false
            assertEquals(VaultUnlockResult.DONE, e.app.unlock(e.app.snapshot.locked!!, strong))
            val sealed = e.server.usage
            if (sealed != null) {
                val ledger = io.silencelen.andvari.core.client.UsageLedger.parse(e.app.vault!!.openUsage(sealed).decodeToString())
                assertNull(ledger[bank], "the dropped use is never sent")
            }
        }
    }

    /**
     * The password change's first wait: a lock while the new password's KDF runs, before the new wrap is sealed. The
     * seal refuses under the wiped key: nothing is sealed under zeros, nothing is kept or sent, the answer is STALE.
     */
    @Test fun aPasswordChangeALockOvertakesDuringTheNewPasswordsKdfSealsAndSendsNothing() = boundedProbe {
        run {
            val e = env()
            open(e.app)
            val acct = e.instance.account(email)
            val before = acct.wrappedUvk
            val sentBefore = e.server.log.size
            lockDuringKdf(1) { e.lockNow() }
            var result: PasswordChangeResult? = null
            val job = intent { result = e.app.settings.changeMasterPassword(strong, "another Strong password 7 horse") }
            job.answered()
            assertEquals(AppPhase.LOCKED, e.app.snapshot.phase)
            assertEquals(emptyList(), crashes.map { it.toString() }, "the change answers, it does not crash")
            assertEquals(sentBefore, e.server.log.size, "nothing is sent")
            assertEquals(before, acct.wrappedUvk, "the server's wrap is unchanged")
            assertEquals(PasswordChangeResult.STALE, result)
            assertEquals(VaultUnlockResult.WRONG_PASSWORD, e.app.unlock(e.app.snapshot.locked!!, "another Strong password 7 horse"))
            assertEquals(VaultUnlockResult.DONE, e.app.unlock(e.app.snapshot.locked!!, strong))
        }
    }

    /**
     * The password change's last wait: a lock while the request itself is on its way. It was built and sent before the
     * lock, under the whole key; the server takes it, so the change is DONE, and this device keeps the very wrap the
     * server took (no key is used after the answer). Nothing is sent after the lock, and the new password opens both
     * this device and a new one.
     */
    @Test fun aPasswordChangeWhoseRequestALockOvertakesIsDoneAndThisDeviceFollows() = boundedProbe {
        run {
            val e = env()
            open(e.app)
            val acct = e.instance.account(email)
            val newer = "another Strong password 7 horse"
            val held = e.server.hold(WireRoute.PASSWORD_CHANGE)
            var result: PasswordChangeResult? = null
            val job = intent { result = e.app.settings.changeMasterPassword(strong, newer) }
            held.arrived()
            e.lockNow()
            held.release.complete(Unit)
            job.answered()
            assertEquals(emptyList(), crashes.map { it.toString() }, "the change answers, it does not crash")
            assertEquals(emptyList(), e.sentAfterLock(), "nothing is sent after the lock")
            assertEquals(PasswordChangeResult.DONE, result, "the server took it before the lock mattered")
            assertIs<PasswordOpen.Opened>(AccountOpen.openWithPassword(crypto, acct.userId, newer.toCharArray(), e.instance.keys(acct), e.instance.instanceId))
            assertEquals(AppPhase.LOCKED, e.app.snapshot.phase)
            assertEquals(VaultUnlockResult.WRONG_PASSWORD, e.app.unlock(e.app.snapshot.locked!!, strong))
            assertEquals(VaultUnlockResult.DONE, e.app.unlock(e.app.snapshot.locked!!, newer))
            assertEquals(acct.wrappedUvk, assertNotNull(e.app.keeper.established).accountKeys.wrappedUvk, "this device's wrap is the server's")
        }
    }

    /** The app's device link run to the approval screen, a new device (over the same server) on the other side. */
    private suspend fun Env.toApprovable(): DeviceLinkHost.Approvable {
        val a = app
        val server = assertNotNull(links)
        assertEquals(PlainResult.DONE, a.devices.startDeviceLink())
        val shown = assertIs<DeviceLinkHost.Shown>(a.snapshot.account!!.deviceLink)
        val url = assertNotNull(a.devices.deviceLinkToShow(shown))
        val nState = MemoryDeviceState()
        instance.pinnedTrust(nState)
        val sink = object : SessionSink {
            override suspend fun established(session: EstablishedSession) {}
        }
        val n = WireDeviceLinks({ server.client(null, it) }, instance.trust(nState), nState, crypto, { instance.now }, { null }, KnownDevices(nState, crypto), sink,
            { _, _ -> }, "Pixel 9", "android")
        val claimed = assertIs<NewStep.Claimed>(n.start(url, GateEntry.LINK_DEVICE_SCREEN))
        a.devicesFlow.pollDeviceLinkHost()
        val code = assertIs<NewStep.ShowCode>(n.advance(claimed))
        a.devicesFlow.pollDeviceLinkHost()
        val type = assertIs<DeviceLinkHost.TypeDigits>(a.snapshot.account!!.deviceLink)
        assertEquals(DigitsResult.DONE, a.devices.submitDeviceDigits(type, code.code))
        return assertIs<DeviceLinkHost.Approvable>(a.snapshot.account!!.deviceLink)
    }

    /**
     * A device link approved here, the app locking while the approval's last look at the
     * link is on its way: no approval is sent (its bundle would be sealed under a key derived from zeros), the answer is
     * STALE, and the server is told to drop the link.
     */
    @Test fun aDeviceLinkApprovalALockOvertakesSendsNoApprovalAndDropsTheLink() = boundedProbe {
        run {
            val e = env(withLinks = true)
            open(e.app)
            val ok = e.toApprovable()
            val held = e.server.hold(WireRoute.DEVICE_LINK_VIEW)
            var result: ProofResult? = null
            val job = intent { result = e.app.devices.approveWithPassword(ok, strong) }
            held.arrived()
            e.lockNow()
            held.release.complete(Unit)
            job.answered()
            assertEquals(emptyList(), crashes.map { it.toString() }, "the approval answers, it does not crash")
            assertFalse(e.server.log.any { it.first == WireRoute.DEVICE_LINK_APPROVE }, "no approval is sent")
            assertEquals(emptyList(), e.links!!.rows.keys.toList(), "the server was told to drop the link")
            assertEquals(ProofResult.STALE, result)
        }
    }

    /**
     * The person cancels while the approval waits on the server: the screen says
     * cancelled, and the server holds no approval for the new device to pick up (the link is dropped by its id).
     */
    @Test fun aDeviceLinkCancelledDuringTheApprovalLeavesNoApprovalAtTheServer() = boundedProbe {
        run {
            val e = env(withLinks = true)
            open(e.app)
            val ok = e.toApprovable()
            val held = e.server.hold(WireRoute.DEVICE_LINK_VIEW)
            var result: ProofResult? = null
            val job = intent { result = e.app.devices.approveWithPassword(ok, strong) }
            held.arrived()
            var cancelled: PlainResult? = null
            val cancel = intent { cancelled = e.app.devices.cancelDeviceLink() }
            held.release.complete(Unit)
            job.answered()
            cancel.answered("the cancel to answer")
            assertEquals(emptyList(), crashes.map { it.toString() }, "neither the approval nor the cancel crashes")
            assertEquals(PlainResult.DONE, cancelled)
            assertEquals(emptyList(), e.links!!.rows.keys.toList(), "the server holds no approval: the link is dropped")
            assertEquals(ProofResult.STALE, result)
        }
    }

    /**
     * A save with a new file: the upload is on its way when the app locks. The item
     * is not sealed or sent after the lock; the save is kept, and the next unlock finishes it (the change is not lost).
     */
    @Test fun aSaveWithAFileALockOvertakesIsNotSealedAfterTheLockAndIsFinishedAfterTheUnlock() = boundedProbe {
        run {
            val e = env()
            open(e.app)
            val c = assertNotNull(e.app.content)
            c.openAttachmentDraft(null)
            assertEquals(ActionResult.Ok, c.addAttachment("note.txt", "hello".encodeToByteArray()))
            val held = e.server.hold(WireRoute.ATTACHMENT_UPLOAD)
            var result: ActionResult? = null
            val job = launch(start = CoroutineStart.UNDISPATCHED) {
                result = c.saveLogin(null, LoginInput("bank", "alice", "pw-secret", emptyList(), "", "", false), null)
            }
            held.arrived()
            e.lockNow()
            held.release.complete(Unit)
            job.answered()
            assertEquals(emptyList(), e.zeroSealed(), "nothing is sealed under 32 zero bytes")
            assertEquals(emptyList(), e.sentAfterLock(), "nothing is sent after the lock")
            assertEquals(ActionResult.NotDone(null), result)
            // The kept save is finished by the next unlock's content, under the real key.
            e.server.locked = false
            assertEquals(VaultUnlockResult.DONE, e.app.unlock(e.app.snapshot.locked!!, strong))
            assertNotNull(e.app.content).syncQuietly()
            assertTrue(e.server.pushed.any { it.first.op == MutationOp.PUT }, "the kept save was sent after the unlock")
            assertEquals(emptyList(), e.zeroSealed())
        }
    }

    /**
     * A lock while a file is on its way wipes the draft, whose arrays the upload was
     * handed. The server must store the bytes that were sealed, never zeros, so the item that names the file after the
     * next unlock names the file that was saved.
     */
    @Test fun aLockDuringAnUploadNeverLeavesTheServerAFileOtherThanTheOneSealed() = boundedProbe {
        val e = env()
        open(e.app)
        val c = assertNotNull(e.app.content)
        c.openAttachmentDraft(null)
        assertEquals(ActionResult.Ok, c.addAttachment("note.txt", "hello, kept file".encodeToByteArray()))
        val held = e.server.hold(WireRoute.ATTACHMENT_UPLOAD)
        val job = intent { c.saveLogin(null, LoginInput("bank", "alice", "pw-secret", emptyList(), "", "", false), null) }
        held.arrived()
        e.lockNow()
        held.release.complete(Unit)
        job.answered()
        assertEquals(emptyList(), crashes.map { it.toString() })
        val (arrived, stored) = e.server.uploads.single()
        assertTrue(arrived.any { it != 0.toByte() }, "a real file was sent")
        assertTrue(arrived.contentEquals(stored), "the server stored the bytes that were sealed, not what the lock left of them")
    }

    /**
     * The stale-key shape the probes above do not see: a key array
     * kept somewhere across sessions and used again after the next unlock. Every probe above locks during work and looks
     * at what was sent; a holder that outlives the lock sends nothing wrong at the lock itself, it reuses the zeros later.
     * So: unlock, work, lock, unlock again, work again, twice over. Each second session's work (reading the first
     * session's item, a save, a save with a file, a sync, the usage ledger) succeeds, and nothing in it was attempted
     * under an erased key: the shared floor refused nothing, and nothing pushed opens under zeros.
     */
    @Test fun aSessionAfterALockUsesNothingTheLockErased() = boundedProbe {
        val refusals = ArrayList<String>()
        val heard = io.silencelen.andvari.core.crypto.KeyFloor.onRefusal
        io.silencelen.andvari.core.crypto.KeyFloor.onRefusal = { refusals += it; heard?.invoke(it) }
        try {
            val e = env()
            open(e.app)
            val first = assertNotNull(e.app.content)
            assertEquals(ActionResult.Ok, first.saveLogin(null, LoginInput("Bank", "me", "pw-bank", listOf("https://bank.test"), "", "", false), null))
            val bank = first.state.items.single { it.name == "Bank" }.itemId
            assertEquals("pw-bank", first.fillCredential(bank)?.password)
            e.app.vault!!.afterLogAction()
            for (round in 1..2) {
                e.app.lock()
                assertEquals(AppPhase.LOCKED, e.app.snapshot.phase)
                assertEquals(VaultUnlockResult.DONE, e.app.unlock(e.app.snapshot.locked!!, strong), "round $round: the unlock")
                val c = assertNotNull(e.app.content)
                assertEquals(ActionResult.Ok, c.syncQuietly(), "round $round: a sync")
                assertEquals("pw-bank", c.fillCredential(bank)?.password, "round $round: the first session's item opens")
                assertEquals(ActionResult.Ok, c.saveLogin(null, LoginInput("Shop $round", "me", "pw-$round", listOf("https://shop.test"), "", "", false), null), "round $round: a save")
                c.openAttachmentDraft(null)
                assertEquals(ActionResult.Ok, c.addAttachment("note-$round.txt", "kept $round".encodeToByteArray()), "round $round: a file")
                assertEquals(ActionResult.Ok, c.saveLogin(null, LoginInput("Mail $round", "me", "pw-m$round", emptyList(), "", "", false), null), "round $round: a save with a file")
                e.app.vault!!.afterLogAction()
                assertEquals(emptyList(), refusals, "round $round: nothing was attempted under the erased key of an earlier session")
            }
            assertEquals(emptyList(), e.zeroSealed(), "nothing is sealed under 32 zero bytes")
            assertTrue(e.server.pushed.any { it.first.op == MutationOp.PUT && !it.second }, "the second sessions' saves were sent")
            assertTrue(e.server.usagePuts >= 1, "the usage ledger was sealed and sent")
        } finally {
            io.silencelen.andvari.core.crypto.KeyFloor.onRefusal = heard
        }
    }

    /**
     * A save waits behind a sync the lock then cancels: the save is not sealed or
     * sent once the sync lets it through, and it ends as "not done".
     */
    @Test fun aSaveWaitingBehindASyncTheLockCancelsIsNotSealedAfterTheLock() = boundedProbe {
        run {
            val e = env()
            open(e.app)
            val c = assertNotNull(e.app.content)
            val v = assertNotNull(e.app.vault)
            val held = e.server.hold(WireRoute.SYNC)
            v.launch { c.syncQuietly() }
            held.arrived()
            var result: ActionResult? = null
            val job = launch(start = CoroutineStart.UNDISPATCHED) {
                result = c.saveLogin(null, LoginInput("mail", "alice", "pw-2", emptyList(), "", "", false), null)
            }
            e.lockNow()
            held.release.complete(Unit)
            job.answered()
            assertEquals(emptyList(), e.zeroSealed(), "nothing is sealed under 32 zero bytes")
            assertEquals(emptyList(), e.sentAfterLock(), "nothing is sent after the lock")
            assertEquals(ActionResult.NotDone(null), result)
        }
    }
}
