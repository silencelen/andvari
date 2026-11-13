package io.silencelen.andvari.uitestseed

import io.ktor.client.HttpClient
import io.ktor.client.engine.java.Java
import io.silencelen.andvari.core.client.ANDVARI_CLIENT_VERSION
import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.CardData
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.SyncEngine
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.LoginRequest
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.io.File
import java.net.URI
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import kotlin.system.exitProcess

/**
 * Seeds a THROWAWAY andvari server for the iOS UI tests. Two steps, because the server needs its escrow pins before
 * it starts and an account can only be made once it runs:
 *
 *   env  <file>                         write the server's environment (random escrow key, enumeration secret and
 *                                       bootstrap token; the escrow private seed is discarded: nothing is recovered)
 *   seed <origin> <bootstrap token> <email> <master password> <https site origin> <http site origin>
 *                                       enroll the first account with the bootstrap invite, as any client would,
 *                                       confirm its recovery phrase so a sign-in lands in the vault, and save the
 *                                       logins the tests look for
 *   vault <create|delete|restore> <origin> <email> <master password> <vault name>
 *                                       sign in as another device of the account and create, delete or restore one of
 *                                       its shared vaults: what the app on the simulator then learns at its next sync
 *   share <origin> <email> <master password> <vault name> <item name>
 *                                       a second account shares a vault holding one login READ-ONLY with the account,
 *                                       and another device of the account accepts it (see [share])
 *
 * Nothing here is a backdoor: the server is unmodified and every call is one the apps make.
 */
fun main(args: Array<String>) {
    when (args.firstOrNull()) {
        "env" -> env(File(args.getOrNull(1) ?: usage()))
        "seed" -> if (args.size == 7) seed(args[1], args[2], args[3], args[4], args[5], args[6]) else usage()
        "vault" -> if (args.size == 6 && args[1] in setOf("create", "delete", "restore")) vault(args[1], args[2], args[3], args[4], args[5]) else usage()
        "share" -> if (args.size == 6) share(args[1], args[2], args[3], args[4], args[5]) else usage()
        else -> usage()
    }
}

private fun usage(): Nothing {
    System.err.println(
        "usage: uitest-seed env <file> | seed <origin> <token> <email> <password> <https site> <http site> | " +
            "vault <create|delete|restore> <origin> <email> <password> <vault name> | share <origin> <email> <password> <vault name> <item name>",
    )
    exitProcess(2)
}

private fun env(out: File) {
    val crypto = createCryptoProvider()
    val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
    out.writeText(
        listOf(
            "ANDVARI_RECOVERY_PUBKEY=${Bytes.toB64(recovery.publicKey)}",
            "ANDVARI_RECOVERY_FINGERPRINT=${Escrow.fingerprint(crypto, recovery.publicKey)}",
            "ANDVARI_ENUM_SECRET=${Bytes.toB64(crypto.randomBytes(32))}",
            "ANDVARI_BOOTSTRAP_TOKEN=${Bytes.toB64(crypto.randomBytes(24))}",
        ).joinToString("\n", postfix = "\n"),
    )
}

/** RFC 6238's test secret, so anyone can check a code the tests show. */
private const val TOTP = "otpauth://totp/andvari-uitest?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA1&digits=6&period=30"

private fun seed(origin: String, token: String, email: String, password: String, site: String, httpSite: String): Unit = runBlocking {
    val crypto = createCryptoProvider()
    val api = AndvariApi(origin, HttpClient(Java), platform = "linux")
    val policy = api.clientPolicy()
    val (request, account) = Account.enroll(
        inviteToken = token,
        email = email,
        displayName = "UI test",
        password = password,
        params = policy.kdfParams,
        recoveryPublicKey = Bytes.fromB64(api.recoveryPubkey()),
        recoveryFingerprint = policy.recoveryFingerprint,
        deviceName = "uitest-seed",
        crypto = crypto,
        platform = "linux",
    )
    val session = api.register(request)
    // What a client does once the person has typed the phrase back; without it the next sign-in stops at the phrase.
    api.recoverySelfConfirm(session.recoveryPieceId)
    val engine = SyncEngine(api, account, InMemoryVaultCache())
    engine.sync()
    val logins = listOf(
        ItemDoc(type = "login", name = "UITest Site", favorite = true, login = LoginData("alice", "alice-Passw0rd-site", listOf("$site/"), TOTP)),
        ItemDoc(type = "login", name = "UITest Site second", login = LoginData("alice.second", "second-Passw0rd-site", listOf("$site/login.html"))),
        ItemDoc(type = "login", name = "UITest Plain HTTP", login = LoginData("bob", "bob-Passw0rd-http", listOf("$httpSite/"))),
        ItemDoc(type = "login", name = "Example Mail", login = LoginData("carol@example.com", "carol-Passw0rd-mail", listOf("https://mail.example.com"), TOTP)),
        ItemDoc(type = "login", name = "No Address", login = LoginData("dave", "dave-Passw0rd-none")),
        ItemDoc(type = "note", name = "UITest Note", notes = "A note the tests open."),
        // The industry's test number: it passes the check digit and belongs to no one.
        ItemDoc(type = "card", name = "UITest Card", card = CardData(cardholderName = "UI Test", number = "4111111111111111", expMonth = "12", expYear = "2031", securityCode = "123")),
    )
    logins.forEach { engine.save(null, it) }
    engine.sync()
    check(engine.items().size == logins.size) { "the server holds ${engine.items().size} items, expected ${logins.size}" }
    api.logout()
    println("seeded ${logins.size} items for $email at $origin")
    // The HTTP client's threads are not daemons.
    exitProcess(0)
}

/** A sign-in as a new device of the account, as any client makes one. */
private suspend fun signIn(origin: String, email: String, password: String, crypto: CryptoProvider): Pair<AndvariApi, Account> {
    val api = AndvariApi(origin, HttpClient(Java), platform = "linux")
    val pre = api.prelogin(email)
    val authKey = Account.deriveAuthKey(password, pre.kdfSalt, pre.kdfParams, crypto)
    val session = api.login(LoginRequest(email, authKey, Account.deviceInfo("uitest-other-device", "linux")))
    return api to Account.unlock(session.userId, password, session.accountKeys, crypto)
}

/** Another device of the account creates, deletes or restores the shared vault named [name], as its owner. */
private fun vault(action: String, origin: String, email: String, password: String, name: String): Unit = runBlocking {
    val crypto = createCryptoProvider()
    val (api, account) = signIn(origin, email, password, crypto)
    val engine = SyncEngine(api, account, InMemoryVaultCache())
    engine.sync()
    when (action) {
        "create" -> engine.createSharedVault(name)
        "delete" -> {
            val found = engine.vaultInfos().filter { it.type == "shared" && it.name == name }
            check(found.size == 1) { "expected one shared vault named \"$name\", found ${found.size}" }
            engine.deleteSharedVault(found.single().vaultId)
        }
        else -> {
            val found = engine.listDeleted().filter { it.name == name }
            check(found.size == 1) { "expected one deleted vault named \"$name\", found ${found.size}" }
            engine.restoreSharedVault(found.single().vaultId, found.single().deleteId)
        }
    }
    api.logout()
    println("$action: \"$name\" done")
    exitProcess(0)
}

/**
 * A vault the account only READS, reached the way a person reaches one. The test account (the server's admin) mints
 * an invite for a new second account, as the admin page does, and the second account enrolls with it. That account
 * creates the shared vault [vaultName] holding the login [itemName], checks the test account's identity code and adds
 * it as a reader. Another device of the test account then accepts the invitation, typing the sharer's identity code.
 * Accepting posts the account's own wrap of the vault key, so the app on the simulator adopts the vault at its next
 * sync without an invitation screen of its own.
 */
private fun share(origin: String, email: String, password: String, vaultName: String, itemName: String): Unit = runBlocking {
    val crypto = createCryptoProvider()
    val (api, account) = signIn(origin, email, password, crypto)
    val engine = SyncEngine(api, account, InMemoryVaultCache())
    engine.sync()

    val sharerEmail = "sharer-${Bytes.toHexLower(crypto.randomBytes(4))}@andvari-uitest.test"
    val sharerPassword = "sharer ${Bytes.toHexLower(crypto.randomBytes(16))}"
    val inviteToken = adminInvite(origin, api.currentTokens()?.accessToken ?: error("the sign-in kept no session"), sharerEmail)
    val sharerApi = AndvariApi(origin, HttpClient(Java), platform = "linux")
    val policy = sharerApi.clientPolicy()
    val (request, sharer) = Account.enroll(
        inviteToken = inviteToken,
        email = sharerEmail,
        displayName = "UI test sharer",
        password = sharerPassword,
        params = policy.kdfParams,
        recoveryPublicKey = Bytes.fromB64(sharerApi.recoveryPubkey()),
        recoveryFingerprint = policy.recoveryFingerprint,
        deviceName = "uitest-sharer",
        crypto = crypto,
        platform = "linux",
    )
    val sharerSession = sharerApi.register(request)
    sharerApi.recoverySelfConfirm(sharerSession.recoveryPieceId)
    val sharerEngine = SyncEngine(sharerApi, sharer, InMemoryVaultCache())
    sharerEngine.sync()
    val vaultId = sharerEngine.createSharedVault(vaultName)
    sharerEngine.save(null, ItemDoc(type = "login", name = itemName, login = LoginData("reader", "read-Only-Passw0rd", listOf("https://read-only.example.com"))), vaultId)
    sharerEngine.sync()
    val served = sharerEngine.lookupMember(email)
    checkNotNull(sharerEngine.verifyMemberTyped(served, account.identityFingerprintShort(), email)) { "the test account's identity code did not match the key the server serves" }
    sharerEngine.addVaultMember(vaultId, served.userId, "reader", email)

    engine.sync()
    val invitation = engine.pendingInvitations().singleOrNull { it.vaultId == vaultId } ?: error("no invitation to \"$vaultName\" reached the test account")
    check(engine.acceptInvitation(invitation, sharer.identityFingerprintShort())) { "the test account could not accept the invitation to \"$vaultName\"" }
    engine.sync()
    check(engine.items().any { it.vaultId == vaultId && it.doc.name == itemName }) { "\"$itemName\" is not readable in \"$vaultName\" after accepting" }
    sharerApi.logout()
    api.logout()

    // What the simulator's app should now see: a further device of the account, which accepted nothing, holds the vault
    // through the account's own wrap after a sync, as a reader.
    val (laterApi, later) = signIn(origin, email, password, crypto)
    val laterEngine = SyncEngine(laterApi, later, InMemoryVaultCache())
    laterEngine.sync()
    check(laterEngine.items().any { it.vaultId == vaultId && it.doc.name == itemName }) { "another device of the account does not hold \"$vaultName\" after a sync" }
    check(later.keySource(vaultId) == Account.KeySource.UVK_WRAP && later.roleFor(vaultId) == "reader") {
        "another device holds \"$vaultName\" through ${later.keySource(vaultId)} as ${later.roleFor(vaultId)}, not through the account's own wrap as a reader"
    }
    laterApi.logout()
    println("share: \"$vaultName\" shared read-only by $sharerEmail, accepted, and held by another device as a reader")
    exitProcess(0)
}

/** POST /api/v1/admin/users as the admin page sends it (no email: the invite token is used here at once). */
private fun adminInvite(origin: String, accessToken: String, email: String): String {
    val body = buildJsonObject {
        put("email", email)
        put("isAdmin", false)
        put("sendEmail", false)
        put("escrowPolicy", "required")
    }.toString()
    val request = HttpRequest.newBuilder(URI.create("$origin/api/v1/admin/users"))
        .header("Content-Type", "application/json")
        .header("Authorization", "Bearer $accessToken")
        .header("X-Andvari-Client", "linux/$ANDVARI_CLIENT_VERSION")
        .POST(HttpRequest.BodyPublishers.ofString(body))
        .build()
    val response = java.net.http.HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString())
    check(response.statusCode() == 200) { "the server refused the invite: ${response.statusCode()} ${response.body()}" }
    return Json.parseToJsonElement(response.body()).jsonObject["inviteToken"]?.jsonPrimitive?.content ?: error("the invite response has no token")
}
