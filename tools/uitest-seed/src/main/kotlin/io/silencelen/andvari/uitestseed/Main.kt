package io.silencelen.andvari.uitestseed

import io.ktor.client.HttpClient
import io.ktor.client.engine.java.Java
import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.CardData
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.SyncEngine
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.runBlocking
import java.io.File
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
 *
 * Nothing here is a backdoor: the server is unmodified and every call is one the apps make.
 */
fun main(args: Array<String>) {
    when (args.firstOrNull()) {
        "env" -> env(File(args.getOrNull(1) ?: usage()))
        "seed" -> if (args.size == 7) seed(args[1], args[2], args[3], args[4], args[5], args[6]) else usage()
        else -> usage()
    }
}

private fun usage(): Nothing {
    System.err.println("usage: uitest-seed env <file> | seed <origin> <token> <email> <password> <https site> <http site>")
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
