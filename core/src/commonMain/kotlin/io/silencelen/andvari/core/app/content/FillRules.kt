package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.FillCard
import io.silencelen.andvari.core.app.FillCredential
import io.silencelen.andvari.core.app.FillLogin
import io.silencelen.andvari.core.client.CardDisplay
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.client.autofill.FillTarget
import io.silencelen.andvari.core.client.autofill.SavedUri
import io.silencelen.andvari.core.client.autofill.UriMatch

/**
 * The AutoFill answers over a working set of decrypted items, shared by the app's content ([ContentController]) and
 * the extension's snapshot reader ([FillSnapshotVault]), so both offer and match exactly alike (the old
 * `AutofillVault` rules). Which items are in the working set is the caller's rule.
 */
internal object FillRules {
    /**
     * The most addresses of one login a fill reads: the first ones, in the item's order. An item's writer may be a
     * hostile co-member, and every address costs a host normalization (IDNA, the public suffix list) on every fill
     * request; past this an address is never matched, offered or put into the system's identity store.
     */
    const val MAX_FILL_ADDRESSES = 100

    /** The addresses of [login] a fill reads ([MAX_FILL_ADDRESSES]). */
    fun addresses(login: LoginData): List<String> = login.uris.take(MAX_FILL_ADDRESSES)

    /** The shared host rule, and a plain-http page matches only an address saved as http. */
    fun matchesAny(uris: List<String>, identifiers: List<String>): Boolean = identifiers.any { identifier ->
        val host = UriMatch.normalizeHost(identifier) ?: return@any false
        val capped = uris.take(MAX_FILL_ADDRESSES)
        val offered = if (identifier.trim().startsWith("http://", ignoreCase = true)) capped.filter { it.trim().startsWith("http://", ignoreCase = true) } else capped
        UriMatch.matchLogins(offered, FillTarget(host, ""))
    }

    /**
     * The logins of [items], those matching one of [hosts] first, then by name. The name, username and host are shown
     * in a suggestion list, so each is a label ([ItemText.label]); what a fill hands out comes from [credential].
     */
    fun logins(items: List<VaultItem>, hosts: List<String>): List<FillLogin> = items
        .filter { it.doc.type == "login" && it.doc.login != null }
        .map { item ->
            val login = item.doc.login!!
            val addresses = addresses(login)
            FillLogin(
                itemId = item.itemId, name = ItemText.label(item.doc.name), username = ItemText.label(login.username.orEmpty()),
                host = addresses.firstOrNull()?.let { UriMatch.normalizeHostUnicode(it) ?: UriMatch.normalizeHost(it) }?.let { ItemText.label(it) },
                matches = matchesAny(addresses, hosts), hasTotp = !login.totp.isNullOrEmpty(),
                uris = addresses.filter { UriMatch.parseSavedUri(it) is SavedUri.Web },
                // App addresses in their own field: never in [uris], where a web rule would read them.
                appUris = addresses.filter { UriMatch.parseSavedUri(it) is SavedUri.AndroidApp }.map { it.trim() },
            )
        }
        .sortedWith(compareByDescending<FillLogin> { it.matches }.thenBy { it.name.lowercase() })

    fun matches(item: VaultItem?, identifiers: List<String>): Boolean = item?.doc?.login?.let { matchesAny(it.uris, identifiers) } == true

    fun credential(item: VaultItem?): FillCredential? {
        val login = item?.takeIf { it.doc.type == "login" }?.doc?.login ?: return null
        return FillCredential(login.username.orEmpty(), login.password.orEmpty())
    }

    /** The payment cards of [items], by name. Nothing secret: [cardField] releases one field at a time. */
    fun cards(items: List<VaultItem>): List<FillCard> = items.filter { it.doc.type == "card" && it.doc.card != null }.map { item ->
        val card = item.doc.card!!
        FillCard(
            itemId = item.itemId, name = ItemText.label(item.doc.name), subtitle = ItemText.label(CardDisplay.subtitle(item.doc)),
            hasNumber = !card.number.isNullOrEmpty(), hasExpiry = !card.expMonth.isNullOrEmpty() && !card.expYear.isNullOrEmpty(),
            hasCvv = !card.securityCode.isNullOrEmpty(), hasName = !card.cardholderName.isNullOrEmpty(),
        )
    }.sortedBy { it.name.lowercase() }

    /** One stored field of a card: "number", "expMonth", "expYear", "cvv", "name" or "postal"; null for anything else. */
    fun cardField(item: VaultItem?, field: String): String? {
        val card = item?.doc?.takeIf { it.type == "card" }?.card ?: return null
        return when (field) {
            "number" -> card.number
            "expMonth" -> card.expMonth
            "expYear" -> card.expYear
            "cvv" -> card.securityCode
            "name" -> card.cardholderName
            "postal" -> card.postalCode
            else -> null
        }?.ifEmpty { null }
    }
}
