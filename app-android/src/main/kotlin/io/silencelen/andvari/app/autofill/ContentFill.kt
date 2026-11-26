package io.silencelen.andvari.app.autofill

import io.silencelen.andvari.core.app.content.VaultContent
import io.silencelen.andvari.core.client.CardData
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.client.autofill.BrowserCertPins
import io.silencelen.andvari.core.client.autofill.FieldKind
import io.silencelen.andvari.core.client.autofill.FillTarget
import io.silencelen.andvari.core.client.autofill.UriMatch

/**
 * Autofill on the new code: what one form may be offered, read from the vault content's working set
 * ([VaultContent.fillLogins], [VaultContent.fillCards]), and the values of one item at a time
 * ([VaultContent.fillCredential], [VaultContent.fillCardField]).
 *
 * **Offers are not releases**. [offersFor] reads no secret: a login is
 * offered with the user name the working set lists and [UNRELEASED] where its password would be, a card with its name
 * alone. The shared code is asked for an item's values ([release]) only when a row that must carry them is built (a
 * verified browser's rows and a vetted app's own logins: the platform fills those on a pick without asking andvari
 * again), or when the person picked the item in a confirm or in andvari's chooser. Nothing merely offered is recorded as
 * a use: the rows built before a pick are read with the shared code's reads that record nothing ([release]), and the one
 * row the platform says the person picked is recorded once ([recordPicked]); a pick inside andvari ([loginById],
 * [cardById]) is recorded by the read itself.
 *
 * The working set is core's: only vaults that are accepted and neither frozen nor failed are in it (a vault in the
 * holding area never is). On top of it this keeps the app's own site rule: a login is offered only when one of its
 * addresses matches one of THIS form's fields ([UriMatch] against each field's [FillTarget]), and a card only when the
 * form is a card form a card may fill (card fields, a known focus frame, and an explicit browser trust).
 */
internal object ContentFill {
    /**
     * Where an offered login's password would be. Never a value: [FillPlan] releases a login before it builds a row
     * that carries values, and [DatasetBuilder] refuses a row that still holds it.
     */
    const val UNRELEASED = "\u0000unreleased"

    /** The form's targets: one per login field, with its frame's domain only in a trusted browser. */
    private fun targets(form: ParsedForm, trusted: Boolean): List<FillTarget> =
        form.fields.filter { it.kind == FieldKind.USERNAME || it.kind == FieldKind.PASSWORD }
            .map { FillTarget(webHost = if (trusted) it.webDomain else null, packageName = form.appPackage) }

    /** The hosts the form is for, for the content's own ordering (matching ones first); never a gate on its own. */
    private fun hosts(form: ParsedForm, trusted: Boolean): List<String> =
        if (trusted) form.fields.mapNotNull { it.webDomain }.distinct() else emptyList()

    /** What [form] may be offered: no secret is read. */
    fun offersFor(content: VaultContent, form: ParsedForm, trusted: Boolean): List<VaultItem> =
        offersFor(content, targets(form, trusted), hosts(form, trusted), cardFormAllowed(form, trusted))

    /** The same over the form's parts (the JVM tests cannot build a form: it holds platform ids). */
    internal fun offersFor(content: VaultContent, targets: List<FillTarget>, hosts: List<String>, cards: Boolean): List<VaultItem> =
        overtakable(emptyList()) { loginOffers(content, targets, hosts) + (if (cards) cardOffers(content) else emptyList()) }

    /**
     * The one place autofill asks the shared code for the vault's content. A lock overtaking the ask (the keys are gone,
     * the key fix) is the lock: nothing to offer and no values, as for a vault already locked, and nothing is logged.
     */
    private inline fun <T> overtakable(locked: T, block: () -> T): T = io.silencelen.andvari.app.Overtaken.orLocked({ locked }, block)

    private fun loginOffers(content: VaultContent, targets: List<FillTarget>, hosts: List<String>): List<VaultItem> {
        if (targets.isEmpty()) return emptyList()
        return content.fillLogins(hosts)
            .map { l -> l to addresses(l) }
            .filter { (_, uris) -> targets.any { t -> UriMatch.matchLogins(uris, t) } }
            .map { (l, uris) ->
                VaultItem(l.itemId, "", 0L, 0L, ItemDoc(type = "login", name = l.name, login = LoginData(username = l.username, password = UNRELEASED, uris = uris)))
            }
    }

    private fun cardOffers(content: VaultContent): List<VaultItem> =
        content.fillCards().filter { it.hasNumber }.map { c -> VaultItem(c.itemId, "", 0L, 0L, ItemDoc(type = "card", name = c.name)) }

    /**
     * A working-set login's addresses as Android matches them: its web addresses and its app addresses
     * (`androidapp://<package>`), which the working set keeps apart ([io.silencelen.andvari.core.app.FillLogin.appUris])
     * so no web matcher sees one. Both come from the working set itself; the item's detail is never read for a fill.
     */
    internal fun addresses(l: io.silencelen.andvari.core.app.FillLogin): List<String> =
        (l.uris + l.appUris).distinct()

    /** Whether a card may be offered on [form] at all: the gates [DatasetBuilder]'s card path applies first. */
    internal fun cardFormAllowed(form: ParsedForm, trusted: Boolean): Boolean =
        form.ccFields.isNotEmpty() && form.cardFillFrame != null && (form.appPackage !in BrowserCertPins.TABLE || trusted)

    /**
     * One item's values for a row that must carry them BEFORE the person picked anything (a verified browser's rows, a
     * vetted app's own logins): a login's or a card's; null when it is no longer there. It records NO use
     * ([VaultContent.fillCredentialUnrecorded], [VaultContent.fillCardFieldUnrecorded]): a row offered is not a row used.
     * The row the person then picks is recorded by [recordPicked].
     */
    fun release(content: VaultContent, itemId: String): VaultItem? =
        loginOf(content, itemId, recorded = false) ?: cardOf(content, itemId, recorded = false)

    /** The masked line of each card of the working set ("Visa ••4242"), for andvari's own chooser: no value is read. */
    fun cardLines(content: VaultContent): Map<String, String> = overtakable(emptyMap()) { content.fillCards().associate { it.itemId to it.subtitle } }

    /**
     * One card of the working set by id, with its values, for a card the person picked inside andvari (the chooser, a
     * confirm): the read records the use. Null when it is no longer there (or a lock overtook the ask).
     */
    fun cardById(content: VaultContent, itemId: String): VaultItem? = cardOf(content, itemId, recorded = true)

    private fun cardOf(content: VaultContent, itemId: String, recorded: Boolean): VaultItem? = overtakable(null) {
        content.fillCards().firstOrNull { it.itemId == itemId && it.hasNumber }?.let { cardItem(content, it, recorded) }
    }

    private fun cardItem(content: VaultContent, c: io.silencelen.andvari.core.app.FillCard, recorded: Boolean): VaultItem {
        fun f(name: String) = if (recorded) content.fillCardField(c.itemId, name) else content.fillCardFieldUnrecorded(c.itemId, name)
        return VaultItem(
            itemId = c.itemId,
            vaultId = "",
            rev = 0L,
            updatedAt = 0L,
            doc = ItemDoc(
                type = "card",
                name = c.name,
                card = CardData(
                    cardholderName = f("name"),
                    number = f("number"),
                    expMonth = f("expMonth"),
                    expYear = f("expYear"),
                    securityCode = f("cvv"),
                    postalCode = f("postal"),
                ),
            ),
        )
    }

    /**
     * One login of the working set by id, with its values, for a login the person picked inside andvari (the chooser, a
     * confirm): the read records the use. Null when it is no longer there.
     */
    fun loginById(content: VaultContent, itemId: String): VaultItem? = loginOf(content, itemId, recorded = true)

    private fun loginOf(content: VaultContent, itemId: String, recorded: Boolean): VaultItem? = overtakable(null) {
        val l = content.fillLogins(emptyList()).firstOrNull { it.itemId == itemId } ?: return@overtakable null
        val cred = (if (recorded) content.fillCredential(itemId) else content.fillCredentialUnrecorded(itemId)) ?: return@overtakable null
        VaultItem(itemId, "", 0L, 0L, ItemDoc(type = "login", name = l.name, login = LoginData(username = cred.username, password = cred.password, uris = addresses(l))))
    }

    /**
     * The rows the platform filled on a pick ([FillPicks.picked], from the platform's own record, read at the next fill
     * request): one use each ([VaultContent.recordFillPicked], which also makes a pick the content already counted within
     * its window the same use). Those rows were built with [release], which records nothing, so each pick counts once.
     * An id that is no longer a login or card of the working set records nothing. A lock overtaking the record is the
     * lock: nothing is recorded.
     *
     * The use is recorded at [offeredAtMs], the time the rows were offered ([FillPicks.lastReplyAtMs]), through
     * [VaultContent.recordFillPickedAt]: the platform says what was picked only at the next fill request, which may be
     * days later, and gives no time. The pick happened between the offer and that request; the offer's time is the one
     * of the two the app knows to be no later than the pick, so a use is never recorded as more recent than it was (a
     * login unused for long still reads as such in vault health). With no time of an offer (the process started after
     * it, so it was not kept), the pick is recorded at the time of this call, as before.
     */
    fun recordPicked(content: VaultContent, itemIds: List<String>, offeredAtMs: Long) {
        for (id in itemIds) {
            overtakable(false) { if (offeredAtMs > 0L) content.recordFillPickedAt(id, offeredAtMs) else content.recordFillPicked(id) }
        }
    }
}
