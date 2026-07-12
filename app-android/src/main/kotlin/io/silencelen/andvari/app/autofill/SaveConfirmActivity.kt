package io.silencelen.andvari.app.autofill

import android.app.assist.AssistStructure
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import android.view.autofill.AutofillManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import io.silencelen.andvari.app.AndvariTheme
import io.silencelen.andvari.app.Session
import io.silencelen.andvari.app.SessionStore
import io.silencelen.andvari.app.VaultSession
import io.silencelen.andvari.core.client.ApiException
import io.silencelen.andvari.core.client.CardData
import io.silencelen.andvari.core.client.CardDisplay
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.autofill.CardNormalize
import io.silencelen.andvari.core.client.autofill.FillTarget
import io.silencelen.andvari.core.client.autofill.UriMatch
import io.silencelen.andvari.core.crypto.CryptoException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.IOException

/**
 * Card confirm variant, resolved POST-unlock (the normalized-PAN dedupe needs the decrypted
 * working set). [display] is brand + masked last4 ("Visa ••4242") — the ONLY card identity
 * the confirm surface ever shows: never a full PAN, never any CVV.
 */
private sealed interface CardPlan {
    val display: String

    data class Update(override val display: String, val itemId: String) : CardPlan
    data class New(override val display: String) : CardPlan
}

/**
 * Login confirm variant, resolved POST-unlock (dedupe needs the decrypted working set). Update
 * carries only (itemId, name, username) — NO doc — which FORCES doSave to re-read the item and
 * .copy()-materialize it (swap only the password), never a field-by-field rebuild (the 0.2.x
 * data-loss class, see :77). `username` is the EXISTING item's username, shown in the confirm so a
 * user can tell a password change from a wrong-account merge (auto-saved logins are named by host).
 * Twin of the extension's saveTargetFor (savetarget.test.ts pins the shared 2a/2b/2c rule).
 */
private sealed interface LoginPlan {
    data class Update(val itemId: String, val name: String, val username: String?) : LoginPlan
    object New : LoginPlan
}

/**
 * "Save to andvari?" — launched by [AndvariAutofillService.onSaveRequest] via an IntentSender after
 * the platform's save UI dismisses, receiving the submitted form's EXTRA_ASSIST_STRUCTURE. Reads the
 * typed values ([SaveExtractor] — the one place autofill touches field VALUES), unlocks the vault if
 * needed (the shared single-token-holder [AutofillUnlock]), shows the user exactly what will be
 * saved, and on confirm writes through the SAME engine the app uses. Values live only in memory here
 * and are never logged. FLAG_SECURE + excluded-from-autofill, mirroring the unlock overlay.
 *
 * 0.7.0 cards: when the extraction carries a Luhn-valid card, a CARD stage runs first, then the
 * login stage if a login was also captured — card-first, but a plain login form's path is never
 * lost. Update-vs-new is decided by normalized-PAN dedupe against the working set's card items:
 *  - PAN match → "Update card?": `.copy()` on the EXISTING doc + card (never a field-by-field
 *    rebuild — the 0.2.x bug), name untouched, only captured fields overwrite, brand recomputed.
 *  - no match → "Save card to andvari?": a NEW ItemDoc(type="card") into the personal vault.
 *    Saving a NEW card from a checkout IS a create path, so it is gated behind
 *    [CardDisplay.CREATE_ENABLED] (dark today, exactly like the natives' "+ Card" buttons —
 *    Option A: no card may be CREATED anywhere until the fielded 0.2.x desktop MSI retires).
 *    The UPDATE variant stays live: it can only touch a card that already exists (as fv2).
 */
class SaveConfirmActivity : ComponentActivity() {
    private var busy by mutableStateOf(false)
    private var errorText by mutableStateOf<String?>(null)
    private var unlocked by mutableStateOf(false)
    private var cardPlan by mutableStateOf<CardPlan?>(null)
    private var cardStageDone by mutableStateOf(false)
    private var loginPlan by mutableStateOf<LoginPlan?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Set BEFORE any content: login AND card confirms render secret-adjacent material here.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        setResult(RESULT_CANCELED) // back / dismiss = don't save

        val structure = intent.assistStructure()
        if (structure == null) { finish(); return }
        val creds = SaveExtractor.extract(structure)
        if (!creds.savable && creds.card == null) { finish(); return } // nothing savable captured

        VaultSession.setAutoLockSeconds(SessionStore(applicationContext).autoLockSeconds)
        unlocked = VaultSession.getIfFresh() != null

        val store = SessionStore(applicationContext)
        val session = store.load()
        if (session == null || session.accessToken.isEmpty()) { finish(); return } // signed out

        // Already unlocked → resolve the card stage now; when the create gate / no-change dedupe
        // leaves nothing savable at all, exit before showing any UI.
        if (unlocked && !resolveStages(creds)) { finish(); return }

        setContent {
            AndvariTheme {
                val plan = cardPlan
                when {
                    !unlocked -> UnlockToSaveCard(
                        email = session.email, subject = saveSubject(creds), busy = busy, error = errorText,
                        onUnlock = { pw -> doUnlock(store, session, pw, creds) }, onCancel = { finish() },
                    )
                    plan != null && !cardStageDone -> CardSaveCard(
                        plan = plan, busy = busy, error = errorText,
                        onConfirm = { doSaveCard(plan, creds) }, onSkip = { advancePastCard(creds) },
                    )
                    loginPlan != null -> SaveCard(
                        plan = loginPlan!!, site = creds.title(), username = creds.username, busy = busy, error = errorText,
                        onSave = { doSave(creds) }, onCancel = { finish() },
                    )
                    else -> {} // both stages consumed — a finish() is already in flight
                }
            }
        }
        // Never let our own save overlay be autofilled (belt-and-suspenders with the service self-guard).
        window.decorView.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
    }

    /** What the unlock prompt says it is unlocking FOR ("a card & login for github.com"). */
    private fun saveSubject(creds: SavedCredentials): String {
        val what = buildList {
            if (creds.card != null) add("a card")
            if (creds.savable) add("a login")
        }.joinToString(" & ")
        val site = (if (!creds.savable) creds.card?.webDomain else null) ?: creds.title()
        return "$what for $site"
    }

    /**
     * Post-unlock stage resolution: decide the card variant from the decrypted working set.
     * Returns false when NOTHING (card or login) remains savable — the caller should finish.
     */
    private fun resolveStages(creds: SavedCredentials): Boolean {
        cardPlan = creds.card?.let { runCatching { cardPlanFor(it) }.getOrNull() }
        // loginPlan null = nothing to save (an unchanged re-login — the dup-registration suppress),
        // not savable, or a lookup error; the login stage renders only when it is non-null. The
        // return gates the whole activity: both null with no card ⇒ finish() (no blank screen).
        loginPlan = if (creds.savable) runCatching { loginPlanFor(creds) }.getOrNull() else null
        return cardPlan != null || loginPlan != null
    }

    private fun cardPlanFor(card: SavedCard): CardPlan? {
        val engine = VaultSession.getIfFresh()?.engine ?: return null
        val display = "${CardDisplay.brandLabel(CardNormalize.brand(card.number)) ?: "Card"} ${CardDisplay.maskedLast4(card.number)}"
        // Dedupe by normalized PAN across the working set's card items (card.number is already
        // digits-only canonical; stored numbers normalize the same way at save, but re-normalize
        // defensively — another writer could have stored separators).
        val match = engine.items()
            .firstOrNull { it.doc.type == "card" && CardNormalize.digitsOnly(it.doc.card?.number ?: "") == card.number }
        if (match != null) {
            // Update only when the checkout actually captured something NEW for this card —
            // otherwise there is nothing to confirm and the stage is skipped.
            val c = match.doc.card ?: CardData()
            val changed = (card.cardholderName != null && card.cardholderName != c.cardholderName) ||
                (card.expMonth != null && card.expMonth != c.expMonth) ||
                (card.expYear != null && card.expYear != c.expYear) ||
                (card.securityCode != null && card.securityCode != c.securityCode)
            return if (changed) CardPlan.Update(display, match.itemId) else null
        }
        // Option A create gate: a NEW card from a checkout is a CREATE, and creation is dark
        // until the 0.2.x desktop MSI retires ([CardDisplay.CREATE_ENABLED] — the same one-line
        // flip as the natives' "+ Card" buttons). The Update branch above is deliberately NOT
        // gated: updating an existing card cannot mint the first fv2 doc, creation can.
        return if (CardDisplay.CREATE_ENABLED) CardPlan.New(display) else null
    }

    /**
     * Save-vs-update for a captured login (mirrors cardPlanFor). Dedupe against the decrypted
     * working set's login items by canonical urimatch. With a username → the exact (host∧username)
     * match; a password-only submit → a password-equal item (2a — a re-login) or a LONE host login
     * (2b — a password change), else New (2c: ambiguous, never overwrite the wrong account). Returns
     * NULL when there is nothing to save (an unchanged re-login) so the login stage is skipped.
     * Twin of the extension's saveTargetFor (savetarget.test.ts pins the shared 2a/2b/2c rule).
     */
    private fun loginPlanFor(creds: SavedCredentials): LoginPlan? {
        val engine = VaultSession.getIfFresh()?.engine ?: return null
        // webDomain is ATTACKER-CONTROLLED (any app populates its own AssistStructure), so gate it on
        // the cert-pin check EXACTLY like the fill side (DatasetBuilder.targetFor:296-297 →
        // TrustedBrowsers.isTrusted): an untrusted package matches only androidapp://<pkg>, never a
        // spoofed web host. Without this, a malicious non-browser app could set webDomain="github.com"
        // and drive an Update that CLOBBERS the user's real github login. Benign native apps already
        // carry webDomain=null, so this is a no-op for them (fill/save symmetry restored).
        val webHost = if (TrustedBrowsers.isTrusted(this, creds.appPackage)) creds.webDomain else null
        val target = FillTarget(webHost = webHost, packageName = creds.appPackage)
        val matches = engine.items().filter {
            it.doc.type == "login" && UriMatch.matchLogins(it.doc.login?.uris ?: emptyList(), target)
        }
        val username = creds.username
        if (!username.isNullOrEmpty()) {
            val exact = matches.firstOrNull { (it.doc.login?.username ?: "") == username } ?: return LoginPlan.New
            // Unchanged username+password re-login → nothing to save (extension :967 parity, amend C).
            return if ((exact.doc.login?.password ?: "") == creds.password) null
            else LoginPlan.Update(exact.itemId, exact.doc.name, exact.doc.login?.username)
        }
        // Password-only: a password-equal item is the SAME login being re-entered → nothing to save (2a).
        if (matches.any { (it.doc.login?.password ?: "") == creds.password }) return null
        val lone = matches.singleOrNull() ?: return LoginPlan.New // 2c: ambiguous multi-login → New (recoverable)
        return LoginPlan.Update(lone.itemId, lone.doc.name, lone.doc.login?.username) // 2b: a password change
    }

    /** "Not now" on the card stage: fall through to the login stage, or exit if there is none. */
    private fun advancePastCard(creds: SavedCredentials) {
        errorText = null
        // BLOCKER 2: gate on loginPlan, not creds.savable — savable can be true while loginPlan is
        // null (an unchanged re-login), and advancing then would strand a blank login stage.
        if (loginPlan != null) cardStageDone = true else finish()
    }

    private fun doUnlock(store: SessionStore, session: Session, password: String, creds: SavedCredentials) {
        if (busy) return
        busy = true; errorText = null
        lifecycleScope.launch {
            runCatching { withContext(Dispatchers.IO) { AutofillUnlock.unlock(this@SaveConfirmActivity, store, session, password) } }
                .onSuccess {
                    busy = false
                    if (!resolveStages(creds)) { finish(); return@onSuccess } // e.g. gated new card, nothing changed, no login
                    unlocked = true
                }
                .onFailure { busy = false; errorText = friendly(it) }
        }
    }

    private fun doSaveCard(plan: CardPlan, creds: SavedCredentials) {
        if (busy) return
        val card = creds.card ?: run { advancePastCard(creds); return }
        // Re-check freshness: an idle auto-lock between unlock and confirm drops us back to the
        // password prompt rather than saving against a stale/closed engine.
        val engine = VaultSession.getIfFresh()?.engine ?: run { unlocked = false; return }
        busy = true; errorText = null
        // Review 2026-07-10 [0]: this activity runs in the autofill-only process where the
        // ViewModel's operationInProgress collector never exists — mirror the in-flight save
        // into the process-wide flag OURSELVES, or the F12 hard-lock timer (and any
        // getIfFresh observer) can close the engine under this save at idle expiry. touch()
        // restarts the idle clock at the user's explicit Save tap. finally covers coroutine
        // cancellation too, so activity death can't latch the flag.
        VaultSession.touch()
        VaultSession.setOperationInProgress(true)
        lifecycleScope.launch {
            try {
            runCatching {
                val doc = when (plan) {
                    is CardPlan.Update -> {
                        // Re-read at save time (a sync may have advanced it since resolve), then
                        // .copy() on the EXISTING doc + card — never a field-by-field rebuild.
                        // Name untouched; only captured (non-null) fields overwrite; number stays
                        // the matched number; brand recomputed (the stored field is display-only).
                        val existing = engine.items().firstOrNull { it.itemId == plan.itemId }
                            ?: throw IllegalStateException("This card is no longer in the vault.")
                        val c = existing.doc.card ?: CardData()
                        existing.doc.copy(
                            card = c.copy(
                                cardholderName = card.cardholderName ?: c.cardholderName,
                                expMonth = card.expMonth ?: c.expMonth,
                                expYear = card.expYear ?: c.expYear,
                                securityCode = card.securityCode ?: c.securityCode,
                                brand = CardNormalize.brand(c.number ?: card.number),
                            ),
                        )
                    }
                    is CardPlan.New -> ItemDoc(
                        // Create path — reachable only with CardDisplay.CREATE_ENABLED (see
                        // cardPlanFor). Canonical fields straight from the extractor; brand
                        // recomputed from the number at save, like every card writer.
                        type = "card",
                        name = plan.display, // "<Brand> ••<last4>"
                        card = CardData(
                            cardholderName = card.cardholderName,
                            number = card.number,
                            expMonth = card.expMonth,
                            expYear = card.expYear,
                            securityCode = card.securityCode,
                            brand = CardNormalize.brand(card.number),
                        ),
                    )
                }
                val itemId = (plan as? CardPlan.Update)?.itemId // null → new item in the personal vault
                withContext(Dispatchers.IO) { engine.save(itemId, doc) }
            }.onSuccess {
                setResult(RESULT_OK) // something was saved, whatever the login stage decides
                if (loginPlan != null) { busy = false; cardStageDone = true } // login stage next — never lost (BLOCKER 2)
                else finish()
            }.onFailure { busy = false; errorText = friendly(it) }
            } finally {
                VaultSession.setOperationInProgress(false)
            }
        }
    }

    private fun doSave(creds: SavedCredentials) {
        if (busy) return
        // Re-check freshness: an idle auto-lock between unlock and confirm drops us back to the
        // password prompt rather than saving against a stale/closed engine.
        val engine = VaultSession.getIfFresh()?.engine ?: run { unlocked = false; return }
        val plan = loginPlan ?: run { finish(); return } // the render gates this on loginPlan != null
        busy = true; errorText = null
        // Review 2026-07-10 [0]: mirror the in-flight save process-wide (see doSaveCard) —
        // the ViewModel's collector doesn't exist in the autofill-only process.
        VaultSession.touch()
        VaultSession.setOperationInProgress(true)
        lifecycleScope.launch {
            try {
            runCatching {
                when (plan) {
                    is LoginPlan.New -> {
                        val doc = ItemDoc(
                            type = "login",
                            name = creds.title(),
                            login = LoginData(username = creds.username, password = creds.password, uris = listOf(creds.uri())),
                        )
                        withContext(Dispatchers.IO) { engine.save(null, doc) } // new item in the personal vault
                    }
                    is LoginPlan.Update -> {
                        // Re-read at save time (a sync may have advanced it), then .copy() on the
                        // EXISTING doc + login — swap ONLY the password; username/uris/totp/
                        // passwordHistory/notes/favorite/extras/attachments all ride the copy. Never
                        // a field-by-field rebuild (the 0.2.x data-loss class, :77). Amendment D.
                        val existing = engine.items().firstOrNull { it.itemId == plan.itemId }
                            ?: throw IllegalStateException("That login is no longer in your vault.")
                        val doc = existing.doc.copy(login = (existing.doc.login ?: LoginData()).copy(password = creds.password))
                        withContext(Dispatchers.IO) { engine.save(plan.itemId, doc) }
                    }
                }
            }.onSuccess {
                setResult(RESULT_OK)
                finish()
            }.onFailure { busy = false; errorText = friendly(it) }
            } finally {
                VaultSession.setOperationInProgress(false)
            }
        }
    }

    private fun friendly(t: Throwable): String = when {
        t is CryptoException -> t.message ?: "Wrong master password."
        t is ApiException && t.status == 401 -> "Session expired — open andvari and sign in again."
        t is IOException -> "Offline — try saving again when you're connected."
        else -> t.message ?: "Couldn't save."
    }

    @Suppress("DEPRECATION")
    private fun Intent.assistStructure(): AssistStructure? =
        if (Build.VERSION.SDK_INT >= 33) {
            getParcelableExtra(AutofillManager.EXTRA_ASSIST_STRUCTURE, AssistStructure::class.java)
        } else {
            getParcelableExtra(AutofillManager.EXTRA_ASSIST_STRUCTURE)
        }
}

@Composable
private fun SaveCard(
    plan: LoginPlan,
    site: String,
    username: String?,
    busy: Boolean,
    error: String?,
    onSave: () -> Unit,
    onCancel: () -> Unit,
) {
    val update = plan as? LoginPlan.Update
    Column(Modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(20.dp)) {
                Text(if (update != null) "Update login?" else "Save to andvari?", style = MaterialTheme.typography.titleLarge)
                Spacer(Modifier.height(4.dp))
                Text(
                    if (update != null) "The password for this saved login will be updated. Its username and other details stay."
                    else "A new login will be saved to your personal vault.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(16.dp))
                if (update != null) {
                    // Show the EXISTING item's name + username so a wrong-account merge is visible (amend A).
                    LabeledValue("Login", update.name)
                    if (!update.username.isNullOrEmpty()) { Spacer(Modifier.height(8.dp)); LabeledValue("Username", update.username) }
                } else {
                    LabeledValue("Site", site)
                    if (!username.isNullOrEmpty()) { Spacer(Modifier.height(8.dp)); LabeledValue("Username", username) }
                }
                Spacer(Modifier.height(8.dp))
                LabeledValue("Password", "•••••••• (will be saved)")
                if (error != null) {
                    Spacer(Modifier.height(12.dp))
                    Text(error, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                }
                Spacer(Modifier.height(20.dp))
                Button(onClick = onSave, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
                    if (busy) CircularProgressIndicator(Modifier.height(18.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                    else Text(if (update != null) "Update login" else "Save to andvari")
                }
                TextButton(onClick = onCancel, enabled = !busy, modifier = Modifier.fillMaxWidth()) { Text("Not now") }
            }
        }
    }
}

/**
 * The card stage ("Update card?" / "Save card to andvari?"). Shows brand + masked last4 ONLY —
 * never the full PAN, never any CVV (FLAG_SECURE is set in onCreate; verified). "Not now" falls
 * through to the login stage when one was captured.
 */
@Composable
private fun CardSaveCard(
    plan: CardPlan,
    busy: Boolean,
    error: String?,
    onConfirm: () -> Unit,
    onSkip: () -> Unit,
) {
    val isUpdate = plan is CardPlan.Update
    Column(Modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(20.dp)) {
                Text(if (isUpdate) "Update card?" else "Save card to andvari?", style = MaterialTheme.typography.titleLarge)
                Spacer(Modifier.height(4.dp))
                Text(
                    if (isUpdate) "This card is already in your vault — its details (expiry, security code, cardholder) will be updated from this checkout. Its name and number stay as they are."
                    else "A new card will be saved to your personal vault.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(16.dp))
                LabeledValue("Card", plan.display)
                if (error != null) {
                    Spacer(Modifier.height(12.dp))
                    Text(error, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                }
                Spacer(Modifier.height(20.dp))
                Button(onClick = onConfirm, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
                    if (busy) CircularProgressIndicator(Modifier.height(18.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                    else Text(if (isUpdate) "Update card" else "Save card")
                }
                TextButton(onClick = onSkip, enabled = !busy, modifier = Modifier.fillMaxWidth()) { Text("Not now") }
            }
        }
    }
}

@Composable
private fun UnlockToSaveCard(
    email: String,
    subject: String,
    busy: Boolean,
    error: String?,
    onUnlock: (String) -> Unit,
    onCancel: () -> Unit,
) {
    var password by remember { mutableStateOf("") }
    Column(Modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(20.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                Text("ᛅ", style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.primary)
                Text("Unlock to save", style = MaterialTheme.typography.titleLarge)
                Text("$email · saving $subject", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(Modifier.height(16.dp))
                OutlinedTextField(
                    value = password, onValueChange = { password = it }, label = { Text("Master password") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth(), visualTransformation = PasswordVisualTransformation(),
                    textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                )
                if (error != null) { Spacer(Modifier.height(8.dp)); Text(error, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
                Spacer(Modifier.height(16.dp))
                Button(onClick = { onUnlock(password) }, enabled = password.isNotBlank() && !busy, modifier = Modifier.fillMaxWidth()) {
                    if (busy) CircularProgressIndicator(Modifier.height(18.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                    else Text("Unlock")
                }
                TextButton(onClick = onCancel, enabled = !busy) { Text("Cancel") }
            }
        }
    }
}

@Composable
private fun LabeledValue(label: String, value: String) {
    Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    Text(value, style = MaterialTheme.typography.bodyMedium, fontFamily = FontFamily.Monospace)
}
