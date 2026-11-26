package io.silencelen.andvari.desktop.trust

import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.RecoveryQuestion
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.WhoCanRecover

// Sign-up, registration, the recovery choice (§7.2, §7.3, §7.7), and password sign-in (§12.1, §4.4), ported from the
// Android app. Passwords are held in `remember` only and cleared once handed to the API.

// ---- an invite opened signed out (§6.7) ----

@Composable
internal fun JoinInviteScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.JoinInvite) {
    AuthColumn {
        WindowHead(UiText.of(screen.headline), screen.instance)
        Main(UiText.ph(Placeholder.CREATE_ACCOUNT_BUTTON), enabled = !s.busy, busy = s.busy) { model.run({ entry.joinFromInvite(screen) }) }
        Second(UiText.ph(Placeholder.SIGN_IN_BUTTON), enabled = !s.busy) { model.run({ entry.signInFromInvite(screen) }) }
        SaidHere(model, s)
        BackRow(model, s)
    }
}

@Composable
internal fun NotTakingAccountsScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.NotTakingAccounts) {
    AuthColumn {
        WindowHead(UiText.of(screen.headline), screen.instance)
        screen.whyNot?.let { Say(it) }
        Gap()
        Second(UiText.ph(Placeholder.SIGN_IN_BUTTON), enabled = !s.busy) { model.run({ entry.signInWhereInvited(screen) }) }
        SaidHere(model, s)
        BackRow(model, s)
    }
}

// ---- §7.2: sign-up by email ----

@Composable
internal fun SignUpEmailScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.SignUpEmail) {
    var email by remember { mutableStateOf("") }
    var age by remember { mutableStateOf(false) }
    val submit = { if (email.isNotBlank() && !s.busy) model.run({ entry.startSignUp(screen, email.trim(), age) }) }
    AuthColumn {
        WindowHead(null, screen.instance, screen.connectWith?.let { UiText.Plain(it) })
        Field(UiText.ph(Placeholder.EMAIL_FIELD), email, onEnter = { submit() }) { email = it }
        if (screen.ageConfirmRequired) Tick(UiText.of(CopyKey.AGE_13_OR_OLDER), age) { age = it }
        if (screen.provingWork) {
            Say(Placeholder.PROVING_WORK, "${screen.workPercent}%")
            LinearProgressIndicator(progress = { screen.workPercent / 100f }, modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp))
        }
        Main(UiText.ph(Placeholder.SEND_CODE), enabled = email.isNotBlank() && !s.busy, busy = s.busy) { submit() }
        SaidHere(model, s)
        BackRow(model, s)
    }
}

/** §7.2: the code screen never says a code went to an account (G6); it says to check spam. */
@Composable
internal fun SignUpCodeScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.SignUpCode) {
    var code by remember { mutableStateOf("") }
    val submit = { if (code.isNotBlank() && !s.busy) model.run({ entry.verifySignUpCode(screen, code.trim()) }) }
    AuthColumn {
        WindowHead(null, screen.instance, UiText.Plain(screen.email))
        Quiet(UiText.of(CopyKey.EMAIL_CHECK_SPAM))
        // Above the code field: core's line (awaiting the owner's wording), true also for an address that has an account.
        Say(screen.codeLine)
        Field(UiText.ph(Placeholder.CODE_FIELD), code, mono = true, onEnter = { submit() }) { code = it }
        Main(UiText.ph(Placeholder.VERIFY_CODE), enabled = code.isNotBlank() && !s.busy, busy = s.busy) { submit() }
        Quieter(UiText.ph(Placeholder.RESEND_CODE), enabled = !s.busy) { model.run({ entry.resendSignUpCode(screen) }) }
        SaidHere(model, s)
        BackRow(model, s)
    }
}

// ---- §7.3, §7.7: the new account's form ----

@Composable
internal fun CreateAccountScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.CreateAccount) {
    var email by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var again by remember { mutableStateOf("") }
    var age by remember { mutableStateOf(false) }
    AuthColumn {
        WindowHead(null, screen.instance)
        // Through a setup link this account becomes the server's operator (§6.7).
        if (screen.via == io.silencelen.andvari.core.app.RegistrationVia.SETUP_LINK) Say(Placeholder.CREATE_AS_OPERATOR, plainName(screen.instance.name))
        screen.invitedBy?.let { Say(Placeholder.INVITED_BY, it) }
        val fixed = screen.fixedEmail
        if (fixed != null) Quiet(UiText.Plain(fixed)) else Field(UiText.ph(Placeholder.EMAIL_FIELD), email) { email = it }
        Field(UiText.ph(Placeholder.DISPLAY_NAME_FIELD), name) { name = it }
        Quiet(UiText.ph(Placeholder.DISPLAY_NAME_HINT))
        SecretField(UiText.ph(Placeholder.NEW_PASSWORD_FIELD), password) { password = it }
        MasterPasswordStrengthHints(password)
        SecretField(UiText.ph(Placeholder.NEW_PASSWORD_AGAIN_FIELD), again) { again = it }
        if (screen.ageConfirmRequired) Tick(UiText.of(CopyKey.AGE_13_OR_OLDER), age) { age = it }
        Gap()
        RecoveryChoice(model, s, screen)
        Gap()
        Main(UiText.ph(Placeholder.CREATE_ACCOUNT_BUTTON), enabled = password.isNotEmpty() && !s.busy, busy = s.busy) {
            if (password != again) {
                model.say(UiText.ph(Placeholder.PASSWORDS_DIFFER))
            } else {
                val input = NewAccountInput(fixed ?: email.trim(), name.trim(), password, age)
                model.run({ entry.createAccount(screen, input) }) { password = ""; again = "" }
            }
        }
        SaidHere(model, s)
        BackRow(model, s)
    }
}

/**
 * The recovery choice (§7.7): "Only me" selected by default; the second option in the public or the family wording;
 * choosing it shows the warning first ([EntryScreen.RecoveryWarning]), the only way to turn operator recovery on.
 * With no choice offered (the public instance under variant R, a card with no recovery key) only the kit sentence.
 */
@Composable
private fun RecoveryChoice(model: TrustModel, s: AppSnapshot, screen: EntryScreen.CreateAccount) {
    val q: RecoveryQuestion? = screen.recovery
    if (q == null) {
        Quiet(UiText.of(CopyKey.RECOVERY_KIT_ONLY))
        return
    }
    Say(q.question, style = MaterialTheme.typography.titleSmall)
    q.takeoverTitle?.let {
        Say(it, color = MaterialTheme.colorScheme.error)
        Say(CopyKey.RECOVERY_KEY_CHANGED_BODY, style = MaterialTheme.typography.bodySmall)
    }
    val onlyMe = screen.whoCanRecover == WhoCanRecover.ONLY_ME
    Choice(UiText.of(q.onlyMe), UiText.of(q.onlyMeDetail), selected = onlyMe, enabled = !s.busy) { if (!onlyMe) model.act { entry.chooseOnlyMe(screen) } }
    Choice(UiText.of(q.meOrOperator), UiText.of(q.meOrOperatorDetail), selected = !onlyMe, enabled = !s.busy) { if (onlyMe) model.act { entry.reviewOperatorRecovery(screen) } }
}

/** §7.7: shown before operator recovery can be chosen. "Turn on" does nothing unless the box is ticked. */
@Composable
internal fun RecoveryWarningScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.RecoveryWarning) {
    var understood by remember { mutableStateOf(false) }
    val w = screen.warning
    AuthColumn {
        WindowHead(UiText.of(w.title))
        w.takeoverTitle?.let {
            Say(it, color = MaterialTheme.colorScheme.error)
            Say(CopyKey.RECOVERY_KEY_CHANGED_BODY)
            Gap(8)
        }
        for (p in w.paragraphs) Say(p, Modifier.padding(bottom = 8.dp))
        Tick(UiText.of(w.understand), understood) { understood = it }
        Gap()
        // The private choice is the way out, first; turning operator recovery on is the filled action after it.
        WayOutThenMain(
            UiText.of(w.keepPrivate), !s.busy, { model.act { entry.keepRecoveryPrivate(screen) } },
            UiText.of(w.turnOn), enabled = understood && !s.busy, busy = false,
        ) { model.act { entry.acceptOperatorRecovery(screen, understood) } }
        SaidHere(model, s)
    }
}

// ---- §12.1, §4.4: password sign-in ----

/** "Email and master password": the server choice first, the public instance only where this build bakes one. */
@Composable
internal fun SignInServerScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.SignInServer) {
    var address by remember { mutableStateOf("") }
    val submit = { if (address.isNotBlank() && !s.busy) model.run({ entry.chooseOwnServer(screen, address.trim()) }) }
    AuthColumn {
        WindowHead(UiText.of(CopyKey.SIGN_IN_PASSWORD))
        if (screen.offersPublicInstance) {
            Second(UiText.ph(Placeholder.PUBLIC_INSTANCE_CHOICE), enabled = !s.busy) { model.run({ entry.choosePublicInstance(screen) }) }
            Gap()
        }
        Say(CopyKey.FIRST_OWN_SERVER, style = MaterialTheme.typography.titleSmall)
        Field(UiText.ph(Placeholder.SERVER_ADDRESS_FIELD), address, mono = true, onEnter = { submit() }) { address = it }
        Main(UiText.ph(Placeholder.SUBMIT_ADDRESS), enabled = address.isNotBlank() && !s.busy, busy = s.busy) { submit() }
        SaidHere(model, s)
        BackRow(model, s)
    }
}

/**
 * The password screen (§4.4): it names the account, the instance and its origin — "Master password for {email} on
 * {name} ({origin})" — from the address as it is typed. The two-step code is asked on the same screen once the
 * server said so; the password is not sent again with it.
 */
@Composable
internal fun SignInScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.SignIn) {
    var email by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var code by remember { mutableStateOf("") }
    // The code step's password is used up by any answer to a code but "code needed" and "done", while the screen may
    // still ask for a code: the password is asked again then, never another code that could only be refused as stale.
    var codeSpent by remember { mutableStateOf(false) }
    val submitPassword = {
        if (email.isNotBlank() && password.isNotEmpty() && !s.busy) {
            val typed = password
            model.run({ entry.submitSignIn(screen, email.trim(), typed) }) { password = ""; if (it == SignInAnswer.CODE_NEEDED) codeSpent = false }
        }
    }
    val submitCode = { if (code.isNotBlank() && !s.busy) model.run({ entry.submitSignInCode(screen, code.trim()) }) { code = ""; codeSpent = codeStepSpent(it) } }
    AuthColumn {
        BrandHead()
        // As the lock screen: one quiet centred naming under the head, the current app's place for its address line. It
        // names the server (its name, its origin) until an address is typed, then the account on that server (§4.4),
        // each once; two lines either way, in a slot of a fixed height, so the fields under it never move.
        FixedSlot(SIGN_IN_TITLE_SLOT) { SignInNaming(screen, email) }
        if (screen.prompt.instance.selfNamed) {
            Say(CopyKey.AS_THE_SERVER_NAMES_ITSELF, Modifier.fillMaxWidth(), MaterialTheme.typography.bodySmall.copy(textAlign = TextAlign.Center), MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Gap(8)
        Field(UiText.ph(Placeholder.EMAIL_FIELD), email) { email = it }
        if (!signInAsksCode(screen, codeSpent)) {
            SecretField(UiText.ph(Placeholder.PASSWORD_FIELD), password, onEnter = { submitPassword() }) { password = it }
            Main(UiText.ph(Placeholder.SIGN_IN_BUTTON), enabled = email.isNotBlank() && password.isNotEmpty() && !s.busy, busy = s.busy) { submitPassword() }
            // As the current app: the wait is named while the password is checked, in a slot, so nothing under it moves.
            FixedSlot(BUSY_LINE_SLOT) { if (s.busy) Quiet(UiText.ph(Placeholder.CHECKING_PASSWORD)) }
        } else {
            Field(UiText.ph(Placeholder.TWO_STEP_CODE_FIELD), code, mono = true, onEnter = { submitCode() }) { code = it }
            Main(UiText.ph(Placeholder.SIGN_IN_BUTTON), enabled = code.isNotBlank() && !s.busy, busy = s.busy) { submitCode() }
        }
        SaidHere(model, s)
        BackRow(model, s)
    }
}

/**
 * The answer to a two-step code used up the step: anything but "code needed" (asked again) and "done". The shared code
 * forgets the step's password at the first code it sends, and on some answers (the keeper's own refusals, the
 * identity fault, a server not reached, too many requests) leaves the screen asking for a code, so each further code
 * would be refused as stale until the person went back.
 */
internal fun codeStepSpent(r: SignInAnswer): Boolean = r != SignInAnswer.CODE_NEEDED && r != SignInAnswer.DONE

/** The sign-in screen asks for the two-step code: the shared code says so, and the step was not used up here. */
internal fun signInAsksCode(screen: EntryScreen.SignIn, codeSpent: Boolean): Boolean = screen.codeNeeded && !codeSpent

/** The sign-in naming's slot: two quiet lines of the body style. */
internal val SIGN_IN_TITLE_SLOT = 52.dp

/** The sign-in screen's naming line once an address is typed ([CopyKey.MASTER_PASSWORD_FOR]); null before. */
internal fun signInTitle(screen: EntryScreen.SignIn, typedEmail: String): UiText? =
    if (typedEmail.isBlank()) null else UiText.of(screen.prompt.titleFor(typedEmail.trim()))

/** [signInTitle], or the server's name over its origin while no address is typed; quiet and centred. */
@Composable
private fun SignInNaming(screen: EntryScreen.SignIn, typedEmail: String) {
    val tone = MaterialTheme.colorScheme.onSurfaceVariant
    val centred = MaterialTheme.typography.bodyLarge.copy(textAlign = TextAlign.Center)
    val instance = screen.prompt.instance
    val line = signInTitle(screen, typedEmail)
    if (line == null) {
        if (instance.name.isNotEmpty()) Text(instance.name, Modifier.fillMaxWidth(), color = tone, style = centred)
        Text(instance.origin, Modifier.fillMaxWidth(), color = tone, style = centred.copy(fontFamily = FontFamily.Monospace))
    } else {
        Text(monospacedOrigin(line.shown(), instance.origin), Modifier.fillMaxWidth(), color = tone, style = centred)
    }
}

/** §8.7: the account requires new devices to be linked. The design gives no wording (reserved keys). */
@Composable
internal fun LinkRequiredScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.LinkRequired) {
    AuthColumn {
        WindowHead(UiText.of(screen.title))
        Say(UiText.of(screen.body))
        Gap()
        Main(UiText.of(CopyKey.SIGN_IN_LINK_DEVICE), enabled = !s.busy, busy = false) { model.act { entry.linkInstead(screen) } }
        Second(UiText.of(CopyKey.CANCEL), enabled = !s.busy) { model.act { entry.back() } }
    }
}
