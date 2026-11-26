package io.silencelen.andvari.app.trust

import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material3.Checkbox
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.app.AuthColumn
import io.silencelen.andvari.app.MasterPasswordStrengthHints
import io.silencelen.andvari.app.SecretField
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.RecoveryQuestion
import io.silencelen.andvari.core.app.WhoCanRecover

// Sign-up, registration, the recovery choice (§7.2, §7.3, §7.7), and password sign-in (§12.1, §4.4). Passwords are
// held in `remember`, never `rememberSaveable`: they never enter saved instance state.

// ---- an invite opened signed out (§6.7) ----

@Composable
internal fun JoinInviteScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.JoinInvite) {
    AuthColumn {
        Title(UiText.of(screen.headline))
        InstanceName(screen.instance)
        Main(UiText.ph(Placeholder.CREATE_ACCOUNT_BUTTON), enabled = !s.busy, busy = s.busy) { model.run({ entry.joinFromInvite(screen) }) }
        Second(UiText.ph(Placeholder.SIGN_IN_BUTTON), enabled = !s.busy) { model.run({ entry.signInFromInvite(screen) }) }
        SaidHere(model, s)
        BackRow(model, s)
    }
}

@Composable
internal fun NotTakingAccountsScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.NotTakingAccounts) {
    AuthColumn {
        Title(UiText.of(screen.headline))
        screen.whyNot?.let { Say(it) }
        InstanceName(screen.instance)
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
    AuthColumn {
        // The screen says what it is for (it had no title, as the drawn screen showed).
        Title(UiText.of(CopyKey.SERVER_CREATE_ACCOUNT))
        InstanceName(screen.instance)
        screen.connectWith?.let { Quiet(UiText.Plain(it)) }
        Field(UiText.ph(Placeholder.EMAIL_FIELD), email, KeyboardType.Email) { email = it }
        if (screen.ageConfirmRequired) Tick(UiText.of(CopyKey.AGE_13_OR_OLDER), age) { age = it }
        if (screen.provingWork) {
            Say(Placeholder.PROVING_WORK, "${screen.workPercent}%")
            LinearProgressIndicator(progress = { screen.workPercent / 100f }, modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp))
        }
        Main(UiText.ph(Placeholder.SEND_CODE), enabled = email.isNotBlank() && !s.busy, busy = s.busy) {
            model.run({ entry.startSignUp(screen, email.trim(), age) })
        }
        SaidHere(model, s)
        BackRow(model, s)
    }
}

/** §7.2: the code screen never says a code went to an account (G6); it says to check spam. */
@Composable
internal fun SignUpCodeScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.SignUpCode) {
    var code by remember { mutableStateOf("") }
    AuthColumn {
        InstanceName(screen.instance)
        Quiet(UiText.Plain(screen.email))
        Quiet(UiText.of(CopyKey.EMAIL_CHECK_SPAM))
        // Above the code field: where the code comes from (awaiting the owner's words).
        Quiet(UiText.of(screen.codeLine))
        Field(UiText.ph(Placeholder.CODE_FIELD), code, KeyboardType.Number, mono = true) { code = it }
        Main(UiText.ph(Placeholder.VERIFY_CODE), enabled = code.isNotBlank() && !s.busy, busy = s.busy) {
            model.run({ entry.verifySignUpCode(screen, code.trim()) })
        }
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
        InstanceName(screen.instance)
        screen.invitedBy?.let { Say(Placeholder.INVITED_BY, it) }
        val fixed = screen.fixedEmail
        if (fixed != null) Quiet(UiText.Plain(fixed)) else Field(UiText.ph(Placeholder.EMAIL_FIELD), email, KeyboardType.Email) { email = it }
        Field(UiText.ph(Placeholder.DISPLAY_NAME_FIELD), name) { name = it }
        Quiet(UiText.ph(Placeholder.DISPLAY_NAME_UNDER))
        SecretField(UiText.ph(Placeholder.NEW_PASSWORD_FIELD).shown(), password) { password = it }
        MasterPasswordStrengthHints(password)
        SecretField(UiText.ph(Placeholder.NEW_PASSWORD_AGAIN_FIELD).shown(), again) { again = it }
        if (screen.ageConfirmRequired) Tick(UiText.of(CopyKey.AGE_13_OR_OLDER), age) { age = it }
        Gap()
        RecoveryChoice(model, s, screen)
        Gap()
        Main(UiText.ph(Placeholder.CREATE_ACCOUNT_BUTTON), enabled = password.isNotEmpty() && !s.busy, busy = s.busy) {
            if (password != again) {
                model.say(UiText.ph(Placeholder.PASSWORDS_DIFFER))
            } else {
                model.run({ entry.createAccount(screen, NewAccountInput(fixed ?: email.trim(), name.trim(), password, age)) })
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
        Title(UiText.of(w.title))
        w.takeoverTitle?.let {
            Say(it, color = MaterialTheme.colorScheme.error)
            Say(CopyKey.RECOVERY_KEY_CHANGED_BODY)
            Gap(8)
        }
        for (p in w.paragraphs) Say(p, Modifier.padding(bottom = 8.dp))
        Tick(UiText.of(w.understand), understood) { understood = it }
        Gap()
        Second(UiText.of(w.keepPrivate), enabled = !s.busy) { model.act { entry.keepRecoveryPrivate(screen) } }
        Main(UiText.of(w.turnOn), enabled = understood && !s.busy, busy = false) { model.act { entry.acceptOperatorRecovery(screen, understood) } }
        SaidHere(model, s)
    }
}

// ---- §12.1, §4.4: password sign-in ----

/** "Email and master password": the server choice first, the public instance only where this build bakes one. */
@Composable
internal fun SignInServerScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.SignInServer) {
    var address by remember { mutableStateOf("") }
    AuthColumn {
        Title(UiText.of(CopyKey.SIGN_IN_PASSWORD))
        if (screen.offersPublicInstance) {
            Second(UiText.ph(Placeholder.PUBLIC_INSTANCE_CHOICE), enabled = !s.busy) { model.run({ entry.choosePublicInstance(screen) }) }
            Gap()
        }
        Say(CopyKey.FIRST_OWN_SERVER, style = MaterialTheme.typography.titleSmall)
        Field(UiText.ph(Placeholder.SERVER_ADDRESS_FIELD), address, KeyboardType.Uri, mono = true) { address = it }
        Main(UiText.ph(Placeholder.SUBMIT_ADDRESS), enabled = address.isNotBlank() && !s.busy, busy = s.busy) {
            model.run({ entry.chooseOwnServer(screen, address.trim()) })
        }
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
    AuthColumn {
        Title(signInTitle(screen, email))
        InstanceName(screen.prompt.instance)
        Field(UiText.ph(Placeholder.EMAIL_FIELD), email, KeyboardType.Email) { email = it }
        if (!screen.codeNeeded) {
            SecretField(UiText.ph(Placeholder.PASSWORD_FIELD).shown(), password) { password = it }
            Main(UiText.ph(Placeholder.SIGN_IN_BUTTON), enabled = email.isNotBlank() && password.isNotEmpty() && !s.busy, busy = s.busy) {
                val typed = password
                model.run({ entry.submitSignIn(screen, email.trim(), typed) }) { password = "" }
            }
        } else if (model.signInCodeSpent.collectAsState().value) {
            // The step's code was used by an answer that kept the code step on show: another code would only be refused
            // as stale. The way back to the password, instead of a field that cannot work.
            Say(UiText.ph(Placeholder.SIGN_IN_CODE_STEP_SPENT))
            Main(UiText.ph(Placeholder.SIGN_IN_START_AGAIN), enabled = !s.busy, busy = false) { model.act { entry.back() } }
        } else {
            Field(UiText.ph(Placeholder.TWO_STEP_CODE_FIELD), code, KeyboardType.Number, mono = true) { code = it }
            Main(UiText.ph(Placeholder.SIGN_IN_BUTTON), enabled = code.isNotBlank() && !s.busy, busy = s.busy) {
                model.submitSignInCode(screen, code.trim()) { code = "" }
            }
        }
        SaidHere(model, s)
        BackRow(model, s)
    }
}

/** The sign-in screen's title: [CopyKey.MASTER_PASSWORD_FOR] once an address is typed, else the instance alone names it. */
internal fun signInTitle(screen: EntryScreen.SignIn, typedEmail: String): UiText =
    if (typedEmail.isBlank()) UiText.of(CopyKey.SIGN_IN_PASSWORD) else UiText.of(screen.prompt.titleFor(typedEmail.trim()))

/** §8.7: the account requires new devices to be linked. Core's keys are reserved; they show the owner's approved words. */
@Composable
internal fun LinkRequiredScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.LinkRequired) {
    AuthColumn {
        Title(UiText.of(screen.title))
        Say(UiText.of(screen.body))
        Gap()
        Main(UiText.of(CopyKey.SIGN_IN_LINK_DEVICE), enabled = !s.busy, busy = false) { model.act { entry.linkInstead(screen) } }
        Second(UiText.of(CopyKey.CANCEL), enabled = !s.busy) { model.act { entry.back() } }
    }
}

// ---- small controls ----

@Composable
internal fun Tick(label: UiText, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        Modifier.fillMaxWidth().toggleable(checked, role = Role.Checkbox, onValueChange = onChange).padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Checkbox(checked, onCheckedChange = null)
        Say(label, Modifier.padding(start = 8.dp))
    }
}

@Composable
private fun Choice(label: UiText, detail: UiText, selected: Boolean, enabled: Boolean, onSelect: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().selectable(selected, enabled = enabled, role = Role.RadioButton, onClick = onSelect).padding(vertical = 6.dp),
        verticalAlignment = Alignment.Top,
    ) {
        RadioButton(selected, onClick = null, enabled = enabled)
        androidx.compose.foundation.layout.Column(Modifier.padding(start = 8.dp)) {
            Say(label)
            Say(detail, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
