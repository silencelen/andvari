package io.silencelen.andvari.app.autofill

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * [DatasetBuilder.saveTrigger] — which fields must CHANGE before Android offers
 * "Save to andvari?". `SaveInfo` cannot be constructed in a JVM unit test, so the rule is
 * factored pure and pinned here (the DatasetBuilderCapTest idiom); this is its only
 * red-when-reverted coverage.
 *
 * The regression these exist for (owner report 2026-08-22): password fields not tied to a
 * username were offered for FILL but never prompted for SAVE.
 *
 * The exact trigger was measured on a real device (drill autofill-formlab), and it is narrower
 * than the framework contract's wording suggests: the save UI is suppressed when a REQUIRED
 * field is **EMPTY at commit**, not merely unchanged. An ABSENT username is fine (never
 * required) and a PREFILLED one is fine (it has a value); the broken case is a username field
 * that EXISTS and is left BLANK — which is exactly a password-only sign-in that still carries
 * one. Making the password the sole required id is what fixes it.
 */
class DatasetBuilderSaveTriggerTest {

    @Test
    fun passwordAloneTriggersSave_usernameOnlyRidesAlong() {
        val t = DatasetBuilder.saveTrigger(passwords = listOf("pw"), usernames = listOf("user"), ccAnchor = null, ccAll = emptyList())
        assertEquals(listOf("pw"), t.required, "the password is the sole trigger")
        assertEquals(listOf("user"), t.optional, "the username still reaches onSaveRequest")
    }

    /** THE BUG, as measured: a username field left EMPTY at commit must not suppress the prompt.
     *  Verified on-device that an ABSENT or PREFILLED username never did — only a blank one. */
    @Test
    fun aUsernameLeftBlankCannotSuppressThePrompt() {
        val t = DatasetBuilder.saveTrigger(passwords = listOf("pw"), usernames = listOf("blank"), ccAnchor = null, ccAll = emptyList())
        assertFalse("blank" in t.required, "a username in the required set is exactly the reported half-working feature")
    }

    /** The genuinely username-less case: an app/context-scoped password. Save must still fire. */
    @Test
    fun aPasswordWithNoUsernameAtAllStillTriggersSave() {
        val t = DatasetBuilder.saveTrigger(passwords = listOf("pw"), usernames = emptyList(), ccAnchor = null, ccAll = emptyList())
        assertEquals(listOf("pw"), t.required)
        assertTrue(t.optional.isEmpty())
    }

    /** A change-password form's every password field stays required — unchanged behaviour. */
    @Test
    fun everyPasswordFieldRemainsRequired() {
        val t = DatasetBuilder.saveTrigger(passwords = listOf("cur", "new", "confirm"), usernames = listOf("u"), ccAnchor = null, ccAll = emptyList())
        assertEquals(listOf("cur", "new", "confirm"), t.required)
    }

    /** Card-only checkout: the single PAN anchor triggers, the rest of the card ride along. */
    @Test
    fun cardOnlyFormsKeepTheirSingleAnchorRule() {
        val t = DatasetBuilder.saveTrigger(passwords = emptyList(), usernames = emptyList(), ccAnchor = "pan", ccAll = listOf("pan", "exp", "cvv"))
        assertEquals(listOf("pan"), t.required)
        assertEquals(listOf("exp", "cvv"), t.optional)
    }

    /** A login sitting on a checkout page: password triggers, card fields AND username ride. */
    @Test
    fun loginOnACheckoutPageCarriesBothCardFieldsAndUsername() {
        val t = DatasetBuilder.saveTrigger(passwords = listOf("pw"), usernames = listOf("u"), ccAnchor = "pan", ccAll = listOf("pan", "exp"))
        assertEquals(listOf("pw"), t.required)
        assertEquals(listOf("pan", "exp", "u"), t.optional)
    }

    /** Nothing worth saving — the caller returns null before ever reaching a SaveInfo. */
    @Test
    fun noPasswordAndNoCardYieldsNoTrigger() {
        val t = DatasetBuilder.saveTrigger(passwords = emptyList(), usernames = listOf("u"), ccAnchor = null, ccAll = emptyList())
        assertTrue(t.required.isEmpty())
    }

    /** An id may never appear in both sets — Android rejects an overlapping SaveInfo. */
    @Test
    fun requiredAndOptionalNeverOverlap() {
        val t = DatasetBuilder.saveTrigger(passwords = listOf("pw"), usernames = listOf("pw", "u"), ccAnchor = null, ccAll = listOf("pw"))
        assertTrue(t.required.none { it in t.optional }, "overlapping ids: ${t.required} / ${t.optional}")
        assertEquals(listOf("u"), t.optional)
    }
}
