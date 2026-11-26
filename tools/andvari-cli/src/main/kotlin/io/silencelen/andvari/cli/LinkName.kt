package io.silencelen.andvari.cli

import io.silencelen.andvari.core.trust.TrustGrammar

/**
 * The name an account goes by in its links (decided on 2026-11-17: a device never invents it). The server serves no
 * account its own name, so only the home where the account was made knows it, from the registration (`--name`, or the
 * address's first part there). On any other home, `link create` and `link open` need it first: given as `--name`, or
 * asked once at a terminal; kept on that home for that account; never made up from the address.
 */
object LinkName {
    /** Asked at a terminal: `{0}` the account's address. */
    const val PROMPT = "The name people you connect with see for {0} (this device keeps it): "

    /**
     * Said, with exit 2 and nothing of a link sent, when the name is not known here and there is no terminal to ask at
     * (the tool's own sentence, not yet on the wording page). `{0}` the account's address.
     */
    const val NEEDED = "This device doesn't know the name {0} goes by in its links: the account was made on another device, and " +
        "the server doesn't keep that name. Nothing was sent. Give it with --name NAME (this device keeps it for this account); " +
        "at a terminal, andvari-cli asks for it."

    /** Said, with exit 2 and nothing sent, for a name a link cannot carry (the tool's own sentence). */
    const val NOT_A_NAME = "That isn't a name a link can carry: it is 1 to 64 bytes of visible characters and spaces, with no " +
        "space at either end. Nothing was sent."

    /** The message key of [NEEDED]. */
    const val KEY_NEEDED = "name_needed"

    /** The name to keep: [given]; else, at a terminal ([ask] not null), the answer to [PROMPT] without the spaces around it; else null. */
    fun read(given: String?, ask: ((String) -> String?)?, emailNorm: String): String? =
        given ?: ask?.invoke(fill(PROMPT, emailNorm))?.trim()

    /** Whether a link can carry [name] (the shared code's own test). */
    fun isName(name: String): Boolean = TrustGrammar.encodeName(name) != null
}
