package io.silencelen.andvari.cli

import io.silencelen.andvari.core.client.recovery.WireAssistedRecovery

/**
 * The mailbox value of a request for the operator's help (spec 03 §18.1, decided on 2026-11-17): every mail with a
 * recovery request's code carries one, and a request that names a value of its own address's, unused and unexpired, is
 * taken even when someone else has used up the address's five requests of the day. The server answers a request the same
 * whatever the value (right, wrong, used, another address's, or none), so this tool cannot know whether a value was right
 * and never says anything that would tell: the person learns it by the mail that arrives.
 *
 * `recover assist --email E` takes it as `--mailbox-value-file F` (its first line) or `$ANDVARI_MAILBOX_VALUE`, never on
 * the command line; with a terminal attached and neither given, it asks one question first ([QUESTION]) and reads the
 * value only when the answer is yes. Without a terminal nothing is asked: standard input stays for the mailed code.
 */
object MailboxValue {
    /** The secret's name: `--mailbox-value-file`, `--mailbox-value-env`. */
    const val NAME = "mailbox-value"

    /** The environment variable read when `--mailbox-value-env` names none. */
    const val ENV = "ANDVARI_MAILBOX_VALUE"

    /** The server's alphabet for the value: capital letters without I and O, digits 2 to 9 (the shared code's own). */
    const val ALPHABET = WireAssistedRecovery.MAILBOX_ALPHABET

    /** The one line that opens the field at a terminal. */
    const val QUESTION = "Have a value from a mail about a request you did not make? [y/N] "

    /** The prompt for the value itself, typed without echo. */
    const val PROMPT = "The value from that mail: "

    /** Said when a value went with the request: the same words whatever the value, since nothing here can tell. */
    const val SENT = "The value from the mail went with the request. The server answers the same whether or not it was right, " +
        "so andvari-cli can't tell: if the email with the 6-digit code arrives, the request went through."

    /** Said, before anything is sent, for a value that cannot be one: it says nothing about any account. */
    const val NOT_A_VALUE = "That isn't a value from such a mail: the value is 16 letters and digits (no I, O, 0 or 1), shown in " +
        "the mail in four groups of four. No request was sent."

    /**
     * [typed] as the request carries it, or null when it is not one: the shared step's own rule
     * ([WireAssistedRecovery.mailboxValueOf]: white space and dashes removed, letters in either case), the one the step
     * applies again when the request is made. The tool asks it first, before anything is dialed: the step itself checks
     * only when the request is made, after the server's card may have been fetched for the Trust Gate.
     */
    fun normal(typed: CharArray): String? = WireAssistedRecovery.mailboxValueOf(String(typed))

    /**
     * The value to send: [given] (a file or the environment) when there is one; else, with a terminal ([ask] and [askSecret]
     * not null), the value typed after a yes to [QUESTION]; else none, and nothing is asked.
     */
    fun read(given: CharArray?, ask: ((String) -> String?)?, askSecret: ((String) -> CharArray?)?): CharArray? {
        if (given != null) return given
        if (ask == null || askSecret == null) return null
        val answer = ask(QUESTION)?.trim()?.lowercase() ?: return null
        if (answer != "y" && answer != "yes") return null
        return askSecret(PROMPT)
    }
}
