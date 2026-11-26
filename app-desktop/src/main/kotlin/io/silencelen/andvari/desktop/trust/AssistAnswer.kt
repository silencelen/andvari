package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.OperatorResult
import io.silencelen.andvari.core.model.wire.AdminRecoveryRequest
import io.silencelen.andvari.core.trust.AnswerRead
import io.silencelen.andvari.core.trust.AnswerRefusal
import io.silencelen.andvari.core.trust.AnswerToken
import io.silencelen.andvari.core.trust.TrustGrammar

/**
 * The answer `recovery-cli assist` produced for one operator-assisted recovery request (spec 04 §7 step 3), as the
 * operator hands it to the console: pasted, or read from a file. It is read on this computer, before the master password
 * is asked and before anything is sent, by the ONE shared reader the command-line tool uses too ([AnswerToken.read], and
 * [AnswerToken.readFile] for a file, which refuses bytes that are not UTF-8). This
 * file is only its caller: it gives each of the reader's eight refusals a sentence of its own.
 *
 * What passes is said for what it is: it names this request and its key and has the size of an answer for the request's
 * address. Nothing here can tell who made it or whether it opens: the person's device, which opens the seal, stays the
 * authority, and the server takes the new password only with the commit value inside the answer.
 */
internal sealed class AssistAnswer {
    /** What to hand to `fulfilRecovery`: [sealed] is the answer token as the shared reader re-made it from its parts (core reads it again against its own listed row). */
    class Ok internal constructor(val sealed: String) : AssistAnswer()

    /** Not sent: [why] is the sentence for the screen ([request] fills the other request's id, when one is named). */
    class Refused internal constructor(val why: Placeholder, val request: String? = null) : AssistAnswer() {
        val text: UiText get() = if (request != null) UiText.ph(why, request) else UiText.ph(why)
    }

    companion object {
        /** The sentence for each refusal of the shared reader: eight refusals, eight sentences. */
        fun words(refusal: AnswerRefusal): Placeholder = when (refusal) {
            AnswerRefusal.EMPTY -> Placeholder.OP_FULFIL_EMPTY
            AnswerRefusal.IS_THE_COPY -> Placeholder.OP_ANSWER_IS_THE_COPY
            AnswerRefusal.NOT_AN_ANSWER -> Placeholder.OP_ANSWER_NOT_ONE
            AnswerRefusal.BARE -> Placeholder.OP_ANSWER_BARE
            AnswerRefusal.OTHER_REQUEST -> Placeholder.OP_ANSWER_OTHER_REQUEST
            AnswerRefusal.OTHER_REQUEST_KEY -> Placeholder.OP_ANSWER_OTHER_KEY
            AnswerRefusal.CUT_SHORT -> Placeholder.OP_ANSWER_CUT_SHORT
            AnswerRefusal.TOO_LONG -> Placeholder.OP_ANSWER_TOO_LONG
        }

        /** The same sentences for core's result of each refusal (core reads the answer again before it sends it; the server's `request_key_mismatch` is [OperatorResult.ANSWER_OTHER_REQUEST_KEY]). Null for any other result. */
        fun words(result: OperatorResult): Placeholder? = when (result) {
            OperatorResult.ANSWER_EMPTY -> words(AnswerRefusal.EMPTY)
            OperatorResult.ANSWER_IS_THE_COPY -> words(AnswerRefusal.IS_THE_COPY)
            OperatorResult.ANSWER_NOT_AN_ANSWER -> words(AnswerRefusal.NOT_AN_ANSWER)
            OperatorResult.ANSWER_BARE -> words(AnswerRefusal.BARE)
            OperatorResult.ANSWER_OTHER_REQUEST -> words(AnswerRefusal.OTHER_REQUEST)
            OperatorResult.ANSWER_OTHER_REQUEST_KEY -> words(AnswerRefusal.OTHER_REQUEST_KEY)
            OperatorResult.ANSWER_CUT_SHORT -> words(AnswerRefusal.CUT_SHORT)
            OperatorResult.ANSWER_TOO_LONG -> words(AnswerRefusal.TOO_LONG)
            else -> null
        }

        /** Read pasted [text] as the answer for the listed [request]. A row whose address is not one reads as no answer. */
        fun read(text: String, request: AdminRecoveryRequest): AssistAnswer {
            val emailNorm = TrustGrammar.emailNorm(request.email) ?: return Refused(Placeholder.OP_REQUEST_ROW_NOT_VALID)
            return of(AnswerToken.read(text, request.requestId, request.rPub, emailNorm))
        }

        /** Read a picked file's [bytes] as the answer for the listed [request], strictly: bytes that are not UTF-8 are not an answer. */
        fun readFile(bytes: ByteArray, request: AdminRecoveryRequest): AssistAnswer {
            val emailNorm = TrustGrammar.emailNorm(request.email) ?: return Refused(Placeholder.OP_REQUEST_ROW_NOT_VALID)
            // A file whose bytes are not text is said as that, in a sentence for a file (the reader's own refusal for it
            // is worded for a paste). The shared reader still decides everything else, strictly, as before.
            if (!isUtf8(bytes)) return Refused(Placeholder.OP_ANSWER_FILE_NOT_TEXT)
            return of(AnswerToken.readFile(bytes, request.requestId, request.rPub, emailNorm))
        }

        /** Whether [bytes] are UTF-8 throughout, read strictly (nothing replaced, nothing kept: the decoder's buffer only). */
        internal fun isUtf8(bytes: ByteArray): Boolean =
            try {
                Charsets.UTF_8.newDecoder()
                    .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                    .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                    .decode(java.nio.ByteBuffer.wrap(bytes))
                    .let { buf -> buf.array().fill(' '); true }
            } catch (e: java.nio.charset.CharacterCodingException) {
                false
            }

        private fun of(r: AnswerRead): AssistAnswer = when (r) {
            is AnswerRead.Ok -> Ok(r.token)
            is AnswerRead.Refused -> Refused(words(r.refusal), r.namedRequest?.takeIf { r.refusal == AnswerRefusal.OTHER_REQUEST })
        }
    }
}
