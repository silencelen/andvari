package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.core.client.pin.CardPin
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.trust.CardFields
import io.silencelen.andvari.core.trust.InstanceCard
import io.silencelen.andvari.core.trust.InstanceKind
import io.silencelen.andvari.core.trust.LogEntry
import io.silencelen.andvari.core.trust.VaultLog

/**
 * The adversaries a proxy cannot be on its own, because they hold a key (design §1):
 *
 * - **T1 as the operator** ("T1 server, which is the operator on an instance they run"): only the operator's key signs a
 *   card, so two cards at one position, or a card that changes `kind`, need it;
 * - **M, a member working with T1**: a member's key signs log entries the log does not authorise.
 *
 * Both sign with an account's own key, which the engine keeps internal: this file is the reason the module compiles
 * as a friend of `:core`. The internal symbol used is `OpenedAccount.signing` (the account's Ed25519 key pair). Every
 * statement is built by the shared code's public builders (`InstanceCard.sign`, `VaultLog.sign`).
 */
object Adversary {
    /**
     * The card after [base] (a pin of the operator's own device), signed with the operator account's key and [change]d.
     * Nothing is stored anywhere: what the proxy serves it to is the scenario's choice.
     */
    fun signCard(op: Host, origin: String, base: CardPin, at: Long, change: (CardFields) -> CardFields = { it }): String {
        val held = op.session(origin) ?: error("the operator is not signed in")
        val signing = held.session.account.signing
        val next = CardFields(
            base.instanceId, base.seq + 1, base.hash, base.origin, base.name, InstanceKind.fromLiteral(base.kind)!!, held.userId,
            Bytes.toB64(signing.publicKey), base.recoveryFp.takeIf { it != "none" }, at,
        )
        return Bytes.toB64(signing.use { InstanceCard.sign(op.crypto, it, change(next)) })
    }

    /** A log entry signed with [member]'s own key whatever the log allows: what a colluding member hands the server (G2). */
    fun signEntry(member: Host, origin: String, entry: LogEntry): String =
        Bytes.toB64((member.session(origin) ?: error("not signed in")).session.account.signing.use { VaultLog.sign(member.crypto, it, entry) })
}
