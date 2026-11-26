package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.EscrowFormat
import io.silencelen.andvari.core.crypto.IdentityCheck
import io.silencelen.andvari.core.crypto.SignedStatement
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

/**
 * One worked example of each new form (spec 04 §3 and §7 step 3), from fixed inputs, for anyone
 * who writes the independent vectors from the specification alone: the escrow statement version 3 and its frame, the
 * assisted-recovery statement version 3 and its frame, the commit hash and the token. A sealed box is randomised, so the
 * frames are what is fixed; the test prints every value (hex for bytes) and checks that the forms open as they should.
 */
class AssistedRecoveryV3ExampleTest {
    private val crypto = createCryptoProvider()

    @Test fun theWorkedExamples() {
        val identitySeed = ByteArray(32) { 0x11 }
        val uvk = ByteArray(32) { 0x22 }
        val recoverySeed = ByteArray(32) { 0x33 }
        val userId = "1b4e28ba-2fa1-4d3b-8a5e-2c3f4d5e6a7b"
        val email = "alice@example.org"
        val issuedAt = 1_794_858_966_854L
        val identity = crypto.boxKeypairFromSeed(identitySeed)
        val signer = crypto.signKeypairFromSeed(identitySeed)
        val recovery = crypto.boxKeypairFromSeed(recoverySeed)
        val recoveryFp = Escrow.fingerprint(crypto, recovery.publicKey)

        val escrowSealed = Escrow.sealUvkV3(crypto, recovery.publicKey, recoveryFp, userId, email, identity.publicKey, signer, uvk, issuedAt)
        val escrowFrame = crypto.sealOpen(recovery.publicKey, recovery.privateKey, escrowSealed)
        val escrowStatement = escrowFrame.copyOfRange(SignedStatement.STATEMENT_OFFSET, escrowFrame.size).decodeToString()
        assertEquals(
            """{"v":3,"purpose":"escrow-uvk","userId":"$userId","email":"YWxpY2VAZXhhbXBsZS5vcmc","identityKey":"${Bytes.toB64(identity.publicKey)}","recoveryFp":"$recoveryFp","issuedAt":$issuedAt,"key":"${Bytes.toB64(uvk)}"}""",
            escrowStatement,
        )
        val check = IdentityCheck(Envelope.sealB64(crypto, uvk, identitySeed, Ad.idkey(userId)), Bytes.toB64(identity.publicKey))
        val opened = Escrow.openForAssist(crypto, recovery, escrowSealed, userId, email, Escrow.fingerprint(crypto, identity.publicKey), check)
        assertEquals(EscrowFormat.V3, opened.format)

        val instanceId = "5d1f0c2e-7a3b-4c4d-9e5f-6a7b8c9d0e1f"
        val requestId = Bytes.toB64(ByteArray(16) { 0x44 })
        val request = crypto.boxKeypairFromSeed(ByteArray(32) { 0x55 })
        val commit = ByteArray(32) { 0x66 }
        val recoverySigner = crypto.signKeypairFromSeed(recoverySeed)
        val answerFrame = AssistedRecovery.sign(crypto, recoverySigner,
            AssistedRecoveryFields(instanceId, userId, requestId, Bytes.toB64(request.publicKey), uvk, issuedAt, email = email, commit = commit))
        val answerStatement = answerFrame.copyOfRange(SignedStatement.STATEMENT_OFFSET, answerFrame.size).decodeToString()
        assertEquals(
            """{"v":3,"purpose":"assisted-recovery","instanceId":"$instanceId","userId":"$userId","email":"YWxpY2VAZXhhbXBsZS5vcmc","requestId":"$requestId","requestKey":"${Bytes.toB64(request.publicKey)}","commit":"${Bytes.toB64(commit)}","uvk":"${Bytes.toB64(uvk)}","issuedAt":$issuedAt}""",
            answerStatement,
        )
        assertEquals(376 + 23, answerStatement.length)
        val sealed = AssistedRecovery.seal(crypto, request.publicKey, answerFrame)
        assertEquals(AnswerToken.sealedBytes(email), sealed.size)
        val commitHash = AssistedRecovery.commitHash(crypto, commit)
        val token = AnswerToken.format(requestId, Bytes.toB64(request.publicKey), commitHash, sealed)
        assertIs<AnswerRead.Ok>(AnswerToken.read(token, requestId, Bytes.toB64(request.publicKey), email))
        val got = assertIs<Checked.Ok<OpenedAssistedRecovery>>(
            AssistedRecovery.openV3(crypto, request.publicKey, request.privateKey, sealed, recoveryFp, instanceId, requestId, email, check, null),
        ).value
        assertEquals(Bytes.toB64(commit), got.commitB64)

        println("EXAMPLE identitySeed=${Bytes.toHexLower(identitySeed)} uvk=${Bytes.toHexLower(uvk)} recoverySeed=${Bytes.toHexLower(recoverySeed)}")
        println("EXAMPLE identityPub=${Bytes.toB64(identity.publicKey)} signerPub=${Bytes.toB64(signer.publicKey)} recoveryPub=${Bytes.toB64(recovery.publicKey)} recoveryFp=$recoveryFp")
        println("EXAMPLE escrowStatement=$escrowStatement")
        println("EXAMPLE escrowStatementLength=${escrowStatement.length} escrowFrameLength=${escrowFrame.size} escrowSealedLength=${escrowSealed.size}")
        println("EXAMPLE escrowFrameHex=${Bytes.toHexLower(escrowFrame)}")
        println("EXAMPLE recoverySignerPub=${Bytes.toB64(recoverySigner.publicKey)} rPub=${Bytes.toB64(request.publicKey)} requestId=$requestId")
        println("EXAMPLE answerStatement=$answerStatement")
        println("EXAMPLE answerStatementLength=${answerStatement.length} answerFrameLength=${answerFrame.size} answerSealedLength=${sealed.size}")
        println("EXAMPLE answerFrameHex=${Bytes.toHexLower(answerFrame)}")
        println("EXAMPLE commitHash=$commitHash")
        println("EXAMPLE tokenHead=${token.removeSuffix(Bytes.toB64(sealed))}")
        println("EXAMPLE token=$token")
    }
}
