package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.Keys
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.ClientPolicy
import io.silencelen.andvari.core.model.PasswordChangeRequest

/**
 * The F61 silent KDF re-key (spec 01 §7, design 2026-07-10 §4) — ONE JVM/Android implementation
 * of the routine that derives a new master key from the password the client just verified,
 * re-wraps the SAME UVK under the new wrapKey, and pushes both to `PUT /account/password`.
 *
 * R44: "one implementation" needs that qualifier. Web ships a deliberate TS sibling —
 * `web/src/vault/kdfupgrade.ts` (`shouldUpgrade`, a documented verbatim replica of
 * [KdfUpgrade.shouldUpgrade], plus `maybeKdfUpgrade`, driven from Welcome.tsx's sign-in path) —
 * because core is Kotlin and the web bundle cannot call it. That is the ONE place this routine's
 * contract has a second landing site: a change here (the zeroization discipline, the
 * `mustChangePassword` re-check after the await, what the offline cache is told) has to be made
 * there too, and neither compiler will say so.
 *
 * WHY THIS FILE EXISTS (audit H85, the F37/G39 pattern). This ~40-line sequence was hand-written
 * twice — Android's `KdfReKey.maybeUpgrade` and an inline copy in the desktop's `DesktopState` —
 * from the same description, with nothing pinning the two together. Both copies happened to agree
 * byte for byte, which is exactly what made the duplication dangerous rather than merely untidy:
 * it is a re-key of the MASTER KEY, so the next one-sided edit (a missed zeroization, a
 * `mustChangePassword` re-check after the network await, a change to what the offline cache is
 * told) would not look like a bug on either side — it would reach the household as "I forgot my
 * password". The desktop copy even carried a comment justifying itself with "app-android is not
 * shared", a reason the G39 hoist had already removed: `core/src/jvmShared` compiles into BOTH
 * `jvmMain` and `androidMain`, so one implementation reaches both apps by construction. Each
 * native is now a thin adapter that supplies its own cache gate through [persist] and its own
 * thread confinement around the call. Nothing about the wire format, the crypto or the decision
 * gate changed in the hoist — the body below is the two former copies verbatim.
 *
 * **The decision gate is [KdfUpgrade.shouldUpgrade] and nothing else** (spec 05 T1): the policy
 * must dominate the account on both cost axes and sit inside the client-side sanity fence, so a
 * hostile `/client-policy` can neither weaken the master-password KDF nor DoS every unlock with
 * an absurd cost. Re-checked HERE, not only at the call sites, so no adapter can forget it.
 *
 * **Best-effort by design**: ANY failure — network, server refusal, a persist that throws — is
 * swallowed. The unlock that triggered this already succeeded, the user is not waiting on it, and
 * the check re-runs at the next online full-password unlock (design §4 step 4). That is also why
 * the `runCatching` deliberately catches everything, cancellation included: a lock or a killed
 * process mid-re-key must be as silent as a 500.
 *
 * **Zero-knowledge preserved**: only the derived `authKey` (old and new) and the re-wrapped UVK
 * cross the wire. The UVK itself never changes across a KDF upgrade (spec 01 §4/§7) — re-deriving
 * it would invalidate every sealed grant and every vault key.
 *
 * Callers MUST have already excluded `mustChangePassword` (A5 — the server's changePassword clears
 * the flag, so a silent re-key would erase an admin's recovery nudge), the offline case, and the
 * quick-unlock case (§7: a biometric unlock has no password to re-key with), and must run this OFF
 * the UI thread — it performs two Argon2id derivations at policy cost.
 */
object KdfReKeyCore {

    /**
     * Re-key iff [KdfUpgrade.shouldUpgrade] approves the move from [keys]' params to [policy]'s.
     *
     * @param api the LIVE session's client — the re-key rides its access token.
     * @param userId the session's user id; it is the envelope AAD ([Ad.uvk]) for the re-wrap, so a
     *   wrong value here would produce a UVK the next unlock cannot open.
     * @param password the master password the client JUST verified (never stored, never logged).
     * @param keys the account keys this session unlocked with — the source of the CURRENT salt and
     *   params for `currentAuthKey`, and the row the persisted copy is derived from.
     * @param account the unlocked account, for its UVK copy.
     * @param crypto test-only seam, null in production. It is resolved INSIDE the `runCatching`
     *   below, exactly where both former copies called `createCryptoProvider()`: a failure to load
     *   the platform's libsodium must stay swallowed like every other failure here, not escape into
     *   a caller that launched this detached and has no handler.
     * @param persist called ONLY after the server accepted the change, with the updated
     *   [AccountKeys] the offline cache must now hold (design §4 step 3: an offline unlock derives
     *   with the cached salt/params, so a stale cache row makes the next offline unlock fail with
     *   what looks like a wrong password). Each platform supplies its OWN cache gate here —
     *   Android's `store.cacheAllowed`, the desktop's `durableCacheEnabled()` + per-origin
     *   namespace — because that gate is genuinely platform state, not part of this routine. A
     *   caller that has no cache passes a no-op.
     */
    suspend fun maybeUpgrade(
        api: AndvariApi,
        userId: String,
        password: String,
        keys: AccountKeys,
        policy: ClientPolicy,
        account: Account,
        crypto: CryptoProvider? = null,
        persist: (AccountKeys) -> Unit,
    ) {
        if (!KdfUpgrade.shouldUpgrade(keys.kdfParams, policy.kdfParams)) return
        runCatching {
            @Suppress("NAME_SHADOWING") val crypto = crypto ?: createCryptoProvider()
            val newSalt = crypto.randomBytes(KdfParams.SALT_BYTES)
            val newParams = policy.kdfParams
            // ZEROIZATION (H80, recheck R22 — Account.enroll's shape): the new MK lives only long
            // enough to split into its two purposes, and the new wrapKey dies once the UVK is
            // sealed under it. authNew is only ever the base64 string the request carries.
            val mkNew = Keys.masterKey(crypto, password, newSalt, newParams)
            val (authNew, wrapNew) = try {
                Bytes.toB64(Keys.authKey(crypto, mkNew)) to Keys.wrapKey(crypto, mkNew)
            } finally {
                mkNew.fill(0)
            }
            // The UVK never changes across a KDF upgrade (spec 01 §4/§7) — re-wrap the SAME UVK
            // under the new wrapKey. The egress copy is zeroed whatever happens.
            val uvk = account.uvkCopyForPlatformWrap()
            val wrappedUvkNew = try {
                Envelope.sealB64(crypto, wrapNew, uvk, Ad.uvk(userId))
            } finally {
                uvk.fill(0)
                wrapNew.fill(0)
            }
            val currentAuth = Account.deriveAuthKey(password, keys.kdfSalt, keys.kdfParams, crypto)
            api.changePassword(
                PasswordChangeRequest(
                    currentAuthKey = currentAuth,
                    newAuthKey = authNew,
                    newKdfSalt = Bytes.toB64(newSalt),
                    newKdfParams = newParams,
                    newWrappedUvk = wrappedUvkNew,
                ),
            )
            // design §4 step 3: the offline cache MUST hold the new salt/params/wrappedUvk or the
            // next offline unlock derives with stale params and fails. AFTER the server accepted —
            // caching params the server never took would break offline unlock in the other
            // direction. The platform's own cache gate lives inside [persist].
            persist(keys.copy(kdfSalt = Bytes.toB64(newSalt), kdfParams = newParams, wrappedUvk = wrappedUvkNew))
        }
    }
}
