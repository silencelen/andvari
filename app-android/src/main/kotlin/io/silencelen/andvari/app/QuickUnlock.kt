package io.silencelen.andvari.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.KdfUpgrade
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.Keys
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.ClientPolicy
import io.silencelen.andvari.core.model.PasswordChangeRequest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.coroutines.resume
import kotlin.math.abs
import kotlin.math.max

/**
 * Android biometric quick unlock (spec 01 §8.1, design 2026-07-10). The SINGLE owner of the
 * Keystore alias, on-disk blob format, AAD, freshness arithmetic and wipe semantics — nothing
 * else in the app touches these. Wraps the account's UVK (never the master password / MK /
 * derived keys) under an auth-per-use, BIOMETRIC_STRONG-gated, non-exportable AES-256-GCM key
 * so a biometric unlock reconstructs exactly what a password unlock reaches minus the password.
 *
 * Fail-to-password invariant (design §5 / spec 01 §8.1): every failure resolves to either a
 * working biometric OR the always-present master-password prompt — never neither. Wipe-class
 * events (enrollment changed, GCM/AAD tamper, corrupt blob, policy flip, revocation,
 * sign-out) destroy the blob + key; a mere temporary lockout or cancel NEVER does (A8).
 */
object QuickUnlock {
    /** Blob schema version; an unknown `v` on disk is treated as corrupt → wipe + password. */
    private const val BLOB_V = 1

    /** 30-day periodic-full-password window (spec 01 §8.1). Calendar-shaped, evaluated on the
     *  monotonic high-water wall clock (A2), not raw wall time. */
    internal const val WINDOW_MS = 30L * 24 * 60 * 60 * 1000

    /** A2: a stamp more than this far in the FUTURE is a clock rollback → fail closed (stale). */
    internal const val CLOCK_SKEW_MS = 5L * 60 * 1000

    /** A2: tolerance on the derived boot reference (wall − elapsedRealtime) drift for deciding
     *  "same boot, clock steady" so the extra monotonic-delta guard applies. */
    internal const val BOOT_SKEW_MS = 60L * 1000

    /** A4: the last-seen client policy must be fresher than this for quick unlock to be eligible;
     *  an admin who flips `offlineCacheAllowed=false` must reach the device within a bounded window
     *  even if only the autofill overlay ever runs. */
    internal const val POLICY_STALE_MS = 7L * 24 * 60 * 60 * 1000

    private const val GCM_TAG_BITS = 128
    private const val KEYSTORE = "AndroidKeyStore"

    private fun alias(userId: String) = "andvari-qu-$userId"
    private fun blobFile(dir: File, userId: String) = File(dir, "quick-unlock-$userId.json")
    /** AAD binds the blob to the account: a blob copied to another profile/user won't open,
     *  and any file tamper fails the GCM tag. */
    private fun aad(userId: String): ByteArray = "andvari/v1|quick-unlock|$userId".encodeToByteArray()

    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    @Serializable
    private data class Blob(val v: Int, val alias: String, val iv: String, val ct: String, val createdAt: Long)

    /** Result of a recover attempt; the caller maps each to the design §5 fallback UX. */
    sealed interface Recover {
        /** UVK recovered — hand straight to `Account.unlockWithUvk`; the caller zeroes it after. */
        class Ok(val uvk: ByteArray) : Recover
        /** User cancelled / pressed "Use master password" / temporary lockout — blob KEPT (A8). */
        data class Fallback(val reason: String?) : Recover
        /** Wipe-class failure (enrollment changed, GCM/AAD tamper, corrupt blob): blob has
         *  been wiped; caller offers re-enroll after the next full-password unlock. */
        data class Wiped(val reason: String) : Recover
    }

    /** Result of an enroll attempt. */
    sealed interface Enroll {
        object Ok : Enroll
        /** User cancelled the consent prompt — no blob written, orphan key removed. */
        object Cancelled : Enroll
        /** Enrollment could not proceed (e.g. no biometric, hardware error) — password stays. */
        data class Failed(val reason: String?) : Enroll
    }

    // ---- eligibility / enrollment / freshness (no prompt) ----

    /**
     * spec 01 §8.1 + A4 gates, all of which must hold to OFFER or USE quick unlock:
     *  - a Class-3 (strong) biometric is enrolled and usable;
     *  - the org permits durable at-rest key material (`offlineCacheAllowed`, persisted in
     *    [SessionStore.cacheAllowed] with fail-open-until-seen semantics);
     *  - the last-seen client policy is fresher than 7 days (A4 — an idle overlay-only device
     *    must periodically re-confirm the policy before trusting a durable unlock secret).
     */
    fun isEligible(context: Context, store: SessionStore): Boolean {
        if (!store.cacheAllowed) return false
        val policyAt = store.policyFetchedAt
        if (policyAt <= 0L || System.currentTimeMillis() - policyAt >= POLICY_STALE_MS) return false
        return hasStrongBiometric(context)
    }

    /** BIOMETRIC_STRONG only — DEVICE_CREDENTIAL is deliberately NOT an accepted authenticator
     *  (a screen PIN is weaker than the master password, spec 01 §8.1). */
    fun hasStrongBiometric(context: Context): Boolean =
        BiometricManager.from(context)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS

    /** True when a well-formed blob of a known version exists for this user. */
    fun isEnrolled(dir: File, userId: String): Boolean = readBlob(dir, userId) != null

    /**
     * A1/A2 freshness: within 30 days of the last REAL full-password unlock, evaluated against a
     * monotonic high-water clock so a wall-clock rollback cannot re-open the window. Reads (and
     * advances) the persisted high-water mark as a side effect.
     */
    fun isFresh(store: SessionStore, userId: String): Boolean {
        val now = System.currentTimeMillis()
        val elapsedNow = android.os.SystemClock.elapsedRealtime()
        val highWater = store.bumpHighWater(now) // monotonically non-decreasing
        return isFreshPure(
            FreshnessInputs(
                nowMs = now,
                elapsedNowMs = elapsedNow,
                stampWallMs = store.lastFullPasswordUnlockAt(userId),
                stampElapsedMs = store.stampElapsedMs(userId),
                stampBootRefMs = store.stampBootRefMs(userId),
                highWaterWallMs = highWater,
                serverFloorMs = store.serverTimeFloorMs,
            ),
        )
    }

    /** Pure inputs for [isFreshPure], extracted so the clock-safety logic is unit-testable
     *  without Android/Keystore. */
    data class FreshnessInputs(
        val nowMs: Long,
        val elapsedNowMs: Long,
        val stampWallMs: Long,
        val stampElapsedMs: Long,
        val stampBootRefMs: Long,
        val highWaterWallMs: Long,
        /** Last SERVER-attested wall time (monotonic). The only clock the device holder can't set. */
        val serverFloorMs: Long,
    )

    /**
     * A1: a zero stamp (never a real full-password unlock, or cleared) is NOT fresh.
     * A2: a future stamp fails closed (stale); the window is measured on the highest clock we
     *     have any reason to trust; and within one boot with a steady clock the monotonic
     *     `elapsedRealtime` delta must ALSO be under 30 days (and never regress).
     *
     * Review 2026-07-10 [2] — the cross-boot hole. `highWaterWallMs` only ratchets from the
     * DEVICE clock as this app observes it, so a dormant phone freezes it; a reboot resets
     * `elapsedRealtime`, voiding the monotonic cross-check. An attacker holding the device could
     * then set the clock to a moment INSIDE the window and quick-unlock forever — exactly what
     * A2 exists to prevent. Elapsed time simply CANNOT be bounded from an attacker-settable
     * clock alone. So:
     *   - SAME boot  → the monotonic clock proves duration; trust it (plus the wall-clock guards).
     *   - CROSS boot → require a server-attested anchor taken AFTER the stamp
     *                  (`serverFloorMs > stampWallMs`) and measure the window against THAT.
     *                  With no such anchor we cannot prove how long the device sat powered off,
     *                  so we fail CLOSED: the master password is required.
     * Practical effect: the first unlock after a reboot uses the master password unless the app
     * has since reached the server (the policy fetch on start advances the floor) — the same
     * before-first-unlock posture Android itself takes, for one honest password entry.
     */
    fun isFreshPure(i: FreshnessInputs): Boolean {
        if (i.stampWallMs <= 0L) return false
        if (i.nowMs < i.stampWallMs - CLOCK_SKEW_MS) return false // clock rolled back past the stamp
        // `nowMs` is attacker-settable; the floor is not. Never let a rollback shrink the window.
        val effectiveNow = max(max(i.nowMs, i.highWaterWallMs), i.serverFloorMs)
        if (effectiveNow - i.stampWallMs >= WINDOW_MS) return false

        val currentBootRef = i.nowMs - i.elapsedNowMs
        val sameBoot = abs(currentBootRef - i.stampBootRefMs) <= BOOT_SKEW_MS
        if (sameBoot) {
            // Same boot, wall clock not stepped: the monotonic clock is authoritative and cheap.
            if (i.elapsedNowMs < i.stampElapsedMs) return false // monotonic went backwards → distrust
            if (i.elapsedNowMs - i.stampElapsedMs >= WINDOW_MS) return false
            return true
        }
        // Cross-boot: the only trustworthy duration evidence is a server contact AFTER the stamp.
        if (i.serverFloorMs <= i.stampWallMs) return false // no anchor → duration unknowable → password
        return i.serverFloorMs - i.stampWallMs < WINDOW_MS
    }

    // ---- wipe ----

    /** Destroy the blob file and the Keystore key. Idempotent, NEVER throws (called from
     *  fail-closed paths and process-blind autofill rails). File-dir form so callers that hold
     *  only `noBackupFilesDir` (the ViewModel) can invoke it without a Context. */
    fun wipe(dir: File, userId: String) {
        runCatching { blobFile(dir, userId).delete() }
        runCatching {
            val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
            if (ks.containsAlias(alias(userId))) ks.deleteEntry(alias(userId))
        }
    }

    // ---- enroll (consented UVK wrap) ----

    /**
     * Wrap the account's UVK under a fresh hardware key after an explicit biometric consent.
     * Called only while unlocked (the UVK is in memory). Does NOT touch the SessionStore
     * freshness stamp — A1: enrollment COPIES the existing real-password stamp by leaving it in
     * place, never mints `now` (that would silently reset the 30-day clock with no password
     * typed). The caller is responsible for the A1 provenance/`mustChangePassword` (A5) gates.
     */
    suspend fun enroll(activity: FragmentActivity, dir: File, userId: String, account: Account): Enroll {
        if (!hasStrongBiometric(activity)) return Enroll.Failed("No usable fingerprint or face on this device.")
        val key = try {
            generateKey(userId)
        } catch (t: Throwable) {
            return Enroll.Failed(null) // never echo a KeyStore message (may reflect input)
        }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key)
        } catch (e: KeyPermanentlyInvalidatedException) {
            wipe(dir, userId); return Enroll.Failed(null)
        } catch (t: Throwable) {
            wipe(dir, userId); return Enroll.Failed(null)
        }
        val outcome = authenticate(activity, cipher, title = "Enable quick unlock")
        return when (outcome) {
            is Auth.Ok -> {
                // A UVK copy egresses core ONLY here (spec 01 §8 enrollment accessor) — sealed
                // straight into the hardware cipher and zeroed immediately, whatever happens.
                val uvk = account.uvkCopyForPlatformWrap()
                try {
                    outcome.cipher.updateAAD(aad(userId))
                    val ct = outcome.cipher.doFinal(uvk)
                    val iv = outcome.cipher.iv
                    writeBlob(dir, userId, Blob(BLOB_V, alias(userId), b64(iv), b64(ct), System.currentTimeMillis()))
                    Enroll.Ok
                } catch (t: Throwable) {
                    wipe(dir, userId); Enroll.Failed(null)
                } finally {
                    uvk.fill(0)
                }
            }
            is Auth.Cancelled -> { wipe(dir, userId); Enroll.Cancelled } // remove the orphan key
            is Auth.PermanentLockout -> { wipe(dir, userId); Enroll.Failed("Too many attempts — try again later.") }
            is Auth.TempLockout -> { wipe(dir, userId); Enroll.Failed("Too many attempts — try again in a moment.") }
            is Auth.Error -> { wipe(dir, userId); Enroll.Failed(null) }
        }
    }

    // ---- recover (biometric UVK decrypt) ----

    /**
     * Decrypt the stored UVK behind a fresh biometric prompt. Maps every failure to the spec 01
     * §8.1 table. `KeyPermanentlyInvalidatedException` is caught at BOTH `Cipher.init` and
     * `doFinal` (A9 — the surface varies by OEM/API) and converges on the same wipe outcome.
     */
    suspend fun recoverUvk(activity: FragmentActivity, dir: File, userId: String): Recover {
        val blob = readBlob(dir, userId) ?: run { wipe(dir, userId); return Recover.Wiped("Quick unlock needs to be set up again.") }
        val key = try {
            loadKey(userId)
        } catch (t: Throwable) {
            wipe(dir, userId); return Recover.Wiped("Quick unlock needs to be set up again.")
        } ?: run { wipe(dir, userId); return Recover.Wiped("Quick unlock needs to be set up again.") }

        // Review 2026-07-10 [1]: android.util.Base64.decode THROWS on a malformed field, and
        // readBlob validates only JSON/v/alias. An uncaught throw here would kill the AUTOFILL
        // process (its call site has no runCatching, unlike the main app's op{}). Converge a
        // corrupt blob onto the contracted wipe→password path (design §5 failure matrix).
        val iv: ByteArray
        val ct: ByteArray
        try {
            iv = fromB64(blob.iv)
            ct = fromB64(blob.ct)
        } catch (t: Throwable) {
            wipe(dir, userId); return Recover.Wiped("Quick unlock needs to be set up again.")
        }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        } catch (e: KeyPermanentlyInvalidatedException) { // A9 (surface 1/2)
            wipe(dir, userId); return Recover.Wiped("Your biometrics changed — enter your master password.")
        } catch (t: Throwable) {
            wipe(dir, userId); return Recover.Wiped("Quick unlock needs to be set up again.")
        }

        return when (val outcome = authenticate(activity, cipher, title = "Unlock andvari")) {
            is Auth.Ok -> try {
                outcome.cipher.updateAAD(aad(userId))
                Recover.Ok(outcome.cipher.doFinal(ct))
            } catch (e: KeyPermanentlyInvalidatedException) { // A9 (surface 2/2)
                wipe(dir, userId); Recover.Wiped("Your biometrics changed — enter your master password.")
            } catch (t: Throwable) { // GCM tag / AAD mismatch (tamper) → wipe
                wipe(dir, userId); Recover.Wiped("Quick unlock needs to be set up again.")
            }
            // A8: NO lockout — temporary OR permanent — ever wipes a VALID enrollment. Falling
            // back to the password leaves the blob intact. Wiping here would be attacker- and
            // toddler-triggerable destruction (present a wrong finger until Android escalates)
            // for zero security gain: the Keystore key is auth-per-use + BIOMETRIC_STRONG, so a
            // locked-out attacker could never have used it. (enroll()'s lockout wipe is
            // different and correct: it cleans up an ORPHAN key when no valid enrollment exists.)
            is Auth.TempLockout -> Recover.Fallback("Too many attempts — enter your master password.")
            is Auth.Cancelled -> Recover.Fallback(null)
            is Auth.PermanentLockout -> Recover.Fallback("Too many attempts — enter your master password.")
            is Auth.Error -> Recover.Fallback(null)
        }
    }

    // ---- BiometricPrompt suspend bridge ----

    private sealed interface Auth {
        class Ok(val cipher: Cipher) : Auth
        object Cancelled : Auth
        object TempLockout : Auth
        object PermanentLockout : Auth
        data class Error(val code: Int) : Auth
    }

    /** Runs one BiometricPrompt over [cipher] on the main thread and suspends until it resolves.
     *  BIOMETRIC_STRONG only → a negative button ("Use master password") is mandatory. A single
     *  rejected attempt (`onAuthenticationFailed`) is not terminal — the system prompt stays up. */
    private suspend fun authenticate(activity: FragmentActivity, cipher: Cipher, title: String): Auth =
        withContext(Dispatchers.Main) {
            suspendCancellableCoroutine { cont ->
                val prompt = BiometricPrompt(
                    activity,
                    activity.mainExecutor,
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationError(code: Int, msg: CharSequence) {
                            if (!cont.isActive) return
                            cont.resume(
                                when (code) {
                                    BiometricPrompt.ERROR_LOCKOUT -> Auth.TempLockout
                                    BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> Auth.PermanentLockout
                                    BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                                    BiometricPrompt.ERROR_USER_CANCELED,
                                    BiometricPrompt.ERROR_CANCELED,
                                    -> Auth.Cancelled
                                    else -> Auth.Error(code)
                                },
                            )
                        }

                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            if (!cont.isActive) return
                            val c = result.cryptoObject?.cipher
                            if (c == null) cont.resume(Auth.Error(-1)) else cont.resume(Auth.Ok(c))
                        }

                        override fun onAuthenticationFailed() { /* one bad read; prompt remains */ }
                    },
                )
                val info = BiometricPrompt.PromptInfo.Builder()
                    .setTitle(title)
                    .setNegativeButtonText("Use master password")
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    .setConfirmationRequired(false)
                    .build()
                runCatching { prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher)) }
                    .onFailure { if (cont.isActive) cont.resume(Auth.Error(-1)) }
                cont.invokeOnCancellation { runCatching { prompt.cancelAuthentication() } }
            }
        }

    // ---- Keystore key ----

    private fun generateKey(userId: String): SecretKey {
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        // Prefer StrongBox; fall back to the TEE when the SoC lacks it (StrongBoxUnavailableException).
        try {
            gen.init(keySpec(userId, strongBox = true)); return gen.generateKey()
        } catch (e: StrongBoxUnavailableException) {
            gen.init(keySpec(userId, strongBox = false)); return gen.generateKey()
        }
    }

    private fun keySpec(userId: String, strongBox: Boolean): KeyGenParameterSpec {
        val b = KeyGenParameterSpec.Builder(
            alias(userId),
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true) // adding a fingerprint/face invalidates the key
            .setUnlockedDeviceRequired(true) // unusable while locked / before first unlock after boot
        // Auth-per-use binding: every encrypt/decrypt needs a fresh BiometricPrompt CryptoObject.
        if (android.os.Build.VERSION.SDK_INT >= 30) {
            b.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        } else {
            @Suppress("DEPRECATION")
            b.setUserAuthenticationValidityDurationSeconds(-1) // API 29: -1 == biometric-only auth-per-use
        }
        if (strongBox) b.setIsStrongBoxBacked(true)
        return b.build()
    }

    private fun loadKey(userId: String): SecretKey? {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        return ks.getKey(alias(userId), null) as? SecretKey
    }

    // ---- blob file I/O ----

    private fun readBlob(dir: File, userId: String): Blob? {
        val f = blobFile(dir, userId)
        if (!f.exists()) return null
        return runCatching { json.decodeFromString(Blob.serializer(), f.readText()) }
            .getOrNull()
            ?.takeIf { it.v == BLOB_V && it.alias == alias(userId) }
    }

    private fun writeBlob(dir: File, userId: String, blob: Blob) {
        val f = blobFile(dir, userId)
        val tmp = File(dir, "quick-unlock-$userId.json.tmp")
        tmp.writeText(json.encodeToString(Blob.serializer(), blob))
        if (!tmp.renameTo(f)) { // atomic swap; fall back to overwrite if rename is unsupported
            f.writeText(json.encodeToString(Blob.serializer(), blob))
            tmp.delete()
        }
    }

    private fun b64(b: ByteArray): String = android.util.Base64.encodeToString(b, android.util.Base64.NO_WRAP or android.util.Base64.URL_SAFE)
    private fun fromB64(s: String): ByteArray = android.util.Base64.decode(s, android.util.Base64.URL_SAFE)
}

/**
 * A3: durable-offline-data purge, reachable from BOTH the main app and the autofill-only
 * process. Two shapes: a policy-flip purge (the org forbade the durable cache — the session is
 * still valid) and a revocation purge (a definitive 401 — the session is dead). Both destroy the
 * quick-unlock blob (spec 01 §8.1 clearing events), so this is the one place that stays in step
 * with [QuickUnlock.wipe].
 */
object OfflineData {
    /** Delete the durable vault cache DB (+ its wal/shm) for a user. */
    fun deleteVaultCache(noBackupDir: File, userId: String) {
        for (suffix in listOf("", "-wal", "-shm")) File(noBackupDir, "vault-$userId.db$suffix").delete()
    }

    /** `offlineCacheAllowed=false`: drop the cache DB, cached accountKeys and the quick-unlock
     *  secret — but KEEP the session (tokens still valid; this is not a revocation). */
    fun purgeCacheForbidden(noBackupDir: File, store: SessionStore, userId: String) {
        deleteVaultCache(noBackupDir, userId)
        store.clearAccountKeys()
        QuickUnlock.wipe(noBackupDir, userId)
        store.clearFullPasswordStamp(userId)
    }

    /** Definitive server rejection (device revoked): everything [purgeCacheForbidden] does, plus
     *  `store.clear()` — the persisted session/tokens/F58 flag are dead. */
    fun purgeRevoked(noBackupDir: File, store: SessionStore, userId: String) {
        deleteVaultCache(noBackupDir, userId)
        QuickUnlock.wipe(noBackupDir, userId)
        store.clearFullPasswordStamp(userId)
        store.clear() // also removes accountKeys
    }
}

/**
 * F61 KDF upgrade (spec 01 §7, design §4). Silent re-key with the password the client just
 * verified, when the org policy raised the Argon2id cost. Shared by the main app (inline) and the
 * autofill overlay (detached, A6). ZK-preserving: only the derived authKey and the re-wrapped UVK
 * cross the wire, via the existing `PUT /account/password`.
 */
object KdfReKey {
    /**
     * Re-key iff [KdfUpgrade.shouldUpgrade] approves the move (policy ≥ account on both cost axes,
     * inside sanity bounds — never sideways/down/absurd, so a hostile server can't weaken the KDF).
     * Best-effort: ANY failure is swallowed (the unlock already succeeded; the check re-runs next
     * online full-password unlock). Callers MUST have already excluded `mustChangePassword` (A5)
     * and the offline case, and run this off the main thread (two Argon2id derivations).
     */
    suspend fun maybeUpgrade(
        api: AndvariApi,
        store: SessionStore,
        userId: String,
        password: String,
        keys: AccountKeys,
        policy: ClientPolicy,
        account: Account,
    ) {
        if (!KdfUpgrade.shouldUpgrade(keys.kdfParams, policy.kdfParams)) return
        runCatching {
            val crypto = createCryptoProvider()
            val newSalt = crypto.randomBytes(KdfParams.SALT_BYTES)
            val newParams = policy.kdfParams
            val mkNew = Keys.masterKey(crypto, password, newSalt, newParams)
            val authNew = Bytes.toB64(Keys.authKey(crypto, mkNew))
            val wrapNew = Keys.wrapKey(crypto, mkNew)
            // The UVK never changes across a KDF upgrade (spec 01 §4/§7) — re-wrap the SAME UVK
            // under the new wrapKey. Copy egress is zeroed whatever happens.
            val uvk = account.uvkCopyForPlatformWrap()
            val wrappedUvkNew = try {
                Envelope.sealB64(crypto, wrapNew, uvk, Ad.uvk(userId))
            } finally {
                uvk.fill(0)
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
            // next offline unlock derives with stale params and fails. Only when the cache is allowed.
            if (store.cacheAllowed) {
                store.saveAccountKeys(
                    keys.copy(kdfSalt = Bytes.toB64(newSalt), kdfParams = newParams, wrappedUvk = wrappedUvkNew),
                )
            }
        }
    }
}
