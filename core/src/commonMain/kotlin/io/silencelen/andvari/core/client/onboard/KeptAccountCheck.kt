package io.silencelen.andvari.core.client.onboard

import io.silencelen.andvari.core.client.KdfUpgrade
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.KdfParams

/** How the key a sign-in opened compares with what the device keeps of the same account. */
internal enum class KeptMatch {
    /** A kept wrap opened with the typed password, to exactly this key. */
    OPENED,

    /**
     * No kept wrap opened with the typed password, and this key opened the copy's own record sealed under the account's
     * key (its identity seed) to the identity this device recorded: the same key, kept under another master password.
     */
    SEALED,

    /**
     * No kept wrap opened with the typed password and the key does not open the copy's sealed identity seed, but the copy
     * itself is damaged ([KeptAccountCheck.copyDamaged]): its records cannot be read, or the seed the server served opens
     * under this key to the very identity key the copy records. Nothing could be compared, so it is refused all the same,
     * with the reason that says the way out (remove this device's copy, then sign in or recover).
     */
    DAMAGED,

    /** Not this account's key as this device knows it. */
    DIFFERENT,
}

/**
 * Spec 01 §7, a sign-in on a device that already keeps the account: before a sign-in replaces anything the device keeps,
 * the key it opened from the server's wrap is shown to be the account's key as this device knows it.
 *
 * - **Where a kept wrap opens with the typed password** (this device's own wrap, or the wrap of a password change sent
 *   from here whose answer never came), the key it opens is this device's account key, and the two are compared in
 *   constant time: equal is [KeptMatch.OPENED], anything else [KeptMatch.DIFFERENT]. A kept wrap at the prelogin's salt
 *   and cost is opened with the sign-in's own wrap key, so it costs no derivation; one at another salt or cost costs one,
 *   derived before the login is sent ([prepare]) and only when that cost passes the whole fence.
 * - **Where none opens** (the password was changed since this device last kept a wrap: on another device, or by a server
 *   that brings back an older wrap), the key must open what the copy holds sealed under the account's key: the identity
 *   seed it kept, sealed with the associated data that names the account. It must open, and the key derived from it must
 *   be, compared in constant time, the identity key this device kept beside it, which the device checked against that
 *   seed when it opened the copy. This proves the same key: the seed was sealed under the account's key with an
 *   authenticated cipher, and a second key that opens the same sealed bytes to the same seed would have to give the same
 *   key stream at that nonce, which no one can find. [KeptMatch.SEALED].
 *
 * Nothing derived is kept: the kept wraps' opened keys and the seed are wiped before this answers.
 */
internal object KeptAccountCheck {
    /**
     * Before the login: the typed [password] (borrowed: only copies are derived from, and they are wiped) derived under
     * each wrap [kept] holds whose salt or cost differ from the prelogin's ([preSalt], [preParams]). A wrap whose cost
     * is outside the whole fence, or whose salt does not decode, is not derived at: it cannot open.
     */
    fun prepare(crypto: CryptoProvider, kept: KeptAccountKeys, password: CharArray, preSalt: ByteArray, preParams: KdfParams): KeptWrapKeys {
        val keys = ArrayList<Pair<KeptWrap, PasswordKeys>>()
        for (w in wraps(kept)) {
            val salt = keptBytes(w.kdfSalt) ?: continue
            if (Bytes.ctEquals(salt, preSalt) && w.kdfParams == preParams) continue
            if (!KdfUpgrade.withinFence(w.kdfParams)) continue
            val k = try {
                PasswordKeys.derive(crypto, password.copyOf(), salt, w.kdfParams, served = true)
            } catch (e: CryptoException) {
                null
            } catch (e: IllegalArgumentException) {
                null
            } ?: continue
            keys += w to k
        }
        return KeptWrapKeys(kept, keys)
    }

    /**
     * How [uvk] (borrowed, never kept or changed) compares with [kept] for the account [userId]; [signIn] is the sign-in's
     * own keys, at the prelogin's salt and cost; [served] the account's keys as the server answered them (its sealed seed
     * tells a damaged copy from another key, [KeptMatch.DAMAGED]).
     */
    fun match(crypto: CryptoProvider, userId: String, uvk: ByteArray, kept: KeptWrapKeys, signIn: PasswordKeys, served: io.silencelen.andvari.core.model.wire.AccountKeys): KeptMatch {
        for (w in wraps(kept.kept)) {
            val key = wrapKeyFor(w, kept, signIn) ?: continue
            val opened = try {
                Envelope.openB64(crypto, key, w.wrappedUvk, Ad.uvk(userId))
            } catch (e: CryptoException) {
                null
            } catch (e: IllegalArgumentException) {
                null
            } ?: continue
            try {
                return if (Bytes.ctEquals(opened, uvk)) KeptMatch.OPENED else KeptMatch.DIFFERENT
            } finally {
                opened.fill(0)
            }
        }
        return when {
            opensKeptSeed(crypto, userId, uvk, kept.kept.own) -> KeptMatch.SEALED
            copyDamaged(kept.kept.own, identityUnder(crypto, userId, uvk, served.encryptedIdentitySeed)) -> KeptMatch.DAMAGED
            else -> KeptMatch.DIFFERENT
        }
    }

    /**
     * A copy of the wrap key under which one of [kept]'s wraps opens to exactly [uvk] (borrowed) for [userId], or null:
     * what [match] answered [KeptMatch.OPENED] for. A flow hands it to the session keeper, which opens its own kept wrap
     * with it before it takes a session over a copy whose sealed seed does not open ([keptWrapOpensTo]). Only a flow that
     * holds the typed password's keys can have it.
     */
    fun provingKey(crypto: CryptoProvider, userId: String, uvk: ByteArray, kept: KeptWrapKeys, signIn: PasswordKeys): ByteArray? {
        for (w in wraps(kept.kept)) {
            val key = wrapKeyFor(w, kept, signIn) ?: continue
            val opened = openWrap(crypto, key, w, userId) ?: continue
            try {
                if (Bytes.ctEquals(opened, uvk)) return key.copyOf()
            } finally {
                opened.fill(0)
            }
        }
        return null
    }

    /**
     * Whether the typed password ([signIn], and [kept]'s keys derived from it) opens one of the wraps [kept] holds of the
     * account [userId], whatever key it opens to: the password is this account's as this device knows it. Asked when the
     * server refuses the password's proof, to tell its refusal apart from a wrong password.
     */
    fun typedPasswordOpensAKeptWrap(crypto: CryptoProvider, userId: String, kept: KeptWrapKeys, signIn: PasswordKeys): Boolean {
        for (w in wraps(kept.kept)) {
            val key = wrapKeyFor(w, kept, signIn) ?: continue
            val opened = openWrap(crypto, key, w, userId) ?: continue
            opened.fill(0)
            return true
        }
        return false
    }

    /**
     * The session keeper's own check of a flow's [wrapKey] (borrowed): it opens one of the wraps [kept] holds of the
     * account [userId] (this device's own, or an unanswered change's) to exactly [uvk] (borrowed), compared in constant
     * time. This is the sign-in's rule (spec 01 §7: a kept wrap the typed password opens to the same key decides), made
     * by the keeper itself on what it keeps: nothing a flow says is believed.
     */
    fun keptWrapOpensTo(crypto: CryptoProvider, userId: String, uvk: ByteArray, kept: KeptAccountKeys, wrapKey: ByteArray): Boolean {
        for (w in wraps(kept)) {
            val opened = openWrap(crypto, wrapKey, w, userId) ?: continue
            try {
                if (Bytes.ctEquals(opened, uvk)) return true
            } finally {
                opened.fill(0)
            }
        }
        return false
    }

    private fun openWrap(crypto: CryptoProvider, key: ByteArray, w: KeptWrap, userId: String): ByteArray? = try {
        Envelope.openB64(crypto, key, w.wrappedUvk, Ad.uvk(userId))
    } catch (e: CryptoException) {
        null
    } catch (e: IllegalArgumentException) {
        null
    }

    /**
     * A recovery's key ([uvk], borrowed, never kept or changed) against what the device keeps of the account [userId]:
     * a recovery exists for the person who can open no wrap the device keeps (the master password is lost), so no kept wrap
     * is compared; the copy's own identity seed, sealed under the account's key and not under any password, still must
     * open to the identity key the device kept beside it. Null when it does, or when [kept] is not this account's (or is
     * none): then nothing of this account is kept here to compare with. Otherwise the refusal:
     * [io.silencelen.andvari.core.client.session.Establishing.KEPT_COPY_DAMAGED] when the copy is damaged ([copyDamaged],
     * with [servedIdentity] the identity key the served seed opened to under [uvk], or null), else
     * [io.silencelen.andvari.core.client.session.Establishing.SERVER_KEYS_NOT_KNOWN_HERE].
     */
    fun recoveredKeyRefusal(crypto: CryptoProvider, userId: String, uvk: ByteArray, kept: KeptAccountKeys?, servedIdentity: ByteArray?): String? {
        if (kept == null || kept.userId != userId) return null
        if (opensKeptSeed(crypto, userId, uvk, kept.own)) return null
        return if (copyDamaged(kept.own, servedIdentity)) io.silencelen.andvari.core.client.session.Establishing.KEPT_COPY_DAMAGED
        else io.silencelen.andvari.core.client.session.Establishing.SERVER_KEYS_NOT_KNOWN_HERE
    }

    /** The identity key that [seedB64] (a served sealed identity seed) opens to under [uvk] (borrowed) for [userId], or null. */
    fun identityUnder(crypto: CryptoProvider, userId: String, uvk: ByteArray, seedB64: String): ByteArray? {
        val seed = try {
            Envelope.openB64(crypto, uvk, seedB64, Ad.idkey(userId))
        } catch (e: CryptoException) {
            return null
        } catch (e: IllegalArgumentException) {
            return null
        }
        try {
            val identity = crypto.boxKeypairFromSeed(seed)
            identity.privateKey.fill(0)
            return identity.publicKey
        } finally {
            seed.fill(0)
        }
    }

    /**
     * Asked only once a key did not open [own]'s sealed identity seed: whether that is the copy's own damage rather than
     * another key. True when the copy's identity record or sealed seed cannot even be read, or when [identity] (the
     * identity key a seed the server served opens to under that key, or null) is, compared in constant time, the very key
     * [own] records: only the account's key holder can seal the account's seed, so such a key holds what the copy holds,
     * and the copy's seed is what failed. Either way nothing could be compared, and the caller still refuses.
     */
    fun copyDamaged(own: io.silencelen.andvari.core.model.wire.AccountKeys, identity: ByteArray?): Boolean {
        // The identity record is read as every opening reads it ([AccountOpen.check], [opensKeptSeed]: strictly).
        val recorded = Bytes.fromB64Exact(own.identityPub, 32) ?: return true
        // The sealed seed is read as the opening reads it ([Envelope.openB64]): a text the opener takes is never "damaged".
        if (keptBytes(own.encryptedIdentitySeed) == null) return true
        return identity != null && Bytes.ctEquals(recorded, identity)
    }

    /**
     * A text this device KEPT, decoded by the very decoder its opening uses ([Envelope.openB64] and the unlock's salt read
     * both use [Bytes.fromB64]), or null when that decoder refuses it. Every judgment here of whether a kept text can be
     * read goes through this, so a kept text that opens is never judged unreadable. What a server serves is read strictly
     * before it is kept ([ServedKeyForm]); a text kept before that rule (one in a tolerated form) still opens, and is
     * judged by what the opening does with it.
     */
    internal fun keptBytes(text: String): ByteArray? = try {
        Bytes.fromB64(text)
    } catch (e: CryptoException) {
        null
    } catch (e: IllegalArgumentException) {
        null
    }

    private fun wraps(kept: KeptAccountKeys): List<KeptWrap> =
        listOfNotNull(KeptWrap(kept.own.kdfSalt, kept.own.kdfParams, kept.own.wrappedUvk), kept.pending)

    private fun wrapKeyFor(w: KeptWrap, kept: KeptWrapKeys, signIn: PasswordKeys): ByteArray? {
        val salt = keptBytes(w.kdfSalt) ?: return null
        if (Bytes.ctEquals(salt, signIn.salt) && w.kdfParams == signIn.params) return signIn.wrapKey
        return kept.wrapKeys.firstOrNull { it.first.kdfSalt == w.kdfSalt && it.first.kdfParams == w.kdfParams && it.first.wrappedUvk == w.wrappedUvk }?.second?.wrapKey
    }

    /** [uvk] opens [own]'s sealed identity seed to the identity key [own] records, compared in constant time. */
    internal fun opensKeptSeed(crypto: CryptoProvider, userId: String, uvk: ByteArray, own: io.silencelen.andvari.core.model.wire.AccountKeys): Boolean {
        val recorded = Bytes.fromB64Exact(own.identityPub, 32) ?: return false
        val seed = try {
            Envelope.openB64(crypto, uvk, own.encryptedIdentitySeed, Ad.idkey(userId))
        } catch (e: CryptoException) {
            return false
        } catch (e: IllegalArgumentException) {
            return false
        }
        try {
            val identity = crypto.boxKeypairFromSeed(seed)
            try {
                return Bytes.ctEquals(recorded, identity.publicKey)
            } finally {
                identity.privateKey.fill(0)
            }
        } finally {
            seed.fill(0)
        }
    }
}
