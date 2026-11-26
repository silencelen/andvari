package io.silencelen.andvari.app.autofill

import android.content.Context
import io.silencelen.andvari.app.trust.TrustSeam
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.InstanceCardState
import io.silencelen.andvari.core.app.SaveQueueStore
import io.silencelen.andvari.core.app.SaveQueued
import io.silencelen.andvari.core.app.content.ContentCapture
import io.silencelen.andvari.core.crypto.CryptoProvider

/**
 * "Save to andvari?" on the new code (design 2026-11-09, "Saving"): the service never opens the vault for a save. It
 * seals what the person submitted to the account's published key and puts it in the content's save queue through the
 * content's own call ([ContentCapture.queue], [io.silencelen.andvari.app.trust.AndroidSaveQueue]); the unlocked app reads the queue, saves
 * by itself only what core's rules allow (always listed, with an undo), and lists the rest for the person to save or
 * discard. Nothing here is a write to the vault.
 *
 * The site a capture is queued under follows the fill's rule: a web domain only from a trusted browser (the launder,
 * [launderUntrustedCapture]), else the app's own `androidapp://<package>`; a browser capture with no trusted domain is
 * not queued (it could never fill).
 */
internal object AutofillSave {
    /** How one save request ended. */
    enum class Outcome {
        QUEUED,

        /** Nobody is signed in on this device (the first screen, with no account the server signed out kept here). */
        NOT_SIGNED_IN,

        /** The session takes no saves now: the server ended it (a read-only copy), or the server is stopped here. */
        NOT_NOW,

        /** Nothing to queue: no password, no site this login could fill, or core refused it (a full queue, a long field). */
        REFUSED,
    }

    /**
     * Whether the session takes saves at all: an account whose server still serves it. Not under a session the server
     * ended ([io.silencelen.andvari.core.app.LockedScreen.signedOutByServer], or its copy open read-only:
     * [io.silencelen.andvari.core.app.AccountSnapshot.signedOutByServer]), not while the server is stopped or its pin
     * damaged, and not signed out. Both facts are read from the snapshot itself, so a fill process that never saw
     * the lock screen still tells.
     */
    fun sessionTakesSaves(s: AppSnapshot): Boolean {
        val card = s.instance?.card
        if (card is InstanceCardState.Stopped || card is InstanceCardState.Damaged) return false
        return when (s.phase) {
            AppPhase.LOCKED -> s.locked != null && !s.locked!!.signedOutByServer
            AppPhase.UNLOCKED -> s.account?.let { !it.serverStopped && !it.signedOutByServer } == true
            AppPhase.STARTING, AppPhase.ENTRY -> false
        }
    }

    /** [sessionTakesSaves] for this process's session; false when it cannot be told. */
    fun takesSaves(context: Context): Boolean = runCatching {
        sessionTakesSaves(TrustSeam.model(context).api.snapshot)
    }.getOrDefault(false)

    /**
     * What a save meets in the session: [refusedAs] when it takes no save (null: it takes one), and [noKey] for a
     * session that takes saves but has no key published. Each outcome is said in words true of it.
     */
    class SaveSession internal constructor(val refusedAs: Outcome?, val noKey: Outcome)

    /**
     * [s] read for a save. Nobody signed in: [Outcome.NOT_SIGNED_IN] (an account the server signed out and this phone
     * keeps is [Outcome.NOT_NOW]'s, which says so). Signed in with no key: the plain "not saved" ([Outcome.REFUSED]),
     * never the server's policy: the list of caught logins is outside a policy that forbids keeping data on the phone
     * (decided on 2026-11-18), whose key the shared code keeps published under it, so the policy is never why.
     */
    fun saveSession(s: AppSnapshot): SaveSession {
        if (s.phase == AppPhase.ENTRY && s.keptSignedOut == null) return SaveSession(Outcome.NOT_SIGNED_IN, Outcome.NOT_SIGNED_IN)
        if (!sessionTakesSaves(s)) return SaveSession(Outcome.NOT_NOW, Outcome.NOT_NOW)
        return SaveSession(null, Outcome.REFUSED)
    }

    /** [saveSession] for this process's session; when it cannot be read, only "not saved" is said. */
    fun session(context: Context): SaveSession = runCatching {
        saveSession(TrustSeam.model(context).api.snapshot)
    }.getOrDefault(SaveSession(Outcome.REFUSED, Outcome.REFUSED))

    /**
     * The site a capture is queued under, made by the content's own helpers: [ContentCapture.webSite] for a web domain
     * reported by a verified browser ([verifiedBrowser]: the service's [TrustedBrowsers] verdict), with the scheme the
     * browser reported (none: the domain alone, and the person is asked before it is saved); else
     * [ContentCapture.appSite] for the app's own package. Null, and nothing is queued, for a browser with no trusted
     * domain: a browser's own package is never an app's site (it is a window onto every web origin). A domain from
     * anything but a verified browser never names the capture, even if the launder was skipped.
     *
     * In an app that is not a verified browser, a capture whose fields belong to a web page
     * (a web domain, or HTML fields: [SavedCredentials.webPage]) is refused. It is never filed as the app's own login,
     * which would let a page shown inside the app replace the app's stored password by itself.
     */
    fun captureSite(creds: SavedCredentials, verifiedBrowser: Boolean): String? {
        val domain = creds.webDomain?.takeIf { verifiedBrowser }
        if (domain != null) return ContentCapture.webSite(domain, creds.webScheme)
        if (verifiedBrowser || creds.appPackage in io.silencelen.andvari.core.client.autofill.BrowserCertPins.TABLE) return null
        if (creds.webPage || creds.webDomain != null) return null
        return ContentCapture.appSite(creds.appPackage)
    }

    /**
     * Queue [creds] (already laundered) if the session takes saves, through the content's own call
     * ([ContentCapture.queue]: its package and host check, its source). Pure over its stores (tested).
     */
    fun capture(queue: SaveQueueStore, crypto: CryptoProvider, creds: SavedCredentials, verifiedBrowser: Boolean, session: SaveSession, nowMs: Long): Outcome {
        session.refusedAs?.let { return it }
        val password = creds.password
        if (password.isNullOrEmpty()) return Outcome.REFUSED
        val site = captureSite(creds, verifiedBrowser) ?: return Outcome.REFUSED
        return when (runCatching { ContentCapture.queue(queue, crypto, site, creds.username.orEmpty(), password, nowMs) }.getOrDefault(SaveQueued.REFUSED)) {
            SaveQueued.QUEUED -> Outcome.QUEUED
            SaveQueued.NO_ACCOUNT -> session.noKey
            SaveQueued.REFUSED -> Outcome.REFUSED
        }
    }

    /** What the capture names as its source (core's `CapturedLogin.source`): the content's own. */
    const val SOURCE = ContentCapture.SOURCE
}
