package io.silencelen.andvari.server

/**
 * The invite email is every household member's FIRST contact with andvari, and the UI audit
 * (2026-07) flagged the old unbranded plaintext link as phishing-indistinguishable. Both transports
 * (SMTP MimeMultipart, Graph HTML body) now render from this ONE source: a branded, inline-styled
 * treasury card with an explicit anti-phishing inoculation line and posture-ACCURATE recovery copy
 * (item #2): the invite's own escrowPolicy is threaded in, so a waived invitee is told they'll make
 * their OWN recovery code (never sent hunting for a printed sheet), a required invitee is told about
 * the household sheet ceremony, the inviter is NAMED (anti-phishing: "Jacob invited you" beats
 * "someone"), and the ~1-hour fuse is stated concretely from the invite's real expiresAt.
 *
 * The enrollLink is server-generated (an EnrollLink payload), never user input, so it is inserted
 * verbatim; it is a scheme+host+base64url fragment with no HTML-significant characters. The inviter
 * name IS member-typed free text — sanitized here (controls stripped, length-capped, HTML-escaped
 * in html()) so it can't smuggle header/markup primitives into either transport.
 */
object InviteEmailBody {
    const val SUBJECT = "You're invited to andvari"

    /** Inviter displayName is member-typed free text: strip every control char (the header/markup
     *  injection primitives), cap the length, and fall back to the old neutral phrase when it
     *  sanitizes away (blank name / no row). NOT HTML-escaped here — html() does that. */
    private fun inviterPhrase(inviterName: String?): String {
        val clean = inviterName?.filter { !it.isISOControl() }?.trim()?.take(64)
        return if (clean.isNullOrEmpty()) "Someone in your household" else clean
    }

    /** The fuse in whole minutes (ceil, floor 1), computed at RENDER time so the copy stays honest
     *  even if the off-thread send lags the mint by a little. */
    private fun fusePhrase(expiresAt: Long): String {
        val mins = (((expiresAt - now()).coerceAtLeast(0) + 59_999) / 60_000).coerceAtLeast(1)
        return if (mins == 1L) "1 minute" else "$mins minutes"
    }

    /** Posture-accurate recovery copy (item #2): every invitee makes their own recovery code at
     *  setup; only a required-escrow invitee ALSO faces the printed-sheet check (§F.1 typed-sheet
     *  ceremony for emailed links) — never point a waived invitee at a sheet that doesn't exist. */
    private fun recoveryCopy(escrowWaived: Boolean): String =
        if (escrowWaived) {
            "During setup you'll create a recovery code of your own — it's your way back into your hoard if you ever forget your master password, so save it somewhere safe."
        } else {
            "During setup you'll create a recovery code of your own, and you'll be asked to confirm a short code from your household's printed recovery sheet — your household admin has it, so keep them handy."
        }

    private fun htmlEscape(s: String): String = s
        .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        .replace("\"", "&quot;").replace("'", "&#39;")

    /** Plain-text alternative (SMTP multipart) + the graceful degradation for text-only clients. */
    fun text(enrollLink: String, inviterName: String?, escrowWaived: Boolean, expiresAt: Long): String = """
        You've been invited to andvari — your household's password manager.

        ${inviterPhrase(inviterName)} set up this invite for you. Open this link on the
        same network as the app to create your account:

        $enrollLink

        This link is a one-time key: it expires in about ${fusePhrase(expiresAt)} and
        can't be reused once opened.

        ${recoveryCopy(escrowWaived)}

        andvari will never ask for your master password by email or link. If you weren't
        expecting this invite, you can safely ignore it.
    """.trimIndent()

    /** Branded HTML (inline styles only — email clients strip <style>/external CSS; no images, so
     *  nothing to block). Warm-paper card + gold wordmark; the link appears as a button AND as
     *  copyable text for clients that suppress the button. */
    fun html(enrollLink: String, inviterName: String?, escrowWaived: Boolean, expiresAt: Long): String {
        val sans = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif"
        val inviter = htmlEscape(inviterPhrase(inviterName))
        return """
            <!doctype html>
            <html lang="en">
              <body style="margin:0;padding:0;background:#efe9db;">
                <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#efe9db;padding:32px 14px;">
                  <tr><td align="center">
                    <table role="presentation" width="480" cellpadding="0" cellspacing="0" style="width:100%;max-width:480px;background:#fbf8f1;border:1px solid #e0d8c5;border-radius:14px;">
                      <tr><td style="padding:26px 32px 4px;">
                        <div style="font-family:Georgia,'Times New Roman',serif;font-size:23px;letter-spacing:.5px;"><span style="color:#9a7420;font-weight:bold;">and</span><span style="color:#2c2517;">vari</span></div>
                        <div style="font-family:$sans;font-size:11px;letter-spacing:2px;text-transform:uppercase;color:#786c50;margin-top:3px;">the keeper of the hoard</div>
                      </td></tr>
                      <tr><td style="padding:14px 32px 0;">
                        <h1 style="font-family:Georgia,'Times New Roman',serif;font-size:21px;font-weight:normal;color:#2c2517;margin:8px 0 10px;">You've been invited</h1>
                        <p style="font-family:$sans;font-size:15px;line-height:1.6;color:#42392a;margin:0 0 18px;"><b>$inviter</b> set up an invite for you to join <b>andvari</b>, your household's password manager. Open the link below <b>on the same network as the app</b> to create your account.</p>
                      </td></tr>
                      <tr><td align="center" style="padding:2px 32px 18px;">
                        <a href="$enrollLink" style="display:inline-block;background:#9a7420;color:#fdf9f0;text-decoration:none;font-family:$sans;font-size:15px;font-weight:600;padding:13px 30px;border-radius:10px;">Set up your account</a>
                      </td></tr>
                      <tr><td style="padding:0 32px 6px;">
                        <p style="font-family:$sans;font-size:13px;line-height:1.6;color:#6b6047;margin:0 0 14px;">This link is a <b>one-time key</b> — it expires in about <b>${fusePhrase(expiresAt)}</b> and can't be reused once opened. ${recoveryCopy(escrowWaived)}</p>
                        <p style="font-family:$sans;font-size:13px;line-height:1.55;color:#42392a;margin:0 0 6px;padding:11px 14px;background:#f4efe4;border-left:3px solid #9a7420;border-radius:6px;">andvari will never ask for your master password by email or link. If you weren't expecting this invite, you can safely ignore it.</p>
                      </td></tr>
                      <tr><td style="padding:16px 32px 26px;border-top:1px solid #e0d8c5;">
                        <p style="font-family:$sans;font-size:11px;color:#786c50;margin:0 0 5px;">If the button doesn't work, copy this link:</p>
                        <p style="font-family:'SF Mono',ui-monospace,Menlo,Consolas,monospace;font-size:11px;color:#9a7420;word-break:break-all;margin:0;">$enrollLink</p>
                      </td></tr>
                    </table>
                  </td></tr>
                </table>
              </body>
            </html>
        """.trimIndent()
    }
}
