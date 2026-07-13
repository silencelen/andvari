package io.silencelen.andvari.server

/**
 * The invite email is every household member's FIRST contact with andvari, and the UI audit
 * (2026-07) flagged the old unbranded plaintext link as phishing-indistinguishable. Both transports
 * (SMTP MimeMultipart, Graph HTML body) now render from this ONE source: a branded, inline-styled
 * treasury card with an explicit anti-phishing inoculation line and posture-NEUTRAL recovery copy
 * (the old "you'll need the printed recovery sheet" was wrong for the default emailed/waived flow,
 * which produces the member's own on-device phrase instead of a sheet).
 *
 * The enrollLink is server-generated (an EnrollLink payload), never user input, so it is inserted
 * verbatim; it is a scheme+host+base64url fragment with no HTML-significant characters.
 */
object InviteEmailBody {
    const val SUBJECT = "You're invited to andvari"

    /** Plain-text alternative (SMTP multipart) + the graceful degradation for text-only clients. */
    fun text(enrollLink: String): String = """
        You've been invited to andvari — your household's password manager.

        Someone in your household set up an invite for you. Open this link on the same
        network as the app to create your account:

        $enrollLink

        This link is a one-time key: it expires within the hour and can't be reused once
        opened. If your household admin gave you a recovery sheet or code, keep it handy to
        finish setting up.

        andvari will never ask for your master password by email or link. If you weren't
        expecting this invite, you can safely ignore it.
    """.trimIndent()

    /** Branded HTML (inline styles only — email clients strip <style>/external CSS; no images, so
     *  nothing to block). Warm-paper card + gold wordmark; the link appears as a button AND as
     *  copyable text for clients that suppress the button. */
    fun html(enrollLink: String): String {
        val sans = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif"
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
                        <p style="font-family:$sans;font-size:15px;line-height:1.6;color:#42392a;margin:0 0 18px;">Someone in your household set up an invite for you to join <b>andvari</b>, your household's password manager. Open the link below <b>on the same network as the app</b> to create your account.</p>
                      </td></tr>
                      <tr><td align="center" style="padding:2px 32px 18px;">
                        <a href="$enrollLink" style="display:inline-block;background:#9a7420;color:#fdf9f0;text-decoration:none;font-family:$sans;font-size:15px;font-weight:600;padding:13px 30px;border-radius:10px;">Set up your account</a>
                      </td></tr>
                      <tr><td style="padding:0 32px 6px;">
                        <p style="font-family:$sans;font-size:13px;line-height:1.6;color:#6b6047;margin:0 0 14px;">This link is a <b>one-time key</b> — it expires within the hour and can't be reused once opened. If your household admin gave you a recovery sheet or code, keep it handy to finish setting up.</p>
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
