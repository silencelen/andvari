package io.silencelen.andvari.core.model.wire

/**
 * Every machine `error` code spec 03 names (§0.1's generic refusals and §0.2's route-specific ones),
 * so the server emits and the clients key on one spelling. A client MUST still handle a code it does
 * not know as a generic refusal (spec 03 §0.1: clients key on `error`).
 *
 * `bad_<field>` codes are formed from the field's snake_case name ([badField]); only the ones a route
 * names explicitly are listed here.
 */
object WireErrors {
    // ---- generic (§0.1) ----
    const val BAD_REQUEST = "bad_request"
    const val BODY_TOO_LARGE = "body_too_large"
    const val RATE_LIMITED = "rate_limited"
    const val INTERNAL = "internal"
    const val MISSING_TOKEN = "missing_token"
    const val INVALID_CREDENTIALS = "invalid_credentials"
    const val TOTP_ENROLLMENT_REQUIRED = "totp_enrollment_required"
    const val REAUTH_FAILED = "reauth_failed"
    const val NOT_OPERATOR = "not_operator"
    const val OPERATOR_WEB_REFUSED = "operator_web_refused"
    const val UPGRADE_REQUIRED = "upgrade_required"
    const val NOT_FOUND = "not_found"

    // ---- instance and card (§17) ----
    const val BAD_CARD = "bad_card"
    const val CARD_HEAD_MOVED = "card_head_moved"
    const val HANDOVER_TARGET_INVALID = "handover_target_invalid"
    const val BAD_ROTATION = "bad_rotation"

    // ---- sign-up and registration (§14) ----
    const val SIGNUP_CLOSED = "signup_closed"
    const val SIGNUP_FULL = "signup_full"
    const val INVALID_EMAIL = "invalid_email"
    const val EMAIL_DOMAIN_BLOCKED = "email_domain_blocked"
    const val AGE_CONFIRM_REQUIRED = "age_confirm_required"
    const val POW_REQUIRED = "pow_required"
    const val BAD_POW = "bad_pow"
    const val MAIL_UNAVAILABLE = "mail_unavailable"
    const val BAD_CODE = "bad_code"
    const val SETUP_DONE = "setup_done"
    const val SETUP_INCOMPLETE = "setup_incomplete"
    const val BAD_TICKET = "bad_ticket"
    const val LINK_UNKNOWN = "link_unknown"
    const val LINK_EXPIRED = "link_expired"
    const val LINK_USED = "link_used"
    const val KIND_MISMATCH = "kind_mismatch"
    const val EMAIL_MISMATCH = "email_mismatch"
    const val SIGNUP_DAILY_MAX = "signup_daily_max"
    const val EMAIL_TAKEN = "email_taken"
    const val USER_ID_TAKEN = "user_id_taken"
    const val VAULT_ID_TAKEN = "vault_id_taken"
    const val BAD_GENESIS = "bad_genesis"
    const val ESCROW_NOT_ALLOWED = "escrow_not_allowed"
    const val OPERATOR_RECOVERY_UNAVAILABLE = "operator_recovery_unavailable"
    const val BAD_ESCROW = "bad_escrow"

    /**
     * `400` on `POST /auth/register`, `PUT /account/recovery` and `PUT /escrow/self` (spec 03 §3.1, §3.2; added
     * 2026-11-16): the recovery copy is well formed but not of the one form the server stores, the version-3 copy that
     * names the account's address (its size for that address, spec 04 §3). Nothing is stored. Sent by an app that seals
     * an older form; checked after [BAD_ESCROW], so a malformed copy keeps that code.
     */
    const val ESCROW_WRONG_FORM = "escrow_wrong_form"
    const val PERSONAL_VAULT_MISMATCH = "personal_vault_mismatch"
    const val KDF_TOO_WEAK = "kdf_too_weak"
    const val KDF_MEM_NOT_KIB_MULTIPLE = "kdf_mem_not_kib_multiple"
    const val BAD_KDF_SALT = "bad_kdf_salt"
    const val RECOVERY_REQUIRED = "recovery_required"

    // ---- sessions and TOTP (§2) ----
    const val TOTP_REQUIRED = "totp_required"
    const val LINK_REQUIRED = "link_required"
    const val INVALID_REFRESH = "invalid_refresh"
    const val SESSION_REVOKED = "session_revoked"
    const val REFRESH_REUSE = "refresh_reuse"
    const val REFRESH_EXPIRED = "refresh_expired"
    const val REAUTH_REQUIRED = "reauth_required"
    const val BAD_TOTP_CODE = "bad_totp_code"
    const val NO_PENDING_TOTP = "no_pending_totp"
    const val TOTP_NOT_ENROLLED = "totp_not_enrolled"

    // ---- account (§3, §13, §16.7) ----
    const val STALE_STATE = "stale_state"
    const val BAD_ACCOUNT_STATE = "bad_account_state"
    const val NO_GRANT = "no_grant"
    const val CREDENTIAL_CHANGED = "credential_changed"
    const val ESCROW_NOT_DUE = "escrow_not_due"
    const val BAD_USAGE_BLOB = "bad_usage_blob"
    const val NO_SUCH_DEVICE = "no_such_device"
    const val CANNOT_TARGET_SELF = "cannot_target_self"
    const val CONFIRM_EMAIL_MISMATCH = "confirm_email_mismatch"
    const val TOTP_CODE_REQUIRED = "totp_code_required"
    const val ACCOUNT_DELETE_BLOCKED = "account_delete_blocked"
    const val ACCOUNT_DELETE_LOG_STALE = "account_delete_log_stale"
    const val AT_AHEAD = "at_ahead"
    const val BAD_LEAVES = "bad_leaves"

    // ---- kit recovery (§12) ----
    const val INVALID_TICKET = "invalid_ticket"
    const val RECOVERY_ACCOUNT_NOT_ACTIVE = "recovery_account_not_active"
    const val RECOVERY_PIECE_STALE = "recovery_piece_stale"

    // ---- sync, items, attachments (§4, §5, §9) ----
    const val RESYNC_REQUIRED = "resync_required"
    const val BATCH_TOO_LARGE = "batch_too_large"
    const val BAD_OP = "bad_op"
    const val PUT_WITHOUT_ITEM = "put_without_item"
    const val ITEM_NOT_DELETED = "item_not_deleted"
    const val FV_DOWNGRADE = "fv_downgrade"
    const val UNKNOWN_ATTACHMENT = "unknown_attachment"
    const val ATTACHMENT_MISMATCH = "attachment_mismatch"
    const val TOO_MANY_ATTACHMENTS = "too_many_attachments"
    const val DUPLICATE_ATTACHMENT = "duplicate_attachment"
    const val BAD_ATTACHMENT_ID = "bad_attachment_id"
    const val ITEM_ATTACHMENT_QUOTA = "item_attachment_quota"
    const val ITEM_TOO_LARGE = "item_too_large"
    const val QUOTA_EXCEEDED = "quota_exceeded"
    const val NO_WRITE_GRANT = "no_write_grant"
    const val ATTACHMENT_ID_TAKEN = "attachment_id_taken"
    const val ATTACHMENT_TOO_LARGE = "attachment_too_large"

    // ---- vault log and vaults (§10, §11) ----
    const val BAD_FRAME = "bad_frame"
    const val NON_CANONICAL = "non_canonical"
    const val BAD_STATEMENT = "bad_statement"
    const val WRONG_VAULT = "wrong_vault"
    const val BAD_SIGNER = "bad_signer"
    const val BAD_SIGNATURE = "bad_signature"
    const val NOT_VAULT_OWNER = "not_vault_owner"
    const val NOT_SHARED_VAULT = "not_shared_vault"
    const val LOG_HEAD_MOVED = "log_head_moved"

    /** `409` to a vault's deletion that named a read point: an item of the vault moved since; nothing is stored. */
    const val VAULT_ITEMS_MOVED = "vault_items_moved"
    const val PRECONDITION = "precondition"
    const val BAD_EXPIRY = "bad_expiry"
    const val MEMBER_LIMIT = "member_limit"
    const val NOT_CONNECTED = "not_connected"
    const val OFFER_EXPIRED = "offer_expired"
    const val BAD_AFTER = "bad_after"
    const val VAULT_DELETED = "vault_deleted"
    const val STALE_META = "stale_meta"
    const val OWNER_WRAP_IMMUTABLE = "owner_wrap_immutable"
    const val BAD_META_BLOB = "bad_meta_blob"
    const val BAD_WRAPPED_VK = "bad_wrapped_vk"
    const val BAD_GRANT = "bad_grant"

    // ---- links and device links (§15, §16) ----
    const val BAD_KIND = "bad_kind"
    const val BAD_TOKEN_HASH = "bad_token_hash"
    const val LINK_ID_TAKEN = "link_id_taken"
    const val LINK_STATE = "link_state"
    const val LINK_CLAIMED = "link_claimed"
    const val BAD_PROOF = "bad_proof"
    const val BAD_PLATFORM = "bad_platform"

    // ---- assisted recovery (§18) ----
    const val REQUEST_UNKNOWN = "request_unknown"
    const val REQUEST_STATE = "request_state"

    /** §18.5: the commit carries no commit value, or one that is not a `b64_32`. */
    const val BAD_COMMIT = "bad_commit"

    /** §18.5: the commit value's hash is not the one stored with the newest answer (5 per request; the fifth cancels it). */
    const val COMMIT_MISMATCH = "commit_mismatch"

    /** §18.6: the upload's request key is not the row's: an answer made for another request. */
    const val REQUEST_KEY_MISMATCH = "request_key_mismatch"

    // ---- operator (§7, §18.6) ----
    const val NO_SUCH_USER = "no_such_user"
    const val NOT_DISABLED_LONG_ENOUGH = "not_disabled_long_enough"
    const val NO_ESCROW = "no_escrow"
    const val NOT_TIGHTER = "not_tighter"

    // ---- misc (§8) ----
    const val BAD_PREFIX = "bad_prefix"
    const val HIBP_TIMEOUT = "hibp_timeout"

    /** `400 bad_<field>` for a field that fails its type or limit (spec 03 §0.1): `bad_vault_id` for `vaultId`. */
    fun badField(lowerCamelField: String): String {
        val sb = StringBuilder("bad_")
        for (c in lowerCamelField) {
            if (c in 'A'..'Z') sb.append('_').append(c + ('a' - 'A')) else sb.append(c)
        }
        return sb.toString()
    }

    /** `502 hibp_upstream_<status>` (spec 03 §0.2 row 87). */
    fun hibpUpstream(status: Int): String = "hibp_upstream_$status"
}
