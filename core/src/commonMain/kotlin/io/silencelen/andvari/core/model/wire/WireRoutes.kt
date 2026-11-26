package io.silencelen.andvari.core.model.wire

import kotlin.reflect.KClass

/** Who may call a route (spec 03 §0.1, the index's third column). */
enum class Caller {
    /** Unauthenticated; a capability in the body or path may still be required. */
    NONE,
    /** A live session of an `active` account. */
    SESSION,
    /** A session plus a fresh `currentAuthKey` in the body (†): a wrong one is `403 reauth_failed`. */
    SESSION_REAUTH,
    /** A session of the operator account, not minted by the web client. */
    OPERATOR,
    /** An operator session plus a fresh `currentAuthKey` (†). */
    OPERATOR_REAUTH,
    /** A `?ticket=` or a bearer on the WebSocket upgrade (§6). */
    TICKET_OR_BEARER,
    /** Not reachable from the network (`/metrics`). */
    HOST,
}

/** The shape of a body that is not one JSON object of a listed type. */
enum class BodyShape {
    /** One JSON value of the listed type ([WireRoute.responseList] for an array). */
    JSON,
    /** No body. */
    NONE,
    /** The plain-text `ok`. */
    OK,
    /** Plain text of the route's own format. */
    TEXT,
    /** Raw bytes (attachments, downloads). */
    BYTES,
    /** WebSocket frames ([EventFrame], and the text `ping`/`pong`). */
    WEBSOCKET,
}

/**
 * Spec 03 §0.2's route index as data: 95 HTTP routes (row 20 is retired; rows 91 and 92 hold three and
 * two routes). [row] is the index row, [path] the full path with `{param}` segments, [success] the
 * success status. [request] / [response] name the body type when the shape is [BodyShape.JSON].
 *
 * The section the index cites wins over this table where they disagree (spec 03 §0.2); a test pins the
 * count and the uniqueness of every (method, path).
 */
enum class WireRoute(
    val row: Int,
    val method: String,
    val path: String,
    val caller: Caller,
    val versionChecked: Boolean,
    /** **R**: answers `404 not_found` on a public instance, before anything else (§18.6). */
    val refusedOnPublic: Boolean,
    val success: Int,
    val requestShape: BodyShape,
    val request: KClass<*>?,
    val responseShape: BodyShape,
    val response: KClass<*>?,
    val responseList: Boolean = false,
) {
    // ---- instance and policy ----
    CLIENT_POLICY(1, "GET", "/api/v1/client-policy", Caller.NONE, false, false, 200, BodyShape.NONE, null, BodyShape.JSON, ClientPolicy::class),
    INSTANCE(2, "GET", "/api/v1/instance", Caller.NONE, false, false, 200, BodyShape.NONE, null, BodyShape.JSON, InstanceResponse::class),
    INSTANCE_CARD_PUT(3, "PUT", "/api/v1/instance/card", Caller.OPERATOR_REAUTH, false, false, 200, BodyShape.JSON, InstanceCardPut::class, BodyShape.JSON, InstanceCardPutResponse::class),
    INSTANCE_ROTATION_PUT(4, "PUT", "/api/v1/instance/rotation", Caller.OPERATOR_REAUTH, false, true, 200, BodyShape.JSON, InstanceRotationPut::class, BodyShape.OK, null),
    RECOVERY_PUBKEY(5, "GET", "/api/v1/recovery-pubkey", Caller.NONE, false, true, 200, BodyShape.NONE, null, BodyShape.TEXT, null),

    // ---- sign-up and registration ----
    SIGNUP_START(6, "POST", "/api/v1/signup/start", Caller.NONE, false, false, 202, BodyShape.JSON, SignupStartRequest::class, BodyShape.JSON, SignupStartResponse::class),
    SIGNUP_VERIFY(7, "POST", "/api/v1/signup/verify", Caller.NONE, false, false, 200, BodyShape.JSON, SignupVerifyRequest::class, BodyShape.JSON, SignupVerifyResponse::class),
    REGISTER(8, "POST", "/api/v1/auth/register", Caller.NONE, true, false, 200, BodyShape.JSON, RegisterRequest::class, BodyShape.JSON, SessionResponse::class),

    // ---- sessions ----
    PRELOGIN(9, "POST", "/api/v1/auth/prelogin", Caller.NONE, false, false, 200, BodyShape.JSON, PreloginRequest::class, BodyShape.JSON, PreloginResponse::class),
    LOGIN(10, "POST", "/api/v1/auth/login", Caller.NONE, true, false, 200, BodyShape.JSON, LoginRequest::class, BodyShape.JSON, SessionResponse::class),
    REFRESH(11, "POST", "/api/v1/auth/refresh", Caller.NONE, false, false, 200, BodyShape.JSON, RefreshRequest::class, BodyShape.JSON, TokenPair::class),
    LOGOUT(12, "POST", "/api/v1/auth/logout", Caller.SESSION, false, false, 200, BodyShape.NONE, null, BodyShape.OK, null),
    /** Ends exactly the session that issued `refreshToken` (spec 03 §2; a consumed token ends its whole device row). `200 ok` whatever the token. */
    END_SESSION(93, "POST", "/api/v1/auth/end-session", Caller.NONE, false, false, 200, BodyShape.JSON, RefreshRequest::class, BodyShape.OK, null),
    TOTP_STATUS(13, "GET", "/api/v1/account/totp", Caller.SESSION, false, false, 200, BodyShape.NONE, null, BodyShape.JSON, TotpStatus::class),
    TOTP_SETUP(14, "POST", "/api/v1/account/totp/setup", Caller.SESSION, false, false, 200, BodyShape.JSON, TotpSetupRequest::class, BodyShape.JSON, TotpSetupResponse::class),
    TOTP_CONFIRM(15, "POST", "/api/v1/account/totp/confirm", Caller.SESSION, false, false, 200, BodyShape.JSON, TotpCodeRequest::class, BodyShape.OK, null),
    TOTP_DISABLE(16, "POST", "/api/v1/account/totp/disable", Caller.SESSION_REAUTH, false, false, 200, BodyShape.JSON, TotpDisableRequest::class, BodyShape.OK, null),

    // ---- account ----
    ACCOUNT_KEYS(17, "GET", "/api/v1/account/keys", Caller.SESSION, false, false, 200, BodyShape.NONE, null, BodyShape.JSON, AccountKeys::class),
    ACCOUNT_STATE_GET(18, "GET", "/api/v1/account/state", Caller.SESSION, false, false, 200, BodyShape.NONE, null, BodyShape.JSON, AccountStateResponse::class),
    ACCOUNT_STATE_PUT(19, "PUT", "/api/v1/account/state", Caller.SESSION, true, false, 200, BodyShape.JSON, AccountStatePut::class, BodyShape.JSON, AccountStateResponse::class),
    PASSWORD_CHANGE(21, "PUT", "/api/v1/account/password", Caller.SESSION_REAUTH, true, false, 200, BodyShape.JSON, PasswordChangeRequest::class, BodyShape.OK, null),
    ACCOUNT_RECOVERY_PUT(22, "PUT", "/api/v1/account/recovery", Caller.SESSION_REAUTH, true, false, 200, BodyShape.JSON, AccountRecoveryPut::class, BodyShape.JSON, AccountStateResponse::class),
    ESCROW_SELF(23, "PUT", "/api/v1/escrow/self", Caller.SESSION, true, true, 200, BodyShape.JSON, EscrowSelfPut::class, BodyShape.OK, null),
    USAGE_GET(24, "GET", "/api/v1/usage", Caller.SESSION, false, false, 200, BodyShape.NONE, null, BodyShape.JSON, UsageResponse::class),
    USAGE_PUT(25, "PUT", "/api/v1/usage", Caller.SESSION, true, false, 200, BodyShape.JSON, UsagePut::class, BodyShape.OK, null),
    DEVICES(26, "GET", "/api/v1/account/devices", Caller.SESSION, false, false, 200, BodyShape.NONE, null, BodyShape.JSON, Device::class, responseList = true),
    DEVICE_REVOKE(27, "POST", "/api/v1/account/devices/{deviceId}/revoke", Caller.SESSION_REAUTH, false, false, 200, BodyShape.JSON, ReauthRequest::class, BodyShape.OK, null),
    REQUIRE_LINK(28, "PUT", "/api/v1/account/require-link", Caller.SESSION_REAUTH, false, false, 200, BodyShape.JSON, RequireLinkPut::class, BodyShape.OK, null),
    ACCOUNT_RECOVERY_REQUESTS(29, "GET", "/api/v1/account/recovery-requests", Caller.SESSION, false, true, 200, BodyShape.NONE, null, BodyShape.JSON, RecoveryRequestSummary::class, responseList = true),
    ACCOUNT_DELETE_PREVIEW(30, "GET", "/api/v1/account/delete/preview", Caller.SESSION, true, false, 200, BodyShape.NONE, null, BodyShape.JSON, AccountDeletePreview::class),
    ACCOUNT_DELETE(31, "POST", "/api/v1/account/delete", Caller.SESSION_REAUTH, true, false, 200, BodyShape.JSON, AccountDeleteRequest::class, BodyShape.JSON, DeletedAtResponse::class),

    // ---- recovery with the kit ----
    RECOVERY_SELF_VERIFY(32, "POST", "/api/v1/recovery/self/verify", Caller.NONE, false, false, 200, BodyShape.JSON, RecoveryVerifyRequest::class, BodyShape.JSON, RecoveryVerifyResponse::class),
    RECOVERY_SELF_COMMIT(33, "POST", "/api/v1/recovery/self/commit", Caller.NONE, true, false, 200, BodyShape.JSON, RecoveryCommitRequest::class, BodyShape.JSON, SessionResponse::class),
    RECOVERY_SELF_SETUP(34, "PUT", "/api/v1/recovery/self-setup", Caller.SESSION_REAUTH, false, false, 200, BodyShape.JSON, RecoverySelfSetupRequest::class, BodyShape.JSON, RecoverySelfSetupResponse::class),
    RECOVERY_SELF_CONFIRM(35, "POST", "/api/v1/recovery/self/confirm", Caller.SESSION, false, false, 200, BodyShape.JSON, RecoverySelfConfirmRequest::class, BodyShape.OK, null),

    // ---- sync, items, attachments, events ----
    SYNC(36, "GET", "/api/v1/sync", Caller.SESSION, true, false, 200, BodyShape.NONE, null, BodyShape.JSON, SyncResponse::class),
    PUSH(37, "POST", "/api/v1/sync/push", Caller.SESSION, true, false, 200, BodyShape.JSON, PushRequest::class, BodyShape.JSON, PushResponse::class),
    ITEM_VERSIONS(38, "GET", "/api/v1/items/{itemId}/versions", Caller.SESSION, false, false, 200, BodyShape.NONE, null, BodyShape.JSON, ItemVersionsResponse::class),
    ITEMS_DELETED(39, "GET", "/api/v1/items/deleted", Caller.SESSION, false, false, 200, BodyShape.NONE, null, BodyShape.JSON, DeletedItemsResponse::class),
    ITEM_RESTORE(40, "POST", "/api/v1/items/{itemId}/restore", Caller.SESSION, true, false, 200, BodyShape.JSON, ItemUpload::class, BodyShape.JSON, RevResponse::class),
    ITEM_PURGE(41, "POST", "/api/v1/items/{itemId}/purge", Caller.SESSION, false, false, 200, BodyShape.NONE, null, BodyShape.JSON, RevResponse::class),
    ATTACHMENT_UPLOAD(42, "POST", "/api/v1/attachments/{attachmentId}", Caller.SESSION, true, false, 200, BodyShape.BYTES, null, BodyShape.JSON, AttachmentMeta::class),
    ATTACHMENT_GET(43, "GET", "/api/v1/attachments/{attachmentId}", Caller.SESSION, false, false, 200, BodyShape.NONE, null, BodyShape.BYTES, null),
    EVENTS_TICKET(44, "POST", "/api/v1/events/ticket", Caller.SESSION, false, false, 200, BodyShape.NONE, null, BodyShape.JSON, EventsTicketResponse::class),
    EVENTS(45, "GET", "/api/v1/events", Caller.TICKET_OR_BEARER, false, false, 101, BodyShape.NONE, null, BodyShape.WEBSOCKET, EventFrame::class),

    // ---- shared vaults and the vault log ----
    LOG_APPEND(46, "POST", "/api/v1/vaults/{vaultId}/log", Caller.SESSION, true, false, 200, BodyShape.JSON, LogAppendRequest::class, BodyShape.JSON, LogAppendResponse::class),
    LOG_FETCH(47, "GET", "/api/v1/vaults/{vaultId}/log", Caller.SESSION, true, false, 200, BodyShape.NONE, null, BodyShape.JSON, LogPage::class),
    VAULT_MEMBERS(48, "GET", "/api/v1/vaults/{vaultId}/members", Caller.SESSION, true, false, 200, BodyShape.NONE, null, BodyShape.JSON, VaultMemberSummary::class, responseList = true),
    VAULTS_DELETED(49, "GET", "/api/v1/vaults/deleted", Caller.SESSION, true, false, 200, BodyShape.NONE, null, BodyShape.JSON, DeletedVaultSummary::class, responseList = true),
    VAULT_META(50, "PUT", "/api/v1/vaults/{vaultId}/meta", Caller.SESSION, true, false, 200, BodyShape.JSON, VaultMetaPut::class, BodyShape.JSON, RevResponse::class),
    VAULT_SELF_WRAP(51, "PUT", "/api/v1/vaults/{vaultId}/grant/self-wrap", Caller.SESSION, true, false, 200, BodyShape.JSON, SelfWrapPut::class, BodyShape.JSON, RevResponse::class),

    // ---- links ----
    LINK_CREATE(52, "POST", "/api/v1/links", Caller.SESSION, true, false, 201, BodyShape.JSON, LinkCreateRequest::class, BodyShape.JSON, LinkCreatedResponse::class),
    LINK_FETCH(53, "GET", "/api/v1/links/{linkId}", Caller.NONE, false, false, 200, BodyShape.NONE, null, BodyShape.JSON, LinkFetchResponse::class),
    LINK_ANSWER(54, "POST", "/api/v1/links/{linkId}/answer", Caller.SESSION, true, false, 200, BodyShape.JSON, LinkAnswerRequest::class, BodyShape.OK, null),
    LINK_REVEAL(55, "POST", "/api/v1/links/{linkId}/reveal", Caller.SESSION, true, false, 200, BodyShape.JSON, LinkRevealRequest::class, BodyShape.OK, null),
    LINK_ANSWERS(56, "GET", "/api/v1/links/answers", Caller.SESSION, true, false, 200, BodyShape.NONE, null, BodyShape.JSON, LinkAnswer::class, responseList = true),
    LINK_ACK(57, "POST", "/api/v1/links/{linkId}/ack", Caller.SESSION, true, false, 200, BodyShape.NONE, null, BodyShape.OK, null),
    LINK_REVOKE(58, "DELETE", "/api/v1/links/{linkId}", Caller.SESSION, true, false, 200, BodyShape.NONE, null, BodyShape.OK, null),

    // ---- device links ----
    DEVICE_LINK_CREATE(59, "POST", "/api/v1/device-links", Caller.SESSION, true, false, 201, BodyShape.JSON, DeviceLinkCreateRequest::class, BodyShape.JSON, LinkCreatedResponse::class),
    DEVICE_LINK_VIEW(60, "GET", "/api/v1/device-links/{linkId}", Caller.SESSION, true, false, 200, BodyShape.NONE, null, BodyShape.JSON, DeviceLinkView::class),
    DEVICE_LINK_CLAIM(61, "POST", "/api/v1/device-links/{linkId}/claim", Caller.NONE, true, false, 200, BodyShape.JSON, DeviceLinkClaim::class, BodyShape.OK, null),
    DEVICE_LINK_NONCE(62, "POST", "/api/v1/device-links/{linkId}/nonce", Caller.SESSION, true, false, 200, BodyShape.JSON, DeviceLinkNonceRequest::class, BodyShape.OK, null),
    DEVICE_LINK_POLL(63, "POST", "/api/v1/device-links/{linkId}/poll", Caller.NONE, true, false, 200, BodyShape.JSON, DeviceLinkPollRequest::class, BodyShape.JSON, DeviceLinkPollResponse::class),
    DEVICE_LINK_REVEAL(64, "POST", "/api/v1/device-links/{linkId}/reveal", Caller.NONE, true, false, 200, BodyShape.JSON, DeviceLinkRevealRequest::class, BodyShape.OK, null),
    DEVICE_LINK_APPROVE(65, "POST", "/api/v1/device-links/{linkId}/approve", Caller.SESSION, true, false, 200, BodyShape.JSON, DeviceLinkApproveRequest::class, BodyShape.OK, null),
    DEVICE_LINK_PICKUP(66, "POST", "/api/v1/device-links/{linkId}/pickup", Caller.NONE, true, false, 200, BodyShape.JSON, DeviceLinkPickupRequest::class, BodyShape.JSON, DeviceLinkPickupResponse::class),
    DEVICE_LINK_CANCEL(67, "DELETE", "/api/v1/device-links/{linkId}", Caller.SESSION, true, false, 200, BodyShape.NONE, null, BodyShape.OK, null),

    // ---- operator-assisted recovery ----
    RECOVERY_REQUEST_CREATE(68, "POST", "/api/v1/recovery/requests", Caller.NONE, false, true, 202, BodyShape.JSON, RecoveryRequestCreate::class, BodyShape.JSON, RecoveryRequestCreated::class),
    RECOVERY_REQUEST_VERIFY(69, "POST", "/api/v1/recovery/requests/{requestId}/verify", Caller.NONE, false, true, 200, BodyShape.JSON, RecoveryRequestVerify::class, BodyShape.JSON, RecoveryRequestVerified::class),
    RECOVERY_REQUEST_VETO(70, "POST", "/api/v1/recovery/requests/{requestId}/veto", Caller.SESSION, false, true, 200, BodyShape.JSON, RecoveryVetoRequest::class, BodyShape.OK, null),
    RECOVERY_REQUEST_POLL(71, "POST", "/api/v1/recovery/requests/{requestId}/poll", Caller.NONE, false, true, 200, BodyShape.JSON, RecoveryPollRequest::class, BodyShape.JSON, RecoveryPollResponse::class),
    RECOVERY_REQUEST_COMMIT(72, "POST", "/api/v1/recovery/requests/{requestId}/commit", Caller.NONE, true, true, 200, BodyShape.JSON, RecoveryRequestCommit::class, BodyShape.JSON, SessionResponse::class),

    // ---- operator ----
    ADMIN_ACCOUNTS(73, "GET", "/api/v1/admin/accounts", Caller.OPERATOR, false, false, 200, BodyShape.NONE, null, BodyShape.JSON, AccountSummary::class, responseList = true),
    ADMIN_ACCOUNT_DISABLE(74, "POST", "/api/v1/admin/accounts/{userId}/disable", Caller.OPERATOR_REAUTH, false, false, 200, BodyShape.JSON, AccountDisableRequest::class, BodyShape.OK, null),
    ADMIN_ACCOUNT_ENABLE(75, "POST", "/api/v1/admin/accounts/{userId}/enable", Caller.OPERATOR_REAUTH, false, false, 200, BodyShape.JSON, ReauthRequest::class, BodyShape.OK, null),
    ADMIN_ACCOUNT_DELETE(76, "POST", "/api/v1/admin/accounts/{userId}/delete", Caller.OPERATOR_REAUTH, false, false, 200, BodyShape.JSON, OperatorDeleteRequest::class, BodyShape.JSON, DeletedAtResponse::class),
    ADMIN_ACCOUNT_DEVICES(77, "GET", "/api/v1/admin/accounts/{userId}/devices", Caller.OPERATOR, false, false, 200, BodyShape.NONE, null, BodyShape.JSON, Device::class, responseList = true),
    ADMIN_DEVICE_REVOKE(78, "POST", "/api/v1/admin/devices/{deviceId}/revoke", Caller.OPERATOR_REAUTH, false, false, 200, BodyShape.JSON, ReauthRequest::class, BodyShape.OK, null),
    ADMIN_QUOTA(79, "PUT", "/api/v1/admin/accounts/{userId}/quota", Caller.OPERATOR_REAUTH, false, false, 200, BodyShape.JSON, QuotaPut::class, BodyShape.JSON, Quota::class),
    ADMIN_POLICY_GET(80, "GET", "/api/v1/admin/policy", Caller.OPERATOR, false, false, 200, BodyShape.NONE, null, BodyShape.JSON, AdminPolicy::class),
    ADMIN_POLICY_PUT(81, "PUT", "/api/v1/admin/policy", Caller.OPERATOR_REAUTH, false, false, 200, BodyShape.JSON, AdminPolicyPut::class, BodyShape.JSON, AdminPolicy::class),
    ADMIN_AUDIT(82, "GET", "/api/v1/admin/audit", Caller.OPERATOR, false, false, 200, BodyShape.NONE, null, BodyShape.JSON, AuditRow::class, responseList = true),
    ADMIN_STATUS(83, "GET", "/api/v1/admin/status", Caller.OPERATOR, false, false, 200, BodyShape.NONE, null, BodyShape.JSON, AdminStatus::class),
    ADMIN_RECOVERY_REQUESTS(84, "GET", "/api/v1/admin/recovery-requests", Caller.OPERATOR, false, true, 200, BodyShape.NONE, null, BodyShape.JSON, AdminRecoveryRequest::class, responseList = true),
    ADMIN_ESCROW(85, "POST", "/api/v1/admin/accounts/{userId}/escrow", Caller.OPERATOR_REAUTH, false, true, 200, BodyShape.JSON, ReauthRequest::class, BodyShape.JSON, AdminEscrowResponse::class),
    ADMIN_RECOVERY_FULFIL(86, "POST", "/api/v1/admin/recovery-requests/{requestId}/fulfil", Caller.OPERATOR_REAUTH, false, true, 200, BodyShape.JSON, RecoveryFulfilRequest::class, BodyShape.OK, null),

    // ---- misc ----
    HIBP_RANGE(87, "GET", "/api/v1/hibp/range/{prefix}", Caller.SESSION, false, false, 200, BodyShape.NONE, null, BodyShape.TEXT, null),
    HEALTHZ(88, "GET", "/healthz", Caller.NONE, false, false, 200, BodyShape.NONE, null, BodyShape.TEXT, null),
    METRICS(89, "GET", "/metrics", Caller.HOST, false, false, 200, BodyShape.NONE, null, BodyShape.TEXT, null),
    ROBOTS(90, "GET", "/robots.txt", Caller.NONE, false, false, 200, BodyShape.NONE, null, BodyShape.TEXT, null),
    DOWNLOADS_MANIFEST(91, "GET", "/downloads/manifest.json", Caller.NONE, false, false, 200, BodyShape.NONE, null, BodyShape.BYTES, null),
    DOWNLOADS_MANIFEST_SIG(91, "GET", "/downloads/manifest.json.sig", Caller.NONE, false, false, 200, BodyShape.NONE, null, BodyShape.BYTES, null),
    DOWNLOADS_FILE(91, "GET", "/downloads/{file}", Caller.NONE, false, false, 200, BodyShape.NONE, null, BodyShape.BYTES, null),
    SELFHOST(92, "GET", "/selfhost", Caller.NONE, false, false, 200, BodyShape.NONE, null, BodyShape.BYTES, null),
    SELFHOST_FILE(92, "GET", "/selfhost/{file}", Caller.NONE, false, false, 200, BodyShape.NONE, null, BodyShape.BYTES, null);

    /** True for the † routes (a fresh `currentAuthKey` in the body). */
    val reauth: Boolean get() = caller == Caller.SESSION_REAUTH || caller == Caller.OPERATOR_REAUTH

    /**
     * True for the routes whose request carries no credential (design §4.4 "No credential goes to an origin without a
     * pin in force"): the public `GET`s a first pin needs (the card chain, the client policy, a link's sealed offer) and
     * the instance's other public files. Every other route carries one, in its bearer, its body (a refresh token, an
     * email for prelogin, `authKey`, a claim, a capability) or both, and goes only to an origin whose pin is in force.
     * The client's dialer reads it from here ([io.silencelen.andvari.core.client.net.OriginGuard]); a request sent with
     * a bearer carries a credential whatever its route.
     */
    val credentialFree: Boolean get() = when (this) {
        INSTANCE, CLIENT_POLICY, LINK_FETCH, RECOVERY_PUBKEY, HEALTHZ, ROBOTS,
        DOWNLOADS_MANIFEST, DOWNLOADS_MANIFEST_SIG, DOWNLOADS_FILE, SELFHOST, SELFHOST_FILE -> true
        else -> false
    }

    /** [path] with each `{name}` replaced from [params]; a missing parameter throws. Ids are already checked by the caller. */
    fun pathWith(vararg params: Pair<String, String>): String {
        var p = path
        for ((k, v) in params) p = p.replace("{$k}", v)
        require('{' !in p) { "missing path parameter in $p" }
        return p
    }
}
