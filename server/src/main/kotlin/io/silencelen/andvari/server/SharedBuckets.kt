package io.silencelen.andvari.server

/**
 * The buckets that two or more routes draw on together. A bucket's name is its budget in the limiter, and the
 * limiter resets and limits each call by that call's own window and limit, so two definitions under one name undo
 * each other's limits. Every name is therefore defined exactly once in the server (pinned by `RateBucketNamesTest`),
 * and routes that share a budget share one of these definitions.
 */
object SharedBuckets {
    /** `totp_verify` 5/min per device: turning two-step sign-in off (row 16) and an account deletion's code (row 31). */
    val TOTP_VERIFY = Bucket.devicePerMinute("totp_verify", 5)

    /** `device_link_poll` 60/min per IP: the new device's poll and reveal (rows 63 and 64). */
    val DEVICE_LINK_POLL = Bucket.ipPerMinute("device_link_poll", 60)

    /** `vault_destructive` 10/h per device: the log's `offer`, `delete` and `remove` (§10.5) and the rename (row 50). */
    val VAULT_DESTRUCTIVE = Bucket.devicePerHour("vault_destructive", 10)

    /** `recovery_commit` 5/min per IP: the kit's commit (row 33) and the assisted commit (row 72). */
    val RECOVERY_COMMIT = Bucket.ipPerMinute("recovery_commit", 5)

    /** `login` per IP at the configured rate: sign-in (row 10) and device-link pickup (row 66). */
    fun login(config: Config): Bucket = Bucket.ipPerMinute("login", config.loginRatePerMin)
}
