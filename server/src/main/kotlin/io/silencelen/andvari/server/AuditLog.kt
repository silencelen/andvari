package io.silencelen.andvari.server

import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.slf4j.LoggerFactory

/**
 * Structured audit trail to stdout (→ journald → Alloy → Loki). One JSON object per
 * line under the "andvari.audit" logger; DB copy (audit table) feeds the admin API.
 * NEVER log secret material — types + ids + coarse metadata only (spec 02 §5).
 */
object AuditLog {
    private val logger = LoggerFactory.getLogger("andvari.audit")

    fun log(type: String, userId: String?, deviceId: String?, ip: String?, meta: String?) {
        val line = buildJsonObject {
            put("audit", true)
            put("type", type)
            if (userId != null) put("userId", userId)
            if (deviceId != null) put("deviceId", deviceId)
            if (ip != null) put("ip", ip)
            if (meta != null) put("meta", meta)
        }
        logger.info(line.toString())
    }
}
