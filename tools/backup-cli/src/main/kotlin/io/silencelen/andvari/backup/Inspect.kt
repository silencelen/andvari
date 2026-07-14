package io.silencelen.andvari.backup

import io.silencelen.andvari.core.client.Backup
import io.silencelen.andvari.core.client.BackupAttachmentEntry
import io.silencelen.andvari.core.client.BackupException
import io.silencelen.andvari.core.client.BackupPayload
import io.silencelen.andvari.core.crypto.CryptoProvider
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.io.File

/**
 * spec 07 §3 — the offline reader of record for `.andvari` backups, built on the :core
 * reference impl ([Backup.open]). OFFLINE like everything here: input is a file, no
 * network (enforced by the classpath-guard test), nothing written except by `extract`.
 * All logic lives in this object so tests drive it directly; Main.kt only does IO.
 */

/** One manifest entry's verification outcome (tag checked via [Backup.OpenedBackup.readAttachment]). */
data class AttachmentCheck(
    val entry: BackupAttachmentEntry,
    /** Owning item's name, or the itemId if the manifest points at no item in the file. */
    val itemName: String,
    val pass: Boolean,
    val detail: String,
)

data class VerifyReport(
    val opened: Backup.OpenedBackup,
    /** Display label → item count, declared vaults first (0-count vaults included),
     *  then any vaultId that items reference but `vaults[]` never declared. */
    val itemsPerVault: List<Pair<String, Int>>,
    val checks: List<AttachmentCheck>,
    /** Non-null when the file's section count disagrees with the manifest (extra
     *  unlisted sections — a section the manifest can't vouch for). */
    val framingMismatch: String?,
) {
    val pass: Boolean get() = framingMismatch == null && checks.all { it.pass }
}

object BackupInspect {
    /** The standard item Json config (mirrors Backup/Account) — dump must render docs
     *  through the exact serializers the vault uses, unknown-field overlay included. */
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    private val pretty = Json { prettyPrint = true }

    /**
     * `verify`: [Backup.open] (the full §2.2 validation ladder + section-0 AEAD), then
     * check EVERY manifest entry's attachment section — tag via readAttachment, plus a
     * plaintext-size-vs-manifest cross-check — and that the file carries no attachment
     * sections the manifest doesn't list. Open failures propagate as [BackupException]
     * with the spec error code; per-attachment failures are collected, never fatal, so
     * the summary names everything that is wrong in one pass.
     */
    fun verify(crypto: CryptoProvider, passphrase: String, file: ByteArray): VerifyReport {
        val opened = Backup.open(crypto, passphrase, file)
        val payload = opened.payload

        val byVault = payload.items.groupingBy { it.vaultId }.eachCount()
        val declared = payload.vaults.map { it.vaultId }.toSet()
        val itemsPerVault = payload.vaults.map { v ->
            "${v.name} (${v.type}, ${v.role})" to (byVault[v.vaultId] ?: 0)
        } + byVault.filterKeys { it !in declared }.map { (vaultId, n) ->
            "$vaultId (not declared in vaults[])" to n
        }

        val checks = payload.attachments.map { entry ->
            val itemName = itemName(payload, entry.itemId)
            try {
                val plain = opened.readAttachment(entry)
                val size = plain.size.toLong()
                plain.fill(0) // verify never keeps plaintext
                if (size == entry.size) {
                    AttachmentCheck(entry, itemName, true, "tag ok, $size bytes")
                } else {
                    AttachmentCheck(entry, itemName, false, "decrypts, but $size bytes != manifest size ${entry.size}")
                }
            } catch (e: BackupException) {
                AttachmentCheck(entry, itemName, false, "${e.code}: ${e.message}")
            }
        }

        val framingMismatch = if (opened.attachmentSectionCount != payload.attachments.size) {
            "file has ${opened.attachmentSectionCount} attachment section(s) but the manifest lists ${payload.attachments.size}"
        } else {
            null
        }
        return VerifyReport(opened, itemsPerVault, checks, framingMismatch)
    }

    /**
     * `dump`: the authenticated payload as pretty JSON. Secrets are REDACTED unless
     * [secrets] — see [Redact] for exactly what masks (the file's owner may need the raw
     * values for actual recovery, hence the flag).
     */
    fun dumpJson(payload: BackupPayload, secrets: Boolean): String {
        val tree = json.encodeToJsonElement(BackupPayload.serializer(), payload)
        return pretty.encodeToString(JsonElement.serializer(), if (secrets) tree else Redact.tree(tree))
    }

    // ---- extract ----

    data class ExtractedFile(val file: File, val bytes: Long)

    /**
     * `extract`: write each embedded attachment to `outDir/<itemName>-<attachmentName>`
     * (names sanitized — path separators and control chars become `_`, so nothing can
     * escape [outDir]). Targets are PRE-FLIGHTED before any byte is written: an existing
     * file or two entries mapping to the same name refuses the whole extract — this tool
     * never overwrites anything.
     */
    fun extract(opened: Backup.OpenedBackup, outDir: File): List<ExtractedFile> {
        val entries = opened.payload.attachments
        if (entries.isEmpty()) return emptyList()
        if (!outDir.isDirectory && !outDir.mkdirs()) {
            throw IllegalStateException("cannot create output directory $outDir")
        }

        // Pre-flight every target so a refusal happens before ANY write.
        val seen = HashSet<String>()
        val planned = entries.map { entry ->
            val name = sanitizeFileName("${itemName(opened.payload, entry.itemId)}-${entry.name}")
            if (!seen.add(name)) {
                throw IllegalStateException("two attachments map to the same output name '$name' — extract to an empty directory per run")
            }
            val target = File(outDir, name)
            if (target.exists()) {
                throw IllegalStateException("refusing to overwrite existing file $target")
            }
            // Belt-and-braces: sanitized names contain no separators, so this cannot fire.
            check(target.canonicalFile.parentFile == outDir.canonicalFile) { "sanitized name escaped $outDir" }
            entry to target
        }

        return planned.map { (entry, target) ->
            val plain = opened.readAttachment(entry) // BackupException (spec code) propagates
            try {
                target.writeBytes(plain)
            } finally {
                plain.fill(0)
            }
            ExtractedFile(target, entry.size)
        }
    }

    /** `/`, `\` and control chars → `_`; blank or dots-only results get a safe stand-in.
     *  Everything else (spaces, unicode, leading dots within a composite name) is kept —
     *  the output must stay recognizable next to the item it came from. */
    fun sanitizeFileName(raw: String): String {
        val cleaned = buildString(raw.length) {
            for (c in raw) append(if (c == '/' || c == '\\' || c.code < 0x20 || c.code == 0x7F) '_' else c)
        }
        return if (cleaned.isBlank() || cleaned.all { it == '.' }) "unnamed-attachment" else cleaned
    }

    private fun itemName(payload: BackupPayload, itemId: String): String =
        payload.items.firstOrNull { it.itemId == itemId }?.doc?.name ?: itemId
}

/**
 * Dump redaction (spec 07 §3 tooling posture: the payload holds every password in
 * plaintext, so the DEFAULT output must be safe to scroll on a shared screen or paste
 * into a ticket). Masking is by KEY NAME over the serialized JSON tree — `password`
 * (items and passwordHistory alike), `totp`, `fileKey` (doc refs AND the section
 * manifest), plus card PAN (`number`) + CVV (`securityCode`) and note bodies (`notes`,
 * where login items also stash 2FA backup codes) — so same-named keys inside preserved
 * unknown-field extras are masked too (fail-safe). JSON `null` stays `null`: "no
 * password" must remain distinguishable from "a password you can't see".
 */
object Redact {
    // number/securityCode/notes were MISSING: the old set silently leaked full card numbers + CVV and
    // every secure-note body in cleartext from the "safe to share" default, contradicting the CLI's promise.
    val SECRET_KEYS = setOf("password", "totp", "fileKey", "number", "securityCode", "notes")
    const val MASK = "•••"

    fun tree(element: JsonElement): JsonElement = when (element) {
        is JsonObject -> JsonObject(
            element.entries.associate { (key, value) ->
                key to if (key in SECRET_KEYS && value is JsonPrimitive && value !is JsonNull) {
                    JsonPrimitive(MASK)
                } else {
                    tree(value)
                }
            },
        )
        is JsonArray -> JsonArray(element.map(::tree))
        is JsonPrimitive -> element
    }
}
