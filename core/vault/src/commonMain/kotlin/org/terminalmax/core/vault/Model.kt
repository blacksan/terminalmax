// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.vault

import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long

/** Highest [VaultContent.schemaVersion] this build can read and write. */
const val SUPPORTED_SCHEMA_VERSION: Int = 1

/**
 * Record kinds. [Unknown] stands for any type written by a newer app version; the original name is kept
 * in [VaultRecord.unknownTypeName] so the record round-trips unchanged.
 */
enum class RecordType {
    Host, Identity, PrivateKey, WireGuardProfile, KnownHost, Snippet, Settings, Unknown;

    companion object {
        fun fromWireName(name: String): RecordType =
            entries.firstOrNull { it != Unknown && it.name == name } ?: Unknown
    }
}

/**
 * One vault entry. The ordering of versions of a record is (revision, deviceId) only; [updatedAtEpochMs] is
 * informational and never used for ordering.
 *
 * [payload] is kept as raw JSON so unknown fields from newer versions are never dropped; [extra] keeps unknown
 * record-level fields for the same reason.
 */
@kotlinx.serialization.Serializable(with = VaultRecordSerializer::class)
data class VaultRecord(
    val id: String,
    val type: RecordType,
    val revision: Long,
    val deviceId: String,
    val updatedAtEpochMs: Long,
    val deleted: Boolean,
    val payload: JsonObject,
    val unknownTypeName: String? = null,
    val extra: JsonObject = JsonObject(emptyMap()),
) {
    /** The type name exactly as stored in the file. */
    val wireTypeName: String
        get() = if (type == RecordType.Unknown) unknownTypeName ?: RecordType.Unknown.name else type.name
}

/** Total order on record versions: revision first, then lexicographically larger deviceId wins ties. */
internal fun compareVersions(a: VaultRecord, b: VaultRecord): Int {
    val byRevision = a.revision.compareTo(b.revision)
    return if (byRevision != 0) byRevision else a.deviceId.compareTo(b.deviceId)
}

object VaultRecordSerializer : KSerializer<VaultRecord> {
    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("org.terminalmax.core.vault.VaultRecord")

    private val knownKeys = setOf("id", "type", "revision", "deviceId", "updatedAtEpochMs", "deleted", "payload")

    override fun serialize(encoder: Encoder, value: VaultRecord) {
        val jsonEncoder = encoder as? JsonEncoder ?: throw SerializationException("VaultRecord supports JSON only")
        val out = LinkedHashMap<String, JsonElement>()
        out["id"] = JsonPrimitive(value.id)
        out["type"] = JsonPrimitive(value.wireTypeName)
        out["revision"] = JsonPrimitive(value.revision)
        out["deviceId"] = JsonPrimitive(value.deviceId)
        out["updatedAtEpochMs"] = JsonPrimitive(value.updatedAtEpochMs)
        out["deleted"] = JsonPrimitive(value.deleted)
        out["payload"] = value.payload
        for ((k, v) in value.extra) {
            if (k !in knownKeys) out[k] = v
        }
        jsonEncoder.encodeJsonElement(JsonObject(out))
    }

    override fun deserialize(decoder: Decoder): VaultRecord {
        val jsonDecoder = decoder as? JsonDecoder ?: throw SerializationException("VaultRecord supports JSON only")
        val obj = jsonDecoder.decodeJsonElement().jsonObject
        fun field(name: String): JsonElement =
            obj[name] ?: throw SerializationException("Record is missing '$name'")

        val typeName = field("type").jsonPrimitive.content
        val type = RecordType.fromWireName(typeName)
        val extra = LinkedHashMap<String, JsonElement>()
        for ((k, v) in obj) {
            if (k !in knownKeys) extra[k] = v
        }
        return VaultRecord(
            id = field("id").jsonPrimitive.content,
            type = type,
            revision = field("revision").jsonPrimitive.long,
            deviceId = field("deviceId").jsonPrimitive.content,
            updatedAtEpochMs = obj["updatedAtEpochMs"]?.jsonPrimitive?.long ?: 0L,
            deleted = obj["deleted"]?.jsonPrimitive?.boolean ?: false,
            payload = obj["payload"]?.jsonObject ?: JsonObject(emptyMap()),
            unknownTypeName = if (type == RecordType.Unknown) typeName else null,
            extra = JsonObject(extra),
        )
    }
}

/**
 * Decrypted vault content.
 *
 * @property revision monotonic content revision (bumped by every edit and by merges that change the remote).
 * @property history losing sides of conflicts, capped at [MAX_HISTORY] (oldest dropped).
 */
@kotlinx.serialization.Serializable
data class VaultContent(
    val schemaVersion: Int,
    val vaultId: String,
    val revision: Long,
    val records: List<VaultRecord> = emptyList(),
    val history: List<VaultRecord> = emptyList(),
) {
    companion object {
        const val MAX_HISTORY: Int = 200

        fun empty(vaultId: String): VaultContent =
            VaultContent(schemaVersion = SUPPORTED_SCHEMA_VERSION, vaultId = vaultId, revision = 0L)
    }
}
