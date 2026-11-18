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

/**
 * Highest [VaultContent.schemaVersion] this build can read and write. Format v2 files carry schema version 2 and
 * nothing else is accepted when a file is opened.
 */
const val SUPPORTED_SCHEMA_VERSION: Int = 2

/** Largest revision number (content and record) that is accepted: 2^53 - 1, so it survives a JSON double. */
const val MAX_REVISION: Long = (1L shl 53) - 1

/**
 * Largest increase of the content revision that sync accepts from one remote file compared with the highest revision
 * this device has already seen (2^20). An honest device adds one per edit and one per merge, so a larger jump is a
 * sign of a buggy or hostile writer trying to push the vault to [MAX_REVISION], where it could not be edited again.
 */
const val MAX_REVISION_JUMP: Long = 1L shl 20

/**
 * Revisions above `MAX_REVISION - REVISION_HEADROOM` are never accepted from a remote file, whatever the floor is
 * (a fresh device has no floor to compare with). 2^32 leaves room for 4 billion further edits.
 */
const val REVISION_HEADROOM: Long = 1L shl 32

/** The next revision after [current], failing instead of overflowing. */
internal fun nextRevision(current: Long): Long {
    if (current < 0L || current >= MAX_REVISION) {
        throw VaultException.InvalidContent("revision limit reached")
    }
    return current + 1L
}

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
    /**
     * Checks the structural rules that every content must satisfy, whether it was decoded from a file or built
     * locally: revisions in `[0, 2^53 - 1]` (records from 1), unique non-empty ids of at most [MAX_ID_CHARS]
     * characters, at most [MAX_RECORDS] records and [MAX_HISTORY] history entries, bounded payload size, no id
     * that is used with two different record types, and no record (or history entry) whose revision is above the
     * content revision (honest writers always satisfy it; it stops one record from carrying the vault to the
     * revision limit on its own).
     *
     * @throws VaultException.InvalidContent on the first violation (the message never contains record data)
     */
    fun validate() {
        if (vaultId.isEmpty() || vaultId.length > MAX_ID_CHARS) throw VaultException.InvalidContent("vault id")
        if (revision !in 0L..MAX_REVISION) throw VaultException.InvalidContent("content revision out of range")
        if (records.size > MAX_RECORDS) throw VaultException.InvalidContent("too many records")
        if (history.size > MAX_HISTORY) throw VaultException.InvalidContent("history too long")
        val typeById = HashMap<String, String>(records.size * 2 + 1)
        for (r in records) {
            validateRecord(r)
            if (typeById.put(r.id, r.wireTypeName) != null) throw VaultException.InvalidContent("duplicate record id")
        }
        for (h in history) {
            validateRecord(h)
            val type = typeById[h.id]
            if (type != null && type != h.wireTypeName) {
                throw VaultException.InvalidContent("a record id is used with two types")
            }
        }
    }

    private fun validateRecord(r: VaultRecord) {
        if (r.id.isEmpty() || r.id.length > MAX_ID_CHARS) throw VaultException.InvalidContent("record id length")
        if (r.deviceId.isEmpty() || r.deviceId.length > MAX_ID_CHARS) {
            throw VaultException.InvalidContent("device id length")
        }
        if (r.revision !in 1L..MAX_REVISION) throw VaultException.InvalidContent("record revision out of range")
        if (r.revision > revision) throw VaultException.InvalidContent("record revision above the content revision")
        if (recordSize(r) > MAX_PAYLOAD_CHARS) throw VaultException.InvalidContent("record too large")
    }

    companion object {
        const val MAX_HISTORY: Int = 200
        const val MAX_RECORDS: Int = 10_000
        const val MAX_ID_CHARS: Int = 128

        /** Largest accepted size of one record's payload plus unknown fields, in JSON characters. */
        const val MAX_PAYLOAD_CHARS: Int = 256 * 1024

        /** Approximate serialised size of a record's variable parts, in characters. */
        internal fun recordSize(r: VaultRecord): Int = r.payload.toString().length + r.extra.toString().length

        fun empty(vaultId: String): VaultContent =
            VaultContent(schemaVersion = SUPPORTED_SCHEMA_VERSION, vaultId = vaultId, revision = 0L)
    }
}
