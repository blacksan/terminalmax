// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.vault

import kotlin.random.Random
import kotlinx.serialization.json.JsonObject

/**
 * Applies edits to a [VaultContent]. A new record revision is `max(record revision, content revision) + 1` (a
 * Lamport rule: an edit made after seeing more history always outranks what it saw), the content revision follows,
 * and neither can overflow: at the revision limit an edit fails with [VaultException.InvalidContent].
 *
 * @param clock source of the informational `updatedAtEpochMs` stamp (pass `System::currentTimeMillis`);
 *   it is never used for ordering.
 * @param newId generator for new record ids (random UUID v4 by default).
 * @param revisionFloor the highest revision this device has ever synced; new revisions are above it even when
 *   [content] is older (a crash or a second process can leave the local content behind the sync state). Without
 *   it such an edit would be ranked below a version that is already on the server.
 */
class VaultEditor(
    content: VaultContent,
    private val deviceId: String,
    private val clock: () -> Long = { 0L },
    private val newId: () -> String = { randomUuidV4() },
    private val revisionFloor: Long = 0L,
) {
    init {
        require(deviceId.isNotEmpty() && deviceId.length <= VaultContent.MAX_ID_CHARS) { "Invalid device id" }
    }

    var content: VaultContent = content
        private set

    /**
     * Creates or updates a record. [payload] replaces the stored payload completely; use the typed `upsert*`
     * helpers to keep unknown fields written by newer versions.
     *
     * @throws IllegalArgumentException when [id] exists with a different type
     */
    fun upsert(type: RecordType, id: String? = null, payload: JsonObject): VaultRecord {
        val recordId = id ?: newId()
        require(recordId.isNotEmpty() && recordId.length <= VaultContent.MAX_ID_CHARS) { "Invalid record id" }
        val existing = content.records.firstOrNull { it.id == recordId }
        require(existing == null || existing.type == type) { "Record type cannot change" }
        val updated = VaultRecord(
            id = recordId,
            type = type,
            revision = nextRevision(maxOf(existing?.revision ?: 0L, content.revision, revisionFloor)),
            deviceId = deviceId,
            updatedAtEpochMs = clock(),
            deleted = false,
            payload = payload,
            unknownTypeName = existing?.unknownTypeName,
            extra = existing?.extra ?: VaultJson.emptyObject,
        )
        store(updated)
        return updated
    }

    fun upsertHost(host: HostPayload, id: String? = null): VaultRecord =
        upsertTyped(RecordType.Host, id, Payloads.toJson(host))

    fun upsertIdentity(identity: IdentityPayload, id: String? = null): VaultRecord =
        upsertTyped(RecordType.Identity, id, Payloads.toJson(identity))

    fun upsertPrivateKey(key: PrivateKeyPayload, id: String? = null): VaultRecord =
        upsertTyped(RecordType.PrivateKey, id, Payloads.toJson(key))

    fun upsertWireGuardProfile(profile: WireGuardProfilePayload, id: String? = null): VaultRecord =
        upsertTyped(RecordType.WireGuardProfile, id, Payloads.toJson(profile))

    fun upsertKnownHost(knownHost: KnownHostPayload, id: String? = null): VaultRecord =
        upsertTyped(RecordType.KnownHost, id, Payloads.toJson(knownHost))

    fun upsertSnippet(snippet: SnippetPayload, id: String? = null): VaultRecord =
        upsertTyped(RecordType.Snippet, id, Payloads.toJson(snippet))

    /** Typed update that keeps payload fields the typed class does not know about (written by newer versions). */
    private fun upsertTyped(type: RecordType, id: String?, typed: JsonObject): VaultRecord {
        val existing = id?.let { wanted -> content.records.firstOrNull { it.id == wanted } }
        if (existing == null) return upsert(type, id, typed)
        val known = Payloads.knownKeys(type)
        val merged = LinkedHashMap<String, kotlinx.serialization.json.JsonElement>()
        for ((k, v) in existing.payload) if (k !in known) merged[k] = v
        merged.putAll(typed)
        return upsert(type, id, JsonObject(merged))
    }

    /**
     * Writes a tombstone for [id] (payload and unknown record-level fields cleared so no secrets remain in the record). Returns null if the id
     * is unknown. Deleting an already deleted record is a no-op returning the existing tombstone.
     */
    fun delete(id: String): VaultRecord? {
        val existing = content.records.firstOrNull { it.id == id } ?: return null
        if (existing.deleted) return existing
        val tombstone = existing.copy(
            revision = nextRevision(maxOf(existing.revision, content.revision, revisionFloor)),
            deviceId = deviceId,
            updatedAtEpochMs = clock(),
            deleted = true,
            payload = VaultJson.emptyObject,
            extra = VaultJson.emptyObject, // unknown record-level fields of newer versions may hold secrets too
        )
        store(tombstone)
        // The last live version stays in the history for the restore window (see mergeVaults), exactly as a merge
        // would leave it: the first sync of a plain delete is then not reported as a merge.
        content = content.copy(history = normalizeHistory(content.history.filterNot { it.id == id } + existing))
        return tombstone
    }

    /**
     * Brings a deleted record back from [version], one of its older live versions (kept in the vault history for a
     * while after a deletion, see `mergeVaults`). The result is a **new** version of this device above everything seen
     * (so it outranks the tombstone and replicates like any edit). Returns null when the record does not exist, is
     * not deleted, or [version] is not a live version of it.
     */
    fun restore(version: VaultRecord): VaultRecord? {
        val existing = content.records.firstOrNull { it.id == version.id } ?: return null
        if (!existing.deleted || version.deleted || existing.wireTypeName != version.wireTypeName) return null
        val restored = version.copy(
            revision = nextRevision(maxOf(existing.revision, content.revision, revisionFloor)),
            deviceId = deviceId,
            updatedAtEpochMs = clock(),
            deleted = false,
        )
        store(restored)
        return restored
    }

    private fun store(record: VaultRecord) {
        val others = content.records.filterNot { it.id == record.id }
        content = content.copy(
            revision = maxOf(nextRevision(content.revision), record.revision),
            records = others + record,
        )
    }
}

/** Random (version 4) UUID string. Not a secret; used for record and vault identifiers only. */
fun randomUuidV4(random: Random = Random.Default): String {
    val b = random.nextBytes(16)
    b[6] = ((b[6].toInt() and 0x0f) or 0x40).toByte()
    b[8] = ((b[8].toInt() and 0x3f) or 0x80).toByte()
    val hex = b.joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
    return hex.substring(0, 8) + "-" + hex.substring(8, 12) + "-" + hex.substring(12, 16) + "-" +
        hex.substring(16, 20) + "-" + hex.substring(20, 32)
}
