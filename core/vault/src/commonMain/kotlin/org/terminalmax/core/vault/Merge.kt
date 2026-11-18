// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.vault

/** A record that was changed on both sides; [loser] was moved to the history of the merged vault. */
data class Conflict(val recordId: String, val winner: VaultRecord, val loser: VaultRecord)

/**
 * @property changedLocally the merged content differs from the local content (a pull is needed)
 * @property changedRemotely the merged content differs from the remote content (a push is needed)
 */
data class MergeResult(
    val merged: VaultContent,
    val conflicts: List<Conflict>,
    val changedLocally: Boolean,
    val changedRemotely: Boolean,
)

private val versionComparator = Comparator<VaultRecord> { a, b ->
    val byVersion = compareVersions(a, b)
    if (byVersion != 0) byVersion else VaultJson.json.encodeToString(VaultRecord.serializer(), a)
        .compareTo(VaultJson.json.encodeToString(VaultRecord.serializer(), b))
}

private val historyComparator = Comparator<VaultRecord> { a, b ->
    val byVersion = compareVersions(a, b)
    when {
        byVersion != 0 -> byVersion
        a.id != b.id -> a.id.compareTo(b.id)
        else -> VaultJson.json.encodeToString(VaultRecord.serializer(), a)
            .compareTo(VaultJson.json.encodeToString(VaultRecord.serializer(), b))
    }
}

private fun normalizeHistory(records: Collection<VaultRecord>): List<VaultRecord> =
    records.toSet().sortedWith(historyComparator).takeLast(VaultContent.MAX_HISTORY)

private fun sameRecords(a: List<VaultRecord>, b: List<VaultRecord>): Boolean =
    a.size == b.size && a.associateBy { it.id } == b.associateBy { it.id }

/**
 * Three-way merge of two vault contents.
 *
 * Per record id: versions are ordered by (revision, deviceId) only, never by wall-clock time. A record changed on
 * one side since [base] takes that side; changed on both sides, the higher version wins (ties: larger deviceId, then
 * larger canonical JSON so the result is fully deterministic), the loser goes to history and is reported as a
 * [Conflict]. Tombstones are ordinary records. Records are never dropped, so a record missing on one side is
 * taken from the other. With `base == null` this is a two-way merge by the same ordering; the loser is still kept
 * in history, but it is only reported as a conflict when both versions carry the same revision (otherwise the
 * lower one is most likely an ancestor).
 *
 * The record set is commutative: `mergeVaults(b, l, r)` and `mergeVaults(b, r, l)` produce the same records and
 * history. [localDeviceId] is reserved for attribution and does not influence the result.
 *
 * @throws VaultException.DifferentVault when vault ids differ
 * @throws VaultException.UnsupportedVersion when any input uses a newer schema than this build understands
 */
@Suppress("UNUSED_PARAMETER")
fun mergeVaults(base: VaultContent?, local: VaultContent, remote: VaultContent, localDeviceId: String): MergeResult {
    for (c in listOfNotNull(base, local, remote)) {
        if (c.schemaVersion > SUPPORTED_SCHEMA_VERSION) {
            throw VaultException.UnsupportedVersion(c.schemaVersion, SUPPORTED_SCHEMA_VERSION)
        }
    }
    if (local.vaultId != remote.vaultId || (base != null && base.vaultId != local.vaultId)) {
        throw VaultException.DifferentVault()
    }

    val baseById = base?.records?.associateBy { it.id } ?: emptyMap()
    val localById = local.records.associateBy { it.id }
    val remoteById = remote.records.associateBy { it.id }
    val ids = (localById.keys + remoteById.keys).toSet().sorted()

    val mergedRecords = ArrayList<VaultRecord>(ids.size)
    val conflicts = ArrayList<Conflict>()
    val losers = ArrayList<VaultRecord>()

    for (id in ids) {
        val l = localById[id]
        val r = remoteById[id]
        val b = baseById[id]
        when {
            l == null -> mergedRecords += r!!
            r == null -> mergedRecords += l
            l == r -> mergedRecords += l
            base != null && b != null && l == b -> mergedRecords += r // only remote changed
            base != null && b != null && r == b -> mergedRecords += l // only local changed
            else -> {
                val winner = if (versionComparator.compare(l, r) >= 0) l else r
                val loser = if (winner === l) r else l
                mergedRecords += winner
                losers += loser
                val concurrent = base != null || l.revision == r.revision
                if (concurrent) conflicts += Conflict(id, winner, loser)
            }
        }
    }

    val mergedHistory = normalizeHistory(local.history + remote.history + losers)

    val changedLocally = !sameRecords(mergedRecords, local.records) ||
        mergedHistory != normalizeHistory(local.history)
    val changedRemotely = !sameRecords(mergedRecords, remote.records) ||
        mergedHistory != normalizeHistory(remote.history)

    val revision = if (changedRemotely) maxOf(local.revision, remote.revision) + 1 else remote.revision
    val merged = VaultContent(
        schemaVersion = maxOf(local.schemaVersion, remote.schemaVersion),
        vaultId = local.vaultId,
        revision = revision,
        records = mergedRecords,
        history = mergedHistory,
    )
    return MergeResult(merged, conflicts, changedLocally, changedRemotely)
}

/**
 * Removes tombstones whose record revision is below [olderThanRevision]. Not used in v1: tombstones are kept
 * forever until a safe garbage-collection protocol exists (a pruned tombstone could resurrect a deleted record
 * from a device that has not synced since).
 */
fun pruneTombstones(content: VaultContent, olderThanRevision: Long): VaultContent =
    content.copy(records = content.records.filterNot { it.deleted && it.revision < olderThanRevision })
