// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.vault

/** A record that was changed on both sides; [loser] was moved to the history of the merged vault. */
data class Conflict(val recordId: String, val winner: VaultRecord, val loser: VaultRecord)

/** Which input of a merge carried the stale version. */
enum class MergeSide { Local, Remote }

/**
 * One side presented an older version of a record than the other side (or than the common base) already had, even
 * though it did not change that record itself: the signature of a replayed or stale file. The merge keeps [kept] and
 * never applies the stale input. [ignored] is null when the stale side lacks the record altogether.
 */
data class Regression(
    val recordId: String,
    val kept: VaultRecord,
    val ignored: VaultRecord?,
    val ignoredSide: MergeSide,
)

/**
 * @property regressions stale inputs that were ignored (see [Regression]); a non-empty list with
 *   [MergeSide.Remote] means the server served something older than this device already knew
 * @property changedLocally the merged content differs from the local content (a pull is needed)
 * @property changedRemotely the merged content differs from the remote content (a push is needed)
 */
data class MergeResult(
    val merged: VaultContent,
    val conflicts: List<Conflict>,
    val regressions: List<Regression>,
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

/** Upper bound on the summed size of all history entries (characters of payload JSON); oldest entries go first. */
private const val MAX_HISTORY_CHARS = 1024 * 1024

private fun normalizeHistory(records: Collection<VaultRecord>): List<VaultRecord> {
    val sorted = records.toSet().sortedWith(historyComparator).takeLast(VaultContent.MAX_HISTORY)
    var total = 0L
    for (r in sorted) total += VaultContent.recordSize(r)
    if (total <= MAX_HISTORY_CHARS) return sorted
    var start = 0
    while (start < sorted.size && total > MAX_HISTORY_CHARS) {
        total -= VaultContent.recordSize(sorted[start])
        start++
    }
    return sorted.subList(start, sorted.size).toList()
}

private fun sameRecords(a: List<VaultRecord>, b: List<VaultRecord>): Boolean =
    a.size == b.size && a.associateBy { it.id } == b.associateBy { it.id }

/**
 * Merge of two vault contents, optionally classified against a common [base].
 *
 * Per record id the result is the **maximum** under the total order (revision, deviceId, canonical JSON), i.e. a
 * pure join: commutative, associative and idempotent, and wall-clock time is never used. The base never selects a
 * lower version; it is only used to classify what happened:
 *  - the lower version is the base version (an ordinary fast-forward): nothing is reported;
 *  - the lower version is older than the base version: a [Regression] (a stale or replayed input), even when the
 *    other side changed the record meanwhile; the stale version is not kept in history;
 *  - both sides changed the record (or there is no base and both carry the same revision): a [Conflict], and the
 *    loser is kept in `history`;
 *  - the lower version is not the base version although that side did not change the record: a [Regression], the
 *    sign of a stale or replayed input. It is healed (the higher version wins) and never applied;
 *  - one id with two record types is always reported as a [Conflict] and the loser is kept in `history`.
 *
 * Secrets are scrubbed from history: when the merged record is a tombstone, every history entry of that id with a
 * revision up to the tombstone's is dropped. History is capped at [VaultContent.MAX_HISTORY] entries and about 1 MiB.
 *
 * [localDeviceId] is reserved for attribution and does not influence the result. All inputs are validated.
 *
 * @throws VaultException.DifferentVault when vault ids differ
 * @throws VaultException.UnsupportedVersion when any input uses a newer schema than this build understands
 * @throws VaultException.InvalidContent when an input violates the content rules
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
    base?.validate()
    local.validate()
    remote.validate()

    val baseById = base?.records?.associateBy { it.id } ?: emptyMap()
    val localById = local.records.associateBy { it.id }
    val remoteById = remote.records.associateBy { it.id }
    val ids = (localById.keys + remoteById.keys).toSet().sorted()

    val mergedRecords = ArrayList<VaultRecord>(ids.size)
    val conflicts = ArrayList<Conflict>()
    val regressions = ArrayList<Regression>()
    val losers = ArrayList<VaultRecord>()

    for (id in ids) {
        val l = localById[id]
        val r = remoteById[id]
        val b = baseById[id]
        when {
            l == null -> {
                mergedRecords += r!!
                if (b != null) regressions += Regression(id, kept = r, ignored = null, ignoredSide = MergeSide.Local)
            }
            r == null -> {
                mergedRecords += l
                if (b != null) regressions += Regression(id, kept = l, ignored = null, ignoredSide = MergeSide.Remote)
            }
            l == r -> mergedRecords += l
            else -> {
                val winner = if (versionComparator.compare(l, r) >= 0) l else r
                val loser = if (winner === l) r else l
                mergedRecords += winner
                val loserIsBase = b != null && loser == b
                // A loser that is older than the base is a stale or replayed version, whether or not its side
                // "changed" the record: it is reported as a regression and not kept (it was history long ago).
                val loserBelowBase = b != null && !loserIsBase && versionComparator.compare(loser, b) < 0
                if (!loserIsBase && !loserBelowBase) losers += loser
                val bothChanged = b == null || (l != b && r != b)
                val typeClash = l.wireTypeName != r.wireTypeName
                when {
                    typeClash -> conflicts += Conflict(id, winner, loser)
                    loserBelowBase -> regressions += Regression(
                        id,
                        kept = winner,
                        ignored = loser,
                        ignoredSide = if (loser === r) MergeSide.Remote else MergeSide.Local,
                    )
                    bothChanged && (base != null || l.revision == r.revision) -> conflicts += Conflict(id, winner, loser)
                    !bothChanged && !loserIsBase -> regressions += Regression(
                        id,
                        kept = winner,
                        ignored = loser,
                        ignoredSide = if (loser === r) MergeSide.Remote else MergeSide.Local,
                    )
                }
            }
        }
    }

    val current = HashMap<String, VaultRecord>(mergedRecords.size * 2 + 1)
    for (rec in mergedRecords) current[rec.id] = rec
    val mergedHistory = normalizeHistory(
        (local.history + remote.history + losers).filterNot { h ->
            val cur = current[h.id]
            cur != null && cur.deleted && h.revision <= cur.revision
        },
    )

    val changedLocally = !sameRecords(mergedRecords, local.records) ||
        mergedHistory != normalizeHistory(local.history)
    val changedRemotely = !sameRecords(mergedRecords, remote.records) ||
        mergedHistory != normalizeHistory(remote.history)

    val revision = if (changedRemotely) nextRevision(maxOf(local.revision, remote.revision)) else remote.revision
    val merged = VaultContent(
        schemaVersion = maxOf(local.schemaVersion, remote.schemaVersion),
        vaultId = local.vaultId,
        revision = revision,
        records = mergedRecords,
        history = mergedHistory,
    )
    return MergeResult(merged, conflicts, regressions, changedLocally, changedRemotely)
}

/**
 * Removes tombstones whose record revision is below [olderThanRevision]. Not used: tombstones are kept forever until
 * a safe garbage-collection protocol exists (a pruned tombstone could resurrect a deleted record from a device
 * that has not synced since).
 */
fun pruneTombstones(content: VaultContent, olderThanRevision: Long): VaultContent =
    content.copy(records = content.records.filterNot { it.deleted && it.revision < olderThanRevision })
