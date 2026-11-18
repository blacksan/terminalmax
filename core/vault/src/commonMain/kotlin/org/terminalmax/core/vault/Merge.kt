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

/**
 * How many content revisions after a tombstone the **last live version** of the deleted record stays in `history`
 * (the undo window of an accepted mass deletion, see `VaultSession.restoreFromHistory`). After that window the next
 * merge scrubs it like every other history entry of the record.
 */
const val RESTORE_WINDOW_REVISIONS: Long = 30L

internal fun normalizeHistory(records: Collection<VaultRecord>): List<VaultRecord> {
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
 * lower version; it only classifies what happened, and **a version this device cannot prove it has seen is never
 * dropped silently**. For an id present on both sides with different versions, the lower one (the "loser") is:
 *  - the base version itself: an ordinary fast-forward, nothing is reported;
 *  - a version that either input already keeps in its `history` (it lost a conflict before and was reported then):
 *    nothing is reported again, so merging a merge result is quiet; if it is also in the base's history it is a
 *    [Regression] (a replay of something this device saw);
 *  - a version this device has provably seen before (it is in the base's `history`): a [Regression], a true replay
 *    of an old version. It is not kept in history again;
 *  - anything else: a [Conflict], and the loser is kept in `history`. This covers both sides editing the record,
 *    **two different devices that wrote the same revision** (concurrent by the Lamport rule), a loser that is below
 *    the base revision but unseen (a genuine edit from a device that was behind), and one id with two record types.
 *
 * A version that is lower than the base but not provably an ancestor is a conflict rather than a regression
 * because it is indistinguishable from a real concurrent edit; reporting a conflict costs the user a look at the
 * history, calling it a replay would lose the edit. A record that one side lacks although the base had it is a
 * [Regression] of that side (nothing is ever removed from a vault except by tombstones, which are records).
 *
 * Secrets are scrubbed from history: when the merged record is a tombstone, every history entry of that id with a
 * revision up to the tombstone's is dropped, **except the last live version of the record**, which is kept for
 * [RESTORE_WINDOW_REVISIONS] content revisions after the tombstone so that a deletion that turns out to be wrong
 * (an accepted mass deletion by another device) can still be undone. After the window it is scrubbed too. History is
 * capped at [VaultContent.MAX_HISTORY] entries and about 1 MiB, oldest first, so the undo window of a very large
 * deletion is bounded by that cap. History is a union with a cap and pruning, so it converges but is not
 * associative (see the property tests); the join property is claimed for the record set only.
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
    // Versions this device can prove it has seen: the base versions and everything the base kept in history.
    val seen: Set<VaultRecord> = HashSet<VaultRecord>().also { set ->
        base?.records?.let(set::addAll)
        base?.history?.let(set::addAll)
    }
    val preserved: Set<VaultRecord> = HashSet<VaultRecord>().also { set ->
        set.addAll(local.history)
        set.addAll(remote.history)
    }
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
                val loserSide = if (loser === r) MergeSide.Remote else MergeSide.Local
                val typeClash = l.wireTypeName != r.wireTypeName
                // Two different devices at the same revision are concurrent by the Lamport rule.
                val concurrent = l.revision == r.revision && l.deviceId != r.deviceId
                val loserIsBase = b != null && loser == b
                val loserSeen = loser in seen
                // A loser that either side already keeps in its history was surfaced as a conflict when it lost;
                // merging that result again must stay quiet (this is what makes the merge idempotent).
                val alreadyPreserved = loser in preserved
                when {
                    typeClash -> {
                        conflicts += Conflict(id, winner, loser)
                        losers += loser
                    }
                    alreadyPreserved ->
                        if (loserSeen && !loserIsBase) {
                            regressions += Regression(id, kept = winner, ignored = loser, ignoredSide = loserSide)
                        }
                    concurrent -> {
                        conflicts += Conflict(id, winner, loser)
                        losers += loser
                    }
                    loserIsBase -> Unit // fast-forward
                    loserSeen -> regressions += Regression(id, kept = winner, ignored = loser, ignoredSide = loserSide)
                    else -> {
                        conflicts += Conflict(id, winner, loser)
                        losers += loser
                    }
                }
            }
        }
    }

    val current = HashMap<String, VaultRecord>(mergedRecords.size * 2 + 1)
    for (rec in mergedRecords) current[rec.id] = rec
    // The last live version of every record that ends up deleted stays restorable for a while (see the KDoc).
    val newestInput = maxOf(local.revision, remote.revision)
    val lastLive = HashMap<String, VaultRecord>()
    fun offer(h: VaultRecord) {
        val cur = current[h.id] ?: return
        if (!cur.deleted || h.deleted || h.revision > cur.revision) return
        if (newestInput - cur.revision > RESTORE_WINDOW_REVISIONS) return
        val best = lastLive[h.id]
        if (best == null || historyComparator.compare(h, best) > 0) lastLive[h.id] = h
    }
    for (h in local.history) offer(h)
    for (h in remote.history) offer(h)
    for (h in losers) offer(h)
    for (r in local.records) offer(r)
    for (r in remote.records) offer(r)
    val graveyard: Set<VaultRecord> = lastLive.values.toSet()
    val mergedHistory = normalizeHistory(
        (local.history + remote.history + losers + graveyard).filterNot { h ->
            val cur = current[h.id]
            cur != null && cur.deleted && h.revision <= cur.revision && h !in graveyard
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
