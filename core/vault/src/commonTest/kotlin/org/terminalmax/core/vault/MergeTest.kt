// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.vault

import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class MergeTest {
    private val vaultId = "vault-1"

    private fun payload(value: String) = JsonObject(mapOf("v" to JsonPrimitive(value)))

    private fun record(
        id: String,
        revision: Long,
        deviceId: String,
        value: String = "$deviceId$revision",
        deleted: Boolean = false,
    ) = VaultRecord(
        id = id,
        type = RecordType.Snippet,
        revision = revision,
        deviceId = deviceId,
        updatedAtEpochMs = 0,
        deleted = deleted,
        payload = if (deleted) JsonObject(emptyMap()) else payload(value),
    )

    private fun content(revision: Long, vararg records: VaultRecord, history: List<VaultRecord> = emptyList()) =
        VaultContent(SUPPORTED_SCHEMA_VERSION, vaultId, revision, records.toList(), history)

    private fun byId(c: VaultContent) = c.records.associateBy { it.id }

    @Test
    fun recordChangedOnlyLocallyTakesLocal() {
        val base = content(1, record("a", 1, "A"))
        val local = content(2, record("a", 2, "A"))
        val result = mergeVaults(base, local, base, "A")
        assertEquals(2L, byId(result.merged)["a"]!!.revision)
        assertTrue(result.conflicts.isEmpty())
        assertTrue(result.changedRemotely)
        assertFalse(result.changedLocally)
        assertEquals(3L, result.merged.revision) // max(2, 1) + 1
    }

    @Test
    fun recordChangedOnlyRemotelyTakesRemote() {
        val base = content(1, record("a", 1, "A"))
        val remote = content(2, record("a", 2, "B"))
        val result = mergeVaults(base, base, remote, "A")
        assertEquals("B", byId(result.merged)["a"]!!.deviceId)
        assertTrue(result.changedLocally)
        assertFalse(result.changedRemotely)
        assertEquals(remote.revision, result.merged.revision)
        assertTrue(result.conflicts.isEmpty())
    }

    @Test
    fun differentRecordsOnBothSidesAreUnioned() {
        val base = content(0)
        val local = content(1, record("a", 1, "A"))
        val remote = content(1, record("b", 1, "B"))
        val result = mergeVaults(base, local, remote, "A")
        assertEquals(setOf("a", "b"), byId(result.merged).keys)
        assertTrue(result.changedLocally)
        assertTrue(result.changedRemotely)
        assertEquals(2L, result.merged.revision)
    }

    @Test
    fun bothChangedHigherRevisionWinsLoserGoesToHistory() {
        val base = content(1, record("a", 1, "A"))
        val local = content(3, record("a", 3, "A"))
        val remote = content(2, record("a", 2, "B"))
        val result = mergeVaults(base, local, remote, "A")
        assertEquals(3L, byId(result.merged)["a"]!!.revision)
        assertEquals(1, result.conflicts.size)
        assertEquals("B", result.conflicts[0].loser.deviceId)
        assertEquals(listOf(remote.records[0]), result.merged.history)
    }

    @Test
    fun equalRevisionTieBrokenByLargerDeviceId() {
        val base = content(1, record("a", 1, "A"))
        val local = content(2, record("a", 2, "A"))
        val remote = content(2, record("a", 2, "B"))
        val forward = mergeVaults(base, local, remote, "A")
        val backward = mergeVaults(base, remote, local, "B")
        assertEquals("B", byId(forward.merged)["a"]!!.deviceId)
        assertEquals(byId(forward.merged), byId(backward.merged))
        assertEquals(forward.merged.history, backward.merged.history)
    }

    @Test
    fun deleteVersusEditUsesTheSameOrdering() {
        val base = content(1, record("a", 1, "A"))
        val deleteHigher = content(3, record("a", 3, "A", deleted = true))
        val editLower = content(2, record("a", 2, "B"))
        val r1 = mergeVaults(base, deleteHigher, editLower, "A")
        assertTrue(byId(r1.merged)["a"]!!.deleted)
        assertEquals(1, r1.conflicts.size)

        val deleteLower = content(2, record("a", 2, "A", deleted = true))
        val editHigher = content(3, record("a", 3, "B"))
        val r2 = mergeVaults(base, deleteLower, editHigher, "A")
        assertFalse(byId(r2.merged)["a"]!!.deleted)
        assertEquals(deleteLower.records[0], r2.merged.history.single())
    }

    @Test
    fun tombstonesAreKept() {
        val base = content(1, record("a", 1, "A"))
        val local = content(2, record("a", 2, "A", deleted = true))
        val result = mergeVaults(base, local, base, "A")
        assertTrue(byId(result.merged)["a"]!!.deleted)
        assertEquals(1, result.merged.records.size)
    }

    @Test
    fun withoutBaseAnUnseenLowerVersionIsAConflictAndKeptInHistory() {
        val local = content(1, record("a", 1, "A"))
        val remote = content(2, record("a", 2, "B"))
        val result = mergeVaults(null, local, remote, "A")
        assertEquals(2L, byId(result.merged)["a"]!!.revision)
        assertEquals(1, result.conflicts.size)
        assertTrue(result.regressions.isEmpty())
        assertEquals(listOf(local.records[0]), result.merged.history)
    }

    @Test
    fun withoutBaseEqualRevisionIsAConflict() {
        val local = content(1, record("a", 1, "A"))
        val remote = content(1, record("a", 1, "B"))
        val result = mergeVaults(null, local, remote, "A")
        assertEquals(1, result.conflicts.size)
        assertEquals("B", byId(result.merged)["a"]!!.deviceId)
    }

    @Test
    fun identicalVaultsMergeToNoChange() {
        val c = content(5, record("a", 1, "A"), record("b", 2, "B"))
        val result = mergeVaults(c, c, c, "A")
        assertFalse(result.changedLocally)
        assertFalse(result.changedRemotely)
        assertEquals(5L, result.merged.revision)
    }

    @Test
    fun differentVaultIsRejected() {
        val a = content(1)
        val b = a.copy(vaultId = "other")
        assertFailsWith<VaultException.DifferentVault> { mergeVaults(null, a, b, "A") }
        assertFailsWith<VaultException.DifferentVault> { mergeVaults(b, a, a, "A") }
    }

    @Test
    fun newerSchemaIsRejected() {
        val a = content(1)
        val newer = a.copy(schemaVersion = SUPPORTED_SCHEMA_VERSION + 1)
        assertFailsWith<VaultException.UnsupportedVersion> { mergeVaults(null, a, newer, "A") }
        assertFailsWith<VaultException.UnsupportedVersion> { mergeVaults(null, newer, a, "A") }
        assertFailsWith<VaultException.UnsupportedVersion> { mergeVaults(newer, a, a, "A") }
    }

    @Test
    fun historyIsCappedAndOldestDropped() {
        val localHistory = (1..150).map { record("h$it", it.toLong(), "A") }
        val remoteHistory = (151..300).map { record("h$it", it.toLong(), "A") }
        val result = mergeVaults(
            null,
            content(300, history = localHistory),
            content(300, history = remoteHistory),
            "A",
        )
        assertEquals(VaultContent.MAX_HISTORY, result.merged.history.size)
        assertEquals(101L, result.merged.history.first().revision)
        assertEquals(300L, result.merged.history.last().revision)
    }

    @Test
    fun pruneTombstonesRemovesOnlyOldTombstones() {
        val c = content(
            9,
            record("live", 1, "A"),
            record("oldDead", 2, "A", deleted = true),
            record("newDead", 8, "A", deleted = true),
        )
        val pruned = pruneTombstones(c, olderThanRevision = 5)
        assertEquals(setOf("live", "newDead"), byId(pruned).keys)
    }

    // ---- property-style tests with seeded random vaults ----

    private fun randomBase(rnd: Random): VaultContent {
        val editor = VaultEditor(VaultContent.empty(vaultId), "base")
        repeat(rnd.nextInt(0, 6)) { i ->
            editor.upsert(RecordType.Snippet, "r$i", payload("base$i"))
        }
        return editor.content
    }

    private fun randomEdits(base: VaultContent, device: String, rnd: Random): VaultContent {
        val editor = VaultEditor(base, device)
        repeat(rnd.nextInt(0, 5)) {
            val id = "r${rnd.nextInt(0, 8)}"
            when (rnd.nextInt(3)) {
                0 -> editor.upsert(RecordType.Snippet, id, payload("$device-${rnd.nextInt(1000)}"))
                1 -> editor.delete(id)
                else -> editor.upsert(RecordType.Snippet, id, payload("$device-x${rnd.nextInt(1000)}"))
            }
        }
        return editor.content
    }

    @Test
    fun mergeIsCommutativeForRandomVaults() {
        for (seed in 0 until 300) {
            val rnd = Random(seed)
            val base = randomBase(rnd)
            val a = randomEdits(base, "A", rnd)
            val b = randomEdits(base, "B", rnd)
            for (useBase in listOf(true, false)) {
                val bs = if (useBase) base else null
                val ab = mergeVaults(bs, a, b, "A")
                val ba = mergeVaults(bs, b, a, "B")
                assertEquals(byId(ab.merged), byId(ba.merged), "records differ for seed $seed base=$useBase")
                assertEquals(ab.merged.history, ba.merged.history, "history differs for seed $seed base=$useBase")
                assertEquals(
                    ab.conflicts.map { it.recordId to it.winner },
                    ba.conflicts.map { it.recordId to it.winner },
                    "conflicts differ for seed $seed base=$useBase",
                )
            }
        }
    }

    @Test
    fun mergeConvergesAndIsIdempotentForRandomVaults() {
        for (seed in 1000 until 1300) {
            val rnd = Random(seed)
            val base = randomBase(rnd)
            val a = randomEdits(base, "A", rnd)
            val b = randomEdits(base, "B", rnd)
            val m = mergeVaults(base, a, b, "A").merged
            // Pulling the merged result into either original side (base = common ancestor) changes nothing further.
            val withA = mergeVaults(base, m, a, "A")
            val withB = mergeVaults(base, b, m, "B")
            assertEquals(byId(m), byId(withA.merged), "seed $seed")
            assertEquals(byId(m), byId(withB.merged), "seed $seed")
            assertEquals(m.history, withA.merged.history, "seed $seed")
            assertEquals(m.history, withB.merged.history, "seed $seed")
            // Merging with itself is a no-op.
            val again = mergeVaults(m, m, m, "A")
            assertFalse(again.changedLocally)
            assertFalse(again.changedRemotely)
        }
    }

    @Test
    fun nonConflictingEditsAreNeverLost() {
        for (seed in 2000 until 2200) {
            val rnd = Random(seed)
            val base = randomBase(rnd)
            // A only touches even ids, B only odd ids: no conflicts possible.
            val ea = VaultEditor(base, "A")
            val eb = VaultEditor(base, "B")
            val expected = HashMap<String, String>()
            repeat(rnd.nextInt(0, 4)) {
                val id = "r${rnd.nextInt(0, 4) * 2}"
                val v = "A${rnd.nextInt(1000)}"
                ea.upsert(RecordType.Snippet, id, payload(v)); expected[id] = v
            }
            repeat(rnd.nextInt(0, 4)) {
                val id = "r${rnd.nextInt(0, 4) * 2 + 1}"
                val v = "B${rnd.nextInt(1000)}"
                eb.upsert(RecordType.Snippet, id, payload(v)); expected[id] = v
            }
            val result = mergeVaults(base, ea.content, eb.content, "A")
            assertTrue(result.conflicts.isEmpty(), "seed $seed")
            for ((id, v) in expected) {
                assertEquals(payload(v), byId(result.merged)[id]!!.payload, "seed $seed id $id")
            }
        }
    }
    // ---- format v2: pure join, regressions, scrubbing, validation ----

    @Test
    fun staleRemoteNeverRevertsARecordAndTheUnprovableVersionIsKeptAsAConflict() {
        val base = content(4, record("x", 4, "A"))
        val local = base
        val remote = content(3, record("x", 3, "A"))
        val result = mergeVaults(base, local, remote, "A")
        assertEquals(4L, byId(result.merged)["x"]!!.revision)
        assertTrue(result.changedRemotely) // the healed content must be pushed back
        // x@3 is below the base but this device cannot prove it is an ancestor: it is never dropped silently.
        assertTrue(result.regressions.isEmpty())
        val conflict = result.conflicts.single()
        assertEquals(3L, conflict.loser.revision)
        assertEquals(listOf(remote.records[0]), result.merged.history)
    }

    @Test
    fun aReplayOfAVersionTheDeviceProvablySawIsARegressionAndNotKeptAgain() {
        val old = record("x", 3, "A")
        val base = content(4, record("x", 4, "A"), history = listOf(old))
        val result = mergeVaults(base, base, content(3, old), "A")
        assertEquals(4L, byId(result.merged)["x"]!!.revision)
        val regression = result.regressions.single()
        assertEquals(MergeSide.Remote, regression.ignoredSide)
        assertEquals(old, regression.ignored)
        assertTrue(result.conflicts.isEmpty())
        assertEquals(base.history, result.merged.history)
    }

    // R-S1 case 1: A edited twice (base X@12), the server served the old file to B, B edited X@11 and pushed.
    @Test
    fun aGenuineEditBelowTheBaseRevisionIsAConflictNeverASilentRegression() {
        val base = content(12, record("x", 12, "A"))
        val remoteFromB = content(11, record("x", 11, "B"))
        val onA = mergeVaults(base, base, remoteFromB, "A")
        assertEquals("A", byId(onA.merged)["x"]!!.deviceId)
        assertTrue(onA.regressions.isEmpty())
        assertEquals(remoteFromB.records[0], onA.conflicts.single().loser)
        assertEquals(listOf(remoteFromB.records[0]), onA.merged.history)
        // B later pulls A's file: its own X@11 is the base, a plain fast-forward, and A's history carries X@11.
        val onB = mergeVaults(remoteFromB, remoteFromB, onA.merged, "B")
        assertEquals("A", byId(onB.merged)["x"]!!.deviceId)
        assertTrue(onB.regressions.isEmpty())
        assertEquals(listOf(remoteFromB.records[0]), onB.merged.history)
    }

    // R-S1 case 2: same revision from two devices is always concurrent, whichever side is the base.
    @Test
    fun equalRevisionsFromTwoDevicesAreAConflictEvenWhenOneIsTheBase() {
        val base = content(11, record("x", 11, "A"))
        val remote = content(11, record("x", 11, "B"))
        val onA = mergeVaults(base, base, remote, "A")
        assertEquals(1, onA.conflicts.size)
        assertEquals("B", byId(onA.merged)["x"]!!.deviceId)
        assertEquals(base.records, onA.merged.history)
        val onB = mergeVaults(remote, remote, base, "B")
        assertEquals(1, onB.conflicts.size)
        assertEquals(byId(onA.merged), byId(onB.merged))
        assertEquals(onA.merged.history, onB.merged.history)
    }

    // R-S1 case 3: a crash lost the local save; the next edit is made on stale content and ranks below the base.
    @Test
    fun anEditMadeOnStaleLocalContentIsKeptInHistory() {
        val base = content(12, record("x", 12, "A"))
        val staleEdit = content(11, record("x", 11, "A", value = "my new password"))
        val result = mergeVaults(base, staleEdit, base, "A")
        assertEquals(12L, byId(result.merged)["x"]!!.revision)
        assertEquals(1, result.conflicts.size)
        assertEquals(staleEdit.records, result.merged.history)
        assertTrue(result.regressions.isEmpty())
    }

    @Test
    fun theEditorsRevisionFloorKeepsAnEditAboveWhatWasAlreadySynced() {
        val stale = content(10, record("x", 10, "A"))
        val editor = VaultEditor(stale, "A", revisionFloor = 12L)
        val edited = editor.upsert(RecordType.Snippet, "x", payload("new"))
        assertEquals(13L, edited.revision)
        assertEquals(13L, editor.content.revision)
        editor.content.validate()
    }

    @Test
    fun aReplayedLiveRecordNeverResurrectsADeletedOne() {
        val live = record("x", 3, "A")
        val tombstone = record("x", 4, "A", deleted = true)
        val base = content(4, tombstone)
        val result = mergeVaults(base, content(4, tombstone), content(3, live), "A")
        assertTrue(byId(result.merged)["x"]!!.deleted)
        // The replay cannot be proven to be an ancestor, so it is reported, but the tombstone scrubs it from history.
        assertEquals(1, result.conflicts.size)
        assertTrue(result.merged.history.none { it.id == "x" })
    }

    @Test
    fun aRemoteThatLacksARecordTheBaseHadIsAlsoARegression() {
        val base = content(2, record("x", 1, "A"), record("y", 2, "A"))
        val remote = content(1, record("x", 1, "A"))
        val result = mergeVaults(base, base, remote, "A")
        assertEquals(setOf("x", "y"), byId(result.merged).keys)
        val regression = result.regressions.single()
        assertEquals("y", regression.recordId)
        assertEquals(MergeSide.Remote, regression.ignoredSide)
        assertEquals(null, regression.ignored)
    }

    @Test
    fun aStaleLocalContentIsHealedFromTheBaseAndItsUnseenVersionIsKept() {
        // The crash case: the base (state) is ahead of the local content that the caller failed to persist.
        val base = content(4, record("x", 4, "A"))
        val staleLocal = content(3, record("x", 3, "A"))
        val result = mergeVaults(base, staleLocal, base, "A")
        assertEquals(4L, byId(result.merged)["x"]!!.revision)
        assertEquals(1, result.conflicts.size)
        assertEquals(staleLocal.records, result.merged.history)
        assertTrue(result.changedLocally)
    }

    @Test
    fun ordinaryFastForwardsAreNotRegressions() {
        val base = content(1, record("a", 1, "A"))
        val ahead = content(2, record("a", 2, "A"))
        assertTrue(mergeVaults(base, ahead, base, "A").regressions.isEmpty())
        assertTrue(mergeVaults(base, base, ahead, "A").regressions.isEmpty())
        assertTrue(mergeVaults(null, ahead, base, "A").regressions.isEmpty())
    }

    @Test
    fun allowRollbackStyleInputCannotEraseNewerRecords() {
        // Everything the remote carries is older than local: the record set never reverts.
        val local = content(10, record("a", 5, "A"), record("b", 6, "B"))
        val staleRemote = content(2, record("a", 1, "A"), record("b", 2, "B"))
        val result = mergeVaults(local, local, staleRemote, "A")
        assertEquals(byId(local), byId(result.merged))
        assertEquals(2, result.conflicts.size) // not provably ancestors: kept in history, not dropped silently
    }

    @Test
    fun aTombstoneThatWinsScrubsTheSecretsOfThatRecordFromHistory() {
        val secret = record("k", 2, "B", value = "TOP-SECRET")
        val withHistory = content(3, record("k", 3, "A"), history = listOf(secret))
        val deleted = content(4, record("k", 4, "A", deleted = true), history = listOf(secret))
        val result = mergeVaults(null, withHistory, deleted, "A")
        assertTrue(byId(result.merged)["k"]!!.deleted)
        assertTrue(result.merged.history.none { it.id == "k" }, "old versions of a deleted record must leave the history")
        assertTrue(result.changedLocally)
        // A loser overridden by a tombstone with the same revision is scrubbed too.
        val edit = content(2, record("e", 2, "A", value = "SECRET2"))
        val tomb = content(2, record("e", 2, "B", deleted = true))
        val tie = mergeVaults(null, edit, tomb, "A")
        assertTrue(byId(tie.merged)["e"]!!.deleted)
        assertTrue(tie.merged.history.none { it.id == "e" })
        // Re-merging with a side that still has the entry removes it again (convergent, idempotent).
        val again = mergeVaults(result.merged, result.merged, withHistory, "A")
        assertTrue(again.merged.history.none { it.id == "k" })
    }

    @Test
    fun anIdWithTwoTypesIsAlwaysReportedAndTheLoserIsKept() {
        val snippet = record("x", 3, "A")
        val host = VaultRecord("x", RecordType.Host, 2, "B", 0, false, payload("h"))
        val base = content(1, record("x", 1, "A"))
        val result = mergeVaults(base, content(3, snippet), content(2, host), "A")
        assertEquals(RecordType.Snippet, byId(result.merged)["x"]!!.type)
        assertEquals(1, result.conflicts.size)
        assertTrue(result.merged.history.contains(host))
    }

    @Test
    fun mergeRejectsInvalidContent() {
        val ok = content(1, record("a", 1, "A"))
        val bad = listOf(
            content(-1),
            content(MAX_REVISION + 1),
            content(1, record("a", 1, "A"), record("a", 2, "A")),
            content(1, record("", 1, "A")),
            content(1, record("a", -1, "A")),
            content(1, record("a", Long.MAX_VALUE, "A")),
            content(1, record("a", 2, "A")), // a record above the content revision
            content(1, history = (1..201).map { record("h$it", it.toLong(), "A") }),
        )
        for (b in bad) {
            assertFailsWith<VaultException.InvalidContent> { mergeVaults(null, ok, b, "A") }
            assertFailsWith<VaultException.InvalidContent> { mergeVaults(null, b, ok, "A") }
            assertFailsWith<VaultException.InvalidContent> { mergeVaults(b, ok, ok, "A") }
        }
        val atLimit = content(MAX_REVISION, record("a", MAX_REVISION, "A"))
        assertFailsWith<VaultException.InvalidContent> {
            mergeVaults(null, atLimit, content(MAX_REVISION, record("b", 1, "B")), "A") // revision would overflow
        }
    }

    @Test
    fun mergeIsAssociativeForTheRecordSet() {
        for (seed in 3000 until 3200) {
            val rnd = Random(seed)
            val base = randomBase(rnd)
            val a = randomEdits(base, "A", rnd)
            val b = randomEdits(base, "B", rnd)
            val c = randomEdits(base, "C", rnd)
            fun m(x: VaultContent, y: VaultContent) = mergeVaults(null, x, y, "A").merged
            assertEquals(byId(m(m(a, b), c)), byId(m(a, m(b, c))), "seed $seed")
            assertEquals(byId(m(m(a, b), c)), byId(m(m(c, a), b)), "seed $seed")
        }
    }

    private fun randomContent(rnd: Random, device: String): VaultContent {
        val editor = VaultEditor(VaultContent.empty(vaultId), device)
        repeat(rnd.nextInt(0, 8)) {
            val id = "r${rnd.nextInt(0, 5)}"
            if (rnd.nextInt(4) == 0) editor.delete(id) else editor.upsert(RecordType.Snippet, id, payload("$device${rnd.nextInt(50)}"))
        }
        return editor.content
    }

    @Test
    fun theRecordSetIsAJoinIdempotentCommutativeAndAssociativeForArbitraryInputsAndBases() {
        for (seed in 5000 until 5300) {
            val rnd = Random(seed)
            val a = randomContent(rnd, "A")
            val b = randomContent(rnd, "B")
            val c = randomContent(rnd, "C")
            val base = if (rnd.nextBoolean()) randomContent(rnd, "base") else null
            fun m(x: VaultContent, y: VaultContent) = mergeVaults(base, x, y, "A").merged
            assertEquals(byId(a).keys + byId(b).keys, byId(m(a, b)).keys, "seed $seed")
            assertEquals(byId(m(a, a)), byId(a), "idempotent, seed $seed")
            assertEquals(byId(m(a, b)), byId(m(b, a)), "commutative, seed $seed")
            assertEquals(byId(m(m(a, b), c)), byId(m(a, m(b, c))), "associative, seed $seed")
            // The result never depends on the base: it is the per-id maximum.
            assertEquals(byId(m(a, b)), byId(mergeVaults(null, a, b, "A").merged), "base independent, seed $seed")
        }
    }

    // R-N7: history is a capped union that scrubs under tombstones; it converges but is not associative.
    @Test
    fun historyIsNotAssociativeButTheRecordSetIs() {
        val x3 = record("x", 3, "A")
        val tomb5 = record("x", 5, "A", deleted = true)
        val live6 = record("x", 6, "B")
        val a = content(5, tomb5, history = listOf(x3))
        val b = content(5, tomb5)
        val c = content(6, live6)
        fun m(p: VaultContent, q: VaultContent) = mergeVaults(null, p, q, "A").merged
        assertEquals(byId(m(m(a, b), c)), byId(m(a, m(b, c))))
        assertTrue(m(m(a, b), c).history.none { it.id == "x" && it.revision == 3L })
        assertTrue(m(a, m(b, c)).history.any { it.id == "x" && it.revision == 3L })
    }

    // ---- three devices, stale servers, crashes: everything converges and no winning edit is lost ----

    private class Sim(val vaultId: String) {
        var server: VaultContent = VaultContent.empty(vaultId)
        val snapshots = ArrayList<VaultContent>().also { it += server }
        val expected = HashMap<String, VaultRecord>()
    }

    private class SimDevice(val id: String, var local: VaultContent, var base: VaultContent? = null)

    private fun newer(a: VaultRecord, b: VaultRecord): VaultRecord = if (versionOrder(a, b) >= 0) a else b

    private fun versionOrder(a: VaultRecord, b: VaultRecord): Int {
        val v = compareVersions(a, b)
        if (v != 0) return v
        return VaultJson.json.encodeToString(VaultRecord.serializer(), a)
            .compareTo(VaultJson.json.encodeToString(VaultRecord.serializer(), b))
    }

    @Test
    fun threeDevicesWithStaleServersAndCrashesConvergeWithoutLosingWinningEdits() {
        for (seed in 0 until 60) {
            val rnd = Random(seed)
            val sim = Sim(vaultId)
            val devices = listOf("A", "B", "C").map { SimDevice(it, sim.server) }
            fun record(editor: VaultEditor, id: String) {
                val r = editor.content.records.first { it.id == id }
                sim.expected[id] = sim.expected[id]?.let { newer(it, r) } ?: r
            }
            repeat(40) {
                val d = devices[rnd.nextInt(devices.size)]
                when (rnd.nextInt(4)) {
                    0, 1 -> { // edit or delete
                        val editor = VaultEditor(d.local, d.id)
                        val id = "r${rnd.nextInt(6)}"
                        if (rnd.nextInt(5) == 0 && editor.delete(id) != null) record(editor, id)
                        else { editor.upsert(RecordType.Snippet, id, payload("${d.id}-${rnd.nextInt(1000)}")); record(editor, id) }
                        d.local = editor.content
                    }
                    else -> { // sync, sometimes against a stale snapshot, sometimes crashing before local is saved
                        val remote = if (rnd.nextInt(4) == 0) sim.snapshots[rnd.nextInt(sim.snapshots.size)] else sim.server
                        val result = mergeVaults(d.base, d.local, remote, d.id)
                        if (result.changedRemotely) {
                            sim.server = result.merged
                            sim.snapshots += result.merged
                        }
                        d.base = result.merged
                        if (rnd.nextInt(5) != 0) d.local = result.merged // else: "crash" before the content was saved
                    }
                }
            }
            // Quiescence: every device syncs against the real server until nothing changes.
            repeat(4) {
                for (d in devices) {
                    val result = mergeVaults(d.base, d.local, sim.server, d.id)
                    if (result.changedRemotely) sim.server = result.merged
                    d.base = result.merged
                    d.local = result.merged
                }
            }
            for (d in devices) assertEquals(byId(sim.server), byId(d.local), "seed $seed device ${d.id}")
            // Every record equals the maximum version that any device ever produced for that id.
            for ((id, wanted) in sim.expected) {
                assertEquals(wanted, byId(sim.server)[id], "seed $seed id $id")
            }
        }
    }
}
