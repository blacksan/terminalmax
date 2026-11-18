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
        val local = content(2, record("a", 3, "A"))
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
        val deleteHigher = content(2, record("a", 3, "A", deleted = true))
        val editLower = content(2, record("a", 2, "B"))
        val r1 = mergeVaults(base, deleteHigher, editLower, "A")
        assertTrue(byId(r1.merged)["a"]!!.deleted)
        assertEquals(1, r1.conflicts.size)

        val deleteLower = content(2, record("a", 2, "A", deleted = true))
        val editHigher = content(2, record("a", 3, "B"))
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
    fun withoutBaseLowerRevisionIsKeptInHistoryButNotReportedAsConflict() {
        val local = content(1, record("a", 1, "A"))
        val remote = content(2, record("a", 2, "B"))
        val result = mergeVaults(null, local, remote, "A")
        assertEquals(2L, byId(result.merged)["a"]!!.revision)
        assertTrue(result.conflicts.isEmpty())
        assertEquals(1, result.merged.history.size)
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
        val history = (1..250).map { record("h$it", it.toLong(), "A") }
        val c = content(1, history = history)
        val result = mergeVaults(null, c, c.copy(history = emptyList()), "A")
        assertEquals(VaultContent.MAX_HISTORY, result.merged.history.size)
        assertEquals(51L, result.merged.history.first().revision)
        assertEquals(250L, result.merged.history.last().revision)
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
}
