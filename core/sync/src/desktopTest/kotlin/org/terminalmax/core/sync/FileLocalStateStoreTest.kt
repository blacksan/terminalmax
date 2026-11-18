// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.sync

import java.io.File
import java.nio.file.Files
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking

class FileLocalStateStoreTest {
    private val cleanup = CopyOnWriteArrayList<AutoCloseable>()

    @AfterTest
    fun tearDown() {
        cleanup.forEach { runCatching { it.close() } }
    }

    private fun tempDir(): File {
        val dir = Files.createTempDirectory("tmx-state-test").toFile()
        cleanup += AutoCloseable { dir.deleteRecursively() }
        return dir
    }

    private fun sample(revision: Long = 5L) = LocalSyncState(
        vaults = mapOf(
            "vault-1" to VaultSyncState(
                baseFile = byteArrayOf(0, 1, 2, -1, -128, 127),
                localFile = byteArrayOf(9, 8, 7, -2),
                highestRevision = revision,
                highestKeyEpoch = 2,
                fileDigests = mapOf(4L to "aa", revision to "bb"),
                pendingLocalFile = byteArrayOf(5, 4, 3),
                chainWarning = ChainWarning(1, 2, passwordUnchanged = true, unverified = false),
                pendingHoldsNewerEdits = true,
                discardedPendingEpoch = 3L,
            ),
        ),
        servers = mapOf(
            "http://dav.example/dav/|user" to ServerSyncState(
                capabilities = ServerCapabilities(
                    honoursIfMatch = true,
                    acceptsMatchingIfMatch = true,
                    honoursIfNoneMatchStar = false,
                    honoursIfMatchOnDelete = true,
                    etagChangesOnPut = true,
                    putReturnsEtag = false,
                    strongEtags = true,
                ),
                probedAtEpochMs = 123_456L,
            ),
        ),
        deviceId = "dev-0123",
    )

    @Test
    fun anEmptyDirectoryGivesAnEmptyState() = runBlocking<Unit> {
        val store = FileLocalStateStore(File(tempDir(), "nested/state"))
        assertEquals(LocalSyncState(), store.load())
    }

    @Test
    fun stateSurvivesANewInstanceIncludingBinaryBaseFiles() = runBlocking<Unit> {
        val dir = tempDir()
        FileLocalStateStore(dir).save(sample())
        assertEquals(sample(), FileLocalStateStore(dir).load())
    }

    @Test
    fun aCrashBetweenTheTempWriteAndTheRenameLeavesTheOldStateIntact() = runBlocking<Unit> {
        val dir = tempDir()
        val store = FileLocalStateStore(dir)
        store.save(sample(5))

        store.beforeRenameHook = { throw IllegalStateException("simulated crash") }
        assertFailsWith<IllegalStateException> { store.save(sample(9)) }
        store.beforeRenameHook = null

        // A fresh process sees the old state, the half-written temp file is ignored.
        assertTrue(File(dir, FileLocalStateStore.DEFAULT_FILE_NAME + ".tmp").exists())
        assertEquals(sample(5), FileLocalStateStore(dir).load())

        // And the next save simply overwrites the leftover temp file.
        store.save(sample(9))
        assertEquals(sample(9), FileLocalStateStore(dir).load())
    }

    @Test
    fun damagedFilesFailClosedInsteadOfLoadingAnEmptyState() = runBlocking<Unit> {
        val dir = tempDir()
        FileLocalStateStore(dir).save(sample())
        val file = File(dir, FileLocalStateStore.DEFAULT_FILE_NAME)
        val good = file.readBytes()

        file.writeBytes(good.copyOf(good.size / 2)) // torn write
        assertFailsWith<LocalStateException> { FileLocalStateStore(dir).load() }

        file.writeBytes(good.copyOf().also { it[it.size - 3] = (it[it.size - 3].toInt() xor 1).toByte() }) // bit flip
        assertFailsWith<LocalStateException> { FileLocalStateStore(dir).load() }

        file.writeBytes(good.copyOf().also { it[0] = 0 }) // wrong magic
        assertFailsWith<LocalStateException> { FileLocalStateStore(dir).load() }

        file.writeBytes(ByteArray(0))
        assertFailsWith<LocalStateException> { FileLocalStateStore(dir).load() }

        file.writeBytes(good) // restored
        assertEquals(sample(), FileLocalStateStore(dir).load())
    }

    @Test
    fun resetForgetsTheFloorsButNeverTheVaultContent() = runBlocking<Unit> {
        val dir = tempDir()
        val store = FileLocalStateStore(dir)
        store.save(sample())
        store.reset()
        val after = FileLocalStateStore(dir).load()
        val v = after.vaults.getValue("vault-1")
        assertEquals(sample().vaults.getValue("vault-1").localFile!!.toList(), v.localFile!!.toList())
        assertEquals(listOf<Byte>(5, 4, 3), v.pendingLocalFile!!.toList())
        assertEquals(0L, v.highestRevision)
        assertEquals(0L, v.highestKeyEpoch)
        assertEquals(null, v.baseFile)
        assertTrue(v.fileDigests.isEmpty())
        assertTrue(after.servers.isEmpty())
        assertEquals("dev-0123", after.deviceId)
    }

    @Test
    fun resetRefusesAnUnreadableStateUnlessToldToMoveItAsideAndNeverDeletesIt() = runBlocking<Unit> {
        val dir = tempDir()
        val store = FileLocalStateStore(dir)
        store.save(sample())
        val file = File(dir, FileLocalStateStore.DEFAULT_FILE_NAME)
        file.writeBytes(ByteArray(10))
        assertFailsWith<LocalStateException> { store.reset() }
        assertEquals(10L, file.length(), "untouched")

        store.reset(moveUnreadableAside = true)
        assertEquals(LocalSyncState(), FileLocalStateStore(dir).load())
        val aside = dir.listFiles()!!.filter { ".unreadable-" in it.name }
        assertTrue(aside.isNotEmpty(), "the damaged files are kept")
        assertTrue(aside.any { it.length() == 10L })
    }

    @Test
    fun theRollingPreviousCopyHoldsTheStateBeforeTheLastSave() = runBlocking<Unit> {
        val dir = tempDir()
        val store = FileLocalStateStore(dir)
        store.save(sample(5))
        store.save(sample(9))
        val prev = File(dir, FileLocalStateStore.DEFAULT_FILE_NAME + ".prev")
        assertTrue(prev.exists())
        val candidates = FileLocalStateStore(dir).salvageCandidates()
        assertEquals(listOf(SalvageSource.Current, SalvageSource.Previous), candidates.map { it.source })
        assertEquals(9L, candidates[0].state.vaults.getValue("vault-1").highestRevision)
        assertEquals(5L, candidates[1].state.vaults.getValue("vault-1").highestRevision)
        assertTrue(candidates.all { it.checksumOk })
    }

    @Test
    fun aCrashBetweenTheTwoRenamesLeavesOnlyThePreviousCopyAndLoadUsesIt() = runBlocking<Unit> {
        val dir = tempDir()
        val store = FileLocalStateStore(dir)
        store.save(sample(5))
        store.betweenRenamesHook = { throw IllegalStateException("simulated crash") }
        assertFailsWith<IllegalStateException> { store.save(sample(9)) }
        store.betweenRenamesHook = null
        assertTrue(!File(dir, FileLocalStateStore.DEFAULT_FILE_NAME).exists())
        assertEquals(sample(5), FileLocalStateStore(dir).load())
        // The next save recovers the normal layout.
        val fresh = FileLocalStateStore(dir)
        fresh.save(sample(9))
        assertEquals(sample(9), FileLocalStateStore(dir).load())
    }

    @Test
    fun aDamagedCurrentFileIsNeverSilentlyReplacedByThePreviousCopyButSalvageReadsBoth() = runBlocking<Unit> {
        val dir = tempDir()
        val store = FileLocalStateStore(dir)
        store.save(sample(5))
        store.save(sample(9))
        val file = File(dir, FileLocalStateStore.DEFAULT_FILE_NAME)
        val good = file.readBytes()
        // A bit flip in the payload: the checksum fails, the payload may still decode.
        file.writeBytes(good.copyOf().also { it[it.size - 3] = (it[it.size - 3].toInt() xor 1).toByte() })
        assertFailsWith<LocalStateException> { FileLocalStateStore(dir).load() }
        val candidates = FileLocalStateStore(dir).salvageCandidates()
        assertTrue(candidates.any { it.source == SalvageSource.Previous && it.checksumOk })
    }

    @Test
    fun theDirectoryLockIsExclusiveAndReleasedOnClose() = runBlocking<Unit> {
        val dir = tempDir()
        val first = FileLocalStateStore(dir).lockDirectory()
        assertFailsWith<VaultSessionException.DirectoryInUse> { FileLocalStateStore(dir).lockDirectory() }
        first.close()
        FileLocalStateStore(dir).lockDirectory().close()
    }

    @Test
    fun exclusiveSectionsNeverOverlapAcrossInstancesOnTheSameDirectory() = runBlocking<Unit> {
        val dir = tempDir()
        val stores = listOf(FileLocalStateStore(dir), FileLocalStateStore(dir), FileLocalStateStore(dir))
        val inside = AtomicInteger()
        val maxInside = AtomicInteger()
        stores.map { store ->
            launch(Dispatchers.Default) {
                store.exclusive {
                    maxInside.accumulateAndGet(inside.incrementAndGet()) { x, y -> maxOf(x, y) }
                    delay(40)
                    inside.decrementAndGet()
                }
            }
        }.joinAll()
        assertEquals(1, maxInside.get())
    }

    @Test
    fun anotherInstanceSeesWhatWasSavedOnceItEntersTheExclusiveSection() = runBlocking<Unit> {
        val dir = tempDir()
        val a = FileLocalStateStore(dir)
        val b = FileLocalStateStore(dir)
        assertEquals(LocalSyncState(), b.load())
        a.save(sample())
        assertEquals(sample(), b.exclusive { b.load() })
    }
}
