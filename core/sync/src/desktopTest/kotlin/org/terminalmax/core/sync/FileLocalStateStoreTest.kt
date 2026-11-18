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
                highestRevision = revision,
                highestKeyEpoch = 2,
                highestHeaderRevision = 3,
                fileDigests = mapOf(4L to "aa", revision to "bb"),
            ),
        ),
        servers = mapOf(
            "http://dav.example/dav/|user" to ServerSyncState(
                lastEtag = "\"etag\"",
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
    fun resetIsTheExplicitWayBackToAnEmptyState() = runBlocking<Unit> {
        val dir = tempDir()
        val store = FileLocalStateStore(dir)
        store.save(sample())
        File(dir, FileLocalStateStore.DEFAULT_FILE_NAME).writeBytes(ByteArray(10))
        store.reset()
        assertEquals(LocalSyncState(), FileLocalStateStore(dir).load())
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
