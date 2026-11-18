// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.sync

import java.util.concurrent.CopyOnWriteArrayList
import kotlin.random.Random
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import org.terminalmax.core.sync.FakeDavServer.Config
import org.terminalmax.core.sync.FakeDavServer.EtagStyle
import org.terminalmax.core.vault.HostPayload
import org.terminalmax.core.vault.KdfParams
import org.terminalmax.core.vault.OpenVault
import org.terminalmax.core.vault.VaultCodec
import org.terminalmax.core.vault.VaultContent
import org.terminalmax.core.vault.VaultEditor

class SyncEngineTest {
    private val cleanup = CopyOnWriteArrayList<AutoCloseable>()
    private val fast = KdfParams(memoryKiB = 8 * 1024, iterations = 1, parallelism = 1)
    private var now = 10_000_000L

    @AfterTest
    fun tearDown() {
        cleanup.forEach { runCatching { it.close() } }
    }

    private fun server(config: Config = Config()): FakeDavServer = FakeDavServer(config).also { cleanup += it }

    private fun host(label: String) = HostPayload(label, "10.0.0.1", 22, "admin")

    private inner class Device(
        val id: String,
        val server: FakeDavServer,
        val vault: OpenVault,
        maxAttempts: Int = 5,
        password: String = "p",
    ) {
        val state = InMemoryLocalStateStore()
        val hooks = OpenVaultCodecHooks(vault)
        val store = WebDavStore(server.baseUrl, "u", password.toCharArray())
        val engine = SyncEngine(
            store, hooks, state, id,
            clock = { now },
            random = Random(id.hashCode()),
            sleep = { },
            maxAttempts = maxAttempts,
        )
        var content: VaultContent = vault.content

        fun edit(block: (VaultEditor) -> Unit) {
            val editor = VaultEditor(content, id)
            block(editor)
            content = editor.content
        }

        fun syncResult(options: SyncOptions = SyncOptions()): SyncResult = runBlocking {
            engine.sync(content, options).also { content = it.content }
        }

        fun sync(options: SyncOptions = SyncOptions()): SyncOutcome = syncResult(options).outcome
    }

    private fun records(c: VaultContent) = c.records.associateBy { it.id }

    private fun remoteContent(s: FakeDavServer): VaultContent {
        val opened = VaultCodec.open(s.files.getValue(FakeDavServer.VAULT), "pw".toCharArray())
        return opened.content
    }

    private fun newVault(): OpenVault = VaultCodec.create("pw".toCharArray(), fast)

    /** Device A creates the vault with one host and pushes it; device B opens the uploaded file and syncs once. */
    private fun twoDevices(s: FakeDavServer): Pair<Device, Device> {
        val a = Device("A", s, newVault())
        a.edit { it.upsertHost(host("initial"), id = "h1") }
        assertEquals(SyncOutcome.Pushed, a.sync())
        val bVault = VaultCodec.open(s.files.getValue(FakeDavServer.VAULT), "pw".toCharArray())
        val b = Device("B", s, bVault)
        assertEquals(SyncOutcome.UpToDate, b.sync())
        return a to b
    }

    // ------------------------------------------------------------------ basic flows

    @Test
    fun firstSyncPushesWithCreateOnlyPrecondition() {
        val s = server()
        val a = Device("A", s, newVault())
        a.edit { it.upsertHost(host("one"), id = "h1") }
        assertEquals(SyncOutcome.Pushed, a.sync())
        assertEquals(a.content, remoteContent(s))
        assertTrue(s.requests("PUT", FakeDavServer.VAULT).single().ifNoneMatch == "*")
        runBlocking {
            val st = a.state.load()
            assertEquals(a.content, st.baseContent)
            assertEquals(a.content.revision, st.highestRevisionSeen[a.content.vaultId])
            assertNotNull(st.capabilities)
        }
    }

    @Test
    fun syncingAgainWithoutChangesIsUpToDateAndDoesNotWrite() {
        val s = server()
        val (a, _) = twoDevices(s)
        val puts = s.requests("PUT", FakeDavServer.VAULT).size
        assertEquals(SyncOutcome.UpToDate, a.sync())
        assertEquals(puts, s.requests("PUT", FakeDavServer.VAULT).size)
    }

    @Test
    fun probeResultIsCachedBetweenSyncs() {
        val s = server()
        val (a, _) = twoDevices(s)
        a.sync()
        a.sync()
        val mkcolBefore = s.requests("MKCOL").size
        a.sync(SyncOptions(reprobe = true))
        assertEquals(mkcolBefore + 1, s.requests("MKCOL").size)
    }

    @Test
    fun remoteChangesArePulled() {
        val s = server()
        val (a, b) = twoDevices(s)
        a.edit { it.upsertHost(host("second"), id = "h2") }
        assertEquals(SyncOutcome.Pushed, a.sync())
        assertEquals(SyncOutcome.Pulled, b.sync())
        assertEquals(records(a.content), records(b.content))
        assertEquals(SyncOutcome.UpToDate, b.sync())
    }

    // ------------------------------------------------------------------ convergence

    private fun checkDifferentRecordsConverge(s: FakeDavServer) {
        val (a, b) = twoDevices(s)
        a.edit { it.upsertHost(host("from A"), id = "a1") }
        b.edit { it.upsertHost(host("from B"), id = "b1") }
        assertEquals(SyncOutcome.Pushed, a.sync())
        assertEquals(SyncOutcome.Merged(emptyList()), b.sync())
        assertEquals(SyncOutcome.Pulled, a.sync())
        assertEquals(setOf("h1", "a1", "b1"), records(a.content).keys)
        assertEquals(records(a.content), records(b.content))
        assertEquals(records(a.content), records(remoteContent(s)))
        assertEquals(SyncOutcome.UpToDate, a.sync())
        assertEquals(SyncOutcome.UpToDate, b.sync())
    }

    @Test
    fun twoDevicesEditingDifferentRecordsConverge() = checkDifferentRecordsConverge(server())

    @Test
    fun convergenceOnServerWithoutEtagOnPut() = checkDifferentRecordsConverge(server(Config(etagOnPut = false)))

    @Test
    fun convergenceOnServerWithWeakEtagsUsesTheLock() {
        val s = server(Config(etagStyle = EtagStyle.WEAK))
        checkDifferentRecordsConverge(s)
        assertTrue(s.requests("PUT", FakeDavServer.LOCK).isNotEmpty())
        assertTrue(s.requests("PUT", FakeDavServer.VAULT).all { it.ifMatch == null })
        assertFalse(s.files.containsKey(FakeDavServer.LOCK))
    }

    @Test
    fun convergenceOnServerWithSizeBasedEtagsUsesTheLock() {
        val s = server(Config(etagStyle = EtagStyle.MTIME_SIZE))
        checkDifferentRecordsConverge(s)
        assertTrue(s.requests("PUT", FakeDavServer.LOCK).isNotEmpty())
        assertTrue(s.requests("PUT", FakeDavServer.VAULT).all { it.ifMatch == null })
    }

    @Test
    fun serverIgnoringPreconditionsFallsBackToLockLeaseAndStillConverges() {
        val s = server(Config(honourIfMatch = false, honourIfNoneMatch = false))
        checkDifferentRecordsConverge(s)
        assertTrue(s.requests("PUT", FakeDavServer.LOCK).isNotEmpty())
        assertTrue(s.requests("DELETE", FakeDavServer.LOCK).isNotEmpty())
        assertTrue(s.requests("PUT", FakeDavServer.VAULT).all { it.ifMatch == null && it.ifNoneMatch == null })
        assertFalse(s.files.containsKey(FakeDavServer.LOCK), "lock must be released")
    }

    @Test
    fun conflictingEditsGiveTheSameDeterministicWinnerOnBothDevices() {
        val s = server()
        val (a, b) = twoDevices(s)
        a.edit { it.upsertHost(host("A's version"), id = "h1") }
        b.edit { it.upsertHost(host("B's version"), id = "h1") }
        assertEquals(SyncOutcome.Pushed, a.sync())
        val outcome = b.sync()
        assertIs<SyncOutcome.Merged>(outcome)
        assertEquals(1, outcome.conflicts.size)
        assertEquals("B", outcome.conflicts[0].winner.deviceId) // same revision: larger deviceId wins
        assertEquals("A", outcome.conflicts[0].loser.deviceId)
        assertEquals(SyncOutcome.Pulled, a.sync())

        for (device in listOf(a, b)) {
            assertEquals("B", records(device.content)["h1"]!!.deviceId)
            assertTrue(
                device.content.history.any { it.id == "h1" && it.deviceId == "A" },
                "loser must be kept in history on ${device.id}",
            )
        }
        assertEquals(records(a.content), records(b.content))
        assertEquals(a.content.history, b.content.history)
    }

    @Test
    fun editBeatsDeleteOnATieAndTheTombstoneGoesToHistory() {
        val s = server()
        val (a, b) = twoDevices(s)
        a.edit { it.delete("h1") } // A: revision 2, tombstone
        b.edit { it.upsertHost(host("edited"), id = "h1") } // B: revision 2, larger deviceId
        assertEquals(SyncOutcome.Pushed, a.sync())
        assertIs<SyncOutcome.Merged>(b.sync())
        a.sync()
        for (device in listOf(a, b)) {
            val record = records(device.content)["h1"]!!
            assertFalse(record.deleted)
            assertTrue(device.content.history.any { it.id == "h1" && it.deleted })
        }
    }

    @Test
    fun deleteBeatsEditOnATie() {
        val s = server()
        val (a, b) = twoDevices(s)
        b.edit { it.delete("h1") } // B (larger deviceId) deletes
        a.edit { it.upsertHost(host("edited"), id = "h1") }
        assertEquals(SyncOutcome.Pushed, a.sync())
        assertIs<SyncOutcome.Merged>(b.sync())
        a.sync()
        for (device in listOf(a, b)) {
            assertTrue(records(device.content)["h1"]!!.deleted)
        }
        assertEquals(records(a.content), records(b.content))
    }

    // ------------------------------------------------------------------ concurrency

    @Test
    fun preconditionFailureIsRetriedAndMerged() {
        val s = server()
        val (a, b) = twoDevices(s)
        b.edit { it.upsertHost(host("from B"), id = "b1") }
        val bytesFromB = b.hooks.encrypt(b.content, s.files[FakeDavServer.VAULT])
        // B's upload lands after A has read the file but before A's PUT is evaluated.
        s.beforeNextPut = { s.files[FakeDavServer.VAULT] = bytesFromB }

        a.edit { it.upsertHost(host("from A"), id = "a1") }
        val outcome = a.sync()

        assertEquals(SyncOutcome.Merged(emptyList()), outcome)
        assertTrue(s.requests("PUT", FakeDavServer.VAULT).count { it.ifMatch != null } >= 2, "expected a retried If-Match PUT")
        assertEquals(setOf("h1", "a1", "b1"), records(remoteContent(s)).keys)
        assertEquals(records(a.content), records(remoteContent(s)))
    }

    @Test
    fun concurrentWriterBetweenPutAndReadBackIsDetectedAndNothingIsLost() {
        val s = server()
        val (a, b) = twoDevices(s)
        b.edit { it.upsertHost(host("from B"), id = "b1") }
        val bytesFromB = b.hooks.encrypt(b.content, s.files[FakeDavServer.VAULT])
        s.afterPutBeforeNextGet = { s.files[FakeDavServer.VAULT] = bytesFromB }

        a.edit { it.upsertHost(host("from A"), id = "a1") }
        val result = a.syncResult()

        assertIs<SyncOutcome.Merged>(result.outcome)
        // A's first PUT was overwritten; the retry merged B's record and wrote everything again.
        assertEquals(setOf("h1", "a1", "b1"), records(remoteContent(s)).keys)
        assertEquals(setOf("h1", "a1", "b1"), records(a.content).keys)
        assertTrue(s.requests("PUT", FakeDavServer.VAULT).size >= 3) // initial push + two attempts
    }

    @Test
    fun givesUpAfterMaxAttemptsWhenWritersKeepInterfering() {
        val s = server()
        val (_, b) = twoDevices(s)
        val a = Device("A2", s, VaultCodec.open(s.files.getValue(FakeDavServer.VAULT), "pw".toCharArray()), maxAttempts = 5)
        a.sync()
        b.edit { it.upsertHost(host("from B"), id = "b1") }
        val bytesFromB = b.hooks.encrypt(b.content, s.files[FakeDavServer.VAULT])
        lateinit var arm: () -> Unit
        arm = {
            s.afterPutBeforeNextGet = {
                s.files[FakeDavServer.VAULT] = bytesFromB
                arm()
            }
        }
        arm()
        a.edit { it.upsertHost(host("from A"), id = "a1") }
        val before = s.requests("PUT", FakeDavServer.VAULT).size
        val outcome = a.sync()
        assertEquals(SyncOutcome.Failed(FailureReason.TooManyAttempts, "gave up after 5 attempts"), outcome)
        assertEquals(5, s.requests("PUT", FakeDavServer.VAULT).size - before)
        s.afterPutBeforeNextGet = null
    }

    // ------------------------------------------------------------------ lock lease

    private fun lockedServer() = server(Config(honourIfMatch = false, honourIfNoneMatch = false))

    private fun seedLock(s: FakeDavServer, expiresAt: Long, deviceId: String = "someone-else") {
        s.files[FakeDavServer.LOCK] = LockFile.encode(LockInfo(deviceId, "tok", expiresAt))
    }

    @Test
    fun liveLockHeldByAnotherDeviceBlocksTheSync() {
        val s = lockedServer()
        seedLock(s, expiresAt = now + 30_000)
        val a = Device("A", s, newVault())
        a.edit { it.upsertHost(host("one"), id = "h1") }
        val outcome = a.sync()
        assertEquals(FailureReason.Locked, (outcome as SyncOutcome.Failed).reason)
        assertFalse(s.files.containsKey(FakeDavServer.VAULT))
        assertTrue(s.files.containsKey(FakeDavServer.LOCK), "someone else's lock must be left alone")
    }

    @Test
    fun expiredLockIsOnlyBrokenAfterTwiceTheLease() {
        val s = lockedServer()
        val a = Device("A", s, newVault())
        a.edit { it.upsertHost(host("one"), id = "h1") }

        seedLock(s, expiresAt = now - 1) // expired, but younger than 2x lease
        assertEquals(FailureReason.Locked, (a.sync() as SyncOutcome.Failed).reason)

        seedLock(s, expiresAt = now - 60_001) // older than 2x lease: stale
        assertEquals(SyncOutcome.Pushed, a.sync())
        assertFalse(s.files.containsKey(FakeDavServer.LOCK))
    }

    @Test
    fun ownLeftoverLockAndGarbageLocksAreBroken() {
        val s = lockedServer()
        val a = Device("A", s, newVault())
        a.edit { it.upsertHost(host("one"), id = "h1") }
        seedLock(s, expiresAt = now + 30_000, deviceId = "A")
        assertEquals(SyncOutcome.Pushed, a.sync())
        s.files[FakeDavServer.LOCK] = "not json".toByteArray()
        a.edit { it.upsertHost(host("two"), id = "h2") }
        assertEquals(SyncOutcome.Pushed, a.sync())
    }

    // ------------------------------------------------------------------ rollback and integrity

    @Test
    fun rollbackIsDetectedUnlessExplicitlyOverridden() {
        val s = server()
        val a = Device("A", s, newVault())
        a.edit { it.upsertHost(host("one"), id = "h1") }
        a.sync()
        val oldFile = s.files.getValue(FakeDavServer.VAULT).copyOf()
        val oldRevision = remoteContent(s).revision
        a.edit { it.upsertHost(host("two"), id = "h2") }
        assertEquals(SyncOutcome.Pushed, a.sync())
        assertTrue(remoteContent(s).revision > oldRevision)

        s.files[FakeDavServer.VAULT] = oldFile // malicious or buggy server serves an old snapshot
        val outcome = a.sync()
        assertEquals(FailureReason.RollbackDetected, (outcome as SyncOutcome.Failed).reason)
        assertContentEqualsFile(oldFile, s) // nothing was written over it

        val overridden = a.sync(SyncOptions(allowRollback = true))
        assertFalse(overridden is SyncOutcome.Failed, "override must be honoured: $overridden")
        assertEquals(setOf("h1", "h2"), records(remoteContent(s)).keys) // nothing local was lost
    }

    private fun assertContentEqualsFile(expected: ByteArray, s: FakeDavServer) =
        assertTrue(expected.contentEquals(s.files.getValue(FakeDavServer.VAULT)))

    @Test
    fun tamperedGarbageAndForeignRemoteFilesFailCleanly() {
        val s = server()
        val (a, _) = twoDevices(s)
        val good = s.files.getValue(FakeDavServer.VAULT)

        s.files[FakeDavServer.VAULT] = good.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        assertEquals(FailureReason.BadPasswordOrCorrupt, (a.sync() as SyncOutcome.Failed).reason)

        s.files[FakeDavServer.VAULT] = Random(5).nextBytes(500)
        assertEquals(FailureReason.InvalidRemoteFile, (a.sync() as SyncOutcome.Failed).reason)

        val foreign = Device("X", server(), newVault())
        foreign.edit { it.upsertHost(host("other vault"), id = "x") }
        s.files[FakeDavServer.VAULT] = foreign.hooks.encrypt(foreign.content, null)
        assertEquals(FailureReason.DifferentVault, (a.sync() as SyncOutcome.Failed).reason)

        s.files[FakeDavServer.VAULT] = good // restoring the file lets the device continue
        assertEquals(SyncOutcome.UpToDate, a.sync())
    }

    @Test
    fun failedSyncKeepsLocalContentAndState() {
        val s = server()
        val (a, _) = twoDevices(s)
        a.edit { it.upsertHost(host("unsynced"), id = "h9") }
        val before = a.content
        val stateBefore = runBlocking { a.state.load() }
        s.files[FakeDavServer.VAULT] = Random(1).nextBytes(100)
        assertIs<SyncOutcome.Failed>(a.sync())
        assertEquals(before, a.content)
        assertEquals(stateBefore, runBlocking { a.state.load() })
    }

    // ------------------------------------------------------------------ transport failures

    @Test
    fun wrongCredentialsAndDeadServerAreReportedAsFailures() {
        val s = server(Config(credentials = "u" to "p"))
        val bad = Device("A", s, newVault(), password = "wrong")
        assertEquals(FailureReason.AuthFailed, (bad.sync() as SyncOutcome.Failed).reason)

        val dead = server()
        val a = Device("A", dead, newVault())
        dead.close()
        assertEquals(FailureReason.Network, (a.sync() as SyncOutcome.Failed).reason)
    }
}
