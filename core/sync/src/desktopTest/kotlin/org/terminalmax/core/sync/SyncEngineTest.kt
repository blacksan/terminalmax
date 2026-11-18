// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.sync

import java.io.File
import java.nio.file.Files
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
import org.terminalmax.core.vault.MAX_REVISION
import org.terminalmax.core.vault.MAX_REVISION_JUMP
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
        val state: LocalStateStore = InMemoryLocalStateStore(),
        leaseMillis: Long = SyncEngine.DEFAULT_LEASE_MILLIS,
        requestBudgetMillis: Long = SyncEngine.DEFAULT_REQUEST_BUDGET_MILLIS,
        clock: () -> Long = { now },
    ) {
        val hooks = OpenVaultCodecHooks(vault).also { cleanup += it }
        val store = WebDavStore(server.baseUrl, "u", password.toCharArray())
        val engine = SyncEngine(
            store, hooks, state, id,
            clock = clock,
            random = Random(id.hashCode()),
            sleep = { },
            maxAttempts = maxAttempts,
            leaseMillis = leaseMillis,
            requestBudgetMillis = requestBudgetMillis,
        )
        var content: VaultContent = vault.content

        fun edit(block: (VaultEditor) -> Unit) {
            val editor = VaultEditor(content, id)
            block(editor)
            content = editor.content
        }

        fun syncResult(
            options: SyncOptions = SyncOptions(),
            staged: StagedHeaderChange? = null,
            password: CharArray? = null,
        ): SyncResult = runBlocking {
            engine.sync(content, options, staged, password).also { content = it.content }
        }

        fun sync(options: SyncOptions = SyncOptions()): SyncOutcome = syncResult(options).outcome
    }

    private fun records(c: VaultContent) = c.records.associateBy { it.id }

    private fun remoteContent(s: FakeDavServer, password: String = "pw"): VaultContent {
        val opened = VaultCodec.open(s.files.getValue(FakeDavServer.VAULT), password.toCharArray())
        return opened.content
    }

    private fun openRemote(s: FakeDavServer, password: String = "pw"): OpenVault =
        VaultCodec.open(s.files.getValue(FakeDavServer.VAULT), password.toCharArray())

    private fun realNow() = System.currentTimeMillis()

    private fun tempDir(): File {
        val dir = Files.createTempDirectory("tmx-sync-test").toFile()
        cleanup += AutoCloseable { dir.deleteRecursively() }
        return dir
    }

    private fun vaultFile(s: FakeDavServer) = s.files.getValue(FakeDavServer.VAULT).copyOf()

    private fun failure(outcome: SyncOutcome): FailureReason = (outcome as SyncOutcome.Failed).reason

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
            val vaultState = assertNotNull(st.vaults[a.content.vaultId])
            assertNotNull(vaultState.baseFile)
            assertEquals(a.content.revision, vaultState.highestRevision)
            assertEquals(1L, vaultState.highestKeyEpoch)
            assertNotNull(st.servers[a.store.serverKey]?.capabilities)
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
        val bytesFromB = b.hooks.encrypt(b.content).bytes
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
        val bytesFromB = b.hooks.encrypt(b.content).bytes
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
        val bytesFromB = b.hooks.encrypt(b.content).bytes
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

    /** Ignores preconditions, so every upload goes through the lock file with unconditional lock operations. */
    private fun lockedServer() = server(Config(honourIfMatch = false, honourIfNoneMatch = false))

    private fun seedLock(s: FakeDavServer, expiresAt: Long, deviceId: String = "someone-else", token: String = "tok") {
        s.files[FakeDavServer.LOCK] = LockFile.encode(LockInfo(deviceId, token, expiresAt))
    }

    private fun lockToken(s: FakeDavServer): String? = s.files[FakeDavServer.LOCK]?.let { LockFile.decode(it)?.token }

    @Test
    fun liveLockHeldByAnotherDeviceBlocksTheSync() {
        val s = lockedServer()
        seedLock(s, expiresAt = realNow() + 30_000)
        val a = Device("A", s, newVault())
        a.edit { it.upsertHost(host("one"), id = "h1") }
        assertEquals(FailureReason.Locked, failure(a.sync()))
        assertFalse(s.files.containsKey(FakeDavServer.VAULT))
        assertEquals("tok", lockToken(s), "someone else's lock must be left alone")
    }

    @Test
    fun anExpiredLockIsOnlyBrokenAfterTheGracePeriod() {
        val s = lockedServer()
        val a = Device("A", s, newVault())
        a.edit { it.upsertHost(host("one"), id = "h1") }

        seedLock(s, expiresAt = realNow() - 5_000) // expired, but inside the 30 s grace
        assertEquals(FailureReason.Locked, failure(a.sync()))
        assertEquals("tok", lockToken(s))

        seedLock(s, expiresAt = realNow() - 40_000) // expired and past the grace: takeover
        assertEquals(SyncOutcome.Pushed, a.sync())
        assertFalse(s.files.containsKey(FakeDavServer.LOCK))
    }

    @Test
    fun lockJudgementUsesTheServerClockSoDeviceClockSkewDoesNotMatter() {
        val s = lockedServer()
        // A device whose clock runs a day ahead must still respect a live lock ...
        val ahead = Device("A", s, newVault(), clock = { realNow() + 86_400_000L })
        ahead.edit { it.upsertHost(host("one"), id = "h1") }
        seedLock(s, expiresAt = realNow() + 30_000)
        assertEquals(FailureReason.Locked, failure(ahead.sync()))
        // ... and a device whose clock runs a day behind must still take over a long dead one.
        val behind = Device("B", s, newVault(), clock = { realNow() - 86_400_000L })
        behind.edit { it.upsertHost(host("two"), id = "h2") }
        seedLock(s, expiresAt = realNow() - 60_000)
        assertEquals(SyncOutcome.Pushed, behind.sync())
    }

    @Test
    fun ownLeftoverLockAndGarbageLocksAreBroken() {
        val s = lockedServer()
        val a = Device("A", s, newVault())
        a.edit { it.upsertHost(host("one"), id = "h1") }
        seedLock(s, expiresAt = realNow() + 30_000, deviceId = "A")
        assertEquals(SyncOutcome.Pushed, a.sync())
        s.files[FakeDavServer.LOCK] = "not json".toByteArray()
        a.edit { it.upsertHost(host("two"), id = "h2") }
        assertEquals(SyncOutcome.Pushed, a.sync())
    }

    @Test
    fun aLockCreatedByAnotherDeviceDuringOurAttemptWinsAndWeDoNotProceed() {
        // Weak-length ETags force the lock path while If-None-Match still makes lock creation atomic.
        val s = server(Config(etagOverride = "\"" + "a".repeat(300) + "\""))
        val a = Device("A", s, newVault())
        a.edit { it.upsertHost(host("one"), id = "h1") }
        s.beforeRequest = { method, name ->
            if (method == "PUT" && name == FakeDavServer.LOCK) {
                s.beforeRequest = null
                seedLock(s, expiresAt = realNow() + 60_000, deviceId = "B", token = "b-token")
            }
        }
        assertEquals(FailureReason.Locked, failure(a.sync()))
        assertFalse(s.files.containsKey(FakeDavServer.VAULT), "the loser of the lock race must not write")
        assertEquals("b-token", lockToken(s))
    }

    @Test
    fun aLockTakenOverDuringOurUploadIsNeverDeletedOnRelease() {
        val s = lockedServer()
        val a = Device("A", s, newVault())
        a.edit { it.upsertHost(host("one"), id = "h1") }
        s.beforeRequest = { method, name ->
            if (method == "PUT" && name == FakeDavServer.VAULT) {
                s.beforeRequest = null
                seedLock(s, expiresAt = realNow() + 60_000, deviceId = "B", token = "b-token")
            }
        }
        a.sync()
        assertEquals("b-token", lockToken(s), "another device's live lock must survive our release")
    }

    @Test
    fun aStaleLockIsDeletedConditionallyAndALockReplacedMeanwhileSurvives() {
        // Only If-None-Match is ignored: the lock can be replaced and deleted conditionally on its ETag.
        val s = server(Config(honourIfNoneMatch = false))
        val a = Device("A", s, newVault())
        a.edit { it.upsertHost(host("one"), id = "h1") }
        seedLock(s, expiresAt = realNow() - 60_000, token = "stale")
        s.beforeRequest = { method, name ->
            if (method == "DELETE" && name == FakeDavServer.LOCK) {
                s.beforeRequest = null
                // Another device breaks the same stale lock first and installs its own live one.
                seedLock(s, expiresAt = realNow() + 60_000, deviceId = "B", token = "live")
            }
        }
        assertEquals(FailureReason.Locked, failure(a.sync()))
        assertEquals("live", lockToken(s))
        assertTrue(s.requests("DELETE", FakeDavServer.LOCK).first().ifMatch != null, "the delete must be conditional")
        assertFalse(s.files.containsKey(FakeDavServer.VAULT))
    }

    @Test
    fun theLeaseIsRenewedBeforeTheUploadWhenLittleOfItRemains() {
        val s = lockedServer()
        val a = Device("A", s, newVault(), leaseMillis = 1_000, requestBudgetMillis = 5_000)
        a.edit { it.upsertHost(host("one"), id = "h1") }
        assertEquals(SyncOutcome.Pushed, a.sync())
        // The vault already exists on the first sync, so renewal only happens on an update.
        a.edit { it.upsertHost(host("two"), id = "h2") }
        val before = s.requests("PUT", FakeDavServer.LOCK).size
        assertEquals(SyncOutcome.Pushed, a.sync())
        assertTrue(s.requests("PUT", FakeDavServer.LOCK).size - before >= 2, "expected acquire plus renew")
        assertFalse(s.files.containsKey(FakeDavServer.LOCK))
    }

    // ------------------------------------------------------------------ rollback, replay and integrity

    @Test
    fun anOldRemoteFileReplayedAfterALocalEditIsRefusedAndNeverRevertsTheEdit() {
        val s = server()
        val (a, _) = twoDevices(s)
        val old = vaultFile(s)
        val oldRevision = records(a.content).getValue("h1").revision
        a.edit { it.upsertHost(host("edited"), id = "h1") }
        assertEquals(SyncOutcome.Pushed, a.sync())
        val editedRevision = records(a.content).getValue("h1").revision
        assertTrue(editedRevision > oldRevision)

        s.files[FakeDavServer.VAULT] = old // the server replays the pre-edit file
        val refused = a.syncResult()
        assertEquals(FailureReason.RollbackDetected, failure(refused.outcome))
        assertTrue(old.contentEquals(s.files.getValue(FakeDavServer.VAULT)), "a refused sync must not write")
        assertEquals(editedRevision, records(a.content).getValue("h1").revision)

        // Even with the explicit override the edit survives. The replayed version cannot be proven to be one this
        // device saw (it is not in its history), so it is reported as a conflict and kept in the history, not dropped.
        val healed = a.syncResult(SyncOptions(allowRollback = true))
        assertFalse(healed.outcome is SyncOutcome.Failed, "override must be honoured: ${healed.outcome}")
        assertEquals("h1", (healed.outcome as SyncOutcome.Merged).conflicts.single().recordId)
        assertTrue(a.content.history.any { it.id == "h1" && it.revision == oldRevision })
        assertEquals(editedRevision, records(remoteContent(s)).getValue("h1").revision)
        assertEquals(editedRevision, records(a.content).getValue("h1").revision)
    }

    @Test
    fun aServerServingAPreEditFileToASecondDeviceCannotRevertItsEdit() {
        val s = server()
        val (a, b) = twoDevices(s)
        val preEdit = vaultFile(s)
        a.edit { it.upsertHost(host("A's edit"), id = "h1") }
        assertEquals(SyncOutcome.Pushed, a.sync())
        assertEquals(SyncOutcome.Pulled, b.sync())
        b.edit { it.upsertHost(host("B's edit"), id = "h1") }
        val bRevision = records(b.content).getValue("h1").revision

        s.files[FakeDavServer.VAULT] = preEdit
        assertEquals(FailureReason.RollbackDetected, failure(b.sync()))
        val result = b.syncResult(SyncOptions(allowRollback = true))
        assertEquals("h1", (result.outcome as SyncOutcome.Merged).conflicts.single().recordId)
        assertEquals(bRevision, records(remoteContent(s)).getValue("h1").revision)
        assertEquals(bRevision, records(b.content).getValue("h1").revision)
    }

    @Test
    fun rollbackIsStillDetectedAfterARestartWhenTheFileStoreIsUsed() {
        val dir = tempDir()
        val s = server()
        val a = Device("A", s, newVault(), state = FileLocalStateStore(dir))
        a.edit { it.upsertHost(host("one"), id = "h1") }
        assertEquals(SyncOutcome.Pushed, a.sync())
        val old = vaultFile(s)
        a.edit { it.upsertHost(host("two"), id = "h2") }
        assertEquals(SyncOutcome.Pushed, a.sync())

        // "Restart": a new engine, a new store object on the same directory, the app's own copy of the content.
        val restarted = Device("A", s, openRemote(s), state = FileLocalStateStore(dir))
        restarted.content = a.content
        s.files[FakeDavServer.VAULT] = old
        assertEquals(FailureReason.RollbackDetected, failure(restarted.sync()))
        assertTrue(old.contentEquals(s.files.getValue(FakeDavServer.VAULT)))

        // Control: a device without persistent state has no memory of what it saw and accepts the old file.
        val amnesiac = Device("A", s, VaultCodec.open(old, "pw".toCharArray()))
        amnesiac.content = a.content
        assertFalse(amnesiac.sync() is SyncOutcome.Failed)
    }

    @Test
    fun twoDifferentFilesAtTheSameRevisionAreReportedAsAFork() {
        val s = server()
        val (a, b) = twoDevices(s)
        a.edit { it.upsertHost(host("from A"), id = "a1") }
        assertEquals(SyncOutcome.Pushed, a.sync())
        val revision = a.content.revision
        // A's push advanced its revision by more than one edit; edit B until both sit at the same revision.
        var edits = 0
        while (b.content.revision < revision && edits < 10) {
            b.edit { it.upsertHost(host("from B ${edits + 1}"), id = "b1") }
            edits++
        }
        assertEquals(revision, b.content.revision, "both devices wrote the same revision")
        s.files[FakeDavServer.VAULT] = b.hooks.encrypt(b.content).bytes // a different file, same revision

        val result = a.syncResult()
        assertFalse(result.outcome is SyncOutcome.Failed, "${result.outcome}")
        assertTrue(result.warnings.any { it is SyncWarning.ForkSuspected && it.revision == revision })
        assertEquals(setOf("h1", "a1", "b1"), records(a.content).keys) // nothing lost
    }

    @Test
    fun aRemoteFileThatVanishedIsNotSilentlyRecreatedAndNeverBelowTheFloor() {
        val s = server()
        val (a, _) = twoDevices(s)
        a.edit { it.upsertHost(host("two"), id = "h2") }
        assertEquals(SyncOutcome.Pushed, a.sync())
        val floor = a.content.revision
        s.files.remove(FakeDavServer.VAULT)

        val missing = a.syncResult()
        assertEquals(FailureReason.RemoteMissing, failure(missing.outcome))
        assertFalse(s.files.containsKey(FakeDavServer.VAULT), "nothing may be uploaded without the explicit option")

        val recreated = a.syncResult(SyncOptions(recreateRemote = true))
        assertEquals(SyncOutcome.Pushed, recreated.outcome)
        assertTrue(recreated.warnings.any { it is SyncWarning.RemoteRecreated })
        assertTrue(remoteContent(s).revision > floor, "the recreated file must be above the floor")
        assertEquals(setOf("h1", "h2"), records(remoteContent(s)).keys)
    }

    @Test
    fun aReplayedOldEpochIsRejectedAndNotUploadedAgain() {
        val s = server()
        val (a, b) = twoDevices(s)
        val old = vaultFile(s) // epoch 1
        val staged = a.hooks.stage { VaultCodec.changePassword(it, "second".toCharArray()) }
        assertEquals(SyncOutcome.Pushed, a.syncResult(staged = staged).outcome, "a slot change is published as a transaction")
        assertEquals(2L, VaultCodec.inspect(s.files.getValue(FakeDavServer.VAULT)).keyEpoch)
        b.syncResult(password = "second".toCharArray()) // B learns epoch 2
        assertEquals(2L, b.hooks.keyEpoch)

        s.files[FakeDavServer.VAULT] = old
        val puts = s.requests("PUT", FakeDavServer.VAULT).size
        val outcome = b.sync(SyncOptions(allowRollback = true)) // the override never waives the key-epoch floor
        assertEquals(FailureReason.KeyEpochRollback, failure(outcome))
        assertEquals(puts, s.requests("PUT", FakeDavServer.VAULT).size)
        assertTrue(old.contentEquals(s.files.getValue(FakeDavServer.VAULT)))
    }

    @Test
    fun aPasswordChangeIsPublishedOtherDevicesMustEnterThePasswordAndAnOldEpochIsNeverUploadedAgain() {
        val s = server()
        val (a, b) = twoDevices(s)
        val old = vaultFile(s) // epoch 1
        val staged = a.hooks.stage { VaultCodec.changePassword(it, "new".toCharArray()) }
        val rotated = a.syncResult(staged = staged)
        assertEquals(SyncOutcome.Pushed, rotated.outcome)
        assertEquals(2L, a.hooks.keyEpoch, "the change is committed after the confirmed upload")
        assertEquals(2L, VaultCodec.inspect(s.files.getValue(FakeDavServer.VAULT)).keyEpoch)
        assertEquals(setOf("h1"), records(remoteContent(s, "new")).keys)

        // B still holds the epoch 1 key: it is asked for the password and writes nothing. The chain is verified.
        val puts = s.requests("PUT", FakeDavServer.VAULT).size
        val asked = b.syncResult()
        assertEquals(FailureReason.ReopenRequired, failure(asked.outcome))
        assertTrue(asked.warnings.isEmpty(), "a correctly chained re-key carries no warning")
        assertEquals(puts, s.requests("PUT", FakeDavServer.VAULT).size)

        // A wrong password changes nothing; the right one adopts the new key and continues.
        assertEquals(FailureReason.BadPasswordOrCorrupt, failure(b.syncResult(password = "nope".toCharArray()).outcome))
        assertEquals(1L, b.hooks.keyEpoch)
        b.edit { it.upsertHost(host("from B"), id = "b1") }
        val joined = b.syncResult(password = "new".toCharArray())
        assertFalse(joined.outcome is SyncOutcome.Failed, "${joined.outcome}")
        assertEquals(2L, b.hooks.keyEpoch)
        assertEquals(setOf("h1", "b1"), records(remoteContent(s, "new")).keys)
        assertTrue(joined.warnings.none { it is SyncWarning.KeyEpochChainUnverified })

        // A can keep syncing; a replayed epoch 1 file is a rollback and is not written over.
        assertEquals(SyncOutcome.Pulled, a.sync())
        s.files[FakeDavServer.VAULT] = old
        assertEquals(FailureReason.KeyEpochRollback, failure(a.sync(SyncOptions(allowRollback = true))))
        assertTrue(old.contentEquals(s.files.getValue(FakeDavServer.VAULT)))
    }

    @Test
    fun aReKeyThatIsNotChainedToTheHeldKeyIsReportedEvenWhenThePasswordOpensIt() {
        val s = server()
        val (a, b) = twoDevices(s)
        // Someone who knows a password for this vault id (not the one the honest devices use) re-keys the vault.
        val attackerRoot = VaultCodec.create("evil".toCharArray(), fast, vaultId = a.content.vaultId)
        val attacker = VaultCodec.changePassword(attackerRoot, "evil2".toCharArray())
        val minted = attacker.withContent(a.content.copy(revision = a.content.revision + 1))
        s.files[FakeDavServer.VAULT] = VaultCodec.seal(minted)

        val asked = b.syncResult()
        assertEquals(FailureReason.ReopenRequired, failure(asked.outcome))
        assertTrue(asked.warnings.any { it is SyncWarning.KeyEpochChainUnverified && it.fromEpoch == 1L && it.toEpoch == 2L })
        // The honest password does not open it at all.
        assertEquals(FailureReason.BadPasswordOrCorrupt, failure(b.syncResult(password = "pw".toCharArray()).outcome))
        // A password that does open it still gets the warning.
        val opened = b.syncResult(password = "evil2".toCharArray())
        assertTrue(opened.warnings.any { it is SyncWarning.KeyEpochChainUnverified })
    }

    @Test
    fun aPasswordChangeIsRefusedWhenTheRemoteChangedSinceTheLastSync() {
        val s = server()
        val (a, b) = twoDevices(s)
        b.edit { it.upsertHost(host("written at the old epoch"), id = "b1") }
        assertEquals(SyncOutcome.Pushed, b.sync())

        // Content changed remotely: the change is refused, nothing is uploaded and nothing changes locally.
        val staged = a.hooks.stage { VaultCodec.changePassword(it, "new".toCharArray()) }
        val puts = s.requests("PUT", FakeDavServer.VAULT).size
        assertEquals(FailureReason.RemoteChangedDuringRotation, failure(a.syncResult(staged = staged).outcome))
        assertEquals(puts, s.requests("PUT", FakeDavServer.VAULT).size)
        assertEquals(1L, a.hooks.keyEpoch)
        staged.discard()

        // A normal sync imports (and reports) what was written; the repeated change then goes through.
        assertEquals(SyncOutcome.Pulled, a.sync())
        val again = a.hooks.stage { VaultCodec.changePassword(it, "new".toCharArray()) }
        assertEquals(SyncOutcome.Pushed, a.syncResult(staged = again).outcome)
        assertEquals(setOf("h1", "b1"), records(remoteContent(s, "new")).keys)
    }

    @Test
    fun aPasswordChangePreparedBeforeAnotherDevicesRotationIsRefusedAndNothingIsLost() {
        val s = server()
        val (a, b) = twoDevices(s)
        val stagedA = a.hooks.stage { VaultCodec.changePassword(it, "slot A".toCharArray()) }
        val stagedB = b.hooks.stage { VaultCodec.changePassword(it, "slot B".toCharArray()) }
        assertEquals(SyncOutcome.Pushed, a.syncResult(staged = stagedA).outcome)
        // B prepared its change against epoch 1; the remote is at 2 now.
        val refused = b.syncResult(staged = stagedB, password = "slot A".toCharArray())
        assertTrue(refused.outcome is SyncOutcome.Failed, "${refused.outcome}")
        stagedB.discard()
        assertTrue(b.hooks.keyEpoch <= 2L)
        // The remote is still A's rotation, readable with A's password.
        assertEquals(2L, VaultCodec.inspect(s.files.getValue(FakeDavServer.VAULT)).keyEpoch)
        assertEquals(setOf("h1"), records(remoteContent(s, "slot A")).keys)
        // Re-applying on top of it works.
        b.syncResult(password = "slot A".toCharArray())
        val reapplied = b.hooks.stage { VaultCodec.changePassword(it, "slot B".toCharArray()) }
        assertEquals(SyncOutcome.Pushed, b.syncResult(staged = reapplied).outcome)
        assertEquals(3L, VaultCodec.inspect(s.files.getValue(FakeDavServer.VAULT)).keyEpoch)
    }

    // ------------------------------------------------------------------ hostile files (T-B1)

    private fun hostileSetup(): Triple<FakeDavServer, Device, Device> {
        val s = server()
        val (a, b) = twoDevices(s)
        return Triple(s, a, b)
    }

    private fun assertRefusedAndUntouched(s: FakeDavServer, victim: Device, forged: ByteArray, expected: FailureReason) {
        s.files[FakeDavServer.VAULT] = forged
        val puts = s.requests("PUT", FakeDavServer.VAULT).size
        val before = victim.content
        val outcome = victim.sync()
        assertEquals(expected, failure(outcome), "$outcome")
        assertEquals(puts, s.requests("PUT", FakeDavServer.VAULT).size, "a refused file is never overwritten")
        assertEquals(before, victim.content)
        assertTrue(forged.contentEquals(s.files.getValue(FakeDavServer.VAULT)))
    }

    @Test
    fun aSubstitutedPasswordSlotUnderTheHeldKeyIsRefusedByEveryDevice() {
        val (s, a, b) = hostileSetup()
        val key = HostileFiles.keyOf(a.vault.exportLocalUnlockSecret())
        val genuine = vaultFile(s)
        val attackerSlot = HostileFiles.slotOf(VaultCodec.seal(VaultCodec.create("evil".toCharArray(), fast)))
        val forged = HostileFiles.forge(genuine, key) {
            it.replace(Regex("\\{\"id\":\"pw-[0-9a-f]{16}\",\"type\":\"password\"[^{}]*\\}"), attackerSlot)
        }
        assertRefusedAndUntouched(s, b, forged, FailureReason.HeaderMismatchSameEpoch)
        // The device is not stuck: the genuine file is accepted again, and the password still changes.
        s.files[FakeDavServer.VAULT] = genuine
        assertFalse(b.sync() is SyncOutcome.Failed)
        val staged = b.hooks.stage { VaultCodec.changePassword(it, "next".toCharArray()) }
        assertEquals(SyncOutcome.Pushed, b.syncResult(staged = staged).outcome)
    }

    @Test
    fun aSecondPasswordSlotAddedUnderTheHeldKeyIsAnInvalidFile() {
        val (s, a, b) = hostileSetup()
        val key = HostileFiles.keyOf(a.vault.exportLocalUnlockSecret())
        val genuine = vaultFile(s)
        val slot = HostileFiles.slotOf(genuine)
        val extra = slot.replace(Regex("pw-[0-9a-f]{16}"), "pw-ffffffffffffffff")
        val forged = HostileFiles.forge(genuine, key) { it.replace(slot, "$slot,$extra") }
        s.files[FakeDavServer.VAULT] = forged
        val outcome = b.sync()
        assertTrue(outcome is SyncOutcome.Failed, "$outcome")
        assertTrue(failure(outcome) in setOf(FailureReason.InvalidRemoteFile, FailureReason.BadPasswordOrCorrupt, FailureReason.IntegrityFailure), "$outcome")
        assertTrue(forged.contentEquals(s.files.getValue(FakeDavServer.VAULT)))
    }

    @Test
    fun anInflatedHeaderRevisionFieldIsAnInvalidFileNotAFloor() {
        val (s, a, b) = hostileSetup()
        val key = HostileFiles.keyOf(a.vault.exportLocalUnlockSecret())
        val genuine = vaultFile(s)
        val forged = HostileFiles.forge(genuine, key) { it.replace("\"keyEpoch\":1", "\"keyEpoch\":1,\"headerRevision\":9007199254740000") }
        s.files[FakeDavServer.VAULT] = forged
        val outcome = b.sync()
        assertTrue(outcome is SyncOutcome.Failed, "$outcome")
        // The genuine file is still accepted afterwards: no floor was poisoned.
        s.files[FakeDavServer.VAULT] = genuine
        assertFalse(b.sync() is SyncOutcome.Failed)
    }

    @Test
    fun aStagedChangeNeedsAnExistingRemote() {
        val s = server()
        val a = Device("A", s, newVault())
        val staged = a.hooks.stage { VaultCodec.changePassword(it, "new".toCharArray()) }
        assertEquals(FailureReason.RemoteMissing, failure(a.syncResult(staged = staged).outcome))
        staged.discard()
    }

    // ------------------------------------------------------------------ revision inflation

    private fun withRevision(source: Device, revision: Long): ByteArray {
        val c = source.content
        val inflated = c.copy(
            revision = revision,
            records = c.records.map { it.copy(revision = revision) },
        )
        return source.hooks.encrypt(inflated).bytes
    }

    @Test
    fun aRemoteThatJumpsFarAboveTheFloorIsNotMergedAndLocalEditingStillWorks() {
        val s = server()
        val (a, b) = twoDevices(s)
        val floor = a.content.revision
        s.files[FakeDavServer.VAULT] = withRevision(b, floor + MAX_REVISION_JUMP + 1)
        assertEquals(FailureReason.SuspiciousRevisionJump, failure(a.sync()))
        a.edit { it.upsertHost(host("still editable"), id = "h2") }
        // A jump within the bound is accepted.
        s.files[FakeDavServer.VAULT] = withRevision(b, floor + MAX_REVISION_JUMP)
        assertFalse(a.sync() is SyncOutcome.Failed)
    }

    @Test
    fun acceptRevisionJumpAcceptsAFarJumpAndReportsItButNeverAnImpossibleRevision() {
        val s = server()
        val (a, b) = twoDevices(s)
        val floor = a.content.revision
        s.files[FakeDavServer.VAULT] = withRevision(b, floor + MAX_REVISION_JUMP + 1)
        assertEquals(FailureReason.SuspiciousRevisionJump, failure(a.sync()))
        val accepted = a.syncResult(SyncOptions(acceptRevisionJump = true))
        assertFalse(accepted.outcome is SyncOutcome.Failed, "${accepted.outcome}")
        assertTrue(accepted.warnings.any { it is SyncWarning.RevisionJumpAccepted && it.floor == floor })

        // A revision at the format limit stays refused whatever the option says.
        val (s2, _, b2) = hostileSetup()
        val fresh = Device("F", s2, VaultCodec.open(vaultFile(s2), "pw".toCharArray()))
        s2.files[FakeDavServer.VAULT] = withRevision(b2, MAX_REVISION - 1)
        val outcome = fresh.sync(SyncOptions(acceptRevisionJump = true))
        assertTrue(outcome is SyncOutcome.Failed, "$outcome")
    }

    @Test
    fun aSameEpochFileUnderAnotherKeyIsOnlyOpenedByThePasswordAndIsReported() {
        val s = server()
        val (a, b) = twoDevices(s)
        // Two devices created the same vault id independently: same epoch, different keys.
        val rival = VaultCodec.create("rival".toCharArray(), fast, vaultId = a.content.vaultId)
        s.files[FakeDavServer.VAULT] = VaultCodec.seal(rival.withContent(a.content.copy(revision = a.content.revision + 1)))
        val puts = s.requests("PUT", FakeDavServer.VAULT).size
        val asked = b.syncResult()
        // A same-epoch competitor is never adopted on a password alone (a holder of an OLD password could forge it).
        assertEquals(FailureReason.KeyMismatchSameEpoch, failure(asked.outcome))
        val shown = assertNotNull(asked.failureInfo?.competingKeyFingerprint)
        assertEquals(puts, s.requests("PUT", FakeDavServer.VAULT).size)
        assertEquals(
            FailureReason.KeyMismatchSameEpoch,
            failure(b.syncResult(password = "rival".toCharArray()).outcome),
            "the right password without the fingerprint confirmation adopts nothing",
        )
        assertEquals(
            FailureReason.BadPasswordOrCorrupt,
            failure(b.syncResult(SyncOptions(adoptCompetingKeyFingerprint = shown), password = "pw".toCharArray()).outcome),
        )
        assertEquals(
            FailureReason.KeyMismatchSameEpoch,
            failure(b.syncResult(SyncOptions(adoptCompetingKeyFingerprint = "0000-0000"), password = "rival".toCharArray()).outcome),
            "a fingerprint that is not the one shown confirms nothing",
        )
        val opened = b.syncResult(SyncOptions(adoptCompetingKeyFingerprint = shown), password = "rival".toCharArray())
        assertFalse(opened.outcome is SyncOutcome.Failed, "${opened.outcome}")
        assertTrue(opened.warnings.any { it is SyncWarning.ConcurrentRekeyAdopted && it.epoch == 1L }, "${opened.warnings}")
    }

    @Test
    fun aKeyEpochWarningIsRepeatedByEverySyncEvenWhenItFails() {
        val s = server()
        val (a, b) = twoDevices(s)
        val attackerRoot = VaultCodec.create("evil".toCharArray(), fast, vaultId = a.content.vaultId)
        val attacker = VaultCodec.changePassword(attackerRoot, "evil2".toCharArray())
        s.files[FakeDavServer.VAULT] = VaultCodec.seal(attacker.withContent(a.content.copy(revision = a.content.revision + 1)))
        assertTrue(b.syncResult(password = "evil2".toCharArray()).warnings.any { it is SyncWarning.KeyEpochChainUnverified })
        // A later sync that fails for another reason still carries the warning.
        s.files.remove(FakeDavServer.VAULT)
        val failed = b.syncResult()
        assertEquals(FailureReason.RemoteMissing, failure(failed.outcome))
        assertTrue(failed.warnings.any { it is SyncWarning.KeyEpochChainUnverified }, "${failed.warnings}")
    }

    @Test
    fun theSealedPendingRotationIsWrittenBeforeTheUploadAndClearedWhenItIsRefused() {
        val s = server()
        val (a, _) = twoDevices(s)
        var pendingAtPut: ByteArray? = null
        s.beforeNextPut = { pendingAtPut = runBlocking { a.state.load() }.vaults.values.single().pendingLocalFile }
        val staged = a.hooks.stage { VaultCodec.changePassword(it, "new".toCharArray()) }
        assertEquals(SyncOutcome.Pushed, a.syncResult(staged = staged).outcome)
        assertEquals(2L, VaultCodec.inspect(checkNotNull(pendingAtPut) { "no pending rotation was written before the PUT" }).keyEpoch)
        assertEquals(null, runBlocking { a.state.load() }.vaults.values.single().pendingLocalFile, "cleared once committed")
        assertEquals(2L, VaultCodec.inspect(runBlocking { a.state.load() }.vaults.values.single().localFile!!).keyEpoch)
    }

    @Test
    fun aFreshDeviceRefusesARevisionNearTheLimitButAcceptsAnOrdinaryOne() {
        val s = server()
        val (a, _) = twoDevices(s)
        val normal = vaultFile(s)
        s.files[FakeDavServer.VAULT] = withRevision(a, MAX_REVISION - 5)
        val fresh = Device("F", s, VaultCodec.open(normal, "pw".toCharArray()))
        assertEquals(FailureReason.SuspiciousRevisionJump, failure(fresh.sync()))
        s.files[FakeDavServer.VAULT] = withRevision(a, 1000L)
        assertFalse(fresh.sync() is SyncOutcome.Failed)
    }

    // ------------------------------------------------------------------ never drop a genuine edit

    // R-S1 case 3: the app died after the sync state was saved but before the content was; the next edit is made
    // on the stale content. Nothing is lost: the older-numbered edit goes to the history as a conflict.
    @Test
    fun anEditMadeOnStaleContentAfterACrashIsKeptNotDiscarded() {
        val s = server()
        val (a, _) = twoDevices(s)
        val stale = a.content
        a.edit { it.upsertHost(host("v2"), id = "h1") }
        a.edit { it.upsertHost(host("v3"), id = "h1") }
        assertEquals(SyncOutcome.Pushed, a.sync())
        // "Crash": the app comes back with the content it had before the last two edits, and edits again.
        a.content = stale
        a.edit { it.upsertHost(host("my new edit after the crash"), id = "h1") }
        val result = a.syncResult()
        assertFalse(result.outcome is SyncOutcome.Failed, "${result.outcome}")
        assertTrue(result.warnings.none { it is SyncWarning.StaleRemoteIgnored })
        val labels = (a.content.history + a.content.records).filter { it.id == "h1" }
            .map { it.payload["label"].toString() }
        assertTrue(labels.any { it.contains("my new edit after the crash") }, "the edit must survive somewhere: $labels")
    }

    @Test
    fun theFirstSyncOfAnExistingRemoteIsReportedAsTrustOnFirstUse() {
        val s = server()
        val a = Device("A", s, newVault())
        a.edit { it.upsertHost(host("one"), id = "h1") }
        assertTrue(a.syncResult().warnings.isEmpty(), "creating the vault is not a trust decision")

        val b = Device("B", s, openRemote(s))
        val first = b.syncResult()
        assertEquals(SyncOutcome.UpToDate, first.outcome)
        val trust = first.warnings.filterIsInstance<SyncWarning.FirstUseTrust>().single()
        assertEquals(a.content.revision, trust.remoteRevision)
        assertEquals(1L, trust.keyEpoch)
        assertTrue(b.syncResult().warnings.none { it is SyncWarning.FirstUseTrust })
    }

    @Test
    fun anUnusableEtagMakesTheEngineFallBackToTheLockInsteadOfSendingIt() {
        val s = server(Config(etagOverride = "\"" + "a".repeat(300) + "\""))
        val a = Device("A", s, newVault())
        a.edit { it.upsertHost(host("one"), id = "h1") }
        assertEquals(SyncOutcome.Pushed, a.sync())
        a.edit { it.upsertHost(host("two"), id = "h2") }
        assertEquals(SyncOutcome.Pushed, a.sync())
        assertTrue(s.requests("PUT", FakeDavServer.VAULT).all { it.ifMatch == null })
        assertTrue(s.requests("PUT", FakeDavServer.LOCK).isNotEmpty())
        assertEquals(setOf("h1", "h2"), records(remoteContent(s)).keys)
    }

    @Test
    fun unreadableLocalStateFailsClosedInsteadOfSwitchingRollbackProtectionOff() {
        val dir = tempDir()
        val s = server()
        val a = Device("A", s, newVault(), state = FileLocalStateStore(dir))
        a.edit { it.upsertHost(host("one"), id = "h1") }
        assertEquals(SyncOutcome.Pushed, a.sync())
        File(dir, FileLocalStateStore.DEFAULT_FILE_NAME).writeBytes(ByteArray(100) { 7 })

        val restarted = Device("A", s, openRemote(s), state = FileLocalStateStore(dir))
        restarted.content = a.content
        assertEquals(FailureReason.LocalStateUnavailable, failure(restarted.sync()))
    }

    @Test
    fun tamperedGarbageAndForeignRemoteFilesFailCleanly() {
        val s = server()
        val (a, _) = twoDevices(s)
        val good = s.files.getValue(FakeDavServer.VAULT)

        s.files[FakeDavServer.VAULT] = good.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        assertEquals(FailureReason.BadPasswordOrCorrupt, failure(a.sync()))

        s.files[FakeDavServer.VAULT] = Random(5).nextBytes(500)
        assertEquals(FailureReason.InvalidRemoteFile, (a.sync() as SyncOutcome.Failed).reason)

        val foreign = Device("X", server(), newVault())
        foreign.edit { it.upsertHost(host("other vault"), id = "x") }
        s.files[FakeDavServer.VAULT] = foreign.hooks.encrypt(foreign.content).bytes
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
