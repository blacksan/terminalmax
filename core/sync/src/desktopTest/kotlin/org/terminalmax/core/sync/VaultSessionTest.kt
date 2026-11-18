// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.sync

import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.random.Random
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.terminalmax.core.vault.HostPayload
import org.terminalmax.core.vault.KdfParams
import org.terminalmax.core.vault.VaultCodec
import org.terminalmax.core.vault.VaultException

class VaultSessionTest {
    private val cleanup = CopyOnWriteArrayList<AutoCloseable>()
    private val fast = KdfParams(memoryKiB = 8 * 1024, iterations = 1, parallelism = 1)
    private val tuning = SessionTuning(clock = { 10_000_000L }, random = Random(1), sleep = { })

    @AfterTest
    fun tearDown() {
        cleanup.forEach { runCatching { it.close() } }
    }

    private fun dir(): File {
        val d = Files.createTempDirectory("tmx-session-test").toFile()
        cleanup += AutoCloseable { d.deleteRecursively() }
        return d
    }

    private fun server(): FakeDavServer = FakeDavServer(FakeDavServer.Config()).also { cleanup += it }

    private fun remote(s: FakeDavServer) = WebDavStore(s.baseUrl, "u", "p".toCharArray())

    private fun host(label: String) = HostPayload(label, "10.0.0.1", 22, "admin")

    private suspend fun create(d: File = dir(), password: String = "pw") =
        VaultSession.create(d, password.toCharArray(), fast, tuning).also { cleanup += it }

    private suspend fun VaultSession.addHost(label: String, id: String) = edit { it.upsertHost(host(label), id = id) }

    @Test
    fun createEditCloseAndOpenAgainKeepsEveryCommittedEdit() = runBlocking<Unit> {
        val d = dir()
        val session = create(d)
        session.addHost("one", "h1")
        session.addHost("two", "h2")
        val expected = session.content.value
        session.close()

        val reopened = VaultSession.open(d, "pw".toCharArray(), tuning = tuning).also { cleanup += it }
        assertEquals(expected, reopened.content.value)
        reopened.close()
        assertFailsWith<VaultException.BadPasswordOrCorrupt> { VaultSession.open(d, "wrong".toCharArray(), tuning = tuning) }
        assertFailsWith<VaultSessionException.DirectoryHoldsVault> { VaultSession.create(d, "pw".toCharArray(), fast, tuning) }
    }

    @Test
    fun aFailedEditChangesNothingAndIsNotPersisted() = runBlocking<Unit> {
        val d = dir()
        val session = create(d)
        session.addHost("one", "h1")
        val before = session.content.value
        assertFailsWith<IllegalStateException> { session.edit { it.upsertHost(host("half"), id = "h2"); error("boom") } }
        assertEquals(before, session.content.value)
        session.close()
        val again = VaultSession.open(d, "pw".toCharArray(), tuning = tuning).also { cleanup += it }
        assertEquals(before, again.content.value)
    }

    @Test
    fun theLocalUnlockSecretOpensTheSameEpochOnlyAndRevocationIsAPasswordChange() = runBlocking<Unit> {
        val d = dir()
        val session = create(d)
        session.addHost("one", "h1")
        val secret = session.exportLocalUnlockSecret()
        session.close()

        val viaSecret = VaultSession.openWithLocalUnlockSecret(d, secret, tuning).also { cleanup += it }
        assertEquals(1, viaSecret.content.value.records.size)

        // A password change (local-only vault) re-keys: the old secret stops working, the password does.
        viaSecret.changePassword("pw".toCharArray(), "new".toCharArray())
        viaSecret.close()
        val e = assertFailsWith<VaultException.KeyEpochMismatch> { VaultSession.openWithLocalUnlockSecret(d, secret, tuning) }
        assertEquals(2L, e.found)
        assertEquals(1L, e.expected)
        assertFailsWith<VaultException.BadPasswordOrCorrupt> { VaultSession.open(d, "pw".toCharArray(), tuning = tuning) }
        VaultSession.open(d, "new".toCharArray(), tuning = tuning).also { cleanup += it }
    }

    @Test
    fun syncMergesPersistsAndASecondDeviceFollows() = runBlocking<Unit> {
        val s = server()
        val a = create(dir())
        a.addHost("one", "h1")
        assertEquals(SyncOutcome.Pushed, a.sync(remote(s)).outcome)

        // Device B starts from the uploaded file (enrolment by password) and syncs.
        val dirB = dir()
        val bSession = enrol(dirB, s)
        bSession.addHost("from B", "b1")
        assertEquals(SyncOutcome.Pushed, bSession.sync(remote(s)).outcome)
        assertEquals(SyncOutcome.Pulled, a.sync(remote(s)).outcome)
        assertEquals(setOf("h1", "b1"), a.content.value.records.map { it.id }.toSet())
    }

    /** Enrols a second device the supported way: preview the remote vault, then confirm. */
    private suspend fun enrol(dirB: File, s: FakeDavServer): VaultSession =
        VaultSession.join(dirB, remote(s), "pw".toCharArray(), tuning = tuning).confirm().also { cleanup += it }

    @Test
    fun anEditMadeWhileASyncIsInFlightIsNeverBlockedNorLostAndStaysPending() = runBlocking<Unit> {
        val s = server()
        val a = create(dir())
        a.addHost("one", "h1")
        val started = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        s.beforeNextPut = {
            started.complete(Unit)
            runBlocking { release.await() }
        }
        val syncing = async(kotlinx.coroutines.Dispatchers.Default) { a.sync(remote(s)) }
        started.await()
        // The network call is in flight: the edit neither waits for it nor is it overwritten by its result.
        withTimeout(10_000) { a.addHost("during sync", "h2") }
        release.complete(Unit)
        val result = syncing.await()
        assertFalse(result.outcome is SyncOutcome.Failed, "${result.outcome}")
        assertTrue(result.localEditsPending, "the result says that edits made meanwhile are still to be synced")
        assertEquals(setOf("h1", "h2"), a.content.value.records.map { it.id }.toSet())
        assertEquals(setOf("h1"), VaultCodec.open(s.files.getValue(FakeDavServer.VAULT), "pw".toCharArray()).content.records.map { it.id }.toSet())
        val next = a.sync(remote(s))
        assertEquals(SyncOutcome.Pushed, next.outcome)
        assertFalse(next.localEditsPending)
        assertEquals(setOf("h1", "h2"), VaultCodec.open(s.files.getValue(FakeDavServer.VAULT), "pw".toCharArray()).content.records.map { it.id }.toSet())
    }

    @Test
    fun theLocalVaultAndTheSyncStateAreOneAtomicFile() = runBlocking<Unit> {
        val d = dir()
        val s = server()
        val a = create(d)
        a.addHost("one", "h1")
        a.sync(remote(s))
        val file = File(d, FileLocalStateStore.DEFAULT_FILE_NAME)
        assertTrue(file.exists())
        assertEquals(listOf(file.name, file.name + ".lock", file.name + ".prev").sorted(), d.list()!!.sorted())

        // A crash between the temp write and the rename leaves the previous pair intact.
        val store = FileLocalStateStore(d)
        val before = store.load()
        store.beforeRenameHook = { throw IllegalStateException("crash") }
        assertFailsWith<IllegalStateException> { store.save(before.copy(deviceId = "other")) }
        store.beforeRenameHook = null
        val after = FileLocalStateStore(d).load()
        assertEquals(before, after)
        assertContentEquals(before.vaults.values.single().localFile, after.vaults.values.single().localFile)
    }

    @Test
    fun anEditAfterACrashThatLostTheContentIsKeptEvenThoughItsRevisionIsBelowTheSyncedOne() = runBlocking<Unit> {
        val d = dir()
        val s = server()
        val a = create(d)
        a.addHost("v1", "h1")
        a.sync(remote(s))
        a.addHost("v2", "h1")
        a.addHost("v3", "h1")
        a.sync(remote(s))
        a.close()
        // The next process opens the vault: edits are numbered above the synced floor.
        val b = VaultSession.open(d, "pw".toCharArray(), tuning = tuning).also { cleanup += it }
        b.addHost("v4", "h1")
        val record = b.content.value.records.single { it.id == "h1" }
        assertTrue(record.revision > 3)
        assertEquals(SyncOutcome.Pushed, b.sync(remote(s)).outcome)
    }

    @Test
    fun changingThePasswordOfASyncedVaultIsATransactionOtherDevicesFollowWithThePassword() = runBlocking<Unit> {
        val s = server()
        val a = create(dir())
        a.addHost("one", "h1")
        a.sync(remote(s))
        val b = enrol(dir(), s)
        b.sync(remote(s))

        assertFailsWith<IllegalStateException> { a.changePassword("pw".toCharArray(), "new".toCharArray()) } // needs the remote
        assertFailsWith<VaultException.BadPasswordOrCorrupt> {
            a.changePassword("wrong".toCharArray(), "new".toCharArray(), remote(s))
        }
        val changed = a.changePassword("pw".toCharArray(), "new".toCharArray(), remote(s))
        assertFalse(changed.sync.outcome is SyncOutcome.Failed, "${changed.sync.outcome}")
        assertTrue(changed.rekeyed)
        assertEquals(2L, VaultCodec.inspect(s.files.getValue(FakeDavServer.VAULT)).keyEpoch)

        val asked = b.sync(remote(s))
        assertEquals(FailureReason.ReopenRequired, (asked.outcome as SyncOutcome.Failed).reason)
        b.addHost("from B", "b1")
        val joined = b.sync(remote(s), reopenPassword = "new".toCharArray())
        assertFalse(joined.outcome is SyncOutcome.Failed, "${joined.outcome}")
        assertEquals(setOf("h1", "b1"), b.content.value.records.map { it.id }.toSet())
        assertEquals(SyncOutcome.Pulled, a.sync(remote(s)).outcome)
        b.close()
    }

    @Test
    fun aRestartAfterAdoptingAReKeyOpensWithTheNewPassword() = runBlocking<Unit> {
        val s = server()
        val a = create(dir())
        a.addHost("one", "h1")
        a.sync(remote(s))
        val dirB = dir()
        val b = enrol(dirB, s)
        b.sync(remote(s))
        a.changePassword("pw".toCharArray(), "new".toCharArray(), remote(s))
        b.sync(remote(s), reopenPassword = "new".toCharArray())
        b.close()
        assertFailsWith<VaultException.BadPasswordOrCorrupt> { VaultSession.open(dirB, "pw".toCharArray(), tuning = tuning) }
        VaultSession.open(dirB, "new".toCharArray(), tuning = tuning).also { cleanup += it }
    }

    @Test
    fun aPasswordChangeBeforeTheUploadIsConfirmedLeavesTheOldEpochIntact() = runBlocking<Unit> {
        val d = dir()
        val s = server()
        val a = create(d)
        a.addHost("one", "h1")
        a.sync(remote(s))
        // The server refuses the re-keyed upload.
        s.beforeNextPut = { throw RuntimeException("connection dropped") }
        val result = a.changePassword("pw".toCharArray(), "new".toCharArray(), remote(s))
        assertIs<SyncOutcome.Failed>(result.sync.outcome)
        assertFalse(result.rekeyed)
        assertEquals(1L, a.keyEpoch.value)
        s.beforeNextPut = null
        a.close()
        // Old password and epoch are intact locally and remotely; the next sync drops the unpublished change.
        val reopened = VaultSession.open(d, "pw".toCharArray(), tuning = tuning).also { cleanup += it }
        assertEquals(1L, VaultCodec.inspect(s.files.getValue(FakeDavServer.VAULT)).keyEpoch)
        assertNotEquals(0, reopened.content.value.records.size)
        assertFalse(reopened.sync(remote(s)).outcome is SyncOutcome.Failed)
        assertEquals(null, FileLocalStateStore(d).load().vaults.values.single().pendingLocalFile)
        reopened.close()
        assertFailsWith<VaultException.BadPasswordOrCorrupt> { VaultSession.open(d, "new".toCharArray(), tuning = tuning) }
    }

    // ------------------------------------------------------------------ crash points of a password change

    /** Runs a password change whose PUT is dropped; returns the directory with the pending rotation in it. */
    private suspend fun dropRotationUpload(s: FakeDavServer): Pair<File, ByteArray> {
        val d = dir()
        val a = create(d)
        a.addHost("one", "h1")
        a.sync(remote(s))
        s.beforeNextPut = { throw RuntimeException("connection dropped") }
        a.changePassword("pw".toCharArray(), "new".toCharArray(), remote(s))
        s.beforeNextPut = null
        a.close()
        val pending = checkNotNull(FileLocalStateStore(d).load().vaults.values.single().pendingLocalFile) { "no pending rotation" }
        assertEquals(2L, VaultCodec.inspect(pending).keyEpoch)
        return d to pending
    }

    @Test
    fun crashBeforeTheUploadTheNewPasswordOpensThePendingFileButItIsNotPublished() = runBlocking<Unit> {
        val s = server()
        val (d, _) = dropRotationUpload(s)
        val viaNew = VaultSession.open(d, "new".toCharArray(), tuning = tuning).also { cleanup += it }
        assertEquals(2L, viaNew.keyEpoch.value)
        assertTrue(viaNew.hasUnresolvedPasswordChange)
        val result = viaNew.sync(remote(s))
        assertEquals(FailureReason.PendingRotationUnpublished, (result.outcome as SyncOutcome.Failed).reason)
        assertEquals(1L, VaultCodec.inspect(s.files.getValue(FakeDavServer.VAULT)).keyEpoch, "nothing was uploaded")
        // The explicit recovery: publish this device's copy as a new epoch.
        assertFailsWith<VaultSessionException.ConfirmationRequired> { viaNew.replaceRemoteWithLocal(remote(s), "new".toCharArray()) }
        val replaced = viaNew.replaceRemoteWithLocal(remote(s), "new".toCharArray(), confirm = true)
        assertTrue(replaced.replaced, "${replaced.sync.outcome}")
        assertTrue(VaultCodec.inspect(s.files.getValue(FakeDavServer.VAULT)).keyEpoch > 2L)
        assertTrue(replaced.sync.warnings.any { it is SyncWarning.RemoteReplaced })
        assertEquals(setOf("h1"), VaultCodec.open(s.files.getValue(FakeDavServer.VAULT), "new".toCharArray()).content.records.map { it.id }.toSet())
    }

    @Test
    fun crashAfterTheUploadLandedBothPasswordsResolveToTheNewEpoch() = runBlocking<Unit> {
        // The old password: the committed file is epoch 1; the server has epoch 2 -> re-open with the new password.
        run {
            val s = server()
            val (d, pending) = dropRotationUpload(s)
            s.files[FakeDavServer.VAULT] = pending // the upload had landed
            val viaOld = VaultSession.open(d, "pw".toCharArray(), tuning = tuning).also { cleanup += it }
            val asked = viaOld.sync(remote(s))
            assertEquals(FailureReason.ReopenRequired, (asked.outcome as SyncOutcome.Failed).reason)
            val done = viaOld.sync(remote(s), reopenPassword = "new".toCharArray())
            assertFalse(done.outcome is SyncOutcome.Failed, "${done.outcome}")
            assertEquals(2L, viaOld.keyEpoch.value)
            viaOld.close()
            assertEquals(null, FileLocalStateStore(d).load().vaults.values.single().pendingLocalFile)
            VaultSession.open(d, "new".toCharArray(), tuning = tuning).also { cleanup += it }.close()
        }
        // The new password: the pending file is the local one and the server holds it -> nothing to resolve.
        run {
            val s = server()
            val (d, pending) = dropRotationUpload(s)
            s.files[FakeDavServer.VAULT] = pending
            val viaNew = VaultSession.open(d, "new".toCharArray(), tuning = tuning).also { cleanup += it }
            val result = viaNew.sync(remote(s))
            assertFalse(result.outcome is SyncOutcome.Failed, "${result.outcome}")
            viaNew.close()
            assertEquals(null, FileLocalStateStore(d).load().vaults.values.single().pendingLocalFile)
        }
    }

    // ------------------------------------------------------------------ directory, join, backup, salvage

    @Test
    fun aSecondSessionOnTheSameDirectoryFailsFastAndTheDirectoryIsFreeAfterClose() = runBlocking<Unit> {
        val d = dir()
        val first = create(d)
        assertFailsWith<VaultSessionException.DirectoryInUse> { VaultSession.open(d, "pw".toCharArray(), tuning = tuning) }
        assertFailsWith<VaultSessionException.DirectoryInUse> { VaultSession.create(d, "pw".toCharArray(), fast, tuning) }
        first.close()
        VaultSession.open(d, "pw".toCharArray(), tuning = tuning).also { cleanup += it }
    }

    @Test
    fun joinShowsTheVaultAndItsFingerprintAndWritesAndUploadsNothingUntilConfirmed() = runBlocking<Unit> {
        val s = server()
        val a = create(dir())
        a.addHost("one", "h1")
        a.sync(remote(s))
        val puts = s.requests("PUT").size

        val dirB = dir()
        val preview = VaultSession.join(dirB, remote(s), "pw".toCharArray(), tuning = tuning)
        assertEquals(a.fingerprint(), preview.fingerprint)
        assertTrue(Regex("([0-9A-F]{4}-){5}[0-9A-F]{4}").matches(preview.fingerprint), preview.fingerprint)
        assertEquals(a.id, preview.vaultId)
        assertEquals(1L, preview.keyEpoch)
        assertEquals(1, preview.recordCounts.values.sum())
        assertEquals(0, preview.deletedCount)
        assertTrue(FileLocalStateStore(dirB).load().vaults.isEmpty(), "nothing is written before confirm")
        assertEquals(puts, s.requests("PUT").size)
        // The preview holds the directory.
        assertFailsWith<VaultSessionException.DirectoryInUse> { VaultSession.open(dirB, "pw".toCharArray(), tuning = tuning) }
        val b = preview.confirm().also { cleanup += it }
        assertEquals(a.fingerprint(), b.fingerprint())
        assertEquals(a.content.value, b.content.value)
        assertEquals(puts, s.requests("PUT").size, "confirming does not upload either")
        assertFailsWith<IllegalStateException> { preview.confirm() }
    }

    @Test
    fun joinWithAWrongPasswordOrAnEmptyRemoteFailsAndReleasesTheDirectory() = runBlocking<Unit> {
        val s = server()
        val dirB = dir()
        assertFailsWith<VaultSessionException.RemoteHasNoVault> { VaultSession.join(dirB, remote(s), "pw".toCharArray(), tuning = tuning) }
        val a = create(dir())
        a.sync(remote(s))
        assertFailsWith<VaultException.BadPasswordOrCorrupt> { VaultSession.join(dirB, remote(s), "nope".toCharArray(), tuning = tuning) }
        val preview = VaultSession.join(dirB, remote(s), "pw".toCharArray(), tuning = tuning) // the directory was released
        preview.close()
    }

    @Test
    fun aBackupOfTheLocalVaultImportsIntoAFreshDirectory() = runBlocking<Unit> {
        val a = create(dir())
        a.addHost("one", "h1")
        val backup = a.exportBackup()
        val dirB = dir()
        assertFailsWith<VaultException.BadPasswordOrCorrupt> { VaultSession.importBackup(dirB, backup, "nope".toCharArray(), tuning = tuning) }
        val b = VaultSession.importBackup(dirB, backup, "pw".toCharArray(), tuning = tuning).also { cleanup += it }
        assertEquals(a.content.value, b.content.value)
        b.close()
        assertFailsWith<VaultSessionException.DirectoryHoldsVault> { VaultSession.importBackup(dirB, backup, "pw".toCharArray(), tuning = tuning) }
    }

    @Test
    fun aDamagedStateFileFailsOpenWithASpecificErrorAndSalvageReadsThePreviousCopyWithoutDeletingAnything() = runBlocking<Unit> {
        val d = dir()
        val a = create(d)
        a.addHost("one", "h1")
        a.addHost("two", "h2")
        a.close()
        val stateFile = File(d, FileLocalStateStore.DEFAULT_FILE_NAME)
        val prevFile = File(d, FileLocalStateStore.DEFAULT_FILE_NAME + ".prev")
        assertTrue(prevFile.exists())
        stateFile.writeBytes(ByteArray(64) { 7 })
        val damaged = stateFile.readBytes()
        val prev = prevFile.readBytes()

        assertFailsWith<VaultSessionException.StateUnreadable> { VaultSession.open(d, "pw".toCharArray(), tuning = tuning) }
        val found = VaultSession.salvage(d, "pw".toCharArray())
        val recovered = assertIs<SalvageResult.Recovered>(found)
        assertEquals(SalvageSource.Previous, recovered.source)
        assertEquals(1, recovered.recordCount, "the previous copy is one edit behind: the report says what was found")
        assertFalse(recovered.fromPendingRotation)
        assertContentEquals(damaged, stateFile.readBytes(), "salvage changes nothing")
        assertContentEquals(prev, prevFile.readBytes())
        assertIs<SalvageResult.NothingRecovered>(VaultSession.salvage(d, "nope".toCharArray()))

        val restored = VaultSession.importBackup(dir(), recovered.sealedVault, "pw".toCharArray(), tuning = tuning).also { cleanup += it }
        assertEquals(setOf("h1"), restored.content.value.records.map { it.id }.toSet())
    }

    @Test
    fun theMemoryCeilingAppliesToOpenAndToPasswordChanges() = runBlocking<Unit> {
        val d = dir()
        create(d).close()
        assertFailsWith<VaultException.KdfCostTooHigh> {
            VaultSession.open(d, "pw".toCharArray(), memoryCeilingKiB = 4 * 1024, tuning = tuning)
        }
        val a = VaultSession.open(d, "pw".toCharArray(), memoryCeilingKiB = 16 * 1024, tuning = tuning).also { cleanup += it }
        assertFailsWith<VaultException.KdfCostTooHigh> {
            a.changePassword("pw".toCharArray(), "new".toCharArray(), kdf = KdfParams(memoryKiB = 64 * 1024, iterations = 1, parallelism = 1))
        }
        assertEquals(1L, a.keyEpoch.value)
        a.changePassword("pw".toCharArray(), "new".toCharArray(), kdf = KdfParams(memoryKiB = 12 * 1024, iterations = 1, parallelism = 1))
        assertEquals(2L, a.keyEpoch.value)
    }

    @Test
    fun aPasswordChangeListsTheRecordsItImportedFromOtherDevices() = runBlocking<Unit> {
        val s = server()
        val a = create(dir())
        a.addHost("one", "h1")
        a.sync(remote(s))
        val b = enrol(dir(), s)
        b.addHost("from B", "b1")
        b.sync(remote(s))
        val result = a.changePassword("pw".toCharArray(), "new".toCharArray(), remote(s))
        assertFalse(result.sync.outcome is SyncOutcome.Failed, "${result.sync.outcome}")
        val imported = result.imported.single()
        assertEquals("b1", imported.id)
        assertNotEquals(a.fingerprint(), "")
        assertEquals(setOf("h1", "b1"), VaultCodec.open(s.files.getValue(FakeDavServer.VAULT), "new".toCharArray()).content.records.map { it.id }.toSet())
    }

    // ------------------------------------------------------------------ warnings and recovery actions

    private fun forgedUnchainedRekey(s: FakeDavServer): Unit {
        val current = VaultCodec.open(s.files.getValue(FakeDavServer.VAULT), "pw".toCharArray())
        val root = VaultCodec.create("evil".toCharArray(), fast, vaultId = current.vaultId)
        val attacker = VaultCodec.changePassword(root, "evil2".toCharArray())
        s.files[FakeDavServer.VAULT] = VaultCodec.seal(attacker.withContent(current.content.copy(revision = current.content.revision + 1)))
    }

    @Test
    fun theUnverifiedKeyEpochWarningIsRepeatedByEverySyncAndAcrossRestartsUntilAcknowledged() = runBlocking<Unit> {
        val s = server()
        val a = create(dir())
        a.addHost("one", "h1")
        a.sync(remote(s))
        val dirB = dir()
        val b = enrol(dirB, s)
        forgedUnchainedRekey(s)
        val adopted = b.sync(remote(s), reopenPassword = "evil2".toCharArray())
        assertTrue(adopted.warnings.any { it is SyncWarning.KeyEpochChainUnverified }, "${adopted.warnings}")
        assertTrue(b.sync(remote(s)).warnings.any { it is SyncWarning.KeyEpochChainUnverified }, "every later sync repeats it")
        b.close()
        val reopened = VaultSession.open(dirB, "evil2".toCharArray(), tuning = tuning).also { cleanup += it }
        assertTrue(reopened.sync(remote(s)).warnings.any { it is SyncWarning.KeyEpochChainUnverified }, "it survives a restart")
        reopened.acknowledgeKeyEpochWarning()
        assertTrue(reopened.sync(remote(s)).warnings.none { it is SyncWarning.KeyEpochChainUnverified })
    }

    private suspend fun assertReplaceable(s: FakeDavServer, a: VaultSession, expected: FailureReason?) {
        if (expected != null) {
            assertEquals(expected, ((a.sync(remote(s)).outcome) as SyncOutcome.Failed).reason)
        }
        assertFailsWith<VaultSessionException.ConfirmationRequired> { a.replaceRemoteWithLocal(remote(s), "pw".toCharArray()) }
        val replaced = a.replaceRemoteWithLocal(remote(s), "pw".toCharArray(), confirm = true)
        assertTrue(replaced.replaced, "${replaced.sync.outcome}")
        assertTrue(replaced.sync.warnings.any { it is SyncWarning.RemoteReplaced })
        val epoch = VaultCodec.inspect(s.files.getValue(FakeDavServer.VAULT)).keyEpoch
        assertTrue(epoch >= 2L, "the replacement is a new epoch")
        assertEquals(epoch, a.keyEpoch.value)
        assertEquals(setOf("h1"), VaultCodec.open(s.files.getValue(FakeDavServer.VAULT), "pw".toCharArray()).content.records.map { it.id }.toSet())
        assertFalse(a.sync(remote(s)).outcome is SyncOutcome.Failed)
    }

    @Test
    fun replacingAMissingRemoteIsAnExplicitNewEpochUpload() = runBlocking<Unit> {
        val s = server()
        val a = create(dir())
        a.addHost("one", "h1")
        a.sync(remote(s))
        s.files.remove(FakeDavServer.VAULT)
        assertReplaceable(s, a, FailureReason.RemoteMissing)
    }

    @Test
    fun replacingAHostileSameEpochHeaderRestoresTheSharedVaultWithoutAnyMerge() = runBlocking<Unit> {
        val s = server()
        val a = create(dir())
        a.addHost("one", "h1")
        a.sync(remote(s))
        val key = HostileFiles.keyOf(a.exportLocalUnlockSecret())
        val attackerSlot = HostileFiles.slotOf(VaultCodec.seal(VaultCodec.create("evil".toCharArray(), fast)))
        s.files[FakeDavServer.VAULT] = HostileFiles.forge(s.files.getValue(FakeDavServer.VAULT), key) {
            it.replace(Regex("\\{\"id\":\"pw-[0-9a-f]{16}\",\"type\":\"password\"[^{}]*\\}"), attackerSlot)
        }
        assertReplaceable(s, a, FailureReason.HeaderMismatchSameEpoch)
    }

    @Test
    fun replacingARemoteThatTheWorkingPasswordCannotOpenIsAnExplicitNewEpochUpload() = runBlocking<Unit> {
        val s = server()
        val a = create(dir())
        a.addHost("one", "h1")
        a.sync(remote(s))
        // Someone re-keyed the vault with a password this device does not know.
        val foreign = VaultCodec.create("stranger".toCharArray(), fast, vaultId = a.id)
        s.files[FakeDavServer.VAULT] = VaultCodec.seal(VaultCodec.changePassword(foreign, "stranger2".toCharArray()).withContent(a.content.value.copy(revision = 50)))
        assertReplaceable(s, a, null)
    }

    @Test
    fun replacingNothingHappensWhenThePullWorks() = runBlocking<Unit> {
        val s = server()
        val a = create(dir())
        a.addHost("one", "h1")
        a.sync(remote(s))
        val before = s.files.getValue(FakeDavServer.VAULT).copyOf()
        val result = a.replaceRemoteWithLocal(remote(s), "pw".toCharArray(), confirm = true)
        assertFalse(result.replaced)
        assertContentEquals(before, s.files.getValue(FakeDavServer.VAULT))
    }

    @Test
    fun theKeyEpochFlowFollowsPasswordChangesAndTheFingerprintFollowsTheKey() = runBlocking<Unit> {
        val a = create(dir())
        val before = a.fingerprint()
        assertEquals(1L, a.keyEpoch.value)
        a.changePassword("pw".toCharArray(), "new".toCharArray())
        assertEquals(2L, a.keyEpoch.value)
        assertNotEquals(before, a.fingerprint())
    }

    // ------------------------------------------------------------------ fourth review: U-S1 .. U-S13

    private fun reasonOf(r: SyncResult): FailureReason = (r.outcome as SyncOutcome.Failed).reason

    private fun pendingOf(d: File): ByteArray? = runBlocking { FileLocalStateStore(d).load().vaults.values.single().pendingLocalFile }

    @Test
    fun anEditDuringTheUploadOfAPasswordChangeSurvivesACrashInBothFilesAndNothingIsStranded() = runBlocking<Unit> {
        val s = server()
        val d = dir()
        val a = create(d)
        a.addHost("one", "h1")
        a.sync(remote(s))
        s.beforeNextPut = {
            runBlocking { a.addHost("during", "h2") }
            throw RuntimeException("connection dropped")
        }
        val result = a.changePassword("pw".toCharArray(), "new".toCharArray(), remote(s))
        s.beforeNextPut = null
        assertIs<SyncOutcome.Failed>(result.sync.outcome)
        a.close()

        // The old password still opens the committed (old-epoch) file, with the edit.
        val viaOld = VaultSession.open(d, "pw".toCharArray(), tuning = tuning)
        assertEquals(setOf("h1", "h2"), viaOld.content.value.records.map { it.id }.toSet())
        assertTrue(viaOld.hasUnresolvedPasswordChange)
        viaOld.close()

        // The new password opens the pending file, with the edit too; the old file is kept.
        val viaNew = VaultSession.open(d, "new".toCharArray(), tuning = tuning).also { cleanup += it }
        assertEquals(setOf("h1", "h2"), viaNew.content.value.records.map { it.id }.toSet())
        viaNew.addHost("after", "h3")
        viaNew.close()
        val state = FileLocalStateStore(d).load().vaults.values.single()
        assertNotNull(state.localFile)
        assertNotNull(state.pendingLocalFile)
        assertTrue(state.pendingHoldsNewerEdits)
        assertEquals(1L, VaultCodec.inspect(state.localFile!!).keyEpoch, "the old-epoch file is not overwritten")

        // The old password now sees edits that only the pending file has and refuses to drop them silently.
        val again = VaultSession.open(d, "pw".toCharArray(), tuning = tuning).also { cleanup += it }
        assertEquals(FailureReason.PendingRotationHoldsNewerEdits, reasonOf(again.sync(remote(s))))
        val resolved = again.resolvePendingPasswordChange(remote(s), "new".toCharArray())
        assertEquals(PendingResolution.Abandoned, resolved.resolution)
        assertEquals(setOf("h1", "h2", "h3"), again.content.value.records.map { it.id }.toSet(), "no edit is lost")
        assertEquals(1L, VaultCodec.inspect(s.files.getValue(FakeDavServer.VAULT)).keyEpoch)
        assertTrue(resolved.sync.warnings.any { it is SyncWarning.PasswordChangeNotPublished })
        assertEquals(null, pendingOf(d))
    }

    @Test
    fun anUnpublishedPasswordChangeIsPublishedByResolvingItWithTheNewPassword() = runBlocking<Unit> {
        val s = server()
        val (d, _) = dropRotationUpload(s)
        val viaNew = VaultSession.open(d, "new".toCharArray(), tuning = tuning).also { cleanup += it }
        assertFailsWith<VaultException.BadPasswordOrCorrupt> {
            viaNew.resolvePendingPasswordChange(remote(s), "pw".toCharArray())
        }
        val resolved = viaNew.resolvePendingPasswordChange(remote(s), "new".toCharArray())
        assertEquals(PendingResolution.Published, resolved.resolution, "${resolved.sync.outcome}")
        assertEquals(2L, VaultCodec.inspect(s.files.getValue(FakeDavServer.VAULT)).keyEpoch)
        assertFalse(viaNew.hasUnresolvedPasswordChange)
        assertEquals(null, pendingOf(d))
        assertEquals(PendingResolution.NothingPending, viaNew.resolvePendingPasswordChange(remote(s), "new".toCharArray()).resolution)
    }

    @Test
    fun aDiscardedPasswordChangeIsReportedByEverySyncAndAcrossRestartsUntilAcknowledged() = runBlocking<Unit> {
        val s = server()
        val (d, _) = dropRotationUpload(s)
        val viaOld = VaultSession.open(d, "pw".toCharArray(), tuning = tuning).also { cleanup += it }
        assertTrue(viaOld.sync(remote(s)).warnings.any { it is SyncWarning.PasswordChangeNotPublished })
        assertTrue(viaOld.sync(remote(s)).warnings.any { it is SyncWarning.PasswordChangeNotPublished }, "every later sync repeats it")
        viaOld.close()
        val reopened = VaultSession.open(d, "pw".toCharArray(), tuning = tuning).also { cleanup += it }
        assertTrue(reopened.sync(remote(s)).warnings.any { it is SyncWarning.PasswordChangeNotPublished }, "it survives a restart")
        reopened.acknowledgePasswordChangeWarning()
        assertTrue(reopened.sync(remote(s)).warnings.none { it is SyncWarning.PasswordChangeNotPublished })
    }

    @Test
    fun aRemoteThatClaimsAnAbsurdEpochCannotDisableFutureRotations() = runBlocking<Unit> {
        val s = server()
        val a = create(dir())
        a.addHost("one", "h1")
        a.sync(remote(s))
        val current = VaultCodec.open(s.files.getValue(FakeDavServer.VAULT), "pw".toCharArray())
        val evil = VaultCodec.changePassword(
            VaultCodec.create("evil".toCharArray(), fast, vaultId = a.id), "evil2".toCharArray(), atLeastEpoch = 0xFFFF_FFFEL,
        )
        s.files[FakeDavServer.VAULT] = VaultCodec.seal(evil.withContent(current.content.copy(revision = current.content.revision + 1)))
        val pulled = a.sync(remote(s), reopenPassword = "pw".toCharArray())
        assertEquals(FailureReason.BadPasswordOrCorrupt, reasonOf(pulled))
        val replaced = a.replaceRemoteWithLocal(remote(s), "pw".toCharArray(), confirm = true)
        assertTrue(replaced.replaced, "${replaced.sync.outcome}")
        assertEquals(2L, VaultCodec.inspect(s.files.getValue(FakeDavServer.VAULT)).keyEpoch, "own epoch + 1, never the remote's claim")
        val next = a.changePassword("pw".toCharArray(), "third".toCharArray(), remote(s))
        assertTrue(next.rekeyed, "${next.sync.outcome}")
        assertEquals(3L, a.keyEpoch.value)
    }

    @Test
    fun replacingRefusesAFileThatChangedSinceTheOneTheUserWasShownAndTheLinkedRekeyOfAnotherDevice() = runBlocking<Unit> {
        val s = server()
        val a = create(dir())
        a.addHost("one", "h1")
        a.sync(remote(s))
        val b = enrol(dir(), s)
        b.sync(remote(s))
        a.changePassword("pw".toCharArray(), "new".toCharArray(), remote(s))
        // B still has the old password and old key: the remote is the verified successor of its own key.
        val before = s.files.getValue(FakeDavServer.VAULT).copyOf()
        val refused = b.replaceRemoteWithLocal(remote(s), "pw".toCharArray(), confirm = true)
        assertFalse(refused.replaced)
        assertEquals(FailureReason.RemoteRekeyedElsewhere, reasonOf(refused.sync))
        assertContentEquals(before, s.files.getValue(FakeDavServer.VAULT))

        // A digest other than the judged file's replaces nothing.
        val c = create(dir())
        c.addHost("c", "c1")
        c.sync(remote(s)) // a different vault id: the remote of C is then A's vault
        val wrong = c.replaceRemoteWithLocal(remote(s), "pw".toCharArray(), confirm = true, expectedRemoteDigest = "00".repeat(32))
        assertFalse(wrong.replaced)
        assertContentEquals(before, s.files.getValue(FakeDavServer.VAULT))
        b.close()
    }

    @Test
    fun aRemoteWhoseKeyDerivationIsTooHeavyForThisDeviceIsNeverReplaced() = runBlocking<Unit> {
        val s = server()
        val d = dir()
        val a = create(d)
        a.addHost("one", "h1")
        a.sync(remote(s))
        a.close()
        val small = VaultSession.open(d, "pw".toCharArray(), memoryCeilingKiB = 8 * 1024, tuning = tuning).also { cleanup += it }
        val heavy = KdfParams(memoryKiB = 16 * 1024, iterations = 1, parallelism = 1)
        val big = VaultCodec.changePassword(VaultCodec.open(s.files.getValue(FakeDavServer.VAULT), "pw".toCharArray()), "pw".toCharArray(), heavy)
        s.files[FakeDavServer.VAULT] = VaultCodec.seal(big)
        val before = s.files.getValue(FakeDavServer.VAULT).copyOf()
        val pulled = small.sync(remote(s), reopenPassword = "pw".toCharArray())
        assertEquals(FailureReason.RemoteKdfTooHeavyForDevice, reasonOf(pulled))
        val result = small.replaceRemoteWithLocal(remote(s), "pw".toCharArray(), confirm = true)
        assertFalse(result.replaced)
        assertEquals(FailureReason.RemoteKdfTooHeavyForDevice, reasonOf(result.sync))
        assertContentEquals(before, s.files.getValue(FakeDavServer.VAULT))
    }

    @Test
    fun aPendingRotationWhoseRemoteMovedToAnotherKeyAdoptsItOnlyWithTheFingerprintAndKeepsLocalEdits() = runBlocking<Unit> {
        val s = server()
        val (d, _) = dropRotationUpload(s)
        forgedUnchainedRekey(s)
        val viaNew = VaultSession.open(d, "new".toCharArray(), tuning = tuning).also { cleanup += it }
        viaNew.addHost("local", "h9")
        val asked = viaNew.sync(remote(s), reopenPassword = "evil2".toCharArray())
        assertEquals(FailureReason.KeyMismatchSameEpoch, reasonOf(asked))
        val shown = assertNotNull(asked.failureInfo?.competingKeyFingerprint)
        val adopted = viaNew.sync(remote(s), SyncOptions(adoptCompetingKeyFingerprint = shown), "evil2".toCharArray())
        assertFalse(adopted.outcome is SyncOutcome.Failed, "${adopted.outcome}")
        assertTrue(adopted.warnings.any { it is SyncWarning.PasswordChangeNotPublished }, "the local password change did not happen")
        assertTrue(viaNew.content.value.records.any { it.id == "h9" }, "local edits are re-applied")
        assertFalse(viaNew.hasUnresolvedPasswordChange)
    }

    @Test
    fun aKeyEpochRollbackIsReportedAndRecoveredByAnExplicitReplacement() = runBlocking<Unit> {
        val s = server()
        val a = create(dir())
        a.addHost("one", "h1")
        a.sync(remote(s))
        val old = s.files.getValue(FakeDavServer.VAULT).copyOf()
        a.changePassword("pw".toCharArray(), "new".toCharArray(), remote(s))
        s.files[FakeDavServer.VAULT] = old // the server was restored from a backup
        val result = a.sync(remote(s), SyncOptions(allowRollback = true))
        assertEquals(FailureReason.KeyEpochRollback, reasonOf(result))
        val replaced = a.replaceRemoteWithLocal(remote(s), "new".toCharArray(), confirm = true)
        assertTrue(replaced.replaced, "${replaced.sync.outcome}")
        assertEquals(3L, VaultCodec.inspect(s.files.getValue(FakeDavServer.VAULT)).keyEpoch)
    }

    @Test
    fun aMassDeletionByAnotherDeviceNeedsAcceptanceAndCanBeUndoneFromTheHistory() = runBlocking<Unit> {
        val s = server()
        val a = create(dir())
        val ids = (1..12).map { "h$it" }
        a.edit { e -> ids.forEach { e.upsertHost(host("host $it"), id = it) } }
        a.sync(remote(s))
        val b = enrol(dir(), s)
        b.edit { e -> ids.take(11).forEach { e.delete(it) } }
        assertEquals(SyncOutcome.Pushed, b.sync(remote(s)).outcome)

        val refused = a.sync(remote(s))
        assertEquals(FailureReason.LargeRemoteChange, reasonOf(refused))
        assertEquals(11, refused.remoteChanges.deletedIds.size)
        assertEquals(12, a.content.value.records.count { !it.deleted }, "nothing was applied")

        val accepted = a.sync(remote(s), SyncOptions(acceptLargeRemoteChange = true))
        assertFalse(accepted.outcome is SyncOutcome.Failed, "${accepted.outcome}")
        assertTrue(accepted.warnings.any { it is SyncWarning.LargeRemoteChangeAccepted })
        assertEquals(1, a.content.value.records.count { !it.deleted })
        assertEquals(ids.take(11).sorted(), a.restorableRecordIds())

        val restored = a.restoreFromHistory(ids.take(11) + "unknown")
        assertEquals(ids.take(11), restored.restoredIds)
        assertEquals(listOf("unknown"), restored.notRestorableIds)
        assertEquals(12, a.content.value.records.count { !it.deleted })
        a.sync(remote(s))
        b.sync(remote(s))
        assertEquals(12, b.content.value.records.count { !it.deleted }, "the undo replicates like any edit")
        b.close()
    }

    @Test
    fun anEditThatLosesAtCommitTimeIsReportedAsAConflictOfThatSync() = runBlocking<Unit> {
        val s = server()
        val a = create(dir())
        a.addHost("one", "h1")
        a.sync(remote(s))
        val b = enrol(dir(), s)
        b.edit { it.upsertHost(host("b1"), id = "h1") }
        b.edit { it.upsertHost(host("b2"), id = "h1") }
        b.edit { it.upsertHost(host("b3"), id = "h1") }
        b.sync(remote(s))
        a.addHost("two", "h2") // a pending edit, so that the sync uploads
        s.beforeNextPut = { runBlocking { a.addHost("late", "h1") } }
        val result = a.sync(remote(s))
        s.beforeNextPut = null
        val merged = assertIs<SyncOutcome.Merged>(result.outcome, "${result.outcome}")
        assertTrue(merged.conflicts.any { it.winner.id == "h1" }, "${merged.conflicts}")
        b.close()
    }

    @Test
    fun aSecondOpenInTheSameProcessNeverReleasesTheOsLockOfTheLiveSession() = runBlocking<Unit> {
        val d = dir()
        val session = create(d)
        repeat(3) { assertFailsWith<VaultSessionException.DirectoryInUse> { VaultSession.open(d, "pw".toCharArray(), tuning = tuning) } }
        assertFailsWith<VaultSessionException.DirectoryInUse> { VaultSession.create(d, "pw".toCharArray(), fast, tuning) }
        assertEquals(LockProbe.IN_USE, LockProbe.runChild(d), "another process still cannot take the directory")
        session.close()
        assertEquals(LockProbe.ACQUIRED, LockProbe.runChild(d), "it is free once the session is closed")
        VaultSession.open(d, "pw".toCharArray(), tuning = tuning).also { cleanup += it }
    }

    @Test
    fun theVaultDirectoryAndItsFilesAreOwnerOnlyOnPosix() = runBlocking<Unit> {
        val parent = dir()
        if ("posix" !in parent.toPath().fileSystem.supportedFileAttributeViews()) return@runBlocking
        val d = File(parent, "vault/sub")
        val session = create(d)
        session.addHost("one", "h1")
        session.close()
        assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(d.toPath())))
        val files = d.listFiles()!!.filter { it.isFile }
        assertTrue(files.size >= 2, "state and lock files exist: ${files.map { it.name }}")
        for (f in files) {
            assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(f.toPath())), f.name)
        }
    }

    @Test
    fun joiningAVaultAuthoredByAnAttackerFailsWithTheWrongPasswordAndShowsAnotherFingerprintWithTheSame() = runBlocking<Unit> {
        val s = server()
        val a = create(dir())
        a.addHost("one", "h1")
        a.sync(remote(s))
        val genuine = s.files.getValue(FakeDavServer.VAULT).copyOf()
        // Under a password of the attacker's own: the user's password opens nothing.
        s.files[FakeDavServer.VAULT] = VaultCodec.seal(VaultCodec.create("evil".toCharArray(), fast))
        val d = dir()
        assertFailsWith<VaultException.BadPasswordOrCorrupt> { VaultSession.join(d, remote(s), "pw".toCharArray(), tuning = tuning) }
        assertFalse(File(d, FileLocalStateStore.DEFAULT_FILE_NAME).exists(), "nothing was saved")
        // The same password, another vault: the fingerprint differs from the genuine one.
        s.files[FakeDavServer.VAULT] = VaultCodec.seal(VaultCodec.create("pw".toCharArray(), fast))
        VaultSession.join(d, remote(s), "pw".toCharArray(), tuning = tuning).use { preview ->
            assertNotEquals(a.fingerprint(), preview.fingerprint)
            assertNotEquals(a.id, preview.vaultId)
        }
        s.files[FakeDavServer.VAULT] = genuine
        VaultSession.join(d, remote(s), "pw".toCharArray(), tuning = tuning).use { preview ->
            assertEquals(a.fingerprint(), preview.fingerprint)
        }
    }

    @Test
    fun theRollbackFloorsSurviveSalvageAndImport() = runBlocking<Unit> {
        val s = server()
        val d = dir()
        val a = create(d)
        a.addHost("one", "h1")
        a.sync(remote(s))
        val old = s.files.getValue(FakeDavServer.VAULT).copyOf()
        a.addHost("two", "h2")
        a.sync(remote(s))
        val revision = a.content.value.revision
        a.close()
        // Damage the checksum of the state file only: the vault inside is intact.
        val stateFile = File(d, FileLocalStateStore.DEFAULT_FILE_NAME)
        val bytes = stateFile.readBytes()
        bytes[6] = (bytes[6].toInt() xor 0x55).toByte()
        stateFile.writeBytes(bytes)
        val recovered = assertIs<SalvageResult.Recovered>(VaultSession.salvage(d, "pw".toCharArray()))
        assertEquals(revision, recovered.floors.highestRevision)
        assertTrue(recovered.floors.fileDigests.isNotEmpty())
        val fresh = VaultSession.importBackup(dir(), recovered.sealedVault, "pw".toCharArray(), tuning = tuning, floors = recovered.floors)
            .also { cleanup += it }
        s.files[FakeDavServer.VAULT] = old
        assertEquals(FailureReason.RollbackDetected, reasonOf(fresh.sync(remote(s))), "the older server file is refused")
    }

    @Test
    fun migratingToANewVaultReplacesTheRemoteAndMovesTheSession() = runBlocking<Unit> {
        val s = server()
        val d = dir()
        val a = create(d)
        a.addHost("one", "h1")
        a.sync(remote(s))
        val oldId = a.id
        assertFailsWith<VaultSessionException.ConfirmationRequired> { a.migrateToNewVault("pw".toCharArray(), remote(s)) }
        val migrated = a.migrateToNewVault("pw".toCharArray(), remote(s), confirm = true)
        val next = assertNotNull(migrated.session, "${migrated.sync.outcome}").also { cleanup += it }
        assertNotEquals(oldId, next.id)
        assertEquals(setOf("h1"), next.content.value.records.map { it.id }.toSet())
        assertEquals(next.id, VaultCodec.inspect(s.files.getValue(FakeDavServer.VAULT)).vaultId)
        assertNotNull(migrated.previousVault)
        assertFailsWith<IllegalStateException> { a.addHost("late", "x") }
        assertEquals(FailureReason.SessionClosed, reasonOf(a.sync(remote(s))))
        next.close()
        val reopened = VaultSession.open(d, "pw".toCharArray(), tuning = tuning).also { cleanup += it }
        assertEquals(next.id, reopened.id)
    }
}

/** A child JVM that tries to take a vault directory's lock, to prove the OS-level lock of this process is intact. */
object LockProbe {
    const val ACQUIRED = 10
    const val IN_USE = 11

    @JvmStatic
    fun main(args: Array<String>) {
        val code = try {
            FileLocalStateStore(File(args[0])).lockDirectory().close()
            ACQUIRED
        } catch (e: VaultSessionException.DirectoryInUse) {
            IN_USE
        }
        System.exit(code)
    }

    fun runChild(dir: File): Int {
        val path = listOf(
            LockProbe::class.java, FileLocalStateStore::class.java, VaultCodec::class.java, Unit::class.java,
            kotlinx.coroutines.sync.Mutex::class.java, kotlinx.serialization.json.Json::class.java,
            kotlinx.serialization.KSerializer::class.java,
        ).mapNotNull { runCatching { File(it.protectionDomain.codeSource.location.toURI()).path }.getOrNull() }
            .distinct().joinToString(File.pathSeparator)
        val java = File(System.getProperty("java.home"), "bin/java").path
        val process = ProcessBuilder(java, "-cp", path, LockProbe::class.java.name, dir.path)
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.readBytes().decodeToString()
        val code = process.waitFor()
        check(code == ACQUIRED || code == IN_USE) { "the probe failed with $code: $output" }
        return code
    }
}
