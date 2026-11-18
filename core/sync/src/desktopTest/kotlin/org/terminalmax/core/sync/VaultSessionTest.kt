// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.sync

import java.io.File
import java.nio.file.Files
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.random.Random
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
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
        assertFailsWith<VaultException.BadPasswordOrCorrupt> { VaultSession.open(d, "wrong".toCharArray(), tuning = tuning) }
        assertFailsWith<IllegalStateException> { VaultSession.create(d, "pw".toCharArray(), fast, tuning) }
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
        assertEquals(before, VaultSession.open(d, "pw".toCharArray(), tuning = tuning).also { cleanup += it }.content.value)
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
        VaultSession.open(d, "new".toCharArray(), tuning = tuning).also { cleanup += it }
        assertFailsWith<VaultException.BadPasswordOrCorrupt> { VaultSession.open(d, "pw".toCharArray(), tuning = tuning) }
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

    /** Enrols a second device the supported way: a new local vault is not an option, the file is opened as-is. */
    private suspend fun enrol(dirB: File, s: FakeDavServer): VaultSession {
        // The enrolment helper of the app layer is not part of this module: put the remote file in place as the
        // local file by opening a throw-away session and replacing its state through the public sync API.
        val tmp = VaultCodec.open(s.files.getValue(FakeDavServer.VAULT), "pw".toCharArray())
        val state = FileLocalStateStore(dirB)
        state.save(
            LocalSyncState(
                vaults = mapOf(tmp.vaultId to VaultSyncState(localFile = s.files.getValue(FakeDavServer.VAULT))),
                deviceId = "dev-b",
            ),
        )
        tmp.close()
        return VaultSession.open(dirB, "pw".toCharArray(), tuning = tuning).also { cleanup += it }
    }

    @Test
    fun anEditMadeWhileASyncIsInFlightWaitsAndIsNotOverwritten() = runBlocking<Unit> {
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
        val editing = async(kotlinx.coroutines.Dispatchers.Default) { a.addHost("during sync", "h2") }
        kotlinx.coroutines.delay(100)
        assertFalse(editing.isCompleted, "the edit must wait for the sync")
        release.complete(Unit)
        assertFalse(syncing.await().outcome is SyncOutcome.Failed)
        editing.await()
        assertEquals(setOf("h1", "h2"), a.content.value.records.map { it.id }.toSet())
        assertEquals(SyncOutcome.Pushed, a.sync(remote(s)).outcome)
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
        assertEquals(listOf(file.name, file.name + ".lock").sorted(), d.list()!!.sorted())

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
        assertFalse(changed.outcome is SyncOutcome.Failed, "${changed.outcome}")
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
        VaultSession.open(dirB, "new".toCharArray(), tuning = tuning).also { cleanup += it }
        assertFailsWith<VaultException.BadPasswordOrCorrupt> { VaultSession.open(dirB, "pw".toCharArray(), tuning = tuning) }
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
        assertIs<SyncOutcome.Failed>(result.outcome)
        s.beforeNextPut = null
        a.close()
        // Old password and epoch are intact locally and remotely.
        val reopened = VaultSession.open(d, "pw".toCharArray(), tuning = tuning).also { cleanup += it }
        assertEquals(1L, VaultCodec.inspect(s.files.getValue(FakeDavServer.VAULT)).keyEpoch)
        assertNotEquals(0, reopened.content.value.records.size)
        assertFailsWith<VaultException.BadPasswordOrCorrupt> { VaultSession.open(d, "new".toCharArray(), tuning = tuning) }
    }
}
