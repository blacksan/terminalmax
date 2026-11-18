// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.sync

import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom
import kotlin.coroutines.cancellation.CancellationException
import kotlin.random.Random
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.terminalmax.core.vault.KdfParams
import org.terminalmax.core.vault.OpenVault
import org.terminalmax.core.vault.VaultCodec
import org.terminalmax.core.vault.VaultContent
import org.terminalmax.core.vault.VaultEditor
import org.terminalmax.core.vault.VaultException

/**
 * Knobs of a [VaultSession] that tests (and only tests) change. The defaults are the production values.
 */
class SessionTuning(
    val clock: () -> Long = ::systemClockMillis,
    val random: Random = Random.Default,
    val sleep: suspend (Long) -> Unit = { delay(it) },
    val maxAttempts: Int = 5,
    val leaseMillis: Long = SyncEngine.DEFAULT_LEASE_MILLIS,
    val requestBudgetMillis: Long = SyncEngine.DEFAULT_REQUEST_BUDGET_MILLIS,
    val probeMaxAgeMillis: Long = SyncEngine.DEFAULT_PROBE_MAX_AGE_MILLIS,
)

/** A record this device took over from the remote during the sync that precedes a password change. */
data class ImportedRecord(
    val id: String,
    /** The wire name of the record type (for example `Host`, `KnownHost`). */
    val type: String,
    /** Which device wrote that version. */
    val deviceId: String,
    val revision: Long,
    val deleted: Boolean,
)

/**
 * The result of [VaultSession.changePassword].
 *
 * @property sync the outcome of the password-change transaction (its warnings include those of the pre-sync)
 * @property imported what the pre-rotation sync imported from the remote (records written by other devices at the
 *   old key epoch, which the new epoch now carries): show it before the user relies on the change, because a
 *   revoked device may have written some of it
 * @property rekeyed true when the data key was replaced (the exported local unlock secret is stale: export a new one)
 */
data class PasswordChangeResult(
    val sync: SyncResult,
    val imported: List<ImportedRecord>,
    val rekeyed: Boolean,
)

/**
 * The result of [VaultSession.replaceRemoteWithLocal].
 *
 * @property replaced true when the remote file was replaced by this device's copy. False when the final pull attempt
 *   succeeded (nothing needed replacing) or failed for a reason replacement does not cure (network, credentials):
 *   [sync] says which
 */
data class ReplaceRemoteResult(val replaced: Boolean, val sync: SyncResult)

/** What [VaultSession.salvage] recovered, or that it recovered nothing. Nothing is ever deleted or changed. */
sealed class SalvageResult {
    /**
     * The vault was opened with the password from [source]. [revision] and [recordCount] (records that are not
     * deleted) tell the user what was recovered; [sealedVault] is the recovered sealed vault file: give it to
     * [VaultSession.importBackup] in a fresh directory (with the same password) to continue from it.
     * [fromPendingRotation] is true when it was the unpublished new-epoch file of a password change.
     */
    class Recovered(
        val source: SalvageSource,
        val vaultId: String,
        val keyEpoch: Long,
        val revision: Long,
        val recordCount: Int,
        val fromPendingRotation: Boolean,
        val sealedVault: ByteArray,
    ) : SalvageResult()

    /** Neither the state file nor its previous copy held a vault that the password opens. */
    data class NothingRecovered(val triedSources: List<SalvageSource>) : SalvageResult()
}

/**
 * A remote vault that was downloaded and opened for enrolment of this device, **before** anything is written or
 * uploaded. Show [fingerprint] (and [keyEpoch], [revision], [recordCounts]) to the user and compare the fingerprint
 * with the one another device shows ([VaultSession.fingerprint]); only then call [confirm]. [close] abandons it. It
 * holds the directory lock until one of the two is called.
 */
class JoinPreview internal constructor(
    val vaultId: String,
    val keyEpoch: Long,
    /** Content revision of the remote file. */
    val revision: Long,
    /** Live (not deleted) records by type (wire name). */
    val recordCounts: Map<String, Int>,
    /** Deleted records (tombstones). */
    val deletedCount: Int,
    /** See [OpenVault.fingerprint]: six groups of four hex characters. */
    val fingerprint: String,
    private val onConfirm: suspend () -> VaultSession,
    private val onClose: () -> Unit,
) : AutoCloseable {
    @Volatile
    private var used = false

    /**
     * Writes the local state (the remote file becomes this device's local vault and its base; its revision and key
     * epoch become the first floors) and returns the session. Nothing is uploaded; the first [VaultSession.sync]
     * does that.
     */
    suspend fun confirm(): VaultSession {
        check(!used) { "This preview was already confirmed or closed" }
        used = true
        return onConfirm()
    }

    override fun close() {
        if (used) return
        used = true
        onClose()
    }
}

/**
 * One local vault on this device, with everything needed to use it correctly and nothing that can be misused.
 * It owns:
 *  - **the directory**: an OS-level lock on it for the session's whole lifetime, released by [close]. A second
 *    [create] / [open] / [join] on the same directory (another window, another process, another session object)
 *    fails at once with [VaultSessionException.DirectoryInUse] instead of silently losing edits;
 *  - **local persistence**: the sealed local vault file and the sync state (floors, base, digests) live in one
 *    file in the directory that is replaced atomically, with a rolling previous copy (see [FileLocalStateStore]), so
 *    a crash leaves the old pair or the new pair and never a mixture; every edit and every sync result is committed
 *    there before it is published in [content];
 *  - **the data key**, held in memory while the session is open; superseded keys (after a password change or a
 *    re-key adopted from another device) are zeroed by the session, not by the caller;
 *  - **serialisation without blocking edits**: [sync], [changePassword] and [replaceRemoteWithLocal] run one at a
 *    time, but they do their network I/O on a snapshot and take the state lock only to commit; an [edit] never waits
 *    for the network. If edits were made while a sync ran, the sync commits the *join* of its result and those
 *    edits, reports [SyncResult.localEditsPending], and the edits go out with the next sync.
 *
 * **Error model.** [edit] throws (`VaultException.InvalidContent`, or whatever the block throws; the session is
 * unchanged). [sync] and [replaceRemoteWithLocal] never throw for protocol, network or server problems: they return a
 * failed [SyncResult]. [changePassword] throws for a wrong old password (`VaultException.BadPasswordOrCorrupt`),
 * for a KDF parameter this device cannot honour (`VaultException.KdfCostTooHigh`) and `IllegalStateException` for a
 * synced vault without a remote; everything about the transaction itself is a failed [SyncResult] inside
 * [PasswordChangeResult]. The static functions throw [VaultSessionException] for directory problems and
 * `VaultException` for a wrong password or a damaged file.
 *
 * The master password is never stored. Per-device convenience unlock (biometrics, OS keychain) uses
 * [exportLocalUnlockSecret] and [openWithLocalUnlockSecret]; the secret is the data key itself and belongs in
 * platform secure storage only (see [OpenVault.exportLocalUnlockSecret]); [keyEpoch] changes whenever it goes stale.
 * **Revoking a lost device means changing the vault password (that replaces the data key and the device's local
 * secret stops working) AND changing the WebDAV credential** (a device that still holds it can write to the share:
 * it cannot read what is written after the change, but it can delete, replace or fill the file). It protects what is
 * written afterwards; it cannot recall what the device already read. See the sync README, "Recovery actions", for
 * every state that needs a user decision.
 */
class VaultSession private constructor(
    private val localStore: FileLocalStateStore,
    private val directoryLock: FileLocalStateStore.DirectoryLock,
    private val vaultId: String,
    private val hooks: OpenVaultCodecHooks,
    private val deviceId: String,
    private val tuning: SessionTuning,
    private val memoryCeilingKiB: Int,
    initial: VaultContent,
    pendingUnresolved: Boolean,
) : AutoCloseable {
    private val operations = Mutex()
    private val state = MutableStateFlow(initial)
    private val keyEpochFlow = MutableStateFlow(hooks.keyEpoch)

    @Volatile
    private var closed = false

    @Volatile
    private var closeRequested = false

    @Volatile
    private var pendingRotationUnresolved = pendingUnresolved

    /** The current local vault content. Updated after every committed [edit] and every successful [sync]. */
    val content: StateFlow<VaultContent> get() = state

    /**
     * The key epoch of the data key held now. It increases after [changePassword] and after a sync adopted a re-key;
     * a previously exported local unlock secret is stale from then on, so export a new one when it changes.
     */
    val keyEpoch: StateFlow<Long> get() = keyEpochFlow

    /** Id of the vault (stable for its lifetime). */
    val id: String get() = vaultId

    /**
     * True while an unpublished password change was found on open and the next sync has not resolved it yet (see
     * the sync README, "A crash during a password change").
     */
    val hasUnresolvedPasswordChange: Boolean get() = pendingRotationUnresolved

    /** See [OpenVault.fingerprint]: compare it between devices out of band (for example when enrolling one). */
    fun fingerprint(): String = hooks.keyFingerprint

    private val view = object : LocalView {
        override suspend fun current(): VaultContent = state.value

        override fun committed(content: VaultContent) {
            state.value = content
            keyEpochFlow.value = hooks.keyEpoch
        }
    }

    private suspend fun <T> operation(block: suspend () -> T): T = operations.withLock {
        check(!closed) { "Session is closed" }
        try {
            block()
        } finally {
            keyEpochFlow.value = hooks.keyEpoch
            if (closeRequested) shutDown()
        }
    }

    /**
     * Applies [block] to the content and commits the result durably before publishing it in [content]. If [block]
     * throws, nothing changes. Revisions are above everything this device has synced, even if the in-memory content
     * were stale. An edit never waits for the network: it only takes the short state lock.
     *
     * @throws org.terminalmax.core.vault.VaultException.InvalidContent when the result breaks the content rules
     */
    suspend fun edit(block: (VaultEditor) -> Unit) {
        check(!closed) { "Session is closed" }
        localStore.exclusive {
            val persisted = localStore.load()
            val vs = persisted.vaults[vaultId] ?: VaultSyncState()
            val editor = VaultEditor(
                state.value, deviceId, tuning.clock, revisionFloor = vs.highestRevision,
            )
            block(editor)
            val edited = editor.content
            if (edited != state.value) {
                val sealed = hooks.sealLocal(edited) // validates the content
                localStore.save(
                    persisted.copy(vaults = persisted.vaults + (vaultId to vs.copy(localFile = sealed))),
                )
                state.value = edited
            }
        }
    }

    /**
     * Synchronises with [remote]. See [SyncEngine] for the protocol. The network I/O runs on a snapshot, without
     * blocking [edit]; the merged content is committed together with the new sync state and published in
     * [content]. When the remote vault was re-keyed (a password change on another device) the result is
     * [FailureReason.ReopenRequired] unless [reopenPassword] (the master password, not retained) is given.
     *
     * Every failure has a documented user action (sync README, "Recovery actions"): [SyncOptions.allowRollback],
     * [SyncOptions.recreateRemote], [SyncOptions.acceptRevisionJump], [replaceRemoteWithLocal], [exportBackup].
     */
    suspend fun sync(
        remote: RemoteStore,
        options: SyncOptions = SyncOptions(),
        reopenPassword: CharArray? = null,
    ): SyncResult = operation {
        resolvePendingRotation(remote)?.let { return@operation it }
        engine(remote).sync(state.value, options, null, reopenPassword)
    }

    /**
     * Changes the master password (and with [kdf] the key-derivation parameters), which **replaces the data key**
     * and so revokes every other device until it enters the new password. [old] is verified against the local vault
     * first. Revoking a lost device also requires changing the WebDAV credential.
     *
     * With a [remote] this is one transaction: a normal sync runs first (so everything written at the old key epoch
     * is imported; [PasswordChangeResult.imported] lists it), then the re-keyed file is uploaded **only if the remote
     * file is still exactly what that sync left**, and the change is committed locally only after the upload is read
     * back. Before the upload the sealed new-epoch local file is written durably as a *pending rotation*, so a crash
     * at any point is resolvable (see [open]). A failure before the commit leaves the old password and epoch intact.
     * If another device changed the vault in the meantime the result is [FailureReason.RemoteChangedDuringRotation]
     * or [FailureReason.HeaderChangedRemotely]: nothing was changed, repeat the call.
     *
     * Without a [remote] it is only allowed for a vault that has never been synced; a synced vault needs its remote
     * (an `IllegalStateException` otherwise), because re-keying only locally would strand the other devices.
     *
     * A device that is still at the old epoch can keep writing old-epoch files; only devices that have seen the new
     * epoch refuse them, so revocation is effective once every remaining device has synced at the new epoch.
     *
     * @throws VaultException.BadPasswordOrCorrupt when [old] is wrong
     * @throws VaultException.KdfCostTooHigh when [kdf] asks for more memory than this session's ceiling
     */
    suspend fun changePassword(
        old: CharArray,
        new: CharArray,
        remote: RemoteStore? = null,
        options: SyncOptions = SyncOptions(),
        kdf: KdfParams? = null,
    ): PasswordChangeResult = operation {
        val vs = localStore.load().vaults[vaultId] ?: VaultSyncState()
        val localFile = checkNotNull(vs.localFile) { "The session has no local vault file" }
        VaultCodec.open(localFile, old, memoryCeilingKiB).close() // verifies the old password
        if (kdf != null && kdf.memoryKiB > memoryCeilingKiB) {
            throw VaultException.KdfCostTooHigh("the new key-derivation memory exceeds this device's ceiling")
        }
        if (remote == null) {
            check(!vs.established) { "This vault has been synced: pass its remote so that every device can follow" }
            val staged = hooks.stage { VaultCodec.changePassword(it, new, kdf) }
            try {
                localStore.exclusive {
                    val fresh = localStore.load()
                    val current = fresh.vaults[vaultId] ?: VaultSyncState()
                    val sealed = hooks.sealLocalStaged(state.value, staged)
                    localStore.save(
                        fresh.copy(vaults = fresh.vaults + (vaultId to current.copy(localFile = sealed, pendingLocalFile = null))),
                    )
                    hooks.commitStaged(staged)
                }
            } finally {
                staged.discard() // no-op once committed
            }
            return@operation PasswordChangeResult(SyncResult(SyncOutcome.UpToDate, state.value), emptyList(), rekeyed = true)
        }
        resolvePendingRotation(remote)?.let { return@operation PasswordChangeResult(it, emptyList(), rekeyed = false) }
        val engine = engine(remote)
        val before = state.value
        val pre = engine.sync(before, options)
        if (pre.outcome is SyncOutcome.Failed) return@operation PasswordChangeResult(pre, emptyList(), rekeyed = false)
        val imported = importedRecords(before, pre.content)
        val staged = hooks.stage { VaultCodec.changePassword(it, new, kdf) }
        try {
            val result = engine.sync(state.value, options, staged, null)
            val warnings = (pre.warnings + result.warnings).distinct()
            if (result.outcome is SyncOutcome.Failed) {
                return@operation PasswordChangeResult(SyncResult(result.outcome, state.value, warnings), imported, rekeyed = false)
            }
            val outcome = if (pre.outcome is SyncOutcome.Merged) pre.outcome else result.outcome
            PasswordChangeResult(
                SyncResult(outcome, result.content, warnings, result.localEditsPending || pre.localEditsPending),
                imported,
                rekeyed = true,
            )
        } finally {
            staged.discard() // no-op once committed
        }
    }

    /** Versions in [after] that were written by another device and are not in [before]. */
    private fun importedRecords(before: VaultContent, after: VaultContent): List<ImportedRecord> {
        val known = before.records.mapTo(HashSet()) { Triple(it.id, it.revision, it.deviceId) }
        return after.records
            .filter { it.deviceId != deviceId && Triple(it.id, it.revision, it.deviceId) !in known }
            .map { ImportedRecord(it.id, it.wireTypeName, it.deviceId, it.revision, it.deleted) }
    }

    /**
     * **Recovery action** for a remote this device cannot work with: a file of the same key epoch with a different
     * header ([FailureReason.HeaderMismatchSameEpoch]), a file at the same or a higher epoch that the password does
     * not open ([FailureReason.BadPasswordOrCorrupt]), a missing remote ([FailureReason.RemoteMissing]), a remote
     * that is not a vault, or an unpublished password change that cannot be published
     * ([FailureReason.PendingRotationUnpublished]).
     *
     * It first makes a final attempt to pull (with [password] as the reopen password); if that works, nothing is
     * replaced. Otherwise it uploads this device's local vault as a **new key epoch** (a rotation with [password], at
     * an epoch above anything on the server and above this device's), conditional on the remote still being the file
     * it just looked at, reads it back, and reports [SyncWarning.RemoteReplaced]. Other devices that know the
     * password open it with their password ([FailureReason.ReopenRequired]); they see an unverified chain unless
     * they were one epoch behind. **Whatever was on the server is gone from the share**, and the content other
     * devices wrote there and this device never pulled is lost unless they still hold it locally: export a backup
     * first ([exportBackup]) if in doubt. Change the WebDAV credential if the reason was a hostile writer.
     *
     * @param password the master password (verified against the local vault)
     * @param confirm must be true: a replacement is never implicit
     * @throws VaultSessionException.ConfirmationRequired when [confirm] is false
     * @throws VaultException.BadPasswordOrCorrupt when [password] is wrong
     */
    suspend fun replaceRemoteWithLocal(
        remote: RemoteStore,
        password: CharArray,
        confirm: Boolean = false,
    ): ReplaceRemoteResult {
        if (!confirm) throw VaultSessionException.ConfirmationRequired("Replacing the remote vault")
        return operation {
            val vs = localStore.load().vaults[vaultId] ?: VaultSyncState()
            val localFile = checkNotNull(vs.localFile) { "The session has no local vault file" }
            VaultCodec.open(localFile, password, memoryCeilingKiB).close()
            val engine = engine(remote)
            // An unresolved pending rotation is part of the final pull attempt (and superseded by a replacement).
            val pull = pullBeforeReplacing(engine, remote, password)
            val failure = (pull.outcome as? SyncOutcome.Failed)?.reason
            if (failure == null || failure !in REPLACEABLE) return@operation ReplaceRemoteResult(false, pull)
            val remoteEpoch = try {
                remote.read()?.let { runCatching { VaultCodec.inspect(it.bytes).keyEpoch }.getOrNull() } ?: 0L
            } catch (e: CancellationException) {
                throw e
            } catch (e: RemoteIoException) {
                return@operation ReplaceRemoteResult(false, pull)
            }
            val staged = hooks.stage { VaultCodec.changePassword(it, password, null, atLeastEpoch = remoteEpoch + 1L) }
            try {
                val result = engine.sync(state.value, SyncOptions(), staged, null, ReplaceRemote(remoteEpoch))
                ReplaceRemoteResult(replaced = result.outcome !is SyncOutcome.Failed, sync = result)
            } finally {
                staged.discard()
            }
        }
    }

    private suspend fun pullBeforeReplacing(engine: SyncEngine, remote: RemoteStore, password: CharArray): SyncResult =
        resolvePendingRotation(remote) ?: engine.sync(state.value, SyncOptions(), null, password)

    /**
     * Acknowledges the re-key warning ([SyncWarning.KeyEpochChainUnverified] / [SyncWarning.ConcurrentRekeyAdopted]):
     * until this is called every sync result repeats it, across restarts, because the warning is part of the persisted
     * state. Call it only after the user has seen it.
     */
    suspend fun acknowledgeKeyEpochWarning() {
        check(!closed) { "Session is closed" }
        localStore.exclusive {
            val persisted = localStore.load()
            val vs = persisted.vaults[vaultId] ?: return@exclusive
            if (vs.chainWarning != null) {
                localStore.save(persisted.copy(vaults = persisted.vaults + (vaultId to vs.copy(chainWarning = null))))
            }
        }
    }

    /**
     * **Recovery action:** the sealed local vault file as it is right now (content and key epoch of this session),
     * for the user to keep somewhere safe. It is opened with the vault password by [importBackup] (or by
     * [VaultCodec.open]). It contains no more than the vault file on the server does; it is as safe as that file.
     * Works in every state, including when sync is stuck.
     */
    fun exportBackup(): ByteArray {
        check(!closed) { "Session is closed" }
        return hooks.sealLocal(state.value)
    }

    /**
     * A per-device convenience-unlock secret for the current data key (see [OpenVault.exportLocalUnlockSecret]).
     * Store it only in platform secure storage and zero the array after use. It stops working after any password
     * change ([keyEpoch] changes); [openWithLocalUnlockSecret] then fails with `KeyEpochMismatch` and the UI asks for
     * the password.
     */
    fun exportLocalUnlockSecret(): ByteArray = hooks.exportLocalUnlockSecret()

    /**
     * Zeroes the data key held in memory and releases the directory. The session cannot be used afterwards. If an
     * operation ([sync], [changePassword], ...) is running, the close happens as soon as it ends (it is never
     * done under it); [edit] racing with a close fails with `IllegalStateException`.
     */
    override fun close() {
        closeRequested = true
        if (operations.tryLock()) {
            try {
                shutDown()
            } finally {
                operations.unlock()
            }
        }
    }

    @Synchronized
    private fun shutDown() {
        if (closed) return
        closed = true
        hooks.close()
        directoryLock.close()
    }

    private fun engine(remote: RemoteStore) = SyncEngine(
        remote, hooks, localStore, deviceId,
        clock = tuning.clock,
        random = tuning.random,
        sleep = tuning.sleep,
        maxAttempts = tuning.maxAttempts,
        leaseMillis = tuning.leaseMillis,
        requestBudgetMillis = tuning.requestBudgetMillis,
        probeMaxAgeMillis = tuning.probeMaxAgeMillis,
        view = view,
    )

    // ------------------------------------------------------------------ an unpublished password change

    /**
     * Resolves the pending rotation of the state (see [open]) against the remote before any sync. Returns a failed
     * result when the session cannot go on, null otherwise.
     */
    private suspend fun resolvePendingRotation(remote: RemoteStore): SyncResult? {
        val vs = localStore.load().vaults[vaultId] ?: return null
        val pending = vs.pendingLocalFile ?: return null
        val pendingEpoch = try {
            VaultCodec.inspect(pending).keyEpoch
        } catch (e: VaultException) {
            setPending(null)
            return null
        }
        val remoteFile = try {
            remote.read()
        } catch (e: CancellationException) {
            throw e
        } catch (e: RemoteAuthException) {
            return SyncResult(SyncOutcome.Failed(FailureReason.AuthFailed, e.message), state.value)
        } catch (e: RemoteIoException) {
            return SyncResult(SyncOutcome.Failed(FailureReason.Network, e.message), state.value)
        }
        val landed = remoteFile != null && try {
            VaultCodec.haveSameHeader(remoteFile.bytes, pending)
        } catch (e: VaultException) {
            false
        }
        val openedWithNewKey = hooks.keyEpoch >= pendingEpoch
        when {
            // The password change reached the server and this session already holds its key: nothing to resolve.
            landed && openedWithNewKey -> setPending(null)
            // It reached the server but this session still holds the old key: the sync reports ReopenRequired and
            // adopting the new password clears the pending rotation.
            landed -> Unit
            // It never reached the server (or was superseded) and this session holds the old key: discard it.
            !openedWithNewKey -> setPending(null)
            // This session was opened with the new password of a change that is not on the server.
            else -> return SyncResult(
                SyncOutcome.Failed(
                    FailureReason.PendingRotationUnpublished,
                    "the password change was not published: open with the old password, or replace the remote",
                ),
                state.value,
            )
        }
        return null
    }

    private suspend fun setPending(file: ByteArray?) {
        localStore.exclusive {
            val persisted = localStore.load()
            val vs = persisted.vaults[vaultId] ?: return@exclusive
            localStore.save(persisted.copy(vaults = persisted.vaults + (vaultId to vs.copy(pendingLocalFile = file))))
        }
        if (file == null) pendingRotationUnresolved = false
    }

    companion object {
        private val REPLACEABLE = setOf(
            FailureReason.HeaderMismatchSameEpoch,
            FailureReason.BadPasswordOrCorrupt,
            FailureReason.RemoteMissing,
            FailureReason.InvalidRemoteFile,
            FailureReason.IntegrityFailure,
            FailureReason.PendingRotationUnpublished,
        )

        /**
         * Creates a new vault protected by [password] in [dir] (created if missing) and holds the directory.
         *
         * @throws VaultSessionException.DirectoryInUse when another session holds [dir]
         * @throws VaultSessionException.DirectoryHoldsVault when [dir] already holds a vault
         * @throws VaultSessionException.StateUnreadable when the directory's state file is damaged
         * @throws LocalStateException when the directory cannot be used
         */
        suspend fun create(
            dir: File,
            password: CharArray,
            kdf: KdfParams = KdfParams.Default,
            tuning: SessionTuning = SessionTuning(),
        ): VaultSession {
            val localStore = FileLocalStateStore(dir)
            val lock = localStore.lockDirectory()
            try {
                return localStore.exclusive {
                    val persisted = loadState(localStore)
                    if (persisted.vaults.isNotEmpty()) throw VaultSessionException.DirectoryHoldsVault()
                    val vault = VaultCodec.create(password, kdf)
                    try {
                        val deviceId = persisted.deviceId ?: newDeviceId()
                        val sealed = VaultCodec.seal(vault)
                        localStore.save(
                            persisted.copy(
                                vaults = mapOf(vault.vaultId to VaultSyncState(localFile = sealed)),
                                deviceId = deviceId,
                            ),
                        )
                        VaultSession(
                            localStore, lock, vault.vaultId, OpenVaultCodecHooks(vault, KdfParams.PLATFORM_CEILING_KIB),
                            deviceId, tuning, KdfParams.PLATFORM_CEILING_KIB, vault.content, false,
                        )
                    } finally {
                        vault.close()
                    }
                }
            } catch (e: Throwable) {
                lock.close()
                throw e
            }
        }

        /**
         * Opens the vault in [dir] with the master [password] and holds the directory. [memoryCeilingKiB] is the
         * most memory this device accepts for one key derivation (pass a lower value on small devices); it applies to
         * this open and to every later re-key adoption and password change of the session.
         *
         * **After a crash during a password change** the state may hold an unpublished new-epoch file (the
         * "pending rotation"). The password is tried against the committed local file first and, when that fails,
         * against the pending file: the old password opens the committed vault (the unpublished change is dropped by
         * the next sync unless the server has it), the new password opens the pending one. The next [sync] resolves
         * which of them the server holds.
         *
         * @throws VaultSessionException.DirectoryInUse when another session holds [dir]
         * @throws VaultSessionException.StateUnreadable when the state file is damaged: see [salvage]
         * @throws VaultSessionException.NoVault when [dir] holds no vault
         * @throws org.terminalmax.core.vault.VaultException.BadPasswordOrCorrupt for a wrong password
         * @throws org.terminalmax.core.vault.VaultException.KdfCostTooHigh when the vault's key derivation exceeds
         *   [memoryCeilingKiB] (or does not fit in memory)
         */
        suspend fun open(
            dir: File,
            password: CharArray,
            memoryCeilingKiB: Int = KdfParams.PLATFORM_CEILING_KIB,
            tuning: SessionTuning = SessionTuning(),
        ): VaultSession = openWith(dir, tuning, memoryCeilingKiB, allowPending = true) { file ->
            VaultCodec.open(file, password, memoryCeilingKiB)
        }

        /**
         * Opens the vault in [dir] with a secret from [exportLocalUnlockSecret] (biometrics, OS keychain). The caller
         * zeroes [secret] afterwards.
         *
         * @throws org.terminalmax.core.vault.VaultException.KeyEpochMismatch when the vault has been re-keyed since
         *   the secret was exported: ask for the password and export a new secret
         */
        suspend fun openWithLocalUnlockSecret(
            dir: File,
            secret: ByteArray,
            tuning: SessionTuning = SessionTuning(),
            memoryCeilingKiB: Int = KdfParams.PLATFORM_CEILING_KIB,
        ): VaultSession = openWith(dir, tuning, memoryCeilingKiB, allowPending = false) { file ->
            VaultCodec.openWithLocalUnlockSecret(file, secret)
        }

        private suspend fun openWith(
            dir: File,
            tuning: SessionTuning,
            memoryCeilingKiB: Int,
            allowPending: Boolean,
            open: (ByteArray) -> OpenVault,
        ): VaultSession {
            val localStore = FileLocalStateStore(dir)
            val lock = localStore.lockDirectory()
            try {
                return localStore.exclusive {
                    val persisted = loadState(localStore)
                    val entries = persisted.vaults.entries.filter { it.value.localFile != null }
                    if (entries.size > 1) throw VaultSessionException.AmbiguousDirectory()
                    val entry = entries.singleOrNull() ?: throw VaultSessionException.NoVault()
                    val vs = entry.value
                    var openedPending = false
                    val vault = try {
                        open(vs.localFile!!)
                    } catch (e: VaultException.BadPasswordOrCorrupt) {
                        val pending = vs.pendingLocalFile
                        if (!allowPending || pending == null) throw e
                        openedPending = true
                        open(pending)
                    }
                    try {
                        var next = persisted
                        if (openedPending) {
                            // The new password opened the unpublished change: from now on that file is the local one
                            // (edits are sealed under its key), and the pending marker stays until a sync resolves it.
                            next = next.copy(vaults = next.vaults + (entry.key to vs.copy(localFile = vs.pendingLocalFile)))
                        }
                        val deviceId = next.deviceId ?: newDeviceId().also { next = next.copy(deviceId = it) }
                        if (next !== persisted) localStore.save(next)
                        VaultSession(
                            localStore, lock, vault.vaultId, OpenVaultCodecHooks(vault, memoryCeilingKiB), deviceId, tuning,
                            memoryCeilingKiB, vault.content, vs.pendingLocalFile != null,
                        )
                    } finally {
                        vault.close()
                    }
                }
            } catch (e: Throwable) {
                lock.close()
                throw e
            }
        }

        /**
         * Enrols this device in the vault that [remote] holds: downloads and opens it with [password] and **uploads
         * nothing and writes nothing**. The returned [JoinPreview] shows what the file contains and its
         * [JoinPreview.fingerprint]; compare that with [fingerprint] on a device that already has the vault (a
         * server that serves an old or foreign file is thereby noticed), then call [JoinPreview.confirm]. The
         * directory is held until the preview is confirmed or closed.
         *
         * @throws VaultSessionException.RemoteHasNoVault when the remote has no file
         * @throws VaultSessionException.DirectoryHoldsVault when [dir] already holds a vault
         * @throws RemoteIoException on a network or server failure ([RemoteAuthException] for bad credentials)
         * @throws org.terminalmax.core.vault.VaultException for a wrong password or a file that cannot be opened
         */
        suspend fun join(
            dir: File,
            remote: RemoteStore,
            password: CharArray,
            memoryCeilingKiB: Int = KdfParams.PLATFORM_CEILING_KIB,
            tuning: SessionTuning = SessionTuning(),
        ): JoinPreview {
            val localStore = FileLocalStateStore(dir)
            val lock = localStore.lockDirectory()
            var vault: OpenVault? = null
            try {
                val persisted = loadState(localStore)
                if (persisted.vaults.isNotEmpty()) throw VaultSessionException.DirectoryHoldsVault()
                val file = remote.read() ?: throw VaultSessionException.RemoteHasNoVault()
                val opened = VaultCodec.open(file.bytes, password, memoryCeilingKiB)
                vault = opened
                val content = opened.content
                val live = content.records.filterNot { it.deleted }.groupingBy { it.wireTypeName }.eachCount()
                return JoinPreview(
                    vaultId = opened.vaultId,
                    keyEpoch = opened.keyEpoch,
                    revision = content.revision,
                    recordCounts = live.toSortedMap(),
                    deletedCount = content.records.count { it.deleted },
                    fingerprint = opened.fingerprint,
                    onConfirm = {
                        try {
                            localStore.exclusive {
                                val deviceId = persisted.deviceId ?: newDeviceId()
                                val digest = MessageDigest.getInstance("SHA-256").digest(file.bytes)
                                    .joinToString("") { "%02x".format(it) }
                                localStore.save(
                                    persisted.copy(
                                        vaults = mapOf(
                                            opened.vaultId to VaultSyncState(
                                                baseFile = file.bytes,
                                                localFile = file.bytes,
                                                highestRevision = content.revision,
                                                highestKeyEpoch = opened.keyEpoch,
                                                fileDigests = mapOf(content.revision to digest),
                                            ),
                                        ),
                                        deviceId = deviceId,
                                    ),
                                )
                                VaultSession(
                                    localStore, lock, opened.vaultId, OpenVaultCodecHooks(opened, memoryCeilingKiB),
                                    deviceId, tuning, memoryCeilingKiB, content, false,
                                )
                            }
                        } catch (e: Throwable) {
                            lock.close()
                            throw e
                        } finally {
                            opened.close()
                        }
                    },
                    onClose = {
                        opened.close()
                        lock.close()
                    },
                )
            } catch (e: Throwable) {
                vault?.close()
                lock.close()
                throw e
            }
        }

        /**
         * Creates a vault in the empty directory [dir] from [backup] (a file from [exportBackup] or
         * [SalvageResult.Recovered.sealedVault]), opened with [password]. The vault keeps its identity and key epoch;
         * the device starts without sync floors, so its first [sync] with a remote is a trust-on-first-use sync
         * ([SyncWarning.FirstUseTrust]).
         *
         * @throws VaultSessionException.DirectoryHoldsVault when [dir] already holds a vault
         * @throws org.terminalmax.core.vault.VaultException for a wrong password or a file that cannot be opened
         */
        suspend fun importBackup(
            dir: File,
            backup: ByteArray,
            password: CharArray,
            memoryCeilingKiB: Int = KdfParams.PLATFORM_CEILING_KIB,
            tuning: SessionTuning = SessionTuning(),
        ): VaultSession {
            val localStore = FileLocalStateStore(dir)
            val lock = localStore.lockDirectory()
            try {
                return localStore.exclusive {
                    val persisted = loadState(localStore)
                    if (persisted.vaults.isNotEmpty()) throw VaultSessionException.DirectoryHoldsVault()
                    val vault = VaultCodec.open(backup, password, memoryCeilingKiB)
                    try {
                        val deviceId = persisted.deviceId ?: newDeviceId()
                        localStore.save(
                            persisted.copy(
                                vaults = mapOf(vault.vaultId to VaultSyncState(localFile = backup.copyOf())),
                                deviceId = deviceId,
                            ),
                        )
                        VaultSession(
                            localStore, lock, vault.vaultId, OpenVaultCodecHooks(vault, memoryCeilingKiB), deviceId, tuning,
                            memoryCeilingKiB, vault.content, false,
                        )
                    } finally {
                        vault.close()
                    }
                }
            } catch (e: Throwable) {
                lock.close()
                throw e
            }
        }

        /**
         * Recovers what it can from a damaged state file in [dir], **without deleting or changing anything**: it
         * reads the state file leniently (its checksum may fail while the vault inside is intact) and the rolling
         * previous copy, and tries [password] on the sealed local vault (and an unpublished password change) of each,
         * newest first. The result tells what was found (revision, record count) and carries the sealed vault for
         * [importBackup] into a fresh directory. The sync floors of a recovered state may be one step older than they
         * were, which only weakens rollback detection until the next sync.
         *
         * @throws VaultSessionException.DirectoryInUse when a session holds [dir]
         */
        suspend fun salvage(
            dir: File,
            password: CharArray,
            memoryCeilingKiB: Int = KdfParams.PLATFORM_CEILING_KIB,
        ): SalvageResult {
            val localStore = FileLocalStateStore(dir)
            localStore.lockDirectory().use {
                val tried = ArrayList<SalvageSource>()
                for (candidate in localStore.salvageCandidates()) {
                    val source = candidate.source
                    tried += source
                    for (vs in candidate.state.vaults.values) {
                        for ((file, pending) in listOf(vs.localFile to false, vs.pendingLocalFile to true)) {
                            if (file == null) continue
                            val opened = try {
                                VaultCodec.open(file, password, memoryCeilingKiB)
                            } catch (e: VaultException) {
                                continue
                            }
                            try {
                                return SalvageResult.Recovered(
                                    source = source,
                                    vaultId = opened.vaultId,
                                    keyEpoch = opened.keyEpoch,
                                    revision = opened.content.revision,
                                    recordCount = opened.content.records.count { !it.deleted },
                                    fromPendingRotation = pending,
                                    sealedVault = file.copyOf(),
                                )
                            } finally {
                                opened.close()
                            }
                        }
                    }
                }
                return SalvageResult.NothingRecovered(tried)
            }
        }

        private suspend fun loadState(localStore: FileLocalStateStore): LocalSyncState = try {
            localStore.load()
        } catch (e: LocalStateException) {
            throw VaultSessionException.StateUnreadable(e)
        }

        private fun newDeviceId(): String {
            val bytes = ByteArray(8)
            SecureRandom().nextBytes(bytes)
            return "dev-" + bytes.joinToString("") { "%02x".format(it) }
        }
    }
}
