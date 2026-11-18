// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.sync

import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom
import kotlin.coroutines.cancellation.CancellationException
import kotlin.random.Random
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.terminalmax.core.vault.KdfParams
import org.terminalmax.core.vault.OpenVault
import org.terminalmax.core.vault.VaultCodec
import org.terminalmax.core.vault.VaultContent
import org.terminalmax.core.vault.VaultEditor
import org.terminalmax.core.vault.VaultException
import org.terminalmax.core.vault.VaultRecord
import org.terminalmax.core.vault.mergeVaults

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
 * @property published true when the re-keyed file **did reach the server** although the call failed (only the local
 *   commit failed): the new password is live for every other device; sync again, it resolves the rest
 */
data class PasswordChangeResult(
    val sync: SyncResult,
    val imported: List<ImportedRecord>,
    val rekeyed: Boolean,
    val published: Boolean = false,
)

/**
 * The result of [VaultSession.replaceRemoteWithLocal].
 *
 * @property replaced true when the remote file was replaced by this device's copy. False when the final pull attempt
 *   succeeded (nothing needed replacing), failed for a reason replacement does not cure (network, credentials, a key
 *   derivation this device is too small for) or the remote changed meanwhile: [sync] says which
 */
data class ReplaceRemoteResult(val replaced: Boolean, val sync: SyncResult)

/** How [VaultSession.resolvePendingPasswordChange] ended. */
enum class PendingResolution {
    /** There was no unpublished password change. */
    NothingPending,

    /** The server already held the change; this device now follows it (the new password is live). */
    AlreadyPublished,

    /** The server was still exactly what it was before the change: the change was **published now**. */
    Published,

    /**
     * The change never reached the server and was dropped: the old password stays live and the revocation did NOT
     * happen ([SyncWarning.PasswordChangeNotPublished] repeats until acknowledged). Edits made meanwhile are kept.
     */
    Abandoned,

    /** Nothing was resolved: [ResolvePendingResult.sync] says why. */
    Unresolved,
}

/** The result of [VaultSession.resolvePendingPasswordChange]: what happened and the sync result behind it. */
data class ResolvePendingResult(val resolution: PendingResolution, val sync: SyncResult)

/** The result of [VaultSession.restoreFromHistory]. */
data class RestoreResult(val restoredIds: List<String>, val notRestorableIds: List<String>)

/**
 * The result of [VaultSession.migrateToNewVault].
 *
 * @property session the session of the new vault (it holds the directory now, and the old session object is closed);
 *   null when the migration did not happen ([sync] says why)
 * @property previousVault the sealed file of the vault that was left (opened with the same password): keep it until
 *   every device has enrolled in the new vault
 */
class MigrationResult(val session: VaultSession?, val sync: SyncResult, val previousVault: ByteArray?)

/**
 * The rollback floors of a vault on one device: a remote file below them is a rollback or a replay. They are carried by
 * [SalvageResult.Recovered] and seed [VaultSession.importBackup].
 */
data class SyncFloors(
    val highestRevision: Long = 0L,
    val highestKeyEpoch: Long = 0L,
    val fileDigests: Map<Long, String> = emptyMap(),
)

/** What [VaultSession.salvage] recovered, or that it recovered nothing. Nothing is ever deleted or changed. */
sealed class SalvageResult {
    /**
     * The vault was opened with the password from [source]. [revision] and [recordCount] (records that are not
     * deleted) tell the user what was recovered; [sealedVault] is the recovered sealed vault file: give it to
     * [VaultSession.importBackup] in a fresh directory (with the same password and [floors]) to continue from it.
     * [fromPendingRotation] is true when it was the unpublished new-epoch file of a password change. [floors] are the
     * rollback floors of the salvaged state (they may be one save older than the lost state; they are never lower than
     * what the recovered file itself implies when imported).
     */
    class Recovered(
        val source: SalvageSource,
        val vaultId: String,
        val keyEpoch: Long,
        val revision: Long,
        val recordCount: Int,
        val fromPendingRotation: Boolean,
        val sealedVault: ByteArray,
        val floors: SyncFloors = SyncFloors(),
    ) : SalvageResult()

    /** Neither the state file nor its previous copy held a vault that the password opens. */
    data class NothingRecovered(val triedSources: List<SalvageSource>) : SalvageResult()
}

/**
 * A remote vault that was downloaded and opened for enrolment of this device, **before** anything is uploaded or
 * saved. Show [fingerprint] and [revision] (and [keyEpoch], [recordCounts]) to the user and compare them with what
 * another device of the user shows ([VaultSession.fingerprint]); only then call [confirm]. **This comparison is the
 * device's only trust-on-first-use check**: the first sync after [confirm] does not warn again. [close] abandons the
 * preview. It holds the directory lock until one of the two is called and keeps the decrypted vault in memory, so
 * always close it (`preview.use { ... }` or `finally`): there is no finalizer and no timeout.
 *
 * Joining only works when the password opens the remote vault: a vault written by someone else under a password
 * of their own fails with `BadPasswordOrCorrupt`; one under the same password but another key shows another
 * fingerprint.
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
 *    fails at once with [VaultSessionException.DirectoryInUse] instead of silently losing edits. The check happens
 *    **before** the lock file is touched (a process-wide registry), so a rejected attempt can never release the OS lock
 *    a live session holds (closing any descriptor of a file drops all of the process's POSIX locks on it);
 *  - **local persistence**: the sealed local vault file and the sync state (floors, base, digests) live in one
 *    file in the directory that is replaced atomically, with a rolling previous copy (see [FileLocalStateStore]), so
 *    a crash leaves the old pair or the new pair and never a mixture; every edit and every sync result is committed
 *    there before it is published in [content]. On POSIX the directory is created `0700` and every file `0600`;
 *  - **the data key**, held in memory while the session is open; superseded keys (after a password change or a
 *    re-key adopted from another device) are zeroed by the session, not by the caller;
 *  - **serialisation without blocking edits**: [sync], [changePassword] and [replaceRemoteWithLocal] run one at a
 *    time, but they do their network I/O on a snapshot and take the state lock only to commit; an [edit] never waits
 *    for the network. If edits were made while a sync ran, the sync commits the *join* of its result and those
 *    edits, reports [SyncResult.localEditsPending], and the edits go out with the next sync. An edit that loses to a
 *    newer remote version of the same record in that join is moved to the history and reported as a conflict of that
 *    sync (nothing disappears unreported).
 *
 * **Error model.** [edit] throws (`VaultException.InvalidContent`, or whatever the block throws; the session is
 * unchanged). [sync] and [replaceRemoteWithLocal] never throw for protocol, network or server problems: they return a
 * failed [SyncResult] (a sync on a closed session returns [FailureReason.SessionClosed]). [changePassword] throws for
 * a wrong old password (`VaultException.BadPasswordOrCorrupt`), for a KDF parameter this device cannot honour
 * (`VaultException.KdfCostTooHigh`) and `IllegalStateException` for a synced vault without a remote; everything about
 * the transaction itself (including an exhausted key epoch counter, [FailureReason.KeyEpochLimitReached]) is a failed
 * [SyncResult] inside [PasswordChangeResult]. The static functions throw [VaultSessionException] for directory
 * problems and `VaultException` for a wrong password or a damaged file.
 *
 * The master password is never stored. Per-device convenience unlock (biometrics, OS keychain) uses
 * [exportLocalUnlockSecret] and [openWithLocalUnlockSecret]; the secret is the data key itself and belongs in
 * platform secure storage only (see [OpenVault.exportLocalUnlockSecret]); [keyEpoch] changes whenever it goes stale.
 * **Revoking a lost device means changing the vault password (that replaces the data key and the device's local
 * secret stops working) AND changing the WebDAV credential** (a device that still holds it can write to the share:
 * it cannot read what is written after the change, but it can delete, replace or fill the file). It protects what is
 * written afterwards; it cannot recall what the device already read. See the sync README, "Recovery actions", for
 * every state that needs a user decision, and "Obligations of the UI layer" for what a UI must do.
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
    heldKeyIsPending: Boolean = false,
    /** True when the state came from the rolling previous copy because the state file itself was missing. */
    val restoredFromPreviousStateCopy: Boolean = false,
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

    /**
     * True while this session holds the key of the unpublished password change (it was opened with the new
     * password): the committed old-epoch local file is kept untouched next to it, and edits go to the pending file.
     */
    @Volatile
    private var openedFromPending = heldKeyIsPending

    /** The password change whose upload is running now, so that an [edit] can keep its pending file current. */
    @Volatile
    private var inFlightStaged: StagedHeaderChange? = null

    /** True while [migrateToNewVault] runs: edits would be lost with the old vault, so they are refused. */
    @Volatile
    private var migrating = false

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
     * True while an unpublished password change exists in the state (found on open, or left by an upload that was
     * refused) and has not been resolved yet: by a sync, [resolvePendingPasswordChange] or [replaceRemoteWithLocal]
     * (see the sync README, "A crash during a password change"). Which password is the live one is stated by those
     * calls' results, not by this flag.
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

    private suspend fun <T> operation(onClosed: (() -> T)? = null, block: suspend () -> T): T = operations.withLock {
        if (closed && onClosed != null) return@withLock onClosed()
        check(!closed) { "Session is closed" }
        try {
            block()
        } finally {
            keyEpochFlow.value = hooks.keyEpoch
            refreshPendingFlags()
            if (closeRequested) shutDown()
        }
    }

    /** Re-reads from the state whether a pending rotation still exists (it is also cleared by the engine). */
    private suspend fun refreshPendingFlags() {
        try {
            val pending = localStore.load().vaults[vaultId]?.pendingLocalFile != null
            pendingRotationUnresolved = pending
            if (!pending) openedFromPending = false
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            // The state cannot be read: leave the flags as they are, the next operation reports the problem.
        }
    }

    private suspend fun loadVaultState(): VaultSyncState = localStore.load().vaults[vaultId] ?: VaultSyncState()

    /** The sealed file that the held key opens (the pending file while this session was opened from it). */
    private fun heldFile(vs: VaultSyncState): ByteArray? =
        if (openedFromPending) vs.pendingLocalFile ?: vs.localFile else vs.localFile

    /** Opens [heldFile] with [password] (verifies it) and returns the opened vault; the caller closes it. */
    private fun openHeld(vs: VaultSyncState, password: CharArray): OpenVault {
        val file = checkNotNull(heldFile(vs)) { "The session has no local vault file" }
        return VaultCodec.open(file, password, memoryCeilingKiB)
    }

    /**
     * Applies [block] to the content and commits the result durably before publishing it in [content]. If [block]
     * throws, nothing changes. Revisions are above everything this device has synced, even if the in-memory content
     * were stale. An edit never waits for the network: it only takes the short state lock. While a password change is
     * in flight the edit also updates the pending new-epoch file in the same save, so a crash at any moment leaves
     * both files with the edit; in a session opened with the new password of an unpublished change the edit goes to
     * the pending file (the old-epoch file is kept as it is until the change is resolved).
     *
     * @throws org.terminalmax.core.vault.VaultException.InvalidContent when the result breaks the content rules
     * @throws IllegalStateException when the session is closed or a migration to a new vault is running
     */
    suspend fun edit(block: (VaultEditor) -> Unit) {
        applyEdit(block)
    }

    private suspend fun applyEdit(block: (VaultEditor) -> Unit) {
        check(!closed) { "Session is closed" }
        localStore.exclusive {
            // Checked again under the state lock: a close or a migration may have started meanwhile.
            check(!closed) { "Session is closed" }
            check(!migrating) { "The vault is being migrated to a new vault; edit the new one" }
            val persisted = localStore.load()
            val vs = persisted.vaults[vaultId] ?: VaultSyncState()
            val editor = VaultEditor(
                state.value, deviceId, tuning.clock, revisionFloor = vs.highestRevision,
            )
            block(editor)
            val edited = editor.content
            if (edited != state.value) {
                val sealed = hooks.sealLocal(edited) // validates the content
                val staged = inFlightStaged
                val pending = vs.pendingLocalFile
                val pendingIsStaged = staged != null && pending != null &&
                    try {
                        hooks.claimedKeyEpoch(pending) == staged.keyEpoch
                    } catch (e: VaultException) {
                        false
                    }
                val updated = when {
                    pendingIsStaged -> vs.copy(
                        localFile = if (openedFromPending) vs.localFile else sealed,
                        pendingLocalFile = hooks.sealLocalStaged(edited, staged!!),
                    )
                    openedFromPending -> vs.copy(pendingLocalFile = sealed, pendingHoldsNewerEdits = true)
                    else -> vs.copy(localFile = sealed)
                }
                localStore.save(persisted.copy(vaults = persisted.vaults + (vaultId to updated)))
                state.value = edited
            }
        }
    }

    /**
     * Synchronises with [remote]. See [SyncEngine] for the protocol. The network I/O runs on a snapshot, without
     * blocking [edit]; the merged content is committed together with the new sync state and published in
     * [content]. When the remote vault was re-keyed (a password change on another device) the result is
     * [FailureReason.ReopenRequired] unless [reopenPassword] (the master password, not retained) is given. A
     * competing key at the *same* epoch is [FailureReason.KeyMismatchSameEpoch] and needs
     * [SyncOptions.adoptCompetingKeyFingerprint] as well. An unpublished password change is resolved first (see
     * [resolvePendingPasswordChange]).
     *
     * Every failure has a documented user action (sync README, "Recovery actions"): [SyncOptions.allowRollback],
     * [SyncOptions.recreateRemote], [SyncOptions.acceptRevisionJump], [SyncOptions.acceptLargeRemoteChange],
     * [replaceRemoteWithLocal], [migrateToNewVault], [exportBackup].
     */
    suspend fun sync(
        remote: RemoteStore,
        options: SyncOptions = SyncOptions(),
        reopenPassword: CharArray? = null,
    ): SyncResult = operation(onClosed = { closedResult() }) {
        resolvePendingRotation(remote)?.let { return@operation it }
        engine(remote).sync(state.value, options, null, reopenPassword)
    }

    private fun closedResult() = SyncResult(
        SyncOutcome.Failed(FailureReason.SessionClosed, "the session is closed"), state.value,
    )

    /**
     * Changes the master password (and with [kdf] the key-derivation parameters), which **replaces the data key**
     * and so revokes every other device until it enters the new password. [old] is verified against the local vault
     * first. Revoking a lost device also requires changing the WebDAV credential.
     *
     * With a [remote] this is one transaction: a normal sync runs first (so everything written at the old key epoch
     * is imported; [PasswordChangeResult.imported] lists it), then the re-keyed file is uploaded **only if the remote
     * file is still exactly what that sync left**, and the change is committed locally only after the upload is read
     * back. Before the upload the sealed new-epoch local file is written durably as a *pending rotation*, and every
     * edit made until the commit updates it too, so a crash at any point is resolvable (see [open]). A failure
     * before the commit leaves the old password and epoch intact. If another device changed the vault in the meantime
     * the result is [FailureReason.RemoteChangedDuringRotation] or [FailureReason.HeaderChangedRemotely]: nothing was
     * changed, repeat the call. When the key epoch counter is exhausted the result is
     * [FailureReason.KeyEpochLimitReached] (use [migrateToNewVault]).
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
        val vs = loadVaultState()
        openHeld(vs, old).close() // verifies the old password
        if (kdf != null && kdf.memoryKiB > memoryCeilingKiB) {
            throw VaultException.KdfCostTooHigh("the new key-derivation memory exceeds this device's ceiling")
        }
        if (remote == null) {
            check(!vs.established) { "This vault has been synced: pass its remote so that every device can follow" }
            val staged = stageRotation(new, kdf, atLeastEpoch = 0L)
                ?: return@operation PasswordChangeResult(epochLimitResult(), emptyList(), rekeyed = false)
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
        val staged = stageRotation(new, kdf, atLeastEpoch = 0L)
            ?: return@operation PasswordChangeResult(epochLimitResult(), imported, rekeyed = false)
        inFlightStaged = staged
        try {
            val result = engine.sync(state.value, options, staged, null)
            val warnings = (pre.warnings + result.warnings).distinct()
            if (result.outcome is SyncOutcome.Failed) {
                return@operation PasswordChangeResult(
                    SyncResult(result.outcome, state.value, warnings, failureInfo = result.failureInfo),
                    imported,
                    rekeyed = false,
                    published = result.failureInfo?.published == true,
                )
            }
            val outcome = if (pre.outcome is SyncOutcome.Merged) pre.outcome else result.outcome
            PasswordChangeResult(
                SyncResult(
                    outcome, result.content, warnings, result.localEditsPending || pre.localEditsPending,
                    remoteChanges = pre.remoteChanges,
                ),
                imported,
                rekeyed = true,
            )
        } finally {
            finishStaged(staged)
        }
    }

    /**
     * Prepares the key change of a rotation, or returns null when the key epoch counter leaves no room (a rotation
     * must not run into the limit: [migrateToNewVault] is the way out). [atLeastEpoch] is only ever derived from this
     * device's authenticated state.
     */
    private fun stageRotation(password: CharArray, kdf: KdfParams?, atLeastEpoch: Long): StagedHeaderChange? {
        val target = maxOf(hooks.keyEpoch + 1L, atLeastEpoch)
        if (target > VaultCodec.MAX_KEY_EPOCH - VaultCodec.KEY_EPOCH_HEADROOM) return null
        return try {
            hooks.stage { VaultCodec.changePassword(it, password, kdf, atLeastEpoch = atLeastEpoch) }
        } catch (e: VaultException.InvalidContent) {
            null // the epoch counter is exhausted
        }
    }

    private fun epochLimitResult() = SyncResult(
        SyncOutcome.Failed(
            FailureReason.KeyEpochLimitReached,
            "the key epoch counter leaves no room for another rotation: migrate to a new vault",
        ),
        state.value,
    )

    /** Ends a staged change: clears the in-flight marker and releases the key under the state lock (see [edit]). */
    private suspend fun finishStaged(staged: StagedHeaderChange) {
        withContext(NonCancellable) {
            localStore.exclusive {
                inFlightStaged = null
                staged.discard() // no-op once committed
            }
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
     * header ([FailureReason.HeaderMismatchSameEpoch]) or under another key ([FailureReason.KeyMismatchSameEpoch]), a
     * file at the same or a higher epoch that the password does not open ([FailureReason.BadPasswordOrCorrupt]), a file
     * at a **lower** key epoch ([FailureReason.KeyEpochRollback], for example a server restored from a backup), a
     * missing remote ([FailureReason.RemoteMissing]), a remote that is not a vault, or an unpublished password change
     * that cannot be published ([FailureReason.PendingRotationUnpublished]).
     *
     * It first makes a final attempt to pull (with [password] as the reopen password); if that works, nothing is
     * replaced (a remote that the password opens at a higher epoch is simply followed). Otherwise it uploads this
     * device's local vault as a **new key epoch** (a rotation with [newPassword], default [password]). The epoch is
     * this device's own highest epoch plus one: **never derived from the remote**, whose claim is unauthenticated.
     * The upload is a compare-and-replace: it replaces only the file that the failed pull judged (checked by its
     * SHA-256, with `If-Match` or the lock lease, then read back); if the remote is another file by then (or
     * [expectedRemoteDigest] is not the one judged) nothing is replaced
     * ([FailureReason.RemoteChangedDuringRotation]). It reports [SyncWarning.RemoteReplaced].
     *
     * It is **refused** when the remote's key derivation is too heavy for this device
     * ([FailureReason.RemoteKdfTooHeavyForDevice]: replacing would destroy a good vault because this device is small)
     * and when the remote is the verified successor of this device's key, i.e. the password was changed on another
     * device and [password] is the old one ([FailureReason.RemoteRekeyedElsewhere], unless [overrideLinkedRekey]).
     *
     * Other devices that know the password open the result with it ([FailureReason.ReopenRequired]); they see an
     * unverified chain unless they were one epoch behind. **Whatever was on the server is gone from the share**, and
     * the content other devices wrote there and this device never pulled is lost unless they still hold it locally:
     * export a backup first ([exportBackup]) if in doubt. Change the WebDAV credential if the reason was a hostile
     * writer.
     *
     * @param password the master password (verified against the local vault)
     * @param confirm must be true: a replacement is never implicit
     * @param newPassword the password of the replacement; pass a **different** one so that followers do not see
     *   [SyncWarning.PasswordUnchangedByRekey] (which exists to catch an old password typed into a forged re-key)
     * @param expectedRemoteDigest [FailureInfo.remoteDigest] of the sync result the user was shown, to replace only
     *   that file; null accepts whatever the final pull attempt judged
     * @param overrideLinkedRekey replace even though the password was changed on another device (lost new password)
     * @throws VaultSessionException.ConfirmationRequired when [confirm] is false
     * @throws VaultException.BadPasswordOrCorrupt when [password] is wrong
     */
    suspend fun replaceRemoteWithLocal(
        remote: RemoteStore,
        password: CharArray,
        confirm: Boolean = false,
        newPassword: CharArray? = null,
        expectedRemoteDigest: String? = null,
        overrideLinkedRekey: Boolean = false,
    ): ReplaceRemoteResult {
        if (!confirm) throw VaultSessionException.ConfirmationRequired("Replacing the remote vault")
        return operation {
            val vs = loadVaultState()
            openHeld(vs, password).close()
            val engine = engine(remote)
            // An unresolved pending rotation is part of the final pull attempt (and superseded by a replacement).
            val pull = pullBeforeReplacing(engine, remote, password)
            val failure = (pull.outcome as? SyncOutcome.Failed)?.reason
            if (failure == null || failure !in REPLACEABLE) return@operation ReplaceRemoteResult(false, pull)
            // What the failed pull judged: the replacement replaces exactly that file (or a missing one).
            val judged = pull.failureInfo?.remoteDigest
            if (expectedRemoteDigest != null && expectedRemoteDigest != judged) {
                return@operation ReplaceRemoteResult(
                    false,
                    changedMeanwhile(pull, "the remote file is not the one that was shown to the user"),
                )
            }
            // The new epoch comes from this device's authenticated state only (never from the remote's claim).
            val base = maxOf(hooks.keyEpoch, vs.highestKeyEpoch)
            val staged = stageRotation(newPassword ?: password, null, atLeastEpoch = base + 1L)
                ?: return@operation ReplaceRemoteResult(false, epochLimitResult())
            inFlightStaged = staged
            try {
                val replace = ReplaceRemote(
                    expectedRemoteDigest = judged,
                    checkExpectation = true,
                    refuseLinkedSuccessor = failure == FailureReason.BadPasswordOrCorrupt && !overrideLinkedRekey,
                )
                val result = engine.sync(state.value, SyncOptions(), staged, null, replace)
                ReplaceRemoteResult(replaced = result.outcome !is SyncOutcome.Failed, sync = result)
            } finally {
                finishStaged(staged)
            }
        }
    }

    private fun changedMeanwhile(pull: SyncResult, detail: String) = pull.copy(
        outcome = SyncOutcome.Failed(FailureReason.RemoteChangedDuringRotation, detail),
    )

    private suspend fun pullBeforeReplacing(engine: SyncEngine, remote: RemoteStore, password: CharArray): SyncResult =
        resolvePendingRotation(remote) ?: engine.sync(state.value, SyncOptions(), null, password)

    /**
     * Resolves an **unpublished password change** (see [hasUnresolvedPasswordChange]) explicitly, by consulting the
     * server. [password] is the **new** password of that change (it is verified against the pending file). What
     * happens depends on the server:
     *
     *  - it already holds the change: this device follows it ([PendingResolution.AlreadyPublished]);
     *  - it is still exactly the file this device last synced: the change is **published now** with the new key
     *    ([PendingResolution.Published]; only possible in a session opened with the new password, which holds that
     *    key);
     *  - otherwise the change is dropped and the old password stays live ([PendingResolution.Abandoned], with the
     *    persistent warning [SyncWarning.PasswordChangeNotPublished]); edits that only the pending file holds (made in
     *    a session opened with the new password) are first re-applied onto the vault that is kept (a merge join), so
     *    nothing is lost;
     *  - when it cannot be resolved (the server changed meanwhile, cannot be reached, ...) the result is
     *    [PendingResolution.Unresolved] with the failed [SyncResult]: nothing was changed.
     *
     * In a session opened with the new password the server may also hold *another* key (someone else changed the
     * password at the same time): use [sync] with that password instead (see [FailureReason.KeyMismatchSameEpoch]).
     *
     * @throws VaultException.BadPasswordOrCorrupt when [password] does not open the pending file
     */
    suspend fun resolvePendingPasswordChange(remote: RemoteStore, password: CharArray): ResolvePendingResult = operation {
        val vs = loadVaultState()
        val pending = vs.pendingLocalFile ?: return@operation ResolvePendingResult(
            PendingResolution.NothingPending, SyncResult(SyncOutcome.UpToDate, state.value),
        )
        val pendingVault = VaultCodec.open(pending, password, memoryCeilingKiB)
        try {
            val engine = engine(remote)
            val remoteFile = when (val read = readRemote(remote)) {
                is RemoteRead.Failed -> return@operation ResolvePendingResult(PendingResolution.Unresolved, read.result)
                is RemoteRead.Ok -> read.file
            }
            val landed = remoteFile != null && sameHeaderSafe(remoteFile.bytes, pending)
            if (openedFromPending) {
                if (landed) {
                    adoptLandedPending()
                    return@operation ResolvePendingResult(
                        PendingResolution.AlreadyPublished, engine.sync(state.value, SyncOptions()),
                    )
                }
                val baseFile = vs.baseFile
                if (remoteFile == null || baseFile == null || !remoteFile.bytes.contentEquals(baseFile)) {
                    return@operation ResolvePendingResult(
                        PendingResolution.Unresolved,
                        SyncResult(
                            SyncOutcome.Failed(
                                if (remoteFile == null) FailureReason.RemoteMissing else FailureReason.RemoteChangedDuringRotation,
                                "the server is not what it was when the password change was prepared: open with the " +
                                    "old password, sync, and change the password again (or replace the remote)",
                            ),
                            state.value,
                            failureInfo = remoteFile?.let { FailureInfo(remoteDigest = hooks.fingerprint(it.bytes)) },
                        ),
                    )
                }
                val replace = ReplaceRemote(
                    expectedRemoteDigest = hooks.fingerprint(baseFile),
                    checkExpectation = true,
                    kind = ReplaceRemote.Kind.CompletePending,
                )
                val result = engine.sync(state.value, SyncOptions(), null, null, replace)
                val resolution = if (result.outcome is SyncOutcome.Failed) PendingResolution.Unresolved else PendingResolution.Published
                return@operation ResolvePendingResult(resolution, result)
            }
            // This session holds the old key. Edits that only the pending file has are re-applied first.
            if (vs.pendingHoldsNewerEdits) joinIntoLocal(pendingVault.content)
            if (landed) {
                val result = engine.sync(state.value, SyncOptions(), null, password)
                val resolution = if (result.outcome is SyncOutcome.Failed) PendingResolution.Unresolved else PendingResolution.AlreadyPublished
                return@operation ResolvePendingResult(resolution, result)
            }
            dropPending(discardedEpoch = pendingVault.keyEpoch)
            ResolvePendingResult(PendingResolution.Abandoned, engine.sync(state.value, SyncOptions()))
        } finally {
            pendingVault.close()
        }
    }

    /**
     * **Last-resort recovery** for a vault that cannot go on at all (the key epoch counter or the revision counter is
     * exhausted, or the share is beyond repair and every other recovery was refused): creates a **new vault** (a new
     * vault id and a fresh key, protected by [password]) from this device's live records (deleted records and history
     * are dropped, every record restarts at revision 1) and publishes it **over whatever the remote holds**, as a
     * compare-and-replace of the file read in the attempt. The old vault is abandoned: every other device must enrol in
     * the new one ([join]) and its old vault stays on it until the user removes it. This session object is closed
     * (the directory lock moves to the returned session); [MigrationResult.previousVault] is the sealed old vault.
     * Edits are refused while it runs. The old share is gone from the server: export a backup first.
     *
     * @param password the master password (verified against the local vault; it protects the new vault too)
     * @param confirm must be true
     * @param kdf the key derivation of the new vault; default: that of the current slot
     * @param expectedRemoteDigest replace only a remote file with this SHA-256 (hex); null replaces what is read
     * @throws VaultSessionException.ConfirmationRequired when [confirm] is false
     * @throws VaultException.BadPasswordOrCorrupt when [password] is wrong
     * @throws VaultException.KdfCostTooHigh when [kdf] exceeds this session's memory ceiling
     */
    suspend fun migrateToNewVault(
        password: CharArray,
        remote: RemoteStore,
        confirm: Boolean = false,
        kdf: KdfParams? = null,
        expectedRemoteDigest: String? = null,
    ): MigrationResult {
        if (!confirm) throw VaultSessionException.ConfirmationRequired("Migrating to a new vault")
        return operation {
            val vs = loadVaultState()
            val old = openHeld(vs, password)
            var source: OpenVault? = null
            var fresh: OpenVault? = null
            var newHooks: OpenVaultCodecHooks? = null
            try {
                val params = kdf ?: old.kdfParams
                if (params.memoryKiB > memoryCeilingKiB) {
                    throw VaultException.KdfCostTooHigh("the new key-derivation memory exceeds this device's ceiling")
                }
                source = old.withContent(state.value)
                fresh = VaultCodec.migrateToNewVault(source, password, params)
                val previous = hooks.sealLocal(state.value)
                newHooks = OpenVaultCodecHooks(fresh, memoryCeilingKiB)
                migrating = true
                val newEngine = SyncEngine(
                    remote, newHooks, localStore, deviceId,
                    clock = tuning.clock,
                    random = tuning.random,
                    sleep = tuning.sleep,
                    maxAttempts = tuning.maxAttempts,
                    leaseMillis = tuning.leaseMillis,
                    requestBudgetMillis = tuning.requestBudgetMillis,
                    probeMaxAgeMillis = tuning.probeMaxAgeMillis,
                    view = null,
                    dropVaultOnCommit = vaultId,
                )
                val replace = ReplaceRemote(
                    expectedRemoteDigest = expectedRemoteDigest,
                    checkExpectation = expectedRemoteDigest != null,
                    kind = ReplaceRemote.Kind.NewVault,
                )
                val result = newEngine.sync(fresh.content, SyncOptions(), null, null, replace)
                if (result.outcome is SyncOutcome.Failed) {
                    newHooks.close()
                    return@operation MigrationResult(null, result, null)
                }
                val next = VaultSession(
                    localStore, directoryLock, fresh.vaultId, newHooks, deviceId, tuning, memoryCeilingKiB,
                    result.content, false,
                )
                newHooks = null // owned by the new session
                shutDown(releaseDirectory = false)
                MigrationResult(next, result, previous)
            } finally {
                migrating = false
                newHooks?.close()
                fresh?.close()
                source?.close()
                old.close()
            }
        }
    }

    /**
     * Brings deleted records back from the history. A deletion by another device that this device accepted (for
     * example after [SyncOptions.acceptLargeRemoteChange]) keeps the **last live version** of every deleted record
     * in the history for 30 revisions after the deletion (and as long as the bounded history has room: at most 200
     * entries and about 1 MiB), so it can be undone here. Each restored record becomes a new version of this device
     * above everything seen, so it outranks the tombstone and replicates like any edit. The result lists what was
     * restored and what had nothing to restore (not deleted, unknown, or already scrubbed).
     */
    suspend fun restoreFromHistory(recordIds: Collection<String>): RestoreResult {
        val restored = ArrayList<String>()
        val missing = ArrayList<String>()
        applyEdit { editor ->
            restored.clear()
            missing.clear()
            for (id in recordIds.distinct()) {
                val version = editor.content.history
                    .filter { it.id == id && !it.deleted }
                    .maxWithOrNull(compareBy<VaultRecord>({ it.revision }, { it.deviceId }))
                if (version != null && editor.restore(version) != null) restored += id else missing += id
            }
        }
        return RestoreResult(restored.toList(), missing.toList())
    }

    /** Ids of the deleted records whose last live version is still in the history ([restoreFromHistory] can bring them back). */
    fun restorableRecordIds(): List<String> {
        val content = state.value
        val liveInHistory = content.history.filter { !it.deleted }.map { it.id }.toSet()
        return content.records.filter { it.deleted && it.id in liveInHistory }.map { it.id }.sorted()
    }

    /**
     * Acknowledges the re-key warnings ([SyncWarning.KeyEpochChainUnverified] / [SyncWarning.ConcurrentRekeyAdopted] /
     * [SyncWarning.PasswordUnchangedByRekey]): until this is called every sync result repeats them, across restarts,
     * because they are part of the persisted state. Call it only after the user has seen them.
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
     * Acknowledges [SyncWarning.PasswordChangeNotPublished]: a password change that never reached the server was
     * dropped. Until this is called every sync result repeats the warning, across restarts. Call it only after the
     * user has seen that the **old** password is the live one.
     */
    suspend fun acknowledgePasswordChangeWarning() {
        check(!closed) { "Session is closed" }
        localStore.exclusive {
            val persisted = localStore.load()
            val vs = persisted.vaults[vaultId] ?: return@exclusive
            if (vs.discardedPendingEpoch != null) {
                localStore.save(persisted.copy(vaults = persisted.vaults + (vaultId to vs.copy(discardedPendingEpoch = null))))
            }
        }
    }

    /**
     * **Recovery action:** the sealed local vault file as it is right now (content and key epoch of this session),
     * for the user to keep somewhere safe. It is opened with the vault password by [importBackup] (or by
     * [VaultCodec.open]). It contains no more than the vault file on the server does; it is as safe as that file
     * (and offline-guessable like it: never keep it anywhere less protected than the share). Works in every state,
     * including when sync is stuck.
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
    private fun shutDown(releaseDirectory: Boolean = true) {
        if (closed) return
        closed = true
        hooks.close()
        if (releaseDirectory) directoryLock.close()
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

    private sealed interface RemoteRead {
        class Ok(val file: RemoteFile?) : RemoteRead
        class Failed(val result: SyncResult) : RemoteRead
    }

    private suspend fun readRemote(remote: RemoteStore): RemoteRead = try {
        RemoteRead.Ok(remote.read())
    } catch (e: CancellationException) {
        throw e
    } catch (e: RemoteAuthException) {
        RemoteRead.Failed(SyncResult(SyncOutcome.Failed(FailureReason.AuthFailed, e.message), state.value))
    } catch (e: RemoteIoException) {
        RemoteRead.Failed(SyncResult(SyncOutcome.Failed(FailureReason.Network, e.message), state.value))
    }

    private fun sameHeaderSafe(a: ByteArray, b: ByteArray): Boolean = try {
        hooks.sameHeader(a, b)
    } catch (e: VaultException) {
        false
    }

    private fun claimedEpochOrNull(bytes: ByteArray): Long? = try {
        hooks.claimedKeyEpoch(bytes)
    } catch (e: VaultException) {
        null
    }

    /**
     * Resolves the pending rotation of the state (see [open]) against the remote before any sync. Returns a failed
     * result when the session cannot go on, null otherwise. It never loses an edit and never drops a change silently:
     *
     *  - **opened with the new password** (this session holds the pending key): the change landing on the server is
     *    adopted; another key on the server (same epoch or higher) is left to the engine, which asks for that
     *    password; a server that is still at the old state blocks the sync with
     *    [FailureReason.PendingRotationUnpublished] ([resolvePendingPasswordChange] publishes it);
     *  - **opened with the old password**: a change that landed is adopted by the engine ([FailureReason.ReopenRequired]);
     *    one that did not is dropped with the persistent warning [SyncWarning.PasswordChangeNotPublished], unless it holds
     *    edits that only it has ([FailureReason.PendingRotationHoldsNewerEdits]).
     */
    private suspend fun resolvePendingRotation(remote: RemoteStore): SyncResult? {
        val vs = loadVaultState()
        val pending = vs.pendingLocalFile ?: return null
        val pendingEpoch = try {
            hooks.claimedKeyEpoch(pending)
        } catch (e: VaultException) {
            dropPending(discardedEpoch = null)
            return null
        }
        val remoteFile = when (val read = readRemote(remote)) {
            is RemoteRead.Failed -> return read.result
            is RemoteRead.Ok -> read.file
        }
        val landed = remoteFile != null && sameHeaderSafe(remoteFile.bytes, pending)
        if (openedFromPending) {
            val remoteEpoch = remoteFile?.let { claimedEpochOrNull(it.bytes) }
            when {
                // The password change reached the server and this session holds its key: nothing to resolve.
                landed -> adoptLandedPending()
                // Missing or unparseable: the engine reports it (RemoteMissing, InvalidRemoteFile).
                remoteFile == null || remoteEpoch == null -> Unit
                // Another key at this epoch or a higher one: the engine asks for that password (ReopenRequired /
                // KeyMismatchSameEpoch); adopting it drops the local change with a warning.
                remoteEpoch >= pendingEpoch -> Unit
                // The server is still at the old epoch: the change is not published.
                else -> return SyncResult(
                    SyncOutcome.Failed(
                        FailureReason.PendingRotationUnpublished,
                        "the password change was not published: resolvePendingPasswordChange publishes it, or open " +
                            "with the old password, or replace the remote",
                    ),
                    state.value,
                    failureInfo = FailureInfo(remoteDigest = hooks.fingerprint(remoteFile.bytes)),
                )
            }
        } else {
            when {
                // It reached the server but this session still holds the old key: the sync reports ReopenRequired and
                // adopting the new password clears the pending rotation.
                landed -> Unit
                vs.pendingHoldsNewerEdits -> return SyncResult(
                    SyncOutcome.Failed(
                        FailureReason.PendingRotationHoldsNewerEdits,
                        "an unpublished password change holds edits that this vault lacks: call " +
                            "resolvePendingPasswordChange with the new password",
                    ),
                    state.value,
                    failureInfo = remoteFile?.let { FailureInfo(remoteDigest = hooks.fingerprint(it.bytes)) },
                )
                // It never reached the server (or was superseded) and this session holds the old key: drop it, and
                // keep telling the user that the password did NOT change.
                else -> dropPending(discardedEpoch = pendingEpoch)
            }
        }
        return null
    }

    /** Drops the pending rotation (the old key stays live) and remembers the warning until acknowledged. */
    private suspend fun dropPending(discardedEpoch: Long?) {
        localStore.exclusive {
            val persisted = localStore.load()
            val vs = persisted.vaults[vaultId] ?: return@exclusive
            localStore.save(
                persisted.copy(
                    vaults = persisted.vaults + (
                        vaultId to vs.copy(
                            pendingLocalFile = null,
                            pendingHoldsNewerEdits = false,
                            discardedPendingEpoch = discardedEpoch ?: vs.discardedPendingEpoch,
                        )
                        ),
                ),
            )
        }
        pendingRotationUnresolved = false
    }

    /** The pending change is on the server and this session holds its key: it becomes the committed local file. */
    private suspend fun adoptLandedPending() {
        localStore.exclusive {
            val persisted = localStore.load()
            val vs = persisted.vaults[vaultId] ?: return@exclusive
            val sealed = hooks.sealLocal(state.value)
            localStore.save(
                persisted.copy(
                    vaults = persisted.vaults + (
                        vaultId to vs.copy(localFile = sealed, pendingLocalFile = null, pendingHoldsNewerEdits = false)
                        ),
                ),
            )
        }
        pendingRotationUnresolved = false
        openedFromPending = false
    }

    /** Re-applies [other] (content that only the pending file held) onto the content of this session: a merge join. */
    private suspend fun joinIntoLocal(other: VaultContent) {
        localStore.exclusive {
            val joined = mergeVaults(null, state.value, other, deviceId).merged
            if (joined == state.value) return@exclusive
            val persisted = localStore.load()
            val vs = persisted.vaults[vaultId] ?: return@exclusive
            val sealed = hooks.sealLocal(joined)
            localStore.save(persisted.copy(vaults = persisted.vaults + (vaultId to vs.copy(localFile = sealed))))
            state.value = joined
        }
    }

    companion object {
        /** Failures that `replaceRemoteWithLocal` cures (everything else is a problem a replacement would not fix). */
        private val REPLACEABLE = setOf(
            FailureReason.HeaderMismatchSameEpoch,
            FailureReason.KeyMismatchSameEpoch,
            FailureReason.KeyEpochRollback,
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
         * against the pending file. **Both files are kept** until the change is resolved: the old password opens the
         * committed vault (the next sync drops the unpublished change unless the server has it, with a persistent
         * warning), the new password opens the pending one (edits made in that session go to the pending file; the
         * old-epoch file is not touched). Edits made while the change was in flight are in both files. Resolve it with
         * [sync] or [resolvePendingPasswordChange].
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
                    val fromPrevious = localStore.loadedFromPrevious
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
                        // Nothing about the pending rotation changes here: both files stay until it is resolved.
                        var next = persisted
                        val deviceId = next.deviceId ?: newDeviceId().also { next = next.copy(deviceId = it) }
                        if (next !== persisted) localStore.save(next)
                        VaultSession(
                            localStore, lock, vault.vaultId, OpenVaultCodecHooks(vault, memoryCeilingKiB), deviceId, tuning,
                            memoryCeilingKiB, vault.content, vs.pendingLocalFile != null, openedPending, fromPrevious,
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
         * nothing and saves nothing** (it only creates the directory and its lock file). The returned [JoinPreview]
         * shows what the file contains and its [JoinPreview.fingerprint] and [JoinPreview.revision]; compare them with
         * [fingerprint] on a device that already has the vault (a server that serves an old or foreign file is
         * thereby noticed), then call [JoinPreview.confirm]. The directory is held until the preview is confirmed or
         * closed: close it in a `finally`.
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
         * [SalvageResult.Recovered.sealedVault]), opened with [password]. The vault keeps its identity and key epoch.
         * The device starts with rollback floors: [floors] when given (from [SalvageResult.Recovered.floors]),
         * raised to what the backup itself implies (its content revision and key epoch), so the first sync refuses a
         * remote older than the backup (override with `SyncOptions.allowRollback`) and a missing remote is reported
         * instead of silently re-created. A backup that is older than what the server holds is merged like any
         * other device's content. **Caution:** a backup of an old key epoch continues under that epoch's key; if the
         * password was changed since, the other devices refuse it (and the first sync tells why).
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
            floors: SyncFloors? = null,
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
                        val given = floors ?: SyncFloors()
                        localStore.save(
                            persisted.copy(
                                vaults = mapOf(
                                    vault.vaultId to VaultSyncState(
                                        localFile = backup.copyOf(),
                                        highestRevision = maxOf(given.highestRevision, vault.content.revision),
                                        highestKeyEpoch = maxOf(given.highestKeyEpoch, vault.keyEpoch),
                                        fileDigests = given.fileDigests,
                                    ),
                                ),
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
         * newest first. The result tells what was found (revision, record count) and carries the sealed vault and the
         * rollback [SalvageResult.Recovered.floors] of the salvaged state for [importBackup] into a fresh directory.
         * The floors may be one save older than they were, which only weakens rollback detection by that step.
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
                                    floors = SyncFloors(vs.highestRevision, vs.highestKeyEpoch, vs.fileDigests),
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
