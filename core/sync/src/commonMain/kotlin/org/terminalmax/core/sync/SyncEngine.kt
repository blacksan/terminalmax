// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.sync

import kotlin.coroutines.cancellation.CancellationException
import kotlin.random.Random
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.terminalmax.core.vault.MAX_REVISION
import org.terminalmax.core.vault.MAX_REVISION_JUMP
import org.terminalmax.core.vault.MergeSide
import org.terminalmax.core.vault.REVISION_HEADROOM
import org.terminalmax.core.vault.VaultContent
import org.terminalmax.core.vault.VaultException
import org.terminalmax.core.vault.mergeVaults

/**
 * Marks a [SyncEngine.sync] as the replacement of an unreadable (or missing) remote file by a staged key change.
 * [replacedKeyEpoch] is what the caller believes the replaced file's key epoch was (0 when unknown), for the warning.
 */
class ReplaceRemote(val replacedKeyEpoch: Long = 0L)

/**
 * Synchronises one local [VaultContent] with the remote vault file.
 *
 * Each attempt: read the remote file; if it is absent create it (only for a vault this device has never synced, or
 * with [SyncOptions.recreateRemote]); otherwise decrypt it (a file of the same key epoch whose header differs from
 * this device's is refused, [FailureReason.HeaderMismatchSameEpoch]), check it against the floors this device
 * remembers (key epoch, content revision, file digests), merge it with the local content and the stored base,
 * and upload the result when it differs from the remote. The merge keeps the highest version of every record, so a
 * stale or replayed remote can never revert an edit; a lower version that is not provably one this device saw
 * before is never dropped silently, it goes to the vault history and is reported as a conflict (see `mergeVaults`).
 * A remote whose revision jumps implausibly far above what this device has seen is refused
 * ([FailureReason.SuspiciousRevisionJump]).
 * Uploads are made atomic with `If-Match` / `If-None-Match` when the server was measured to honour them, otherwise
 * under a lock-file lease. Every upload is read back and must be byte-for-byte what was written, otherwise
 * another writer got in between and the attempt is repeated (at most [maxAttempts], with jittered backoff).
 *
 * [sync] returns a [SyncOutcome.Failed] for every failure and throws nothing but [CancellationException].
 * Concurrent calls are serialised. Network I/O never runs inside [LocalStateStore.exclusive]: every state access is
 * one short load-modify-save, and the result is committed by joining it with the live local content ([LocalView]).
 *
 * @param clock wall-clock milliseconds on this device; used for lease bookkeeping and probe age, never to order
 *   records
 * @param sleep suspends for the given milliseconds (injectable so tests do not wait)
 * @param leaseMillis lock lease length; at least three times the HTTP call timeout
 * @param requestBudgetMillis the lease is renewed before the vault upload when less than this remains
 * @param probeMaxAgeMillis the cached probe result of a server is used for this long
 * @param view the caller's live local content; without it [sync]'s `local` argument is the content to commit
 */
class SyncEngine(
    private val store: RemoteStore,
    private val hooks: VaultCodecHooks,
    private val localState: LocalStateStore,
    private val deviceId: String,
    private val clock: () -> Long,
    private val random: Random = Random.Default,
    private val sleep: suspend (Long) -> Unit = { delay(it) },
    private val maxAttempts: Int = 5,
    private val leaseMillis: Long = DEFAULT_LEASE_MILLIS,
    private val requestBudgetMillis: Long = DEFAULT_REQUEST_BUDGET_MILLIS,
    private val probeMaxAgeMillis: Long = DEFAULT_PROBE_MAX_AGE_MILLIS,
    private val view: LocalView? = null,
) {
    private sealed interface Step {
        class Done(val result: SyncResult) : Step
        class Fail(
            val reason: FailureReason,
            val detail: String? = null,
            val warnings: List<SyncWarning> = emptyList(),
        ) : Step
        class Retry(val reason: FailureReason, val forceLock: Boolean = false) : Step
    }

    private val mutex = Mutex()

    /**
     * Synchronises [local] with the remote file. [local] is a **snapshot**: the network I/O runs without holding
     * anything that blocks edits, and the result is committed by joining it with whatever the [LocalView] holds at
     * that moment.
     *
     * @param staged a password change prepared with the hooks, published as one transaction: the remote file must be
     *   byte-identical to the base this device last synced (otherwise [FailureReason.HeaderChangedRemotely] or
     *   [FailureReason.RemoteChangedDuringRotation], nothing uploaded), the sealed new-epoch local file is stored
     *   durably as the state's pending rotation, the re-keyed file is uploaded and read back, and only then is the
     *   change committed locally together with the new sync state
     * @param reopenPassword the master password, used only when the remote file turns out to be at a higher key
     *   epoch, or at the same epoch under another key (the vault was re-keyed elsewhere); without it that case fails
     *   with [FailureReason.ReopenRequired]
     * @param replace with [staged]: publish [staged] **over whatever the remote holds** (nothing, or a file this
     *   device cannot open), without reading it (the recovery action behind `VaultSession.replaceRemoteWithLocal`)
     */
    suspend fun sync(
        local: VaultContent,
        options: SyncOptions = SyncOptions(),
        staged: StagedHeaderChange? = null,
        reopenPassword: CharArray? = null,
        replace: ReplaceRemote? = null,
    ): SyncResult {
        val result = try {
            mutex.withLock { syncLocked(local, options, staged, reopenPassword, replace) }
        } catch (e: CancellationException) {
            throw e
        } catch (e: VaultException) {
            failed(local, reasonFor(e), e.message)
        } catch (e: RemoteAuthException) {
            failed(local, FailureReason.AuthFailed, e.message)
        } catch (e: RemoteIoException) {
            failed(local, FailureReason.Network, e.message)
        } catch (e: LocalStateException) {
            failed(local, FailureReason.LocalStateUnavailable, e.message)
        } catch (e: Exception) {
            failed(local, FailureReason.Unexpected, e::class.simpleName)
        }
        return withStickyWarnings(result, local.vaultId)
    }

    /** The unacknowledged re-key warning of the state is part of every result until the user acknowledges it. */
    private suspend fun withStickyWarnings(result: SyncResult, vaultId: String): SyncResult {
        val chain = try {
            localState.load().vaults[vaultId]?.chainWarning
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            null
        } ?: return result
        val warning: SyncWarning = if (chain.fromEpoch == chain.toEpoch) {
            SyncWarning.ConcurrentRekeyAdopted(chain.toEpoch)
        } else {
            SyncWarning.KeyEpochChainUnverified(chain.fromEpoch, chain.toEpoch)
        }
        if (result.warnings.any { it == warning }) return result
        return result.copy(warnings = result.warnings + warning)
    }

    private suspend fun syncLocked(
        local: VaultContent,
        options: SyncOptions,
        staged: StagedHeaderChange?,
        reopenPassword: CharArray?,
        replace: ReplaceRemote?,
    ): SyncResult {
        try {
            local.validate()
        } catch (e: VaultException.InvalidContent) {
            return failed(local, FailureReason.InvalidLocalContent, e.message)
        }
        val capabilities = capabilities(options)
        var forceLock = false
        var lastReason = FailureReason.TooManyAttempts
        for (attempt in 1..maxAttempts) {
            if (attempt > 1) sleep(backoffMillis(attempt))
            when (val step = attemptOnce(local, capabilities, forceLock, options, staged, reopenPassword, replace)) {
                is Step.Done -> return step.result
                is Step.Fail -> return failed(local, step.reason, step.detail, step.warnings)
                is Step.Retry -> {
                    lastReason = step.reason
                    if (step.forceLock) forceLock = true
                }
            }
        }
        return failed(local, lastReason, "gave up after $maxAttempts attempts")
    }

    private fun reasonFor(e: VaultException): FailureReason = when (e) {
        is VaultException.DifferentVault -> FailureReason.DifferentVault
        is VaultException.UnsupportedVersion -> FailureReason.UnsupportedVersion
        is VaultException.BadPasswordOrCorrupt -> FailureReason.BadPasswordOrCorrupt
        is VaultException.IntegrityFailure -> FailureReason.IntegrityFailure
        is VaultException.HeaderMismatchSameEpoch -> FailureReason.HeaderMismatchSameEpoch
        is VaultException.KeyMismatchSameEpoch -> FailureReason.ReopenRequired
        is VaultException.KeyEpochMismatch ->
            if (e.found > e.expected) FailureReason.ReopenRequired else FailureReason.RollbackDetected
        else -> FailureReason.InvalidRemoteFile
    }

    private fun failed(
        local: VaultContent,
        reason: FailureReason,
        detail: String?,
        warnings: List<SyncWarning> = emptyList(),
    ) = SyncResult(SyncOutcome.Failed(reason, detail), local, warnings)

    private fun backoffMillis(attempt: Int): Long {
        val cap = 100L shl (attempt - 1).coerceAtMost(6)
        return cap / 2 + random.nextLong(cap / 2 + 1)
    }

    private fun nextRevision(current: Long): Long {
        if (current < 0L || current >= MAX_REVISION) throw VaultException.InvalidContent("revision limit reached")
        return current + 1L
    }

    // ------------------------------------------------------------------ state helpers
    // Every one of these is one short load-modify-save under `localState.exclusive` and never touches the network.

    private suspend fun updateServer(change: (ServerSyncState) -> ServerSyncState) {
        localState.exclusive {
            val state = localState.load()
            val key = store.serverKey
            val updated = change(state.servers[key] ?: ServerSyncState())
            localState.save(state.copy(servers = state.servers + (key to updated)))
        }
    }

    /** The cached probe result of this server if it is fresh, otherwise a new probe (which is stored). */
    private suspend fun capabilities(options: SyncOptions): ServerCapabilities {
        val server = localState.load().servers[store.serverKey]
        val cached = server?.capabilities
        val age = clock() - (server?.probedAtEpochMs ?: 0L)
        if (cached != null && !options.reprobe && age in 0L..probeMaxAgeMillis) return cached
        val probed = store.probe()
        updateServer { it.copy(capabilities = probed, probedAtEpochMs = clock()) }
        return probed
    }

    /** Forget the probe so the next sync measures the server again (after any precondition anomaly). */
    private suspend fun invalidateProbe() {
        updateServer { it.copy(capabilities = null, probedAtEpochMs = 0L) }
    }

    private class Committed(val content: VaultContent, val editsPending: Boolean)

    /**
     * Commits a successful sync in one state save: floors, digests, the base file and the sealed local file. The
     * local file is sealed from the **join** of [written] and the content the [LocalView] holds right now, so an edit
     * made while the network I/O ran is never overwritten; [Committed.editsPending] says that there was one. For a
     * [staged] password change the new key is committed (and the pending rotation cleared) inside the same section.
     */
    private suspend fun commitLocal(
        snapshot: VaultContent,
        written: VaultContent,
        file: ByteArray,
        keyEpoch: Long,
        revision: Long,
        digest: String,
        seenRemote: Pair<Long, String>?,
        staged: StagedHeaderChange?,
    ): Committed = localState.exclusive {
        val current = view?.current() ?: snapshot
        val editsPending = current != snapshot
        val final = if (editsPending) mergeVaults(snapshot, current, written, deviceId).merged else written
        val localFile = if (staged != null) hooks.sealLocalStaged(final, staged) else hooks.sealLocal(final)
        val state = localState.load()
        val previous = state.vaults[written.vaultId] ?: VaultSyncState()
        var digests = previous.fileDigests + (revision to digest)
        if (seenRemote != null) digests = digests + seenRemote
        if (digests.size > VaultSyncState.MAX_DIGESTS) {
            val keep = digests.keys.sorted().takeLast(VaultSyncState.MAX_DIGESTS).toSet()
            digests = digests.filterKeys { it in keep }
        }
        val updated = previous.copy(
            baseFile = file,
            localFile = localFile,
            highestRevision = maxOf(previous.highestRevision, revision),
            highestKeyEpoch = maxOf(previous.highestKeyEpoch, keyEpoch),
            fileDigests = digests,
            pendingLocalFile = if (staged != null) null else previous.pendingLocalFile,
        )
        localState.save(state.copy(vaults = state.vaults + (written.vaultId to updated)))
        if (staged != null) hooks.commitStaged(staged)
        view?.committed(final)
        Committed(final, editsPending)
    }

    /**
     * Persists the sealed local file after a re-key was adopted, before the sync that follows, together with the
     * unverified-chain warning (kept until acknowledged) and without the superseded pending rotation.
     */
    private suspend fun recordAdoptedRekey(snapshot: VaultContent, chainWarning: ChainWarning?) {
        localState.exclusive {
            val current = view?.current() ?: snapshot
            val sealed = hooks.sealLocal(current)
            val state = localState.load()
            val previous = state.vaults[snapshot.vaultId] ?: VaultSyncState()
            localState.save(
                state.copy(
                    vaults = state.vaults + (
                        snapshot.vaultId to previous.copy(
                            localFile = sealed,
                            pendingLocalFile = null,
                            chainWarning = chainWarning ?: previous.chainWarning,
                        )
                        ),
                ),
            )
        }
    }

    /** Durably stores the sealed new-epoch local file of a password change **before** it is uploaded. */
    private suspend fun recordPending(vaultId: String, pendingFile: ByteArray?) {
        localState.exclusive {
            val state = localState.load()
            val previous = state.vaults[vaultId] ?: VaultSyncState()
            if (previous.pendingLocalFile == null && pendingFile == null) return@exclusive
            localState.save(state.copy(vaults = state.vaults + (vaultId to previous.copy(pendingLocalFile = pendingFile))))
        }
    }

    // ------------------------------------------------------------------ one attempt

    private suspend fun attemptOnce(
        local: VaultContent,
        capabilities: ServerCapabilities,
        forceLock: Boolean,
        options: SyncOptions,
        staged: StagedHeaderChange?,
        reopenPassword: CharArray?,
        replace: ReplaceRemote?,
    ): Step {
        val needsLock = forceLock || !capabilities.supportsConditionalWrites
        var lease: Lease? = null
        if (needsLock) {
            lease = acquireLock(capabilities) ?: return Step.Retry(FailureReason.Locked)
        }
        try {
            return readMergeWrite(local, lease, capabilities, options, staged, reopenPassword, replace)
        } finally {
            lease?.let { releaseLock(it) }
        }
    }

    private fun decryptBase(vs: VaultSyncState, vaultId: String): DecryptedVault? {
        val file = vs.baseFile ?: return null
        return try {
            hooks.decrypt(file).takeIf { it.content.vaultId == vaultId }
        } catch (e: VaultException) {
            null // an unreadable base degrades to a two-way merge; the floors in the state still apply
        }
    }

    private suspend fun readMergeWrite(
        local: VaultContent,
        lease: Lease?,
        capabilities: ServerCapabilities,
        options: SyncOptions,
        staged: StagedHeaderChange?,
        reopenPassword: CharArray?,
        replace: ReplaceRemote?,
    ): Step {
        val underLock = lease != null
        val state = localState.load()
        val vs = state.vaults[local.vaultId] ?: VaultSyncState()
        val remote = store.read()

        if (replace != null) {
            if (staged == null) return Step.Fail(FailureReason.Unexpected, "a replacement needs a staged key change")
            return publishReplacement(local, staged, replace, remote, vs, lease, capabilities)
        }

        val baseInfo = decryptBase(vs, local.vaultId)
        val base = baseInfo?.content
        // Floors: everything this device has ever seen, including the base it merges against.
        val floorRevision = maxOf(vs.highestRevision, base?.revision ?: 0L)
        val floorEpoch = maxOf(vs.highestKeyEpoch, baseInfo?.keyEpoch ?: 0L)
        val established = vs.established
        val warnings = ArrayList<SyncWarning>()

        if (remote == null) {
            if (staged != null) {
                return Step.Fail(FailureReason.RemoteMissing, "a password change needs an existing remote file")
            }
            if (established && !options.recreateRemote) {
                return Step.Fail(FailureReason.RemoteMissing, "the remote vault file no longer exists")
            }
            if (hooks.keyEpoch < floorEpoch) {
                return Step.Fail(FailureReason.ReopenRequired, "this device holds an older data key than it has seen")
            }
            // Never publish a revision at or below the floor.
            val toPush = if (floorRevision > 0L) {
                local.copy(revision = nextRevision(maxOf(local.revision, floorRevision)))
            } else {
                local
            }
            val enc = hooks.encrypt(toPush)
            val result = store.write(
                enc.bytes,
                ifMatchEtag = null,
                ifNoneMatch = !underLock || capabilities.honoursIfNoneMatchStar,
            )
            if (established) warnings += SyncWarning.RemoteRecreated(toPush.revision)
            return afterWrite(result, enc, toPush, local, SyncOutcome.Pushed, warnings, underLock, null, null)
        }

        // A file at a higher key epoch (or at the same epoch under another key) means the vault was re-keyed (a
        // password change somewhere). Check the chain link with the key we hold; the password is needed to go on.
        val info: DecryptedVault = try {
            hooks.decrypt(remote.bytes)
        } catch (e: VaultException) {
            val sameEpoch = e is VaultException.KeyMismatchSameEpoch
            val fromEpoch = if (e is VaultException.KeyEpochMismatch) e.expected else hooks.keyEpoch
            val toEpoch = if (e is VaultException.KeyEpochMismatch) e.found else hooks.keyEpoch
            if (!sameEpoch && !(e is VaultException.KeyEpochMismatch && e.found > e.expected)) throw e
            if (staged != null) {
                return Step.Fail(
                    FailureReason.HeaderChangedRemotely,
                    "the vault was re-keyed on another device (key epoch $toEpoch)",
                )
            }
            val chain = if (sameEpoch) EpochChain.NotApplicable else hooks.epochChain(remote.bytes)
            val chainWarnings: List<SyncWarning> = when {
                sameEpoch -> listOf(SyncWarning.ConcurrentRekeyAdopted(toEpoch))
                chain == EpochChain.Verified -> emptyList()
                else -> listOf(SyncWarning.KeyEpochChainUnverified(fromEpoch, toEpoch))
            }
            if (reopenPassword == null) {
                return Step.Fail(FailureReason.ReopenRequired, "key epoch $toEpoch needs the master password", chainWarnings)
            }
            val reopened = hooks.reopen(remote.bytes, reopenPassword)
            warnings += chainWarnings
            if (reopened.passwordUnchanged) warnings += SyncWarning.PasswordUnchangedByRekey(fromEpoch, toEpoch)
            // The key changed in memory: persist the local file under it right away (so that a restart can open it
            // with the password that was just typed), and remember an unverifiable chain until it is acknowledged.
            val unverified = sameEpoch || reopened.chain != EpochChain.Verified
            recordAdoptedRekey(local, if (unverified) ChainWarning(fromEpoch, toEpoch) else null)
            hooks.decrypt(remote.bytes)
        }
        val remoteContent = info.content
        if (remoteContent.vaultId != local.vaultId) return Step.Fail(FailureReason.DifferentVault, null, warnings)
        if (info.keyEpoch < floorEpoch) {
            return Step.Fail(
                FailureReason.RollbackDetected,
                "remote key epoch ${info.keyEpoch} is lower than the highest seen ($floorEpoch)",
                warnings,
            )
        }
        if (remoteContent.revision < floorRevision && !options.allowRollback) {
            return Step.Fail(
                FailureReason.RollbackDetected,
                "remote revision ${remoteContent.revision} is lower than the highest seen ($floorRevision)",
                warnings,
            )
        }
        // A revision that jumps far above the floor could leave the vault permanently un-editable.
        val tooHigh = remoteContent.revision > MAX_REVISION - REVISION_HEADROOM
        val tooFar = established && remoteContent.revision > floorRevision && remoteContent.revision - floorRevision > MAX_REVISION_JUMP
        if (tooHigh || (tooFar && !options.acceptRevisionJump)) {
            return Step.Fail(
                FailureReason.SuspiciousRevisionJump,
                "remote revision ${remoteContent.revision} is implausibly far above the highest seen ($floorRevision)",
                warnings,
            )
        }
        if (tooFar) warnings += SyncWarning.RevisionJumpAccepted(remoteContent.revision, floorRevision)

        val digest = hooks.fingerprint(remote.bytes)
        val seenDigest = vs.fileDigests[remoteContent.revision]
        if (seenDigest != null && seenDigest != digest) {
            warnings += SyncWarning.ForkSuspected(remoteContent.revision)
        }
        if (!established) {
            warnings += SyncWarning.FirstUseTrust(remoteContent.revision, info.keyEpoch)
        }

        if (staged != null) {
            return publishStaged(local, staged, remote, info, remoteContent, vs, base, floorRevision, lease, warnings)
        }

        val merge = mergeVaults(base, local, remoteContent, deviceId)
        val staleRemote = merge.regressions.filter { it.ignoredSide == MergeSide.Remote }.map { it.recordId }
        if (staleRemote.isNotEmpty()) warnings += SyncWarning.StaleRemoteIgnored(staleRemote)
        val staleLocal = merge.regressions.filter { it.ignoredSide == MergeSide.Local }.map { it.recordId }
        if (staleLocal.isNotEmpty()) warnings += SyncWarning.LocalContentWasStale(staleLocal)

        val outcome = when {
            merge.conflicts.isNotEmpty() -> SyncOutcome.Merged(merge.conflicts)
            merge.changedLocally && merge.changedRemotely -> SyncOutcome.Merged(emptyList())
            merge.changedRemotely -> SyncOutcome.Pushed
            merge.changedLocally -> SyncOutcome.Pulled
            else -> SyncOutcome.UpToDate
        }

        if (!merge.changedRemotely) {
            val committed = commitLocal(
                local, merge.merged, remote.bytes, info.keyEpoch, remoteContent.revision, digest, null, null,
            )
            return Step.Done(SyncResult(outcome, committed.content, warnings, committed.editsPending))
        }

        var toWrite = merge.merged
        if (toWrite.revision <= floorRevision) toWrite = toWrite.copy(revision = nextRevision(floorRevision))

        val etag = usableEtag(remote.etag)
        if (!underLock && etag == null) {
            // The server normally gives strong ETags but this response did not (or sent an unusable one).
            return Step.Retry(FailureReason.TooManyAttempts, forceLock = true)
        }
        if (lease != null && !renewLease(lease)) return Step.Retry(FailureReason.Locked)

        val enc = hooks.encrypt(toWrite)
        val result = store.write(enc.bytes, ifMatchEtag = if (underLock) null else etag, ifNoneMatch = false)
        return afterWrite(result, enc, toWrite, local, outcome, warnings, underLock, remoteContent.revision to digest, null)
    }

    /**
     * The password-change transaction (see [sync]). The remote file must be byte-identical to the stored base, so
     * nothing written at the old key epoch after the last sync is carried into the new epoch unreported.
     */
    private suspend fun publishStaged(
        local: VaultContent,
        staged: StagedHeaderChange,
        remote: RemoteFile,
        info: DecryptedVault,
        remoteContent: VaultContent,
        vs: VaultSyncState,
        base: VaultContent?,
        floorRevision: Long,
        lease: Lease?,
        warnings: List<SyncWarning>,
    ): Step {
        val underLock = lease != null
        val baseFile = vs.baseFile
        if (baseFile == null || !remote.bytes.contentEquals(baseFile)) {
            return Step.Fail(
                FailureReason.RemoteChangedDuringRotation,
                "the remote vault changed since the last sync; sync first, then repeat the password change",
            )
        }
        val merge = mergeVaults(base, local, remoteContent, deviceId)
        var toWrite = merge.merged
        toWrite = toWrite.copy(revision = nextRevision(maxOf(toWrite.revision, remoteContent.revision, floorRevision)))
        val etag = usableEtag(remote.etag)
        if (!underLock && etag == null) return Step.Retry(FailureReason.TooManyAttempts, forceLock = true)
        if (lease != null && !renewLease(lease)) return Step.Retry(FailureReason.Locked)
        val enc = hooks.encryptStaged(toWrite, staged)
        // Durable BEFORE the upload: a crash anywhere after this point can be resolved from the state alone.
        recordPending(local.vaultId, hooks.sealLocalStaged(toWrite, staged))
        val result = store.write(enc.bytes, ifMatchEtag = if (underLock) null else etag, ifNoneMatch = false)
        return afterWrite(
            result, enc, toWrite, local, SyncOutcome.Pushed, warnings, underLock,
            remoteContent.revision to hooks.fingerprint(remote.bytes), staged,
        )
    }

    /**
     * Publishes [staged] over whatever the remote holds, unread: the recovery action for a remote that cannot be
     * opened (or does not exist). The remote file is replaced only if it is still the one that was just read
     * (`If-Match`, or the lock lease), and the upload is read back like any other.
     */
    private suspend fun publishReplacement(
        local: VaultContent,
        staged: StagedHeaderChange,
        replace: ReplaceRemote,
        remote: RemoteFile?,
        vs: VaultSyncState,
        lease: Lease?,
        capabilities: ServerCapabilities,
    ): Step {
        val underLock = lease != null
        val toWrite = local.copy(revision = nextRevision(maxOf(local.revision, vs.highestRevision)))
        val etag = usableEtag(remote?.etag)
        if (remote != null && !underLock && etag == null) return Step.Retry(FailureReason.TooManyAttempts, forceLock = true)
        if (lease != null && !renewLease(lease)) return Step.Retry(FailureReason.Locked)
        val enc = hooks.encryptStaged(toWrite, staged)
        recordPending(local.vaultId, hooks.sealLocalStaged(toWrite, staged))
        val result = if (remote == null) {
            store.write(enc.bytes, ifMatchEtag = null, ifNoneMatch = !underLock || capabilities.honoursIfNoneMatchStar)
        } else {
            store.write(enc.bytes, ifMatchEtag = if (underLock) null else etag, ifNoneMatch = false)
        }
        val warnings = listOf<SyncWarning>(SyncWarning.RemoteReplaced(staged.keyEpoch, replace.replacedKeyEpoch))
        return afterWrite(result, enc, toWrite, local, SyncOutcome.Pushed, warnings, underLock, null, staged)
    }

    /**
     * Verifies an upload by reading it back; records the new sync state (and, for [staged], commits the header
     * change) only when the bytes are exactly ours.
     */
    private suspend fun afterWrite(
        result: WriteResult,
        enc: EncryptedVault,
        written: VaultContent,
        snapshot: VaultContent,
        outcome: SyncOutcome,
        warnings: List<SyncWarning>,
        underLock: Boolean,
        seenRemote: Pair<Long, String>?,
        staged: StagedHeaderChange?,
    ): Step = when (result) {
        is WriteResult.PreconditionFailed -> {
            // The upload was refused, so the pending rotation (if any) did not happen.
            if (staged != null) recordPending(written.vaultId, null)
            Step.Retry(FailureReason.TooManyAttempts)
        }
        is WriteResult.Failed -> Step.Fail(FailureReason.ServerRejected, result.message)
        is WriteResult.Written -> {
            val readBack = store.read()
            if (readBack == null || !readBack.bytes.contentEquals(enc.bytes)) {
                // Someone else wrote between our PUT and the read-back (or the server lost the write). Under the
                // conditional protocol this should not happen, so measure the server again next time.
                if (!underLock) invalidateProbe()
                Step.Retry(FailureReason.TooManyAttempts)
            } else {
                val committed = commitLocal(
                    snapshot, written, enc.bytes, enc.keyEpoch, written.revision, hooks.fingerprint(enc.bytes),
                    seenRemote, staged,
                )
                Step.Done(SyncResult(outcome, committed.content, warnings, committed.editsPending))
            }
        }
    }

    // ------------------------------------------------------------------ lock lease

    /**
     * @property etag ETag of the lock file as last written or read by us (null when unusable)
     * @property acquiredAtLocalMs local clock reading when the lease was taken or renewed; only differences of
     *   local readings are used, so clock skew cannot matter
     * @property conditional lock replacement and deletion can be made conditional on [etag]
     */
    private class Lease(val token: String, var etag: String?, var acquiredAtLocalMs: Long, val conditional: Boolean)

    /**
     * Takes the lock lease, or returns null when another device holds it or the race for it was lost.
     *
     * A lock is judged on the server's clock (the `Date` of the response that delivered it): it is live until its
     * expiry plus a grace period ([SERVER_CLOCK_GRACE_MILLIS], or [LOCAL_CLOCK_GRACE_MILLIS] when the server sends
     * no `Date`), so clock skew between devices does not break live locks. An expiry further away than two leases
     * is clamped, so a hostile lock file cannot block sync forever. A malformed lock and a lock left by this very
     * device (sync is serialised per device) count as stale. A stale lock is deleted conditionally on the ETag that
     * was read where the server supports it; a failed condition means somebody else got there first.
     *
     * Ownership is verified by reading the lock back. A server that ignores preconditions cannot make the creation
     * atomic, so two devices can still both believe they hold the lease; the read-back of the vault upload and the
     * monotone merge make that window "delayed, not lost" (see the README).
     */
    private suspend fun acquireLock(capabilities: ServerCapabilities): Lease? {
        val conditional = capabilities.supportsConditionalLocks
        val existing = store.readLock()
        val serverNow = store.lastServerDateMillis
        val now = serverNow ?: clock()
        if (existing != null) {
            val info = LockFile.decode(existing.bytes)
            if (info != null && info.deviceId != deviceId) {
                val expiry = minOf(info.expiresAtEpochMs, now + 2 * leaseMillis)
                val grace = if (serverNow != null) SERVER_CLOCK_GRACE_MILLIS else LOCAL_CLOCK_GRACE_MILLIS
                if (now <= expiry + grace) return null
            }
            val deleted = store.deleteLock(if (conditional) usableEtag(existing.etag) else null)
            if (deleted != DeleteResult.Deleted) return null
        }
        val token = hooks.randomToken()
        val expiresAt = (store.lastServerDateMillis ?: clock()) + leaseMillis
        val written = store.writeLock(
            LockFile.encode(LockInfo(deviceId, token, expiresAt)),
            ifMatchEtag = null,
            ifNoneMatch = capabilities.honoursIfNoneMatchStar,
        )
        if (written !is WriteResult.Written) return null
        val back = store.readLock() ?: return null
        val backInfo = LockFile.decode(back.bytes)
        if (backInfo?.token != token) return null
        return Lease(token, usableEtag(back.etag ?: written.etag), clock(), conditional)
    }

    /**
     * Renews the lease before the vault upload when less than [requestBudgetMillis] of it remains, so a slow upload
     * cannot outlive it. Returns false when the lease was lost (the attempt must not write).
     */
    private suspend fun renewLease(lease: Lease): Boolean {
        val remaining = leaseMillis - (clock() - lease.acquiredAtLocalMs)
        if (remaining >= requestBudgetMillis) return true
        val expiresAt = (store.lastServerDateMillis ?: clock()) + leaseMillis
        val written = store.writeLock(
            LockFile.encode(LockInfo(deviceId, lease.token, expiresAt)),
            ifMatchEtag = if (lease.conditional) lease.etag else null,
            ifNoneMatch = false,
        )
        if (written !is WriteResult.Written) return false
        val back = store.readLock() ?: return false
        if (LockFile.decode(back.bytes)?.token != lease.token) return false
        lease.etag = usableEtag(back.etag ?: written.etag)
        lease.acquiredAtLocalMs = clock()
        return true
    }

    /** Deletes the lock only when it still carries our token, and conditionally on its ETag where possible. */
    private suspend fun releaseLock(lease: Lease) {
        withContext(NonCancellable) {
            try {
                val current = store.readLock()
                val info = current?.let { LockFile.decode(it.bytes) }
                if (current != null && info?.token == lease.token) {
                    // PreconditionFailed means another device legitimately took the lock over: leave it alone.
                    store.deleteLock(if (lease.conditional) usableEtag(current.etag) else null)
                }
            } catch (e: Exception) {
                // Best effort: an unreleased lease simply expires.
            }
        }
    }

    companion object {
        /** 10 minutes: at least three times the default HTTP call timeout of two minutes. */
        const val DEFAULT_LEASE_MILLIS: Long = 10 * 60_000L
        const val DEFAULT_REQUEST_BUDGET_MILLIS: Long = 150_000L
        const val DEFAULT_PROBE_MAX_AGE_MILLIS: Long = 7L * 24 * 60 * 60 * 1000

        /** A foreign lock is broken only this long after its expiry when the server's clock is available. */
        const val SERVER_CLOCK_GRACE_MILLIS: Long = 30_000L

        /** Same, when only this device's own clock is available. */
        const val LOCAL_CLOCK_GRACE_MILLIS: Long = 5 * 60_000L
    }
}
