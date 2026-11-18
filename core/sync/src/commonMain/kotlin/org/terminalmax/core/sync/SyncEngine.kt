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
import org.terminalmax.core.vault.MergeSide
import org.terminalmax.core.vault.VaultContent
import org.terminalmax.core.vault.VaultException
import org.terminalmax.core.vault.mergeVaults

/**
 * Synchronises one local [VaultContent] with the remote vault file.
 *
 * Each attempt: read the remote file; if it is absent create it (only for a vault this device has never synced, or
 * with [SyncOptions.recreateRemote]); otherwise decrypt it, check it against the floors this device remembers (key
 * epoch, slot-set revision, content revision, file digests), merge it with the local content and the stored base,
 * and upload the result when it differs from the remote. The merge keeps the highest version of every record, so a
 * stale or replayed remote can never revert an edit; it is reported as a [SyncWarning.StaleRemoteIgnored] instead.
 * Uploads are made atomic with `If-Match` / `If-None-Match` when the server was measured to honour them, otherwise
 * under a lock-file lease. Every upload is read back and must be byte-for-byte what was written, otherwise
 * another writer got in between and the attempt is repeated (at most [maxAttempts], with jittered backoff).
 *
 * [sync] returns a [SyncOutcome.Failed] for every failure and throws nothing but [CancellationException].
 * Concurrent calls are serialised, and [LocalStateStore.exclusive] extends that across processes.
 *
 * @param clock wall-clock milliseconds on this device; used for lease bookkeeping and probe age, never to order
 *   records
 * @param sleep suspends for the given milliseconds (injectable so tests do not wait)
 * @param leaseMillis lock lease length; at least three times the HTTP call timeout
 * @param requestBudgetMillis the lease is renewed before the vault upload when less than this remains
 * @param probeMaxAgeMillis the cached probe result of a server is used for this long
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
) {
    private sealed interface Step {
        class Done(val result: SyncResult) : Step
        class Fail(val reason: FailureReason, val detail: String? = null) : Step
        class Retry(val reason: FailureReason, val forceLock: Boolean = false) : Step
    }

    private val mutex = Mutex()

    suspend fun sync(local: VaultContent, options: SyncOptions = SyncOptions()): SyncResult {
        try {
            return mutex.withLock { localState.exclusive { syncLocked(local, options) } }
        } catch (e: CancellationException) {
            throw e
        } catch (e: VaultException) {
            return failed(local, reasonFor(e), e.message)
        } catch (e: RemoteAuthException) {
            return failed(local, FailureReason.AuthFailed, e.message)
        } catch (e: RemoteIoException) {
            return failed(local, FailureReason.Network, e.message)
        } catch (e: LocalStateException) {
            return failed(local, FailureReason.LocalStateUnavailable, e.message)
        } catch (e: Exception) {
            return failed(local, FailureReason.Unexpected, e::class.simpleName)
        }
    }

    private suspend fun syncLocked(local: VaultContent, options: SyncOptions): SyncResult {
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
            when (val step = attemptOnce(local, capabilities, forceLock, options)) {
                is Step.Done -> return step.result
                is Step.Fail -> return failed(local, step.reason, step.detail)
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
        is VaultException.KeyEpochMismatch ->
            if (e.found > e.expected) FailureReason.ReopenRequired else FailureReason.RollbackDetected
        else -> FailureReason.InvalidRemoteFile
    }

    private fun failed(local: VaultContent, reason: FailureReason, detail: String?) =
        SyncResult(SyncOutcome.Failed(reason, detail), local)

    private fun backoffMillis(attempt: Int): Long {
        val cap = 100L shl (attempt - 1).coerceAtMost(6)
        return cap / 2 + random.nextLong(cap / 2 + 1)
    }

    private fun nextRevision(current: Long): Long {
        if (current < 0L || current >= MAX_REVISION) throw VaultException.InvalidContent("revision limit reached")
        return current + 1L
    }

    // ------------------------------------------------------------------ state helpers

    private suspend fun updateServer(change: (ServerSyncState) -> ServerSyncState) {
        val state = localState.load()
        val key = store.serverKey
        val updated = change(state.servers[key] ?: ServerSyncState())
        localState.save(state.copy(servers = state.servers + (key to updated)))
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

    private suspend fun recordSynced(
        vaultId: String,
        file: ByteArray,
        keyEpoch: Long,
        headerRevision: Long,
        revision: Long,
        digest: String,
        etag: String?,
        seenRemote: Pair<Long, String>?,
    ) {
        val state = localState.load()
        val previous = state.vaults[vaultId] ?: VaultSyncState()
        var digests = previous.fileDigests + (revision to digest)
        if (seenRemote != null) digests = digests + seenRemote
        if (digests.size > VaultSyncState.MAX_DIGESTS) {
            val keep = digests.keys.sorted().takeLast(VaultSyncState.MAX_DIGESTS).toSet()
            digests = digests.filterKeys { it in keep }
        }
        val updated = VaultSyncState(
            baseFile = file,
            highestRevision = maxOf(previous.highestRevision, revision),
            highestKeyEpoch = maxOf(previous.highestKeyEpoch, keyEpoch),
            highestHeaderRevision = maxOf(previous.highestHeaderRevision, headerRevision),
            fileDigests = digests,
        )
        val key = store.serverKey
        val server = (state.servers[key] ?: ServerSyncState()).copy(lastEtag = etag)
        localState.save(state.copy(vaults = state.vaults + (vaultId to updated), servers = state.servers + (key to server)))
    }

    // ------------------------------------------------------------------ one attempt

    private suspend fun attemptOnce(
        local: VaultContent,
        capabilities: ServerCapabilities,
        forceLock: Boolean,
        options: SyncOptions,
    ): Step {
        val needsLock = forceLock || !capabilities.supportsConditionalWrites
        var lease: Lease? = null
        if (needsLock) {
            lease = acquireLock(capabilities) ?: return Step.Retry(FailureReason.Locked)
        }
        try {
            return readMergeWrite(local, lease, capabilities, options)
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
    ): Step {
        val underLock = lease != null
        val state = localState.load()
        val vs = state.vaults[local.vaultId] ?: VaultSyncState()
        val remote = store.read()

        val baseInfo = decryptBase(vs, local.vaultId)
        val base = baseInfo?.content
        // Floors: everything this device has ever seen, including the base it merges against.
        val floorRevision = maxOf(vs.highestRevision, base?.revision ?: 0L)
        val floorEpoch = maxOf(vs.highestKeyEpoch, baseInfo?.keyEpoch ?: 0L)
        val floorHeader = maxOf(vs.highestHeaderRevision, baseInfo?.headerRevision ?: 0L)
        val established = vs.established

        if (remote == null) {
            if (established && !options.recreateRemote) {
                return Step.Fail(FailureReason.RemoteMissing, "the remote vault file no longer exists")
            }
            if (hooks.keyEpoch < floorEpoch) {
                return Step.Fail(FailureReason.ReopenRequired, "this device holds an older data key than it has seen")
            }
            if (hooks.headerRevision < floorHeader) {
                return Step.Fail(FailureReason.RollbackDetected, "this device's key slots are older than ones it has seen")
            }
            // Never publish a revision at or below the floor.
            val toPush = if (floorRevision > 0L) {
                local.copy(revision = nextRevision(maxOf(local.revision, floorRevision)))
            } else {
                local
            }
            val enc = hooks.encrypt(toPush, null)
            val result = store.write(
                enc.bytes,
                ifMatchEtag = null,
                ifNoneMatch = !underLock || capabilities.honoursIfNoneMatchStar,
            )
            val warnings = if (established) listOf(SyncWarning.RemoteRecreated(toPush.revision)) else emptyList()
            return afterWrite(result, enc, toPush, SyncOutcome.Pushed, warnings, underLock, null)
        }

        val info = hooks.decrypt(remote.bytes)
        val remoteContent = info.content
        if (remoteContent.vaultId != local.vaultId) return Step.Fail(FailureReason.DifferentVault)
        if (info.keyEpoch < floorEpoch) {
            return Step.Fail(
                FailureReason.RollbackDetected,
                "remote key epoch ${info.keyEpoch} is lower than the highest seen ($floorEpoch)",
            )
        }
        if (info.headerRevision < floorHeader) {
            return Step.Fail(
                FailureReason.RollbackDetected,
                "remote slot-set revision ${info.headerRevision} is lower than the highest seen ($floorHeader)",
            )
        }
        if (remoteContent.revision < floorRevision && !options.allowRollback) {
            return Step.Fail(
                FailureReason.RollbackDetected,
                "remote revision ${remoteContent.revision} is lower than the highest seen ($floorRevision)",
            )
        }

        val digest = hooks.fingerprint(remote.bytes)
        val warnings = ArrayList<SyncWarning>()
        val seenDigest = vs.fileDigests[remoteContent.revision]
        if (seenDigest != null && seenDigest != digest) {
            warnings += SyncWarning.ForkSuspected(remoteContent.revision)
        }
        if (!established) {
            warnings += SyncWarning.FirstUseTrust(remoteContent.revision, info.keyEpoch, info.headerRevision)
        }

        val merge = mergeVaults(base, local, remoteContent, deviceId)
        val staleRemote = merge.regressions.filter { it.ignoredSide == MergeSide.Remote }.map { it.recordId }
        if (staleRemote.isNotEmpty()) warnings += SyncWarning.StaleRemoteIgnored(staleRemote)
        val staleLocal = merge.regressions.filter { it.ignoredSide == MergeSide.Local }.map { it.recordId }
        if (staleLocal.isNotEmpty()) warnings += SyncWarning.LocalContentWasStale(staleLocal)

        // A local slot change or key rotation must be published even when the content is unchanged.
        val headerPush = hooks.keyEpoch > info.keyEpoch ||
            (hooks.keyEpoch == info.keyEpoch && hooks.headerRevision > info.headerRevision)
        val outcome = when {
            merge.conflicts.isNotEmpty() -> SyncOutcome.Merged(merge.conflicts)
            merge.changedLocally && merge.changedRemotely -> SyncOutcome.Merged(emptyList())
            merge.changedRemotely || headerPush -> SyncOutcome.Pushed
            merge.changedLocally -> SyncOutcome.Pulled
            else -> SyncOutcome.UpToDate
        }

        if (!merge.changedRemotely && !headerPush) {
            recordSynced(
                local.vaultId, remote.bytes, info.keyEpoch, info.headerRevision,
                remoteContent.revision, digest, usableEtag(remote.etag), null,
            )
            return Step.Done(SyncResult(outcome, merge.merged, warnings))
        }

        var toWrite = merge.merged
        if (!merge.changedRemotely) {
            toWrite = toWrite.copy(revision = nextRevision(maxOf(local.revision, remoteContent.revision)))
        }
        if (toWrite.revision <= floorRevision) toWrite = toWrite.copy(revision = nextRevision(floorRevision))

        val etag = usableEtag(remote.etag)
        if (!underLock && etag == null) {
            // The server normally gives strong ETags but this response did not (or sent an unusable one).
            return Step.Retry(FailureReason.TooManyAttempts, forceLock = true)
        }
        if (lease != null && !renewLease(lease)) return Step.Retry(FailureReason.Locked)

        val enc = hooks.encrypt(toWrite, remote.bytes)
        val result = store.write(enc.bytes, ifMatchEtag = if (underLock) null else etag, ifNoneMatch = false)
        return afterWrite(result, enc, toWrite, outcome, warnings, underLock, remoteContent.revision to digest)
    }

    /** Verifies an upload by reading it back; records the new sync state only when the bytes are exactly ours. */
    private suspend fun afterWrite(
        result: WriteResult,
        enc: EncryptedVault,
        written: VaultContent,
        outcome: SyncOutcome,
        warnings: List<SyncWarning>,
        underLock: Boolean,
        seenRemote: Pair<Long, String>?,
    ): Step = when (result) {
        is WriteResult.PreconditionFailed -> Step.Retry(FailureReason.TooManyAttempts)
        is WriteResult.Failed -> Step.Fail(FailureReason.ServerRejected, result.message)
        is WriteResult.Written -> {
            val readBack = store.read()
            if (readBack == null || !readBack.bytes.contentEquals(enc.bytes)) {
                // Someone else wrote between our PUT and the read-back (or the server lost the write). Under the
                // conditional protocol this should not happen, so measure the server again next time.
                if (!underLock) invalidateProbe()
                Step.Retry(FailureReason.TooManyAttempts)
            } else {
                recordSynced(
                    written.vaultId, enc.bytes, enc.keyEpoch, enc.headerRevision, written.revision,
                    hooks.fingerprint(enc.bytes), usableEtag(readBack.etag ?: result.etag), seenRemote,
                )
                Step.Done(SyncResult(outcome, written, warnings))
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
