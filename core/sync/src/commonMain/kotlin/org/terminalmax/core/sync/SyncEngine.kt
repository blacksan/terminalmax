// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.sync

import kotlin.coroutines.cancellation.CancellationException
import kotlin.random.Random
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import org.terminalmax.core.vault.VaultContent
import org.terminalmax.core.vault.VaultException
import org.terminalmax.core.vault.mergeVaults

/**
 * Synchronises one local [VaultContent] with the remote vault file.
 *
 * Each attempt: read remote; if absent upload local (create-only); otherwise decrypt, three-way merge against the
 * stored base, and upload the merge result when it differs from the remote. Uploads are made atomic with
 * `If-Match` / `If-None-Match` when the server was measured to honour them reliably, otherwise under a
 * lock-file lease. Every upload is verified by reading the file back; if the bytes are not exactly what was
 * written, another writer got in between and the attempt is repeated (at most [maxAttempts], with jittered
 * backoff). A remote whose revision is lower than the highest ever seen is refused unless
 * [SyncOptions.allowRollback] is set.
 *
 * @param clock wall-clock milliseconds, used only for lock leases
 * @param sleep suspends for the given milliseconds (injectable so tests do not wait)
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
    private val leaseMillis: Long = 60_000L,
) {
    private sealed interface Step {
        class Done(val result: SyncResult) : Step
        class Fail(val reason: FailureReason, val detail: String? = null) : Step
        class Retry(val reason: FailureReason, val forceLock: Boolean = false) : Step
    }

    suspend fun sync(local: VaultContent, options: SyncOptions = SyncOptions()): SyncResult {
        try {
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
        } catch (e: CancellationException) {
            throw e
        } catch (e: VaultException) {
            val reason = when (e) {
                is VaultException.DifferentVault -> FailureReason.DifferentVault
                is VaultException.UnsupportedVersion -> FailureReason.UnsupportedVersion
                is VaultException.BadPasswordOrCorrupt -> FailureReason.BadPasswordOrCorrupt
                else -> FailureReason.InvalidRemoteFile
            }
            return failed(local, reason, e.message)
        } catch (e: RemoteAuthException) {
            return failed(local, FailureReason.AuthFailed, e.message)
        } catch (e: RemoteIoException) {
            return failed(local, FailureReason.Network, e.message)
        }
    }

    private fun failed(local: VaultContent, reason: FailureReason, detail: String?) =
        SyncResult(SyncOutcome.Failed(reason, detail), local)

    private fun backoffMillis(attempt: Int): Long {
        val cap = 100L shl (attempt - 1).coerceAtMost(6)
        return cap / 2 + random.nextLong(cap / 2 + 1)
    }

    private suspend fun capabilities(options: SyncOptions): ServerCapabilities {
        val state = localState.load()
        val cached = state.capabilities
        if (cached != null && !options.reprobe) return cached
        val probed = store.probe()
        localState.save(localState.load().copy(capabilities = probed))
        return probed
    }

    private suspend fun attemptOnce(
        local: VaultContent,
        capabilities: ServerCapabilities,
        forceLock: Boolean,
        options: SyncOptions,
    ): Step {
        val needsLock = forceLock || !capabilities.supportsConditionalWrites
        var lease: Lease? = null
        if (needsLock) {
            lease = acquireLock(capabilities)
            if (lease == null) return Step.Retry(FailureReason.Locked)
        }
        try {
            return readMergeWrite(local, needsLock, capabilities, options)
        } finally {
            lease?.let { releaseLock(it) }
        }
    }

    private suspend fun readMergeWrite(
        local: VaultContent,
        underLock: Boolean,
        capabilities: ServerCapabilities,
        options: SyncOptions,
    ): Step {
        val state = localState.load()
        val remote = store.read()

        if (remote == null) {
            val bytes = hooks.encrypt(local, null)
            val result = store.write(bytes, ifMatchEtag = null, ifNoneMatch = !underLock || capabilities.honoursIfNoneMatchStar)
            return afterWrite(result, bytes, local, SyncOutcome.Pushed)
        }

        val remoteContent = hooks.decrypt(remote.bytes)
        if (remoteContent.vaultId != local.vaultId) return Step.Fail(FailureReason.DifferentVault)
        val highest = state.highestRevisionSeen[remoteContent.vaultId]
        if (highest != null && remoteContent.revision < highest && !options.allowRollback) {
            return Step.Fail(
                FailureReason.RollbackDetected,
                "remote revision ${remoteContent.revision} is lower than the highest seen ($highest)",
            )
        }

        val base = state.baseContent?.takeIf { it.vaultId == local.vaultId }
        val merge = mergeVaults(base, local, remoteContent, deviceId)
        val outcome = when {
            merge.conflicts.isNotEmpty() -> SyncOutcome.Merged(merge.conflicts)
            merge.changedLocally && merge.changedRemotely -> SyncOutcome.Merged(emptyList())
            merge.changedRemotely -> SyncOutcome.Pushed
            merge.changedLocally -> SyncOutcome.Pulled
            else -> SyncOutcome.UpToDate
        }

        if (!merge.changedRemotely) {
            recordSynced(merge.merged, remote.etag, remoteContent.revision)
            return Step.Done(SyncResult(outcome, merge.merged))
        }

        val conditional = !underLock
        if (conditional && !isStrongEtag(remote.etag)) {
            // The server normally gives strong ETags but this response did not: use the lock path instead.
            return Step.Retry(FailureReason.TooManyAttempts, forceLock = true)
        }
        val bytes = hooks.encrypt(merge.merged, remote.bytes)
        val result = store.write(bytes, ifMatchEtag = if (conditional) remote.etag else null, ifNoneMatch = false)
        return afterWrite(result, bytes, merge.merged, outcome)
    }

    /** Verifies an upload by reading it back; records the new sync state only when the bytes are exactly ours. */
    private suspend fun afterWrite(result: WriteResult, written: ByteArray, merged: VaultContent, outcome: SyncOutcome): Step =
        when (result) {
            is WriteResult.PreconditionFailed -> Step.Retry(FailureReason.TooManyAttempts)
            is WriteResult.Failed -> Step.Fail(FailureReason.ServerRejected, result.message)
            is WriteResult.Written -> {
                val readBack = store.read()
                if (readBack == null || !readBack.bytes.contentEquals(written)) {
                    // Someone else wrote between our PUT and the read-back (or the server lost the write).
                    Step.Retry(FailureReason.TooManyAttempts)
                } else {
                    recordSynced(merged, readBack.etag ?: result.etag, merged.revision)
                    Step.Done(SyncResult(outcome, merged))
                }
            }
        }

    private suspend fun recordSynced(base: VaultContent, etag: String?, observedRevision: Long) {
        val state = localState.load()
        val previous = state.highestRevisionSeen[base.vaultId] ?: 0L
        localState.save(
            state.copy(
                baseContent = base,
                lastEtag = etag,
                highestRevisionSeen = state.highestRevisionSeen + (base.vaultId to maxOf(previous, observedRevision)),
            ),
        )
    }

    // ------------------------------------------------------------------ lock lease

    private class Lease(val token: String)

    /**
     * Takes the lock lease, or returns null when another device holds it. A lock is only broken when it is
     * unreadable, our own (left by a crash), or older than twice the lease. Ownership is verified by reading the
     * lock back, because servers that ignore preconditions cannot make the creation atomic.
     */
    private suspend fun acquireLock(capabilities: ServerCapabilities): Lease? {
        val now = clock()
        val existing = store.readLock()
        if (existing != null) {
            val info = LockFile.decode(existing.bytes)
            if (info != null && info.deviceId != deviceId && now < info.expiresAtEpochMs + leaseMillis) return null
            store.deleteLock()
        }
        val token = random.nextBytes(12).joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
        val bytes = LockFile.encode(LockInfo(deviceId, token, now + leaseMillis))
        val written = store.writeLock(bytes, ifNoneMatch = capabilities.honoursIfNoneMatchStar)
        if (written !is WriteResult.Written) return null
        val back = store.readLock()?.let { LockFile.decode(it.bytes) }
        return if (back?.token == token) Lease(token) else null
    }

    private suspend fun releaseLock(lease: Lease) {
        withContext(NonCancellable) {
            try {
                val current = store.readLock()?.let { LockFile.decode(it.bytes) }
                if (current?.token == lease.token) store.deleteLock()
            } catch (e: RemoteIoException) {
                // Best effort: an unreleased lease simply expires.
            }
        }
    }
}
