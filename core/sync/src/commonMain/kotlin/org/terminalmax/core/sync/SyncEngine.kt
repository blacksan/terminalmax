// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.sync

import kotlin.coroutines.cancellation.CancellationException
import kotlin.random.Random
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.terminalmax.core.vault.Conflict
import org.terminalmax.core.vault.MAX_REVISION
import org.terminalmax.core.vault.MAX_REVISION_JUMP
import org.terminalmax.core.vault.MergeSide
import org.terminalmax.core.vault.REVISION_HEADROOM
import org.terminalmax.core.vault.VaultContent
import org.terminalmax.core.vault.VaultException
import org.terminalmax.core.vault.mergeVaults

/**
 * Marks a [SyncEngine.sync] as the **replacement** of the remote file (which this device cannot merge) by one of its own
 * files, published unread. What the remote file held is gone from the share, so it is a compare-and-replace:
 *
 * @property expectedRemoteDigest SHA-256 (lower-case hex) of the remote file the caller judged unusable; null together
 *   with [checkExpectation] means "the remote file did not exist"
 * @property checkExpectation when true, the file read in the attempt must have exactly [expectedRemoteDigest],
 *   otherwise nothing is replaced ([FailureReason.RemoteChangedDuringRotation]); an attempt that has to be retried
 *   (lost race) re-reads and fails the same check, so it never overwrites a file it did not judge
 * @property refuseLinkedSuccessor refuse (with [FailureReason.RemoteRekeyedElsewhere]) when the remote file is the
 *   verified successor of this device's key (the password was changed on another device)
 * @property kind what is published
 */
class ReplaceRemote(
    val expectedRemoteDigest: String? = null,
    val checkExpectation: Boolean = false,
    val refuseLinkedSuccessor: Boolean = false,
    val kind: Kind = Kind.Replace,
) {
    enum class Kind {
        /** A staged key change (a new key epoch) over whatever is there; reported as `SyncWarning.RemoteReplaced`. */
        Replace,

        /** The held key's current file, completing an unpublished password change (the key epoch is the held one). */
        CompletePending,

        /** The first file of a brand-new vault (another vault id) over the old vault's file; drops the old vault's state. */
        NewVault,
    }
}

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
 * @param dropVaultOnCommit the vault id whose state entry is removed in the same state write as the first commit (the
 *   migration to a new vault); null otherwise
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
    private val dropVaultOnCommit: String? = null,
) {
    private sealed interface Step {
        class Done(val result: SyncResult) : Step
        class Fail(
            val reason: FailureReason,
            val detail: String? = null,
            val warnings: List<SyncWarning> = emptyList(),
            val competingKeyFingerprint: String? = null,
            val published: Boolean = false,
            val changes: RemoteChangeSummary = RemoteChangeSummary.EMPTY,
        ) : Step
        class Retry(val reason: FailureReason, val forceLock: Boolean = false) : Step
    }

    private val mutex = Mutex()

    /** Facts about the remote file of the sync call that is running (calls are serialised by [mutex]). */
    private class Trace {
        var remoteDigest: String? = null
    }

    private var trace = Trace()

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
        val result = mutex.withLock {
            trace = Trace()
            try {
                syncLocked(local, options, staged, reopenPassword, replace)
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
        }
        return withStickyWarnings(result, local.vaultId)
    }

    /**
     * The unacknowledged warnings of the state (an adopted re-key that could not be verified or kept the password, a
     * discarded password change) are part of every result until the user acknowledges them.
     */
    private suspend fun withStickyWarnings(result: SyncResult, vaultId: String): SyncResult {
        val vs = try {
            localState.load().vaults[vaultId]
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            null
        } ?: return result
        val sticky = ArrayList<SyncWarning>()
        vs.chainWarning?.let { chain ->
            if (chain.fromEpoch == chain.toEpoch) {
                sticky += SyncWarning.ConcurrentRekeyAdopted(chain.toEpoch)
            } else if (chain.unverified) {
                sticky += SyncWarning.KeyEpochChainUnverified(chain.fromEpoch, chain.toEpoch)
            }
            if (chain.passwordUnchanged) sticky += SyncWarning.PasswordUnchangedByRekey(chain.fromEpoch, chain.toEpoch)
        }
        vs.discardedPendingEpoch?.let { sticky += SyncWarning.PasswordChangeNotPublished(it) }
        val missing = sticky.filter { w -> result.warnings.none { it == w } }
        if (missing.isEmpty()) return result
        return result.copy(warnings = result.warnings + missing)
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
                is Step.Fail -> return failed(
                    local, step.reason, step.detail, step.warnings, step.competingKeyFingerprint, step.published, step.changes,
                )
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
        is VaultException.KeyMismatchSameEpoch -> FailureReason.KeyMismatchSameEpoch
        is VaultException.KeyEpochMismatch ->
            if (e.found > e.expected) FailureReason.ReopenRequired else FailureReason.KeyEpochRollback
        // A file this device is too small for is not "invalid": replacing it would destroy a good vault.
        is VaultException.KdfCostTooHigh -> FailureReason.RemoteKdfTooHeavyForDevice
        else -> FailureReason.InvalidRemoteFile
    }

    private fun failed(
        local: VaultContent,
        reason: FailureReason,
        detail: String?,
        warnings: List<SyncWarning> = emptyList(),
        competingKeyFingerprint: String? = null,
        published: Boolean = false,
        changes: RemoteChangeSummary = RemoteChangeSummary.EMPTY,
    ): SyncResult {
        val digest = trace.remoteDigest
        val info = if (digest != null || competingKeyFingerprint != null || published) {
            FailureInfo(digest, competingKeyFingerprint, published)
        } else {
            null
        }
        return SyncResult(
            SyncOutcome.Failed(reason, detail), local, warnings, remoteChanges = changes, failureInfo = info,
        )
    }

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

    private class Committed(val content: VaultContent, val editsPending: Boolean, val conflicts: List<Conflict>)

    /**
     * Commits a successful sync in one state save: floors, digests, the base file and the sealed local file. The
     * local file is sealed from the **join** of [written] and the content the [LocalView] holds right now, so an edit
     * made while the network I/O ran is never overwritten; [Committed.editsPending] says that there was one, and
     * [Committed.conflicts] lists the edits that lost to a newer remote version of the same record in that join (they
     * are in the history; the caller reports them as conflicts). For a [staged] password change the new key is
     * committed in the same section. [clearsPending] drops the state's pending rotation (a staged change, or a
     * completed one).
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
        clearsPending: Boolean = staged != null,
    ): Committed = localState.exclusive {
        val current = view?.current() ?: snapshot
        val editsPending = current != snapshot
        val joined = if (editsPending) mergeVaults(snapshot, current, written, deviceId) else null
        val final = joined?.merged ?: written
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
            pendingLocalFile = if (clearsPending) null else previous.pendingLocalFile,
            pendingHoldsNewerEdits = if (clearsPending) false else previous.pendingHoldsNewerEdits,
        )
        val others = if (dropVaultOnCommit != null) state.vaults - dropVaultOnCommit else state.vaults
        localState.save(state.copy(vaults = others + (written.vaultId to updated)))
        if (staged != null) hooks.commitStaged(staged)
        view?.committed(final)
        Committed(final, editsPending, joined?.conflicts ?: emptyList())
    }

    /** An edit that lost at commit time is a conflict of this very sync. */
    private fun withCommitConflicts(outcome: SyncOutcome, extra: List<Conflict>): SyncOutcome = when {
        extra.isEmpty() -> outcome
        outcome is SyncOutcome.Merged -> SyncOutcome.Merged(outcome.conflicts + extra)
        else -> SyncOutcome.Merged(extra)
    }

    /**
     * Persists the sealed local file after a re-key was adopted, before the sync that follows, together with the
     * warnings that must survive until acknowledged ([chainWarning]; [discardedPendingEpoch] when the adoption
     * superseded a password change of this device that never reached the server) and without the superseded pending
     * rotation.
     */
    private suspend fun recordAdoptedRekey(snapshot: VaultContent, chainWarning: ChainWarning?, discardedPendingEpoch: Long?) {
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
                            pendingHoldsNewerEdits = false,
                            chainWarning = chainWarning ?: previous.chainWarning,
                            discardedPendingEpoch = discardedPendingEpoch ?: previous.discardedPendingEpoch,
                        )
                        ),
                ),
            )
        }
    }

    /**
     * Durably stores the sealed new-epoch local file of a password change **before** it is uploaded. It is sealed
     * from the join of [written] and the content the [LocalView] holds right now, so an edit made after the snapshot
     * was taken is in it (and every later edit is added by `VaultSession.edit` while the change is in flight): a
     * crash anywhere afterwards leaves a pending file that is never behind the committed local file.
     */
    private suspend fun recordPending(snapshot: VaultContent, written: VaultContent, staged: StagedHeaderChange) {
        localState.exclusive {
            val current = view?.current() ?: snapshot
            val final = if (current != snapshot) mergeVaults(snapshot, current, written, deviceId).merged else written
            val pending = hooks.sealLocalStaged(final, staged)
            val state = localState.load()
            val previous = state.vaults[snapshot.vaultId] ?: VaultSyncState()
            localState.save(
                state.copy(
                    vaults = state.vaults + (
                        snapshot.vaultId to previous.copy(pendingLocalFile = pending, pendingHoldsNewerEdits = false)
                        ),
                ),
            )
        }
    }

    /** Forgets the pending rotation (the upload was refused, so the change did not happen). */
    private suspend fun clearPending(vaultId: String) {
        localState.exclusive {
            val state = localState.load()
            val previous = state.vaults[vaultId] ?: VaultSyncState()
            if (previous.pendingLocalFile == null) return@exclusive
            localState.save(
                state.copy(
                    vaults = state.vaults + (vaultId to previous.copy(pendingLocalFile = null, pendingHoldsNewerEdits = false)),
                ),
            )
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

    /** What the merge changed in the records this device had live before it (ids only). */
    private fun summarize(local: VaultContent, merged: VaultContent): RemoteChangeSummary {
        val mergedById = merged.records.associateBy { it.id }
        val localIds = HashSet<String>(local.records.size * 2 + 1)
        val changed = ArrayList<String>()
        val deleted = ArrayList<String>()
        val knownHosts = ArrayList<String>()
        var live = 0
        for (l in local.records) {
            localIds += l.id
            if (l.deleted) continue
            live++
            val m = mergedById[l.id] ?: continue
            when {
                m.deleted -> deleted += l.id
                m != l -> {
                    changed += l.id
                    if (m.type == org.terminalmax.core.vault.RecordType.KnownHost) knownHosts += l.id
                }
            }
        }
        val added = merged.records.filter { it.id !in localIds && !it.deleted }.map { it.id }
        return RemoteChangeSummary(changed, deleted, added, knownHosts, live)
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
        trace.remoteDigest = remote?.let { hooks.fingerprint(it.bytes) }

        if (replace != null) {
            if (staged == null && replace.kind == ReplaceRemote.Kind.Replace) {
                return Step.Fail(FailureReason.Unexpected, "a replacement needs a staged key change")
            }
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
            val higherEpoch = e is VaultException.KeyEpochMismatch && e.found > e.expected
            if (!sameEpoch && !higherEpoch) throw e // a lower epoch or an unusable file: reported by reasonFor
            val fromEpoch = if (e is VaultException.KeyEpochMismatch) e.expected else hooks.keyEpoch
            val toEpoch = if (e is VaultException.KeyEpochMismatch) e.found else hooks.keyEpoch
            if (staged != null) {
                return Step.Fail(
                    FailureReason.HeaderChangedRemotely,
                    "the vault was re-keyed on another device (key epoch $toEpoch)",
                )
            }
            if (sameEpoch) {
                // A competing key at the SAME epoch cannot be linked to anything this device still holds (it keeps no
                // previous-epoch key), and a password that opens it may be an OLD one: it is adopted only when the user
                // confirmed the fingerprint of exactly this file.
                val claimed = hooks.claimedFingerprint(remote.bytes)
                if (reopenPassword == null || options.adoptCompetingKeyFingerprint != claimed) {
                    return Step.Fail(
                        FailureReason.KeyMismatchSameEpoch,
                        "a file of the same key epoch ($toEpoch) is under another key; confirm its fingerprint " +
                            "after checking it on another device",
                        competingKeyFingerprint = claimed,
                    )
                }
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
            // An unpublished password change of this device that this file supersedes is dropped: say so, until
            // acknowledged. (A file that IS the pending change is the change landing: nothing to report.)
            val discarded = vs.pendingLocalFile?.let { pending ->
                try {
                    if (hooks.sameHeader(remote.bytes, pending)) null else hooks.claimedKeyEpoch(pending)
                } catch (e: VaultException) {
                    0L
                }
            }
            if (discarded != null) warnings += SyncWarning.PasswordChangeNotPublished(discarded)
            // The key changed in memory: persist the local file under it right away (so that a restart can open it
            // with the password that was just typed), and remember what the user must still be told.
            val unverified = sameEpoch || reopened.chain != EpochChain.Verified
            val sticky = if (unverified || reopened.passwordUnchanged) {
                ChainWarning(fromEpoch, toEpoch, passwordUnchanged = reopened.passwordUnchanged, unverified = unverified)
            } else {
                null
            }
            recordAdoptedRekey(local, sticky, discarded)
            hooks.decrypt(remote.bytes)
        }
        val remoteContent = info.content
        if (remoteContent.vaultId != local.vaultId) return Step.Fail(FailureReason.DifferentVault, null, warnings)
        if (info.keyEpoch < floorEpoch) {
            return Step.Fail(
                FailureReason.KeyEpochRollback,
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

        // A remote that deletes or changes a large part of what this device has is not applied without the user's say.
        val changes = summarize(local, merge.merged)
        val affected = changes.changedIds.size + changes.deletedIds.size
        if (affected > maxOf(LARGE_CHANGE_MINIMUM, changes.liveRecordsBefore / 4)) {
            if (!options.acceptLargeRemoteChange) {
                return Step.Fail(
                    FailureReason.LargeRemoteChange,
                    "the remote would delete ${changes.deletedIds.size} and change ${changes.changedIds.size} of " +
                        "${changes.liveRecordsBefore} records; nothing was applied",
                    warnings,
                    changes = changes,
                )
            }
            warnings += SyncWarning.LargeRemoteChangeAccepted(changes.changedIds.size, changes.deletedIds.size)
        }

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
            return Step.Done(
                SyncResult(
                    withCommitConflicts(outcome, committed.conflicts), committed.content, warnings,
                    committed.editsPending, changes,
                ),
            )
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
        return afterWrite(
            result, enc, toWrite, local, outcome, warnings, underLock, remoteContent.revision to digest, null, changes,
        )
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
        recordPending(local, toWrite, staged)
        val result = store.write(enc.bytes, ifMatchEtag = if (underLock) null else etag, ifNoneMatch = false)
        return afterWrite(
            result, enc, toWrite, local, SyncOutcome.Pushed, warnings, underLock,
            remoteContent.revision to hooks.fingerprint(remote.bytes), staged,
        )
    }

    /**
     * Publishes one of this device's own files over whatever the remote holds, **unread** (the recovery actions behind
     * `VaultSession.replaceRemoteWithLocal`, `resolvePendingPasswordChange` and `migrateToNewVault`). Compare-and-
     * replace: the file read in this attempt must be the one the caller judged ([ReplaceRemote.checkExpectation]),
     * the PUT carries `If-Match` of that very read (or happens under the lock lease), and the upload is read back.
     * A lost race is never retried into a different file: the retry re-reads and fails the expectation.
     */
    private suspend fun publishReplacement(
        local: VaultContent,
        staged: StagedHeaderChange?,
        replace: ReplaceRemote,
        remote: RemoteFile?,
        vs: VaultSyncState,
        lease: Lease?,
        capabilities: ServerCapabilities,
    ): Step {
        val underLock = lease != null
        if (replace.checkExpectation) {
            val actual = remote?.let { hooks.fingerprint(it.bytes) }
            if (actual != replace.expectedRemoteDigest) {
                return Step.Fail(
                    FailureReason.RemoteChangedDuringRotation,
                    "the remote file is not the one that was judged (it changed meanwhile); nothing was replaced",
                )
            }
        }
        if (replace.refuseLinkedSuccessor && remote != null) {
            val chain = try {
                hooks.epochChain(remote.bytes)
            } catch (e: VaultException) {
                EpochChain.NotApplicable
            }
            if (chain == EpochChain.Verified) {
                return Step.Fail(
                    FailureReason.RemoteRekeyedElsewhere,
                    "the remote is the re-key of this device's key: the password was changed on another device",
                )
            }
        }
        val toWrite = local.copy(revision = nextRevision(maxOf(local.revision, vs.highestRevision)))
        val etag = usableEtag(remote?.etag)
        if (remote != null && !underLock && etag == null) return Step.Retry(FailureReason.TooManyAttempts, forceLock = true)
        if (lease != null && !renewLease(lease)) return Step.Retry(FailureReason.Locked)
        val enc = if (staged != null) hooks.encryptStaged(toWrite, staged) else hooks.encrypt(toWrite)
        if (staged != null) recordPending(local, toWrite, staged)
        val result = if (remote == null) {
            store.write(enc.bytes, ifMatchEtag = null, ifNoneMatch = !underLock || capabilities.honoursIfNoneMatchStar)
        } else {
            store.write(enc.bytes, ifMatchEtag = if (underLock) null else etag, ifNoneMatch = false)
        }
        val warnings = if (replace.kind == ReplaceRemote.Kind.Replace && staged != null) {
            val replacedEpoch = remote?.let {
                try {
                    hooks.claimedKeyEpoch(it.bytes) // unauthenticated: for the message only
                } catch (e: VaultException) {
                    0L
                }
            } ?: 0L
            listOf<SyncWarning>(SyncWarning.RemoteReplaced(staged.keyEpoch, replacedEpoch))
        } else {
            emptyList()
        }
        return afterWrite(
            result, enc, toWrite, local, SyncOutcome.Pushed, warnings, underLock, null, staged,
            clearsPending = staged != null || replace.kind == ReplaceRemote.Kind.CompletePending,
        )
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
        changes: RemoteChangeSummary = RemoteChangeSummary.EMPTY,
        clearsPending: Boolean = staged != null,
    ): Step = when (result) {
        is WriteResult.PreconditionFailed -> {
            // The upload was refused, so the pending rotation (if any) did not happen.
            if (staged != null) clearPending(written.vaultId)
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
                try {
                    val committed = commitLocal(
                        snapshot, written, enc.bytes, enc.keyEpoch, written.revision, hooks.fingerprint(enc.bytes),
                        seenRemote, staged, clearsPending,
                    )
                    Step.Done(
                        SyncResult(
                            withCommitConflicts(outcome, committed.conflicts), committed.content, warnings,
                            committed.editsPending, changes,
                        ),
                    )
                } catch (e: LocalStateException) {
                    // The upload landed but this device could not record it: for a password change the new password
                    // is already live on the server.
                    if (staged != null) {
                        Step.Fail(
                            FailureReason.LocalStateUnavailable,
                            "the upload landed but could not be recorded locally: " + e.message,
                            warnings,
                            published = true,
                        )
                    } else {
                        throw e
                    }
                }
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

        /**
         * A pull that deletes or changes more of this device's live records than `max(this, 25%)` is refused unless
         * the user accepts it ([SyncOptions.acceptLargeRemoteChange]).
         */
        const val LARGE_CHANGE_MINIMUM: Int = 10

        /** A foreign lock is broken only this long after its expiry when the server's clock is available. */
        const val SERVER_CLOCK_GRACE_MILLIS: Long = 30_000L

        /** Same, when only this device's own clock is available. */
        const val LOCAL_CLOCK_GRACE_MILLIS: Long = 5 * 60_000L
    }
}
