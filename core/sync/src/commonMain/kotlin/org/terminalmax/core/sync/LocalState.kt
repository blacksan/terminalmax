// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.sync

import org.terminalmax.core.vault.VaultContent

/** The local sync state cannot be read, is corrupt, or cannot be written. Sync fails closed instead of resetting it. */
class LocalStateException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * A re-key that this device adopted and that the user must still be told about, remembered until the user
 * acknowledges it (`VaultSession.acknowledgeKeyEpochWarning`). [fromEpoch] == [toEpoch] means a competing key at the
 * same epoch. [unverified] is false when the chain verified and only [passwordUnchanged] (the typed password also opens
 * the slot this device held before: see `SyncWarning.PasswordUnchangedByRekey`) is the reason for the warning.
 */
data class ChainWarning(
    val fromEpoch: Long,
    val toEpoch: Long,
    val passwordUnchanged: Boolean = false,
    val unverified: Boolean = true,
)

/**
 * What a device remembers about one vault between syncs. It holds no secrets (but it is not "nothing": the vault id,
 * revision and key-epoch floors, file digests and the device id are stored in the clear, see `FileLocalStateStore`):
 * [baseFile] is the encrypted file
 * exactly as it was last synced (the three-way merge base is decrypted from it with the data key when needed) and
 * [localFile] is the sealed local vault. They live in the same on-disk transaction (see `VaultSession`), so the
 * floors, the base and the local content can never diverge after a crash.
 *
 * The "highest" values are floors: a remote file below any of them is a rollback or a replay.
 *
 * @property baseFile the vault file as of the last successful sync, or null
 * @property localFile this device's own sealed vault file (its current local content), or null when the state is
 *   used without a `VaultSession`
 * @property pendingLocalFile the fully sealed **new-epoch** local file of a password change that is being
 *   published: written durably before the upload, cleared once the change is committed (or known not to have
 *   happened). After a crash it is what lets the new password open the vault (see `VaultSession.open`).
 * @property pendingHoldsNewerEdits the pending file holds edits that the committed [localFile] does not (they were made
 *   in a session opened with the new password): dropping the pending file would lose them
 * @property discardedPendingEpoch the key epoch of an unpublished password change that was dropped, until the user
 *   acknowledges the warning (`SyncWarning.PasswordChangeNotPublished`)
 * @property chainWarning a key epoch change this device adopted without being able to verify its chain, until acknowledged
 * @property highestRevision highest content revision ever read from or written to the remote
 * @property highestKeyEpoch highest key epoch seen
 * @property fileDigests SHA-256 hex of the files seen, by content revision, newest [MAX_DIGESTS] only; a different
 *   file at an already seen revision is a fork
 */
data class VaultSyncState(
    val baseFile: ByteArray? = null,
    val localFile: ByteArray? = null,
    val highestRevision: Long = 0L,
    val highestKeyEpoch: Long = 0L,
    val fileDigests: Map<Long, String> = emptyMap(),
    val pendingLocalFile: ByteArray? = null,
    val chainWarning: ChainWarning? = null,
    val pendingHoldsNewerEdits: Boolean = false,
    val discardedPendingEpoch: Long? = null,
) {
    /** True once this device has synced the vault at least once (so a missing remote file is suspicious). */
    val established: Boolean get() = baseFile != null || highestRevision > 0L

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is VaultSyncState) return false
        return highestRevision == other.highestRevision &&
            highestKeyEpoch == other.highestKeyEpoch &&
            fileDigests == other.fileDigests &&
            chainWarning == other.chainWarning &&
            pendingHoldsNewerEdits == other.pendingHoldsNewerEdits &&
            discardedPendingEpoch == other.discardedPendingEpoch &&
            (baseFile?.contentEquals(other.baseFile) ?: (other.baseFile == null)) &&
            (localFile?.contentEquals(other.localFile) ?: (other.localFile == null)) &&
            (pendingLocalFile?.contentEquals(other.pendingLocalFile) ?: (other.pendingLocalFile == null))
    }

    override fun hashCode(): Int {
        var result = baseFile?.contentHashCode() ?: 0
        result = 31 * result + (localFile?.contentHashCode() ?: 0)
        result = 31 * result + highestRevision.hashCode()
        result = 31 * result + highestKeyEpoch.hashCode()
        result = 31 * result + (pendingLocalFile?.contentHashCode() ?: 0)
        result = 31 * result + (chainWarning?.hashCode() ?: 0)
        result = 31 * result + pendingHoldsNewerEdits.hashCode()
        result = 31 * result + (discardedPendingEpoch?.hashCode() ?: 0)
        result = 31 * result + fileDigests.hashCode()
        return result
    }

    override fun toString(): String =
        "VaultSyncState(base=${baseFile?.size ?: 0} bytes, revision=$highestRevision, keyEpoch=$highestKeyEpoch, " +
            "pending=${pendingLocalFile != null}, digests=${fileDigests.size})"

    companion object {
        const val MAX_DIGESTS: Int = 64
    }
}

/**
 * What a device remembers about one server (see [RemoteStore.serverKey]).
 *
 * @property capabilities result of the last probe of this server, valid for [SyncEngine]'s re-probe interval
 * @property probedAtEpochMs local clock time of that probe
 */
data class ServerSyncState(
    val capabilities: ServerCapabilities? = null,
    val probedAtEpochMs: Long = 0L,
)

/**
 * @property vaults per vault id (floors and base follow the vault across servers on purpose: a vault restored on
 *   another server must not be older than what this device has already seen)
 * @property servers per [RemoteStore.serverKey]
 * @property deviceId random id of this installation, used to attribute record versions (null until a
 *   `VaultSession` created one)
 */
data class LocalSyncState(
    val vaults: Map<String, VaultSyncState> = emptyMap(),
    val servers: Map<String, ServerSyncState> = emptyMap(),
    val deviceId: String? = null,
)

/**
 * Persistence for [LocalSyncState]. Implementations must make [save] atomic (a crash leaves the old state or the
 * new one, never a mixture) and durable, and must throw [LocalStateException] instead of returning an empty state
 * when stored state exists but cannot be read.
 */
interface LocalStateStore {
    suspend fun load(): LocalSyncState
    suspend fun save(state: LocalSyncState)

    /**
     * Runs [block] while nothing else in this process loads-modifies-saves the same state: it is a **short**
     * critical section around one read-modify-write of the state and must never contain network I/O. It is not
     * re-entrant. The default does nothing; the file-backed store implements it with a per-path mutex. Exclusion
     * from *other processes* is not part of it: `VaultSession` holds an OS-level lock on the directory for its
     * whole lifetime (see `FileLocalStateStore.lockDirectory`).
     */
    suspend fun <T> exclusive(block: suspend () -> T): T = block()
}

/**
 * How the engine sees the caller's live local content, so that network I/O can run on a snapshot without blocking
 * edits. At commit time (inside [LocalStateStore.exclusive]) the engine asks for the content as it is **now**; if
 * edits were made since the snapshot it commits the join of the synced result and those edits and reports
 * [SyncResult.localEditsPending]. `VaultSession` implements this over its content flow.
 */
interface LocalView {
    /** The content as it is now, including every committed edit. */
    suspend fun current(): VaultContent

    /** The content that was just committed as the local vault (called inside the state section). */
    fun committed(content: VaultContent)
}

/**
 * Keeps the state in memory only. **Tests only**: it is `internal` so production code cannot use it, because the
 * rollback floors would silently vanish with the process.
 */
internal class InMemoryLocalStateStore(initial: LocalSyncState = LocalSyncState()) : LocalStateStore {
    private var state: LocalSyncState = initial

    override suspend fun load(): LocalSyncState = state

    override suspend fun save(state: LocalSyncState) {
        this.state = state
    }
}
