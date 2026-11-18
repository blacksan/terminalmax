// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.sync

/** The local sync state cannot be read, is corrupt, or cannot be written. Sync fails closed instead of resetting it. */
class LocalStateException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * What a device remembers about one vault between syncs. It holds no secrets: [baseFile] is the encrypted file
 * exactly as it was last synced (the three-way merge base is decrypted from it with the data key when needed) and
 * [localFile] is the sealed local vault. They live in the same on-disk transaction (see `VaultSession`), so the
 * floors, the base and the local content can never diverge after a crash.
 *
 * The "highest" values are floors: a remote file below any of them is a rollback or a replay.
 *
 * @property baseFile the vault file as of the last successful sync, or null
 * @property localFile this device's own sealed vault file (its current local content), or null when the state is
 *   used without a `VaultSession`
 * @property highestRevision highest content revision ever read from or written to the remote
 * @property highestKeyEpoch highest key epoch seen
 * @property highestHeaderRevision highest slot-set revision seen
 * @property fileDigests SHA-256 hex of the files seen, by content revision, newest [MAX_DIGESTS] only; a different
 *   file at an already seen revision is a fork
 */
data class VaultSyncState(
    val baseFile: ByteArray? = null,
    val localFile: ByteArray? = null,
    val highestRevision: Long = 0L,
    val highestKeyEpoch: Long = 0L,
    val highestHeaderRevision: Long = 0L,
    val fileDigests: Map<Long, String> = emptyMap(),
) {
    /** True once this device has synced the vault at least once (so a missing remote file is suspicious). */
    val established: Boolean get() = baseFile != null || highestRevision > 0L

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is VaultSyncState) return false
        return highestRevision == other.highestRevision &&
            highestKeyEpoch == other.highestKeyEpoch &&
            highestHeaderRevision == other.highestHeaderRevision &&
            fileDigests == other.fileDigests &&
            (baseFile?.contentEquals(other.baseFile) ?: (other.baseFile == null)) &&
            (localFile?.contentEquals(other.localFile) ?: (other.localFile == null))
    }

    override fun hashCode(): Int {
        var result = baseFile?.contentHashCode() ?: 0
        result = 31 * result + (localFile?.contentHashCode() ?: 0)
        result = 31 * result + highestRevision.hashCode()
        result = 31 * result + highestKeyEpoch.hashCode()
        result = 31 * result + highestHeaderRevision.hashCode()
        result = 31 * result + fileDigests.hashCode()
        return result
    }

    override fun toString(): String =
        "VaultSyncState(base=${baseFile?.size ?: 0} bytes, revision=$highestRevision, keyEpoch=$highestKeyEpoch, " +
            "headerRevision=$highestHeaderRevision, digests=${fileDigests.size})"

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
     * Runs [block] while no other [SyncEngine] (in this or another process) uses the same state. The default does
     * nothing; the file-backed store implements it with a file lock.
     */
    suspend fun <T> exclusive(block: suspend () -> T): T = block()
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
