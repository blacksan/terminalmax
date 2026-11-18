// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.sync

import org.terminalmax.core.vault.VaultContent

/**
 * What a device remembers between syncs.
 *
 * @property baseContent the content as of the last successful sync (the three-way merge base)
 * @property lastEtag ETag of the remote file as of the last successful sync
 * @property highestRevisionSeen per vault id, the highest revision ever observed remotely or written by this device
 */
data class LocalSyncState(
    val baseContent: VaultContent? = null,
    val lastEtag: String? = null,
    val highestRevisionSeen: Map<String, Long> = emptyMap(),
    val capabilities: ServerCapabilities? = null,
)

/** Persistence for [LocalSyncState]. A file-backed implementation is not part of this module yet. */
interface LocalStateStore {
    suspend fun load(): LocalSyncState
    suspend fun save(state: LocalSyncState)
}

class InMemoryLocalStateStore(initial: LocalSyncState = LocalSyncState()) : LocalStateStore {
    private var state: LocalSyncState = initial

    override suspend fun load(): LocalSyncState = state

    override suspend fun save(state: LocalSyncState) {
        this.state = state
    }
}
