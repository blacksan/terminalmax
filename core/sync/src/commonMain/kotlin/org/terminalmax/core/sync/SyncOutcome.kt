// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.sync

import org.terminalmax.core.vault.Conflict
import org.terminalmax.core.vault.VaultContent

enum class FailureReason {
    /** The remote revision is lower than the highest this device has seen for the vault. */
    RollbackDetected,
    DifferentVault,
    UnsupportedVersion,

    /** Wrong data key, or the remote file was modified or is corrupt. */
    BadPasswordOrCorrupt,
    InvalidRemoteFile,
    Network,
    AuthFailed,

    /** Another device holds the lock lease. */
    Locked,

    /** Lost the race repeatedly (concurrent writers) and ran out of attempts. */
    TooManyAttempts,
    ServerRejected,
}

sealed class SyncOutcome {
    /** Local and remote already agreed. */
    data object UpToDate : SyncOutcome()

    /** Remote changes were applied locally; nothing needed uploading. */
    data object Pulled : SyncOutcome()

    /** Local changes were uploaded; nothing needed applying locally. */
    data object Pushed : SyncOutcome()

    /** Both sides had changes (possibly with [conflicts]); the merged result was uploaded. */
    data class Merged(val conflicts: List<Conflict>) : SyncOutcome()

    data class Failed(val reason: FailureReason, val detail: String? = null) : SyncOutcome()
}

/** [content] is what the caller should now treat as its local vault content (unchanged on failure). */
data class SyncResult(val outcome: SyncOutcome, val content: VaultContent)

data class SyncOptions(
    /** Accept a remote whose revision is lower than the highest seen (explicit user override). */
    val allowRollback: Boolean = false,
    /** Ignore cached server capabilities and probe again. */
    val reprobe: Boolean = false,
)
