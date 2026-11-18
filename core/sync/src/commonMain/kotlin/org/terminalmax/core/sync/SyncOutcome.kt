// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.sync

import org.terminalmax.core.vault.Conflict
import org.terminalmax.core.vault.VaultContent

enum class FailureReason {
    /**
     * The remote file is older than what this device has already seen: a lower content revision (override with
     * [SyncOptions.allowRollback]), or a lower key epoch or slot-set revision (never overridable here).
     */
    RollbackDetected,
    DifferentVault,
    UnsupportedVersion,

    /** Wrong data key, or the remote file was modified or is corrupt. */
    BadPasswordOrCorrupt,

    /** The remote file is authentic for a key but failed its integrity check. */
    IntegrityFailure,
    InvalidRemoteFile,

    /** The local content passed to [SyncEngine.sync] breaks the content rules; nothing was sent. */
    InvalidLocalContent,
    Network,
    AuthFailed,

    /** Another device holds the lock lease. */
    Locked,

    /** Lost the race repeatedly (concurrent writers) and ran out of attempts. */
    TooManyAttempts,
    ServerRejected,

    /**
     * The remote file no longer exists although this device has synced it before. Nothing was uploaded. Retry with
     * [SyncOptions.recreateRemote] to publish this device's copy again (never below the revision already seen).
     */
    RemoteMissing,

    /**
     * The remote file uses a newer data key (the vault key was re-keyed, which happens on every password change).
     * This device needs the master password to continue: call sync again with it. The number in the file's header is
     * not authenticated, so a server can claim this; the password prompt is the only effect, and a file that the
     * password does not open is refused. The result's warnings say whether the re-key is linked to this device's
     * key ([SyncWarning.KeyEpochChainUnverified] when it is not).
     */
    ReopenRequired,

    /**
     * A password change was prepared against a header that is no longer the remote one (another device changed the
     * password or the slot set first). Nothing was uploaded and nothing changed locally; sync, then apply the change
     * again.
     */
    HeaderChangedRemotely,

    /**
     * A password change found that the remote file differs from the last one this device synced (another device
     * wrote content). Nothing was uploaded; the change is refused so that content written at the old key epoch is
     * never imported silently into the new epoch. Run a normal sync (it reports what it imports), then repeat.
     */
    RemoteChangedDuringRotation,

    /**
     * The remote file's content revision is implausibly far above anything this device has seen (more than
     * `MAX_REVISION_JUMP` above its floor, or within `REVISION_HEADROOM` of the revision limit). Such a file could
     * leave the vault permanently un-editable, so it is not merged.
     */
    SuspiciousRevisionJump,

    /** The stored sync state is unreadable or cannot be written. Nothing was synced; the state was not reset. */
    LocalStateUnavailable,

    /** An unexpected error inside the engine; the exception class name is in the detail. */
    Unexpected,
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

/** Things a successful sync wants the user to know about. They never contain record data. */
sealed class SyncWarning {
    /**
     * This device had never synced the vault, so it accepted the remote file on trust: the server could have served
     * an old but authentic copy and nothing local can tell. Show the revision and compare it with another device.
     */
    data class FirstUseTrust(val remoteRevision: Long, val keyEpoch: Long, val headerRevision: Long) : SyncWarning()

    /**
     * The remote carried older versions of these records that this device provably saw before (they are in its
     * history): a replayed file. They were ignored and the newer versions were uploaded again. A hostile server may
     * be behind it. Older versions that this device cannot prove it saw are reported as conflicts instead.
     */
    data class StaleRemoteIgnored(val recordIds: List<String>) : SyncWarning()

    /**
     * The vault was re-keyed (key epoch [toEpoch] > [fromEpoch]) by a device that this one cannot link to its own key:
     * the file is not the direct, correctly chained successor of the epoch this device held. It was opened with the
     * master password, so only someone who knows the password could have made it, but tell the user that the vault
     * was re-keyed by a device this one cannot verify.
     */
    data class KeyEpochChainUnverified(val fromEpoch: Long, val toEpoch: Long) : SyncWarning()

    /** A different file than the one seen before exists at this content [revision]: the server forked its history. */
    data class ForkSuspected(val revision: Long) : SyncWarning()

    /** The remote file had vanished and was re-created from this device's copy (explicit override). */
    data class RemoteRecreated(val revision: Long) : SyncWarning()

    /** This device's own copy was older than what it had synced before and was healed from the base. */
    data class LocalContentWasStale(val recordIds: List<String>) : SyncWarning()
}

/**
 * [content] is what the caller should now treat as its local vault content (unchanged on failure).
 * [warnings] is empty on failure, except that [FailureReason.ReopenRequired] carries the chain warning.
 */
data class SyncResult(
    val outcome: SyncOutcome,
    val content: VaultContent,
    val warnings: List<SyncWarning> = emptyList(),
)

data class SyncOptions(
    /**
     * Accept a remote whose content revision is lower than the highest seen (explicit user override). Safe: the
     * merge never lets an older record replace a newer one. It does not waive key-epoch or slot-set checks.
     */
    val allowRollback: Boolean = false,
    /** Ignore the cached probe result and probe again. */
    val reprobe: Boolean = false,
    /**
     * Allow re-creating a remote file that vanished after this device had synced it. Without it the sync fails with
     * [FailureReason.RemoteMissing] and uploads nothing.
     */
    val recreateRemote: Boolean = false,
)
