// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.sync

import org.terminalmax.core.vault.Conflict
import org.terminalmax.core.vault.VaultContent

enum class FailureReason {
    /**
     * The remote file's content revision is lower than the highest this device has already seen (override with
     * [SyncOptions.allowRollback]; the merge still never lets an older record win). A lower **key epoch** is
     * [KeyEpochRollback].
     */
    RollbackDetected,

    /**
     * The remote file is at a lower **key epoch** than this device holds: typically the WebDAV server was restored from
     * a backup made before a password change (or a hostile server serves an old file). Never overridable by a sync
     * option. Recovery: `VaultSession.replaceRemoteWithLocal` after the user confirmed (it publishes this device's
     * current content at a new key epoch above this device's own, never above a number read from the server).
     */
    KeyEpochRollback,
    DifferentVault,
    UnsupportedVersion,

    /**
     * Wrong data key or password, or the remote file was modified or is corrupt. When the remote file is at the same
     * or a higher key epoch and the user's password cannot open it, the recovery action is
     * `VaultSession.replaceRemoteWithLocal` (see the sync README, "Recovery actions").
     */
    BadPasswordOrCorrupt,

    /**
     * A file of the same vault, key epoch and key whose header differs from this device's: written by a holder of
     * the data key who is not following the format (a compromised device or a malicious co-user). Nothing was
     * merged, adopted or uploaded and the local vault is unchanged. Recovery: `VaultSession.replaceRemoteWithLocal`
     * after changing the WebDAV credential (the writer has write access to the share).
     */
    HeaderMismatchSameEpoch,

    /**
     * A file of the same vault and key epoch under **another data key** (two rotations raced, or someone minted a
     * competing epoch). It is **never adopted just because a password opens it**: a holder of an old password could have
     * made it. [SyncResult.failureInfo] carries [FailureInfo.competingKeyFingerprint], the fingerprint of the key
     * that file claims (compare it with the one another device of yours shows). Recoveries, each an explicit user
     * decision: after checking that fingerprint on another device, sync again with the master password and
     * [SyncOptions.adoptCompetingKeyFingerprint] set to the value you were shown; or `VaultSession.replaceRemoteWithLocal`.
     */
    KeyMismatchSameEpoch,

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
     * The remote file uses a **higher** key epoch (the vault key was re-keyed, which happens on every password
     * change). This device needs the master password to continue: call sync again with it. The number in the file's
     * header is not authenticated, so a server can claim this; the password prompt is the only effect, and a file that
     * the password does not open is refused. The result's warnings say whether the re-key is linked to this device's
     * key ([SyncWarning.KeyEpochChainUnverified] when it is not). A file at the *same* epoch under another key is
     * [KeyMismatchSameEpoch], not this.
     */
    ReopenRequired,

    /**
     * The remote file's key derivation asks for more memory than this device allows (a legitimate password change on
     * a bigger machine, or a hostile file). **Not replaceable**: replacing would destroy a good vault because this
     * device is small. Use a device that can derive the key, or raise the session's memory ceiling.
     */
    RemoteKdfTooHeavyForDevice,

    /**
     * `replaceRemoteWithLocal` found that the remote file is the verified successor of this device's key: the password
     * was **changed on another device**, and the password that was typed is the old one (replacing now would re-publish
     * a revoked password). Sync with the new password instead; `overrideLinkedRekey` exists for the rare case that the
     * new password is lost.
     */
    RemoteRekeyedElsewhere,

    /**
     * The key epoch counter is (nearly) used up: a password change or replacement was refused. Recovery:
     * `VaultSession.migrateToNewVault`.
     */
    KeyEpochLimitReached,

    /**
     * The pull would delete or change more records than a sync should accept silently (more than
     * `max(10, 25%)` of this device's live records). Nothing was merged or uploaded. [SyncResult.remoteChanges] lists
     * what would change. Recovery: look at it, then repeat with [SyncOptions.acceptLargeRemoteChange] for that one call;
     * deleted records stay restorable for a while (`VaultSession.restoreFromHistory`).
     */
    LargeRemoteChange,

    /** The session was closed (or is closing); nothing was done. */
    SessionClosed,

    /**
     * A password change was prepared against a header that is no longer the remote one (another device changed the
     * password first). Nothing was uploaded and nothing changed locally; sync, then apply the change
     * again.
     */
    HeaderChangedRemotely,

    /**
     * A password change found that the remote file differs from the last one this device synced (another device
     * wrote content). Nothing was uploaded; the change is refused so that content written at the old key epoch is
     * never imported silently into the new epoch. Run a normal sync (it reports what it imports), then repeat.
     * The same reason is reported by a replacement (`replaceRemoteWithLocal`) or by completing an unpublished password
     * change when the remote file is no longer the file that was judged: nothing was replaced.
     */
    RemoteChangedDuringRotation,

    /**
     * The remote file's content revision is implausibly far above anything this device has seen (more than
     * `MAX_REVISION_JUMP` above its floor, or within `REVISION_HEADROOM` of the revision limit). Such a file could
     * leave the vault permanently un-editable, so it is not merged. A jump of the first kind can be accepted by the
     * user with [SyncOptions.acceptRevisionJump]; one within `REVISION_HEADROOM` of the limit never.
     */
    SuspiciousRevisionJump,

    /**
     * This session was opened with the password of an unpublished password change (the app was stopped between
     * writing the change and uploading it) and the remote file is not at the new key epoch. Nothing was uploaded and
     * the old-epoch local file is **still there** (opening with the old password works). Recovery:
     * `VaultSession.resolvePendingPasswordChange` (publishes the change if the server is still exactly what it was, or
     * reports why it cannot), or open with the OLD password, or `VaultSession.replaceRemoteWithLocal`.
     */
    PendingRotationUnpublished,

    /**
     * This session holds the old key, an unpublished password change exists, and it holds edits that were made in a
     * session opened with the new password. Syncing now would drop them. Recovery:
     * `VaultSession.resolvePendingPasswordChange` with the new password (it re-applies those edits).
     */
    PendingRotationHoldsNewerEdits,

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
    data class FirstUseTrust(val remoteRevision: Long, val keyEpoch: Long) : SyncWarning()

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
     * was re-keyed by a device this one cannot verify. **It is repeated by every sync result until the user
     * acknowledges it** (`VaultSession.acknowledgeKeyEpochWarning`). Note that a *verified* chain only means "made by
     * a holder of the previous key", which includes a stolen local unlock secret: never present it as "trusted".
     */
    data class KeyEpochChainUnverified(val fromEpoch: Long, val toEpoch: Long) : SyncWarning()

    /** A different file than the one seen before exists at this content [revision]: the server forked its history. */
    data class ForkSuspected(val revision: Long) : SyncWarning()

    /**
     * The vault was re-keyed to the **same** key epoch this device held, under another key (two password changes
     * raced, or someone minted a competing epoch), and it was opened with the master password. Only someone who knows
     * the password (or a password the file was made for) could have done this.
     */
    data class ConcurrentRekeyAdopted(val epoch: Long) : SyncWarning()

    /**
     * The password that opened the re-keyed file also opens the key slot this device held before: the "re-key" kept
     * the password. A genuine password change never does. This happens when an old password is typed into a file that
     * somebody who knew it minted. Check the vault, and change the password.
     */
    data class PasswordUnchangedByRekey(val fromEpoch: Long, val toEpoch: Long) : SyncWarning()

    /** The remote file had vanished and was re-created from this device's copy (explicit override). */
    data class RemoteRecreated(val revision: Long) : SyncWarning()

    /**
     * The remote file was **replaced** by this device's copy as a new key epoch (`VaultSession.replaceRemoteWithLocal`).
     * Whatever was on the server at [replacedKeyEpoch] (0 when there was nothing or it could not be read) is gone
     * from the share. Other devices need the password to follow ([FailureReason.ReopenRequired]).
     */
    data class RemoteReplaced(val newKeyEpoch: Long, val replacedKeyEpoch: Long) : SyncWarning()

    /** A remote revision [remoteRevision] far above this device's floor [floor] was accepted by explicit override. */
    data class RevisionJumpAccepted(val remoteRevision: Long, val floor: Long) : SyncWarning()

    /** This device's own copy was older than what it had synced before and was healed from the base. */
    data class LocalContentWasStale(val recordIds: List<String>) : SyncWarning()

    /**
     * A password change that this device had prepared (key epoch [pendingEpoch]) **never reached the server and was
     * dropped**: the old password is still the live one, and the revocation the user wanted did **not** happen. It is
     * repeated by every sync result until acknowledged (`VaultSession.acknowledgePasswordChangeWarning`).
     */
    data class PasswordChangeNotPublished(val pendingEpoch: Long) : SyncWarning()

    /**
     * A remote change larger than the guard allows was accepted by [SyncOptions.acceptLargeRemoteChange]:
     * [changed] records were replaced and [deleted] were deleted. Deleted records can be restored for a while with
     * `VaultSession.restoreFromHistory`.
     */
    data class LargeRemoteChangeAccepted(val changed: Int, val deleted: Int) : SyncWarning()
}

/**
 * What a pull changed in this device's own records, by id (never record data). Only records that this device had
 * live before the sync are counted as [changedIds] / [deletedIds]; [addedIds] are new to it.
 *
 * @property changedKnownHostIds the subset of [changedIds] that are `KnownHost` records: a changed host key is the
 *   signature of a man-in-the-middle set up through the vault, so a UI should show them prominently
 */
data class RemoteChangeSummary(
    val changedIds: List<String> = emptyList(),
    val deletedIds: List<String> = emptyList(),
    val addedIds: List<String> = emptyList(),
    val changedKnownHostIds: List<String> = emptyList(),
    val liveRecordsBefore: Int = 0,
) {
    val isEmpty: Boolean get() = changedIds.isEmpty() && deletedIds.isEmpty() && addedIds.isEmpty()

    companion object {
        val EMPTY = RemoteChangeSummary()
    }
}

/**
 * Structured detail of a failed [SyncResult] (everything is optional).
 *
 * @property remoteDigest SHA-256 (lower-case hex) of the remote file the attempt judged; null when the remote file
 *   did not exist or was never read. `replaceRemoteWithLocal` replaces only a file with exactly this digest.
 * @property competingKeyFingerprint with [FailureReason.KeyMismatchSameEpoch]: the fingerprint of the key the
 *   competing file claims
 * @property published with a failed password change: true when the re-keyed file **did land on the server** and only
 *   the local commit failed (the new password is live; sync again with it)
 */
data class FailureInfo(
    val remoteDigest: String? = null,
    val competingKeyFingerprint: String? = null,
    val published: Boolean = false,
)

/**
 * [content] is what the caller should now treat as its local vault content (unchanged on failure).
 * [warnings] on failure are only those that remain true without a completed sync: the unacknowledged
 * [SyncWarning.KeyEpochChainUnverified] of an adopted re-key, and the chain warning of [FailureReason.ReopenRequired].
 * [localEditsPending] is true when edits were made while the sync was running: they are part of [content], they were
 * not uploaded, and they go out with the next sync. An edit made during the sync whose record the remote had changed
 * meanwhile can lose at commit time: it is then moved to the history and reported as a conflict in
 * [SyncOutcome.Merged] of that same result.
 */
data class SyncResult(
    val outcome: SyncOutcome,
    val content: VaultContent,
    val warnings: List<SyncWarning> = emptyList(),
    val localEditsPending: Boolean = false,
    /** What the pull changed in this device's records (also set when [FailureReason.LargeRemoteChange] refused it). */
    val remoteChanges: RemoteChangeSummary = RemoteChangeSummary.EMPTY,
    /** Extra facts of a failure (see [FailureInfo]); null for a success and for failures that carry none. */
    val failureInfo: FailureInfo? = null,
)

data class SyncOptions(
    /**
     * Accept a remote whose content revision is lower than the highest seen (explicit user override). Safe: the
     * merge never lets an older record replace a newer one. It does not waive the key-epoch floor.
     */
    val allowRollback: Boolean = false,
    /** Ignore the cached probe result and probe again. */
    val reprobe: Boolean = false,
    /**
     * Allow re-creating a remote file that vanished after this device had synced it. Without it the sync fails with
     * [FailureReason.RemoteMissing] and uploads nothing.
     */
    val recreateRemote: Boolean = false,
    /**
     * Accept a remote whose content revision is more than `MAX_REVISION_JUMP` above this device's floor (a user
     * decision after [FailureReason.SuspiciousRevisionJump]). Only that check is waived: a revision within
     * `REVISION_HEADROOM` of the revision limit is never accepted. Reported as [SyncWarning.RevisionJumpAccepted].
     */
    val acceptRevisionJump: Boolean = false,
    /**
     * Accept a pull that deletes or changes more than `max(10, 25%)` of this device's live records (a user decision
     * after [FailureReason.LargeRemoteChange], for that one call). Reported as [SyncWarning.LargeRemoteChangeAccepted].
     */
    val acceptLargeRemoteChange: Boolean = false,
    /**
     * Adopt a competing key at the same key epoch (a user decision after [FailureReason.KeyMismatchSameEpoch]): the
     * fingerprint that was shown to the user. It is honoured only when it equals the fingerprint of the file found, and
     * only together with the master password; it binds the confirmation to what the user actually saw.
     */
    val adoptCompetingKeyFingerprint: String? = null,
)
