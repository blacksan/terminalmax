// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.sync

import java.io.File
import java.security.SecureRandom
import kotlin.random.Random
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.terminalmax.core.vault.KdfParams
import org.terminalmax.core.vault.OpenVault
import org.terminalmax.core.vault.VaultCodec
import org.terminalmax.core.vault.VaultContent
import org.terminalmax.core.vault.VaultEditor

/**
 * Knobs of a [VaultSession] that tests (and only tests) change. The defaults are the production values.
 */
class SessionTuning(
    val clock: () -> Long = ::systemClockMillis,
    val random: Random = Random.Default,
    val sleep: suspend (Long) -> Unit = { delay(it) },
    val maxAttempts: Int = 5,
    val leaseMillis: Long = SyncEngine.DEFAULT_LEASE_MILLIS,
    val requestBudgetMillis: Long = SyncEngine.DEFAULT_REQUEST_BUDGET_MILLIS,
    val probeMaxAgeMillis: Long = SyncEngine.DEFAULT_PROBE_MAX_AGE_MILLIS,
)

/**
 * One local vault on this device, with everything needed to use it correctly and nothing that can be misused.
 * It owns:
 *  - **local persistence**: the sealed local vault file and the sync state (floors, base, digests) live in one
 *    file in [dir] that is replaced atomically (temp file, `fsync`, atomic rename, directory `fsync`), so a crash
 *    leaves the old pair or the new pair and never a mixture; every edit and every sync result is committed there
 *    before it is published in [content];
 *  - **the data key**, held in memory while the session is open; superseded keys (after a password change or a
 *    re-key adopted from another device) are zeroed by the session, not by the caller;
 *  - **serialisation**: [edit], [sync] and [changePassword] run under one mutex, so an edit can never be
 *    overwritten by a running sync and a sync always starts from the latest edit. An edit made while a sync is in
 *    flight waits for it. One session per directory per process; another process using the same directory is
 *    serialised by a file lock during each operation, but its edits are not merged into this session's [content].
 *
 * The master password is never stored. Per-device convenience unlock (biometrics, OS keychain) uses
 * [exportLocalUnlockSecret] and [openWithLocalUnlockSecret]; the secret is the data key itself and belongs in
 * platform secure storage only (see [OpenVault.exportLocalUnlockSecret]). **Revoking a device is changing the vault
 * password**: that replaces the data key, so a device's local secret stops working and anything it wrote after the
 * change is refused. It protects what is written afterwards; it cannot recall what a device already read.
 */
class VaultSession private constructor(
    private val localStore: FileLocalStateStore,
    private val vaultId: String,
    private val hooks: OpenVaultCodecHooks,
    private val deviceId: String,
    private val tuning: SessionTuning,
    initial: VaultContent,
) : AutoCloseable {
    private val mutex = Mutex()
    private val state = MutableStateFlow(initial)

    @Volatile
    private var closed = false

    /** The current local vault content. Updated after every committed [edit] and every successful [sync]. */
    val content: StateFlow<VaultContent> get() = state

    /** Id of the vault (stable for its lifetime). */
    val id: String get() = vaultId

    /**
     * Applies [block] to the content and commits the result durably before publishing it in [content]. If [block]
     * throws, nothing changes. Revisions are above everything this device has synced, even if the in-memory content
     * were stale.
     *
     * @throws org.terminalmax.core.vault.VaultException.InvalidContent when the result breaks the content rules
     */
    suspend fun edit(block: (VaultEditor) -> Unit) {
        mutex.withLock {
            check(!closed) { "Session is closed" }
            localStore.exclusive {
                val persisted = localStore.load()
                val vs = persisted.vaults[vaultId] ?: VaultSyncState()
                val editor = VaultEditor(
                    state.value, deviceId, tuning.clock, revisionFloor = vs.highestRevision,
                )
                block(editor)
                val edited = editor.content
                if (edited != state.value) {
                    val sealed = hooks.sealLocal(edited) // validates the content
                    localStore.save(
                        persisted.copy(vaults = persisted.vaults + (vaultId to vs.copy(localFile = sealed))),
                    )
                    state.value = edited
                }
            }
        }
    }

    /**
     * Synchronises with [remote]. See [SyncEngine] for the protocol. On success the merged content is committed
     * together with the new sync state and published in [content]. When the remote vault was re-keyed (a password
     * change on another device) the result is [FailureReason.ReopenRequired] unless [reopenPassword] (the master
     * password, not retained) is given.
     */
    suspend fun sync(
        remote: RemoteStore,
        options: SyncOptions = SyncOptions(),
        reopenPassword: CharArray? = null,
    ): SyncResult = mutex.withLock {
        check(!closed) { "Session is closed" }
        val result = engine(remote).sync(state.value, options, null, reopenPassword)
        if (result.outcome !is SyncOutcome.Failed) state.value = result.content
        result
    }

    /**
     * Changes the master password, which **replaces the data key** (and so revokes every other device until it
     * enters the new password). [old] is verified against the local vault first.
     *
     * With a [remote] this is one transaction: a normal sync runs first (so everything written at the old key epoch
     * is imported and reported), then the re-keyed file is uploaded **only if the remote file is still exactly what
     * that sync left**, and the change is committed locally only after the upload is read back. A crash or a
     * failure before that leaves the old password and epoch intact. If another device changed the vault in the
     * meantime the result is [FailureReason.RemoteChangedDuringRotation] or [FailureReason.HeaderChangedRemotely]:
     * nothing was changed, repeat the call.
     *
     * Without a [remote] it is only allowed for a vault that has never been synced; a synced vault needs its remote
     * (an `IllegalStateException` otherwise), because re-keying only locally would strand the other devices.
     *
     * Revocation is effective once every remaining device has synced at the new epoch: a device that is still at the
     * old epoch can keep writing old-epoch files, and those are only refused by devices that have already seen the
     * new epoch. The vault must hold a single password slot (the only kind a session creates); with two,
     * use `VaultCodec` directly.
     */
    suspend fun changePassword(
        old: CharArray,
        new: CharArray,
        remote: RemoteStore? = null,
        options: SyncOptions = SyncOptions(),
        kdf: KdfParams? = null,
    ): SyncResult = mutex.withLock {
        check(!closed) { "Session is closed" }
        val persisted = localStore.load()
        val vs = persisted.vaults[vaultId] ?: VaultSyncState()
        val localFile = checkNotNull(vs.localFile) { "The session has no local vault file" }
        VaultCodec.open(localFile, old).close() // verifies the old password (throws BadPasswordOrCorrupt)
        if (remote == null) {
            check(!vs.established) { "This vault has been synced: pass its remote so that every device can follow" }
            val staged = hooks.stage { VaultCodec.changePassword(it, new, kdf) }
            try {
                localStore.exclusive {
                    val fresh = localStore.load()
                    val current = fresh.vaults[vaultId] ?: VaultSyncState()
                    val sealed = hooks.sealLocalStaged(state.value, staged)
                    localStore.save(fresh.copy(vaults = fresh.vaults + (vaultId to current.copy(localFile = sealed))))
                    hooks.commitStaged(staged)
                }
            } finally {
                staged.discard() // no-op once committed
            }
            return@withLock SyncResult(SyncOutcome.UpToDate, state.value)
        }
        val engine = engine(remote)
        val pre = engine.sync(state.value, options)
        if (pre.outcome is SyncOutcome.Failed) return@withLock pre
        state.value = pre.content
        val staged = hooks.stage { VaultCodec.changePassword(it, new, kdf) }
        try {
            val result = engine.sync(state.value, options, staged, null)
            val warnings = pre.warnings + result.warnings
            if (result.outcome is SyncOutcome.Failed) return@withLock SyncResult(result.outcome, state.value, warnings)
            state.value = result.content
            val outcome = if (pre.outcome is SyncOutcome.Merged) pre.outcome else result.outcome
            SyncResult(outcome, result.content, warnings)
        } finally {
            staged.discard() // no-op once committed
        }
    }

    /**
     * A per-device convenience-unlock secret for the current data key (see [OpenVault.exportLocalUnlockSecret]).
     * Store it only in platform secure storage and zero the array after use. It stops working after any password
     * change; [openWithLocalUnlockSecret] then fails with `KeyEpochMismatch` and the UI asks for the password.
     */
    fun exportLocalUnlockSecret(): ByteArray = hooks.exportLocalUnlockSecret()

    /** Zeroes the data key held in memory. The session cannot be used afterwards. */
    override fun close() {
        closed = true
        hooks.close()
    }

    private fun engine(remote: RemoteStore) = SyncEngine(
        remote, hooks, localStore, deviceId,
        clock = tuning.clock,
        random = tuning.random,
        sleep = tuning.sleep,
        maxAttempts = tuning.maxAttempts,
        leaseMillis = tuning.leaseMillis,
        requestBudgetMillis = tuning.requestBudgetMillis,
        probeMaxAgeMillis = tuning.probeMaxAgeMillis,
    )

    companion object {
        /**
         * Creates a new vault protected by [password] in [dir] (created if missing).
         *
         * @throws IllegalStateException when [dir] already holds a vault
         * @throws LocalStateException when the directory cannot be used
         */
        suspend fun create(
            dir: File,
            password: CharArray,
            kdf: KdfParams = KdfParams.Default,
            tuning: SessionTuning = SessionTuning(),
        ): VaultSession {
            val localStore = FileLocalStateStore(dir)
            return localStore.exclusive {
                val persisted = localStore.load()
                check(persisted.vaults.isEmpty()) { "This directory already holds a vault" }
                val vault = VaultCodec.create(password, kdf)
                try {
                    val deviceId = persisted.deviceId ?: newDeviceId()
                    val sealed = VaultCodec.seal(vault)
                    localStore.save(
                        persisted.copy(
                            vaults = mapOf(vault.vaultId to VaultSyncState(localFile = sealed)),
                            deviceId = deviceId,
                        ),
                    )
                    VaultSession(localStore, vault.vaultId, OpenVaultCodecHooks(vault), deviceId, tuning, vault.content)
                } finally {
                    vault.close()
                }
            }
        }

        /**
         * Opens the vault in [dir] with the master [password]. [memoryCeilingKiB] is the most memory this device
         * accepts for one key derivation (pass a lower value on small devices).
         *
         * @throws org.terminalmax.core.vault.VaultException.BadPasswordOrCorrupt for a wrong password
         * @throws IllegalStateException when [dir] holds no vault
         */
        suspend fun open(
            dir: File,
            password: CharArray,
            memoryCeilingKiB: Int = KdfParams.PLATFORM_CEILING_KIB,
            tuning: SessionTuning = SessionTuning(),
        ): VaultSession = openWith(dir, tuning) { file -> VaultCodec.open(file, password, null, memoryCeilingKiB) }

        /**
         * Opens the vault in [dir] with a secret from [exportLocalUnlockSecret] (biometrics, OS keychain). The caller
         * zeroes [secret] afterwards.
         *
         * @throws org.terminalmax.core.vault.VaultException.KeyEpochMismatch when the vault has been re-keyed since
         *   the secret was exported: ask for the password and export a new secret
         */
        suspend fun openWithLocalUnlockSecret(
            dir: File,
            secret: ByteArray,
            tuning: SessionTuning = SessionTuning(),
        ): VaultSession = openWith(dir, tuning) { file -> VaultCodec.openWithLocalUnlockSecret(file, secret) }

        private suspend fun openWith(dir: File, tuning: SessionTuning, open: (ByteArray) -> OpenVault): VaultSession {
            val localStore = FileLocalStateStore(dir)
            return localStore.exclusive {
                val persisted = localStore.load()
                val entry = persisted.vaults.entries.singleOrNull { it.value.localFile != null }
                checkNotNull(entry) { "This directory holds no vault" }
                val vault = open(entry.value.localFile!!)
                try {
                    val deviceId = persisted.deviceId ?: newDeviceId().also { localStore.save(persisted.copy(deviceId = it)) }
                    VaultSession(localStore, vault.vaultId, OpenVaultCodecHooks(vault), deviceId, tuning, vault.content)
                } finally {
                    vault.close()
                }
            }
        }

        private fun newDeviceId(): String {
            val bytes = ByteArray(8)
            SecureRandom().nextBytes(bytes)
            return "dev-" + bytes.joinToString("") { "%02x".format(it) }
        }
    }
}
