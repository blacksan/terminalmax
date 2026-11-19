// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.feature.app

import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import org.terminalmax.core.sync.FailureReason
import org.terminalmax.core.sync.PendingResolution
import org.terminalmax.core.sync.RemoteAuthException
import org.terminalmax.core.sync.RemoteIoException
import org.terminalmax.core.sync.RemoteStore
import org.terminalmax.core.sync.SyncOptions
import org.terminalmax.core.sync.SyncOutcome
import org.terminalmax.core.sync.SyncResult
import org.terminalmax.core.sync.SyncWarning
import org.terminalmax.core.sync.VaultSession
import org.terminalmax.core.sync.WebDavStore
import org.terminalmax.core.vault.RecordType
import org.terminalmax.core.vault.VaultContent

/** WebDAV connection details, stored as a Settings record in the vault. */
data class SyncConfig(val url: String = "", val username: String = "", val password: String = "") {
    val isComplete: Boolean get() = url.isNotBlank() && username.isNotBlank()
    override fun toString(): String = "SyncConfig(url=$url)"
}

internal const val SYNC_SETTINGS_ID = "settings-webdav"

internal fun VaultContent.syncConfig(): SyncConfig? {
    val record = records.firstOrNull { it.id == SYNC_SETTINGS_ID && it.type == RecordType.Settings && !it.deleted } ?: return null
    fun field(name: String): String = runCatching { record.payload[name]?.jsonPrimitive?.contentOrNull }.getOrNull().orEmpty()
    return SyncConfig(field("url"), field("username"), field("password"))
}

enum class MessageKind { Info, Success, Warning, Error }

data class SyncMessage(val kind: MessageKind, val text: String)

/**
 * A sync outcome that needs a decision from the user. Each is answered with exactly one retry carrying the one
 * documented recovery option (never persisted); see the UI obligations in the sync module README.
 */
sealed interface SyncDecision {
    data class LargeRemoteChange(val changed: Int, val deleted: Int, val added: Int, val knownHostsChanged: Int) : SyncDecision

    /** The server holds an older revision than this device has seen. */
    data object Rollback : SyncDecision

    /** The file is gone from the server although this device synced it before. */
    data object RemoteMissing : SyncDecision

    data object RevisionJump : SyncDecision

    /** The vault was re-keyed (password changed elsewhere): the password is needed. */
    data class Reopen(val warnings: List<String>, val unverifiedChain: Boolean) : SyncDecision

    /** A competing key at the same epoch: compare [fingerprint] with another device, then give the password. */
    data class CompetingKey(val fingerprint: String) : SyncDecision

    /** Replace the server copy with this device's copy (costly, irreversible). */
    data class ReplaceRemote(val reason: String, val remoteDigest: String?, val changeCredentialAdvice: Boolean) : SyncDecision

    /** An unpublished password change exists on this device. */
    data object PendingPasswordChange : SyncDecision

    /** Warnings that must be shown and acknowledged. */
    data class Acknowledge(val lines: List<String>, val chainUnverified: Boolean, val passwordChangeNotPublished: Boolean) : SyncDecision
}

data class SyncUiState(
    val busy: Boolean = false,
    val config: SyncConfig = SyncConfig(),
    val testMessage: SyncMessage? = null,
    val lastResult: SyncMessage? = null,
    val details: List<String> = emptyList(),
    val decision: SyncDecision? = null,
)

/** WebDAV settings, "Test server", "Sync now" and the dialogs for the outcomes that need a decision. */
@OptIn(ExperimentalCoroutinesApi::class)
class SyncViewModel(
    private val scope: CoroutineScope,
    private val vault: VaultViewModel,
    private val prefs: AppPrefs,
    private val remoteFactory: (url: String, user: String, password: CharArray) -> RemoteStore =
        { url, user, password -> WebDavStore(url, user, password) },
    private val autoSyncDelayMillis: Long = 10_000L,
) {
    private val mutableState = MutableStateFlow(SyncUiState())
    val state: StateFlow<SyncUiState> get() = mutableState

    private val syncLock = Mutex()

    @Volatile
    private var syncing = false

    init {
        scope.launch {
            vault.session.collectLatest { s ->
                if (s == null) {
                    mutableState.value = SyncUiState()
                    return@collectLatest
                }
                mutableState.update { it.copy(config = s.content.value.syncConfig() ?: SyncConfig()) }
                if (prefs.autoSync.value && s.content.value.syncConfig()?.isComplete == true) {
                    runSync(auto = true)
                }
                var pending: Job? = null
                s.content.drop(1).collect {
                    if (!prefs.autoSync.value || syncing) return@collect
                    pending?.cancel()
                    pending = scope.launch {
                        delay(autoSyncDelayMillis)
                        if (s.content.value.syncConfig()?.isComplete == true) runSync(auto = true)
                    }
                }
            }
        }
    }

    suspend fun saveConfig(url: String, username: String, password: String): String? {
        val session = vault.session.value ?: return "The vault is locked."
        val cleanUrl = url.trim()
        if (cleanUrl.isNotEmpty()) {
            try {
                remoteFactory(cleanUrl, username.trim().ifEmpty { "-" }, CharArray(0))
            } catch (e: IllegalArgumentException) {
                return e.message ?: "Invalid WebDAV address."
            }
        }
        return try {
            withContext(Dispatchers.Default) {
                session.edit { e ->
                    e.upsert(
                        RecordType.Settings,
                        SYNC_SETTINGS_ID,
                        JsonObject(
                            mapOf(
                                "url" to JsonPrimitive(cleanUrl),
                                "username" to JsonPrimitive(username.trim()),
                                "password" to JsonPrimitive(password),
                            ),
                        ),
                    )
                }
            }
            mutableState.update { it.copy(config = SyncConfig(cleanUrl, username.trim(), password)) }
            null
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            describeVaultError(e)
        }
    }

    fun testServer(): Job = scope.launch(Dispatchers.Default) {
        val cfg = mutableState.value.config
        if (!cfg.isComplete) {
            mutableState.update { it.copy(testMessage = SyncMessage(MessageKind.Warning, "Enter and save the WebDAV address and user name first.")) }
            return@launch
        }
        mutableState.update { it.copy(busy = true, testMessage = null) }
        val message = try {
            val remote = remoteFactory(cfg.url, cfg.username, cfg.password.toCharArray())
            val caps = remote.probe()
            if (caps.supportsConditionalWrites) {
                SyncMessage(MessageKind.Success, "The server works and supports safe conditional writes.")
            } else {
                SyncMessage(
                    MessageKind.Warning,
                    "The server answers, but it does not fully support conditional requests (If-Match). " +
                        "Sync still works, but two devices syncing at the same moment could overwrite each other.",
                )
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: RemoteAuthException) {
            SyncMessage(MessageKind.Error, "The server rejected the user name or password.")
        } catch (e: RemoteIoException) {
            SyncMessage(MessageKind.Error, "Could not use the server: ${e.message ?: "network error"}")
        } catch (e: IllegalArgumentException) {
            SyncMessage(MessageKind.Error, e.message ?: "Invalid WebDAV address.")
        } catch (e: Exception) {
            SyncMessage(MessageKind.Error, "Unexpected error (${e::class.simpleName}).")
        }
        mutableState.update { it.copy(busy = false, testMessage = message) }
    }

    fun syncNow(): Job = scope.launch(Dispatchers.Default) { runSync(auto = false) }

    fun dismissDecision() {
        mutableState.update { it.copy(decision = null) }
    }

    /**
     * The user agreed to the recovery action behind the pending decision. [password] is the vault password where
     * the decision needs it. Each call is one retry with exactly one option.
     */
    fun resolve(password: String? = null): Job = scope.launch(Dispatchers.Default) {
        val decision = mutableState.value.decision ?: return@launch
        mutableState.update { it.copy(decision = null) }
        val pw = password?.toCharArray()
        try {
            when (decision) {
                is SyncDecision.LargeRemoteChange -> runSync(SyncOptions(acceptLargeRemoteChange = true))
                SyncDecision.Rollback -> runSync(SyncOptions(allowRollback = true))
                SyncDecision.RemoteMissing -> runSync(SyncOptions(recreateRemote = true))
                SyncDecision.RevisionJump -> runSync(SyncOptions(acceptRevisionJump = true))
                is SyncDecision.Reopen -> {
                    if (pw == null || pw.isEmpty()) {
                        setResult(MessageKind.Warning, "Enter the vault password to continue.")
                        mutableState.update { it.copy(decision = decision) }
                    } else {
                        runSync(SyncOptions(), reopen = pw)
                    }
                }
                is SyncDecision.CompetingKey -> {
                    if (pw == null || pw.isEmpty()) {
                        setResult(MessageKind.Warning, "Enter the vault password to continue.")
                        mutableState.update { it.copy(decision = decision) }
                    } else {
                        runSync(SyncOptions(adoptCompetingKeyFingerprint = decision.fingerprint), reopen = pw)
                    }
                }
                is SyncDecision.ReplaceRemote -> replaceRemote(decision, pw)
                SyncDecision.PendingPasswordChange -> resolvePending(pw)
                is SyncDecision.Acknowledge -> acknowledge(decision)
            }
        } finally {
            pw?.fill('\u0000')
        }
    }

    /** The sealed local vault file, for the user to keep (it is only as safe as the server copy). */
    fun backupBytes(): ByteArray? = vault.session.value?.exportBackup()

    private fun setResult(kind: MessageKind, text: String, details: List<String> = emptyList()) {
        mutableState.update { it.copy(lastResult = SyncMessage(kind, text), details = details) }
    }

    private fun remoteOrNull(): RemoteStore? {
        val cfg = vault.session.value?.content?.value?.syncConfig()
        if (cfg == null || !cfg.isComplete) {
            setResult(MessageKind.Warning, "Enter and save the WebDAV address and user name in the sync settings first.")
            return null
        }
        return try {
            remoteFactory(cfg.url, cfg.username, cfg.password.toCharArray())
        } catch (e: IllegalArgumentException) {
            setResult(MessageKind.Error, e.message ?: "Invalid WebDAV address.")
            null
        }
    }

    private suspend fun runSync(options: SyncOptions = SyncOptions(), reopen: CharArray? = null, auto: Boolean = false) {
        val session = vault.session.value ?: return
        if (!syncLock.tryLock()) {
            if (!auto) setResult(MessageKind.Info, "A sync is already running.")
            return
        }
        syncing = true
        mutableState.update { it.copy(busy = true) }
        try {
            val remote = remoteOrNull() ?: return
            val result = try {
                session.sync(remote, options, reopen)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                setResult(MessageKind.Error, "Sync failed unexpectedly (${e::class.simpleName}).")
                return
            }
            handle(result)
        } finally {
            syncing = false
            mutableState.update { it.copy(busy = false) }
            syncLock.unlock()
        }
    }

    private fun handle(result: SyncResult) {
        val warnings = warningLines(result.warnings)
        val details = ArrayList<String>(warnings.lines)
        if (result.remoteChanges.changedKnownHostIds.isNotEmpty()) {
            details += "${result.remoteChanges.changedKnownHostIds.size} saved host key(s) were changed by this sync. " +
                "A changed host key can mean that someone is intercepting a connection: check them before you connect."
        }
        if (result.localEditsPending) details += "Edits you made during the sync will go out with the next sync."
        when (val outcome = result.outcome) {
            SyncOutcome.UpToDate -> setResult(MessageKind.Success, "Up to date. Nothing to change.", details)
            SyncOutcome.Pulled -> setResult(MessageKind.Success, "Changes from the server were applied on this device.", details)
            SyncOutcome.Pushed -> setResult(MessageKind.Success, "Your changes were uploaded to the server.", details)
            is SyncOutcome.Merged -> {
                val n = outcome.conflicts.size
                val text = if (n == 0) {
                    "Both sides had changes; they were merged and uploaded."
                } else {
                    "Both sides had changes; they were merged and uploaded. $n entr${if (n == 1) "y was" else "ies were"} edited on two devices at once: the newer version won and the other is kept in the history."
                }
                setResult(if (n == 0) MessageKind.Success else MessageKind.Warning, text, details)
            }
            is SyncOutcome.Failed -> failure(outcome, result, details)
        }
        if (warnings.needsAck && result.outcome !is SyncOutcome.Failed) {
            mutableState.update {
                it.copy(decision = SyncDecision.Acknowledge(warnings.lines, warnings.chainUnverified, warnings.passwordChangeNotPublished))
            }
        }
    }

    private fun failure(outcome: SyncOutcome.Failed, result: SyncResult, details: List<String>) {
        fun decide(decision: SyncDecision, text: String) {
            setResult(MessageKind.Warning, text, details)
            mutableState.update { it.copy(decision = decision) }
        }
        fun error(text: String) = setResult(MessageKind.Error, text, details)
        val digest = result.failureInfo?.remoteDigest
        when (outcome.reason) {
            FailureReason.LargeRemoteChange -> {
                val c = result.remoteChanges
                decide(
                    SyncDecision.LargeRemoteChange(c.changedIds.size, c.deletedIds.size, c.addedIds.size, c.changedKnownHostIds.size),
                    "The server would change or delete many of your entries. Nothing was applied yet.",
                )
            }
            FailureReason.RollbackDetected -> decide(
                SyncDecision.Rollback,
                "The server has an older version of the vault than this device has already seen. It may have been restored from a backup, or the server may be serving old data.",
            )
            FailureReason.RemoteMissing -> decide(
                SyncDecision.RemoteMissing,
                "The vault file is no longer on the server although this device synced it before.",
            )
            FailureReason.SuspiciousRevisionJump -> decide(
                SyncDecision.RevisionJump,
                "The server's vault jumped far ahead of anything this device has seen, which an honest device would not do.",
            )
            FailureReason.ReopenRequired -> {
                val w = warningLines(result.warnings)
                decide(
                    SyncDecision.Reopen(w.lines, w.chainUnverified),
                    "The vault key was changed (the password was changed on another device). Enter the vault password to follow it.",
                )
            }
            FailureReason.KeyMismatchSameEpoch -> {
                val fp = result.failureInfo?.competingKeyFingerprint
                if (fp == null) {
                    error("Another device made a competing vault key at the same time. Sync again later.")
                } else {
                    decide(SyncDecision.CompetingKey(fp), "Two devices changed the vault key at the same time. Compare the key fingerprint with another device before you continue.")
                }
            }
            FailureReason.KeyEpochRollback -> decide(
                SyncDecision.ReplaceRemote("The server holds a vault from before the last password change, for example a restored backup.", digest, false),
                "The server's vault is older than the last password change on this device.",
            )
            FailureReason.HeaderMismatchSameEpoch -> decide(
                SyncDecision.ReplaceRemote("The server's file does not follow the vault format of this key. A device that knows your vault key, or someone with access to the share, wrote it.", digest, true),
                "The server's vault file is not consistent with this device's vault.",
            )
            FailureReason.BadPasswordOrCorrupt -> decide(
                SyncDecision.ReplaceRemote("The server's file cannot be opened with your vault key: it may be damaged, replaced or from a different vault.", digest, true),
                "The vault file on the server cannot be opened with this device's key.",
            )
            FailureReason.InvalidRemoteFile, FailureReason.IntegrityFailure -> decide(
                SyncDecision.ReplaceRemote("The server's file is damaged or not a vault.", digest, false),
                "The file on the server is damaged or is not a vault.",
            )
            FailureReason.PendingRotationUnpublished, FailureReason.PendingRotationHoldsNewerEdits -> decide(
                SyncDecision.PendingPasswordChange,
                "A password change started on this device never reached the server. The OLD password is still the live one until it is published.",
            )
            FailureReason.RemoteRekeyedElsewhere ->
                error("The password was changed on another device. Use the new password.")
            FailureReason.DifferentVault ->
                error("The server holds a different vault than this device. Check the WebDAV address.")
            FailureReason.UnsupportedVersion -> error("The server's vault was written by a newer version of the app. Update the app.")
            FailureReason.Network -> error("Could not reach the server. Check the network and the address. ${outcome.detail.orEmpty()}".trim())
            FailureReason.AuthFailed -> error("The server rejected the user name or password.")
            FailureReason.Locked -> error("Another device is syncing right now. Try again in a minute.")
            FailureReason.TooManyAttempts -> error("Other devices kept changing the vault during the sync. Try again.")
            FailureReason.ServerRejected -> error("The server refused the upload. ${outcome.detail.orEmpty()}".trim())
            FailureReason.RemoteKdfTooHeavyForDevice ->
                error("The vault now needs more memory to unlock than this device allows (the password was changed on a bigger machine). Use a bigger device.")
            FailureReason.KeyEpochLimitReached -> error("The vault key has been changed too many times. A new vault must be created.")
            FailureReason.InvalidLocalContent -> error("This device's vault content is invalid; nothing was sent.")
            FailureReason.LocalStateUnavailable -> error("The sync state on this device cannot be read or written. Nothing was synced.")
            FailureReason.SessionClosed -> error("The vault is locked.")
            FailureReason.HeaderChangedRemotely, FailureReason.RemoteChangedDuringRotation ->
                error("Another device changed the vault meanwhile. Sync again.")
            else -> error("Sync failed (${outcome.reason}). ${outcome.detail.orEmpty()}".trim())
        }
    }

    private suspend fun replaceRemote(d: SyncDecision.ReplaceRemote, pw: CharArray?) {
        val session = vault.session.value ?: return
        if (pw == null || pw.isEmpty()) {
            setResult(MessageKind.Warning, "Enter the vault password to replace the server copy.")
            mutableState.update { it.copy(decision = d) }
            return
        }
        val remote = remoteOrNull() ?: return
        mutableState.update { it.copy(busy = true) }
        try {
            val r = session.replaceRemoteWithLocal(remote, pw, confirm = true, expectedRemoteDigest = d.remoteDigest)
            if (r.replaced) {
                setResult(
                    MessageKind.Success,
                    "The server copy was replaced by this device's vault. Other devices must enter the vault password to follow.",
                    warningLines(r.sync.warnings).lines,
                )
            } else {
                handle(r.sync)
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            setResult(MessageKind.Error, describeVaultError(e))
        } finally {
            mutableState.update { it.copy(busy = false) }
        }
    }

    private suspend fun resolvePending(pw: CharArray?) {
        val session = vault.session.value ?: return
        if (pw == null || pw.isEmpty()) {
            setResult(MessageKind.Warning, "Enter the password of the pending password change.")
            mutableState.update { it.copy(decision = SyncDecision.PendingPasswordChange) }
            return
        }
        val remote = remoteOrNull() ?: return
        mutableState.update { it.copy(busy = true) }
        try {
            val r = session.resolvePendingPasswordChange(remote, pw)
            when (r.resolution) {
                PendingResolution.NothingPending -> setResult(MessageKind.Info, "There was no unfinished password change.")
                PendingResolution.AlreadyPublished -> setResult(MessageKind.Success, "The password change was already on the server. The new password is live.")
                PendingResolution.Published -> setResult(MessageKind.Success, "The password change was published. The new password is live.")
                PendingResolution.Abandoned -> setResult(MessageKind.Warning, "The password change never reached the server and was dropped. The OLD password is still the live one.")
                PendingResolution.Unresolved -> handle(r.sync)
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            setResult(MessageKind.Error, describeVaultError(e))
        } finally {
            mutableState.update { it.copy(busy = false) }
        }
    }

    private suspend fun acknowledge(d: SyncDecision.Acknowledge) {
        val session = vault.session.value ?: return
        try {
            if (d.chainUnverified) session.acknowledgeKeyEpochWarning()
            if (d.passwordChangeNotPublished) session.acknowledgePasswordChangeWarning()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            setResult(MessageKind.Error, describeVaultError(e))
        }
    }

    private class Warnings(val lines: List<String>, val chainUnverified: Boolean, val passwordChangeNotPublished: Boolean) {
        val needsAck: Boolean get() = chainUnverified || passwordChangeNotPublished
    }

    private fun warningLines(warnings: List<SyncWarning>): Warnings {
        val lines = ArrayList<String>()
        var chain = false
        var notPublished = false
        for (w in warnings) {
            when (w) {
                is SyncWarning.FirstUseTrust -> lines +=
                    "First sync on this device: it accepted the server's vault at revision ${w.remoteRevision}. This is only as trustworthy as the server; compare the revision with another of your devices."
                is SyncWarning.StaleRemoteIgnored -> lines +=
                    "The server offered older versions of ${w.recordIds.size} entr${if (w.recordIds.size == 1) "y" else "ies"} that this device had already seen. They were ignored. A server that does this repeatedly may be replaying old data."
                is SyncWarning.KeyEpochChainUnverified -> {
                    chain = true
                    lines += "The vault key was changed by a device this one cannot verify. Check on another device of yours that you changed the password there, before you rely on this vault."
                }
                is SyncWarning.ForkSuspected -> lines += "The server showed two different files for the same revision (${w.revision}). It may have forked the vault's history."
                is SyncWarning.ConcurrentRekeyAdopted -> lines += "Two password changes happened at once; this device followed one of them. Check the vault and change the password if unsure."
                is SyncWarning.PasswordUnchangedByRekey -> lines += "The vault key was changed but the password stayed the same as before. A real password change never does that. Check the vault and change the password."
                is SyncWarning.RemoteRecreated -> lines += "The vault file was missing and was re-created from this device's copy."
                is SyncWarning.RemoteReplaced -> lines += "The server copy was replaced by this device's vault. Other devices need the vault password to follow."
                is SyncWarning.RevisionJumpAccepted -> lines += "A large revision jump from the server was accepted at your request."
                is SyncWarning.LocalContentWasStale -> lines += "This device's copy was older than what it had synced before and was repaired."
                is SyncWarning.PasswordChangeNotPublished -> {
                    notPublished = true
                    lines += "Your password change did NOT happen: it never reached the server. The old password is still the live one."
                }
                is SyncWarning.LargeRemoteChangeAccepted -> lines += "A large change from the server was accepted at your request: ${w.changed} entries changed and ${w.deleted} deleted. Deleted entries can be restored for a while."
                else -> lines += "The sync reported a notice that this version cannot describe."
            }
        }
        return Warnings(lines, chain, notPublished)
    }
}
