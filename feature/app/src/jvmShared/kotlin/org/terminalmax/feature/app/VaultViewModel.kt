// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.feature.app

import java.io.File
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import org.terminalmax.core.sync.FileLocalStateStore
import org.terminalmax.core.sync.JoinPreview
import org.terminalmax.core.sync.RemoteAuthException
import org.terminalmax.core.sync.RemoteIoException
import org.terminalmax.core.sync.RemoteStore
import org.terminalmax.core.sync.VaultSession
import org.terminalmax.core.sync.VaultSessionException
import org.terminalmax.core.sync.WebDavStore
import org.terminalmax.core.vault.KdfParams
import org.terminalmax.core.vault.VaultException

enum class VaultPhase { NoVault, Locked, Unlocked }

/** What the user must compare with another device before a join is confirmed. */
data class JoinPreviewUi(
    val fingerprint: String,
    val revision: Long,
    val keyEpoch: Long,
    val recordCounts: Map<String, Int>,
)

data class VaultUiState(
    val phase: VaultPhase,
    val busy: Boolean = false,
    val error: String? = null,
    val joinPreview: JoinPreviewUi? = null,
)

/** Creates, joins, unlocks and locks the vault. Holds the one [VaultSession] of the process. */
class VaultViewModel(
    private val scope: CoroutineScope,
    private val directory: File,
    private val kdf: KdfParams = KdfParams.Default,
    private val remoteFactory: (url: String, user: String, password: CharArray) -> RemoteStore =
        { url, user, password -> WebDavStore(url, user, password) },
    private val onLocked: () -> Unit = {},
    private val onUnlocked: () -> Unit = {},
) {
    private val mutableState = MutableStateFlow(VaultUiState(if (vaultExists()) VaultPhase.Locked else VaultPhase.NoVault))
    private val mutableSession = MutableStateFlow<VaultSession?>(null)
    private var preview: JoinPreview? = null

    val state: StateFlow<VaultUiState> get() = mutableState

    /** The open session, or null while the vault is locked. */
    val session: StateFlow<VaultSession?> get() = mutableSession

    private fun vaultExists(): Boolean {
        val name = FileLocalStateStore.DEFAULT_FILE_NAME
        return File(directory, name).exists() || File(directory, "$name.prev").exists()
    }

    private fun begin(): Boolean {
        var started = false
        mutableState.update {
            if (it.busy) {
                it
            } else {
                started = true
                it.copy(busy = true, error = null)
            }
        }
        return started
    }

    private fun fail(message: String) {
        mutableState.update { it.copy(busy = false, error = message) }
    }

    private fun opened(session: VaultSession) {
        mutableSession.value = session
        mutableState.value = VaultUiState(VaultPhase.Unlocked)
        onUnlocked()
    }

    fun create(password: String, confirm: String): Job? {
        if (password.length < MIN_VAULT_PASSWORD) {
            fail("The password needs at least $MIN_VAULT_PASSWORD characters.")
            return null
        }
        if (password != confirm) {
            fail("The two passwords are not the same.")
            return null
        }
        if (!begin()) return null
        return scope.launch(Dispatchers.Default) {
            val chars = password.toCharArray()
            try {
                opened(VaultSession.create(directory, chars, kdf))
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                fail(describeVaultError(e))
            } finally {
                chars.fill('\u0000')
            }
        }
    }

    fun unlock(password: String): Job? {
        if (password.isEmpty()) {
            fail("Enter the vault password.")
            return null
        }
        if (!begin()) return null
        return scope.launch(Dispatchers.Default) {
            val chars = password.toCharArray()
            try {
                opened(VaultSession.open(directory, chars))
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                fail(describeVaultError(e))
            } finally {
                chars.fill('\u0000')
            }
        }
    }

    /** Downloads and opens the remote vault and shows its fingerprint; nothing is saved until [confirmJoin]. */
    fun startJoin(url: String, user: String, davPassword: String, vaultPassword: String): Job? {
        if (url.isBlank() || user.isBlank()) {
            fail("Enter the WebDAV address and user name.")
            return null
        }
        if (vaultPassword.isEmpty()) {
            fail("Enter the vault password.")
            return null
        }
        if (!begin()) return null
        return scope.launch(Dispatchers.Default) {
            val dav = davPassword.toCharArray()
            val pw = vaultPassword.toCharArray()
            try {
                val remote = remoteFactory(url.trim(), user.trim(), dav)
                val p = VaultSession.join(directory, remote, pw)
                preview?.close()
                preview = p
                mutableState.update {
                    it.copy(
                        busy = false,
                        joinPreview = JoinPreviewUi(p.fingerprint, p.revision, p.keyEpoch, p.recordCounts),
                    )
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                fail(describeVaultError(e))
            } finally {
                dav.fill('\u0000')
                pw.fill('\u0000')
            }
        }
    }

    /** The user compared fingerprint and revision with another device and agrees. */
    fun confirmJoin(): Job? {
        val p = preview ?: return null
        if (!begin()) return null
        return scope.launch(Dispatchers.Default) {
            try {
                val session = p.confirm()
                preview = null
                opened(session)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                p.close()
                preview = null
                mutableState.update { it.copy(joinPreview = null) }
                fail(describeVaultError(e))
            }
        }
    }

    fun cancelJoin() {
        preview?.close()
        preview = null
        mutableState.update { it.copy(joinPreview = null, busy = false, error = null) }
    }

    fun clearError() {
        mutableState.update { it.copy(error = null) }
    }

    /** Closes the session (the directory lock is released) and returns to the unlock screen. */
    fun lock() {
        val s = mutableSession.value ?: return
        onLocked()
        mutableSession.value = null
        runCatching { s.close() }
        mutableState.value = VaultUiState(VaultPhase.Locked)
    }
}

internal fun describeVaultError(e: Throwable): String = when (e) {
    is VaultException.BadPasswordOrCorrupt -> "Wrong password, or the vault file is damaged."
    is VaultException.KdfCostTooHigh -> "This vault needs more memory to unlock than this device allows."
    is VaultException.UnsupportedVersion -> "This vault was written by a newer version of the app. Update the app."
    is VaultException.IntegrityFailure -> "The vault failed its integrity check. The password is right but the data was changed."
    is VaultException -> "The vault file cannot be used: ${e.message}"
    is VaultSessionException.DirectoryInUse -> "The vault is already open in another window or process."
    is VaultSessionException.StateUnreadable -> "The vault's local state file is damaged. It was not changed or deleted."
    is VaultSessionException.RemoteHasNoVault -> "The server holds no TerminalMax vault. Create one on another device and sync it first."
    is VaultSessionException.DirectoryHoldsVault -> "This device already has a vault."
    is VaultSessionException.NoVault -> "There is no vault on this device."
    is RemoteAuthException -> "The server rejected the user name or password."
    is RemoteIoException -> "Could not use the server: ${e.message ?: "network error"}"
    is IllegalArgumentException -> e.message ?: "Invalid input."
    else -> "Unexpected error (${e::class.simpleName})."
}
