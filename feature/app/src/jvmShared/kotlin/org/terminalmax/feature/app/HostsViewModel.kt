// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.feature.app

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.withContext
import org.terminalmax.core.vault.VaultContent

/** Result of a save or import: field errors, or a message for a failure that is not about one field. */
data class SaveResult(
    val fieldErrors: Map<HostField, String> = emptyMap(),
    val messages: List<String> = emptyList(),
) {
    val ok: Boolean get() = fieldErrors.isEmpty() && messages.isEmpty()
}

/** Hosts and WireGuard profiles, read from and written to the open vault. */
@OptIn(ExperimentalCoroutinesApi::class)
class HostsViewModel(private val scope: CoroutineScope, private val vault: VaultViewModel) {
    private val content: Flow<VaultContent?> = vault.session.flatMapLatest { it?.content ?: flowOf(null) }

    private val mutableQuery = MutableStateFlow("")
    val query: StateFlow<String> get() = mutableQuery

    val allHosts: StateFlow<List<HostItem>> = content
        .map { it?.hosts() ?: emptyList() }
        .stateIn(scope, SharingStarted.Eagerly, emptyList())

    /** Hosts filtered by the search text (label, address, user name). */
    val hosts: StateFlow<List<HostItem>> = combine(allHosts, mutableQuery) { list, q ->
        val needle = q.trim().lowercase()
        if (needle.isEmpty()) list else list.filter {
            it.label.lowercase().contains(needle) || it.address.lowercase().contains(needle) ||
                it.username.lowercase().contains(needle)
        }
    }.stateIn(scope, SharingStarted.Eagerly, emptyList())

    val profiles: StateFlow<List<WgProfileItem>> = content
        .map { it?.wireGuardProfiles() ?: emptyList() }
        .stateIn(scope, SharingStarted.Eagerly, emptyList())

    fun setQuery(text: String) {
        mutableQuery.value = text
    }

    fun loadDraft(hostId: String?): HostDraft = vault.session.value?.content?.value?.draftFor(hostId) ?: HostDraft()

    suspend fun saveHost(draft: HostDraft): SaveResult {
        val errors = validateHostDraft(draft)
        if (errors.isNotEmpty()) return SaveResult(fieldErrors = errors)
        val session = vault.session.value ?: return SaveResult(messages = listOf("The vault is locked."))
        return try {
            withContext(Dispatchers.Default) { session.saveHost(draft) }
            SaveResult()
        } catch (e: kotlin.coroutines.cancellation.CancellationException) {
            throw e
        } catch (e: Exception) {
            SaveResult(messages = listOf(describeVaultError(e)))
        }
    }

    suspend fun deleteHost(id: String): String? {
        val session = vault.session.value ?: return "The vault is locked."
        return try {
            withContext(Dispatchers.Default) { session.deleteHost(id) }
            null
        } catch (e: kotlin.coroutines.cancellation.CancellationException) {
            throw e
        } catch (e: Exception) {
            describeVaultError(e)
        }
    }

    /** Validates and stores a pasted wg-quick configuration. The private key is never shown again. */
    suspend fun importProfile(label: String, text: String): SaveResult {
        val trimmed = text.trim()
        val errors = ArrayList<String>()
        if (label.isBlank()) errors += "Give the profile a name."
        when (val v = validateWgConfig(trimmed)) {
            is WgValidation.Invalid -> errors += v.errors
            is WgValidation.Valid -> Unit
        }
        if (errors.isNotEmpty()) return SaveResult(messages = errors)
        val session = vault.session.value ?: return SaveResult(messages = listOf("The vault is locked."))
        return try {
            withContext(Dispatchers.Default) { session.importWireGuardProfile(label.trim(), trimmed + "\n") }
            SaveResult()
        } catch (e: kotlin.coroutines.cancellation.CancellationException) {
            throw e
        } catch (e: Exception) {
            SaveResult(messages = listOf(describeVaultError(e)))
        }
    }

    suspend fun deleteProfile(id: String): String? {
        val session = vault.session.value ?: return "The vault is locked."
        return try {
            withContext(Dispatchers.Default) { session.deleteWireGuardProfile(id) }
            null
        } catch (e: kotlin.coroutines.cancellation.CancellationException) {
            throw e
        } catch (e: Exception) {
            describeVaultError(e)
        }
    }
}
