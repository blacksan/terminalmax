// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.feature.app

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.launch

@Composable
fun HostListScreen(container: AppContainer) {
    val vm = container.hosts
    val hosts by vm.hosts.collectAsStateWithLifecycle()
    val all by vm.allHosts.collectAsStateWithLifecycle()
    var query by remember { mutableStateOf(vm.query.value) }
    var toDelete by remember { mutableStateOf<HostItem?>(null) }
    var deleteError by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    ScreenScaffold(
        title = "Hosts",
        floatingActionButton = {
            FloatingActionButton(onClick = { container.navigator.push(Screen.HostEditor(null)) }) {
                Text("Add host", Modifier.padding(horizontal = 20.dp))
            }
        },
    ) {
        Column(Modifier.fillMaxSize()) {
            if (all.isNotEmpty()) {
                TextInput(
                    value = query,
                    onValueChange = { query = it; vm.setQuery(it) },
                    label = "Search hosts",
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                )
            }
            deleteError?.let { ErrorCard(it, Modifier.padding(16.dp)) }
            when {
                all.isEmpty() -> EmptyState(
                    "No hosts yet",
                    "Tap Add host to save your first router or server. Add a WireGuard profile first if it is only reachable through a tunnel.",
                )
                hosts.isEmpty() -> EmptyState("No match", "No host matches \"$query\".")
                else -> LazyColumn(Modifier.fillMaxSize()) {
                    items(hosts, key = { it.id }) { host ->
                        HostRow(
                            host = host,
                            onOpen = {
                                val session = container.sessions.open(host)
                                container.navigator.push(Screen.Terminal(session.id))
                            },
                            onEdit = { container.navigator.push(Screen.HostEditor(host.id)) },
                            onDelete = { toDelete = host },
                        )
                        HorizontalDivider()
                    }
                    item { Column(Modifier.padding(bottom = 88.dp)) {} }
                }
            }
        }
    }

    toDelete?.let { host ->
        ConfirmDialog(
            title = "Delete ${host.label}?",
            text = "The host and its saved login are removed from the vault and, after the next sync, from your other devices. Saved host keys stay.",
            confirmLabel = "Delete",
            onConfirm = {
                toDelete = null
                scope.launch { deleteError = vm.deleteHost(host.id) }
            },
            onDismiss = { toDelete = null },
        )
    }
}

@Composable
private fun HostRow(host: HostItem, onOpen: () -> Unit, onEdit: () -> Unit, onDelete: () -> Unit) {
    ListItem(
        modifier = Modifier.clickable(onClick = onOpen),
        headlineContent = { Text(host.label) },
        supportingContent = {
            val tags = buildList {
                if (host.wireGuardProfileId != null) add("WireGuard")
                if (host.legacy) add("Legacy crypto")
            }
            Text(host.subtitle + if (tags.isEmpty()) "" else "  •  " + tags.joinToString(", "))
        },
        trailingContent = {
            Row {
                TextButton(onClick = onEdit) { Text("Edit") }
                TextButton(onClick = onDelete) { Text("Delete") }
            }
        },
    )
}

@Composable
fun HostEditorScreen(container: AppContainer, hostId: String?) {
    val vm = container.hosts
    val profiles by vm.profiles.collectAsStateWithLifecycle()
    var draft by remember(hostId) { mutableStateOf(vm.loadDraft(hostId)) }
    var errors by remember { mutableStateOf<Map<HostField, String>>(emptyMap()) }
    var message by remember { mutableStateOf<String?>(null) }
    var saving by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    fun save() {
        if (saving) return
        saving = true
        scope.launch {
            val result = vm.saveHost(draft)
            saving = false
            errors = result.fieldErrors
            message = result.messages.firstOrNull()
            if (result.ok) container.navigator.pop()
        }
    }

    ScreenScaffold(
        title = if (hostId == null) "Add host" else "Edit host",
        onBack = { container.navigator.pop() },
        actions = { TextButton(onClick = { save() }, enabled = !saving) { Text("Save") } },
    ) {
        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            message?.let { ErrorCard(it) }
            TextInput(draft.label, { draft = draft.copy(label = it) }, "Name", error = errors[HostField.Label])

            Text("WireGuard", style = MaterialTheme.typography.titleSmall)
            Row(verticalAlignment = Alignment.CenterVertically) {
                RadioButton(selected = draft.wireGuardProfileId == null, onClick = { draft = draft.copy(wireGuardProfileId = null) })
                Text("No tunnel (direct connection)")
            }
            profiles.forEach { p ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    RadioButton(selected = draft.wireGuardProfileId == p.id, onClick = { draft = draft.copy(wireGuardProfileId = p.id) })
                    Text("Through ${p.label}")
                }
            }
            if (profiles.isEmpty()) {
                Text(
                    "To reach a host through a tunnel, import a WireGuard profile first (WireGuard tab).",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            TextInput(
                draft.address,
                { draft = draft.copy(address = it) },
                if (draft.wireGuardProfileId != null) "IP address inside the tunnel" else "Host name or IP address",
                error = errors[HostField.Address],
                supporting = if (draft.wireGuardProfileId != null) "Must be an IP address, for example 192.168.88.1" else null,
                keyboardType = KeyboardType.Uri,
            )
            TextInput(draft.port, { draft = draft.copy(port = it.filter { c -> c.isDigit() }.take(5)) }, "Port", error = errors[HostField.Port], keyboardType = KeyboardType.Number)
            TextInput(draft.username, { draft = draft.copy(username = it) }, "User name", error = errors[HostField.Username])

            Text("Login", style = MaterialTheme.typography.titleSmall)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(selected = draft.auth == AuthKind.Password, onClick = { draft = draft.copy(auth = AuthKind.Password) }, label = { Text("Password") })
                FilterChip(selected = draft.auth == AuthKind.Key, onClick = { draft = draft.copy(auth = AuthKind.Key) }, label = { Text("Private key") })
            }
            if (draft.auth == AuthKind.Password) {
                SecretField(
                    draft.password,
                    { draft = draft.copy(password = it) },
                    "Password",
                    error = errors[HostField.Password],
                    supporting = when {
                        draft.hasStoredPassword -> "A password is stored. Leave empty to keep it."
                        else -> "Leave empty for an account without a password (RouterOS admin default)."
                    },
                )
            } else {
                TextInput(
                    draft.privateKeyPem,
                    { draft = draft.copy(privateKeyPem = it) },
                    "Private key (paste the whole OpenSSH or PEM text)",
                    error = errors[HostField.Key],
                    supporting = if (draft.hasStoredKey) "A key is stored. Leave empty to keep it." else null,
                    singleLine = false,
                    minLines = 4,
                )
                SecretField(draft.passphrase, { draft = draft.copy(passphrase = it) }, "Key passphrase (if the key has one)")
            }

            Text("SSH algorithms", style = MaterialTheme.typography.titleSmall)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(selected = !draft.legacy, onClick = { draft = draft.copy(legacy = false) }, label = { Text("Modern") })
                FilterChip(selected = draft.legacy, onClick = { draft = draft.copy(legacy = true) }, label = { Text("Legacy") })
            }
            if (draft.legacy) {
                WarningCard(
                    "Legacy also offers old, weak algorithms (SHA-1 key exchange, CBC and 3DES ciphers, ssh-rsa and ssh-dss host keys) " +
                        "that some old routers still need. Connections that use them can be broken by an attacker on the network path. " +
                        "Use Legacy only for a device that cannot do better, and prefer a WireGuard tunnel.",
                )
            } else {
                Text(
                    "Modern is the safe default. If a very old router fails with \"no common algorithms\", switch this host to Legacy. The app never falls back by itself.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            TextInput(
                draft.consoleOptions,
                { draft = draft.copy(consoleOptions = it) },
                "RouterOS console options (optional)",
                error = errors[HostField.Options],
                supporting = "Added to the user name, for example +ct80w for a plain terminal of 80 columns.",
            )

            Button(onClick = { save() }, enabled = !saving, modifier = Modifier.fillMaxWidth()) { Text("Save host") }
        }
    }
}
