// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.feature.app

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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.launch

@Composable
fun WireGuardScreen(container: AppContainer) {
    val vm = container.hosts
    val profiles by vm.profiles.collectAsStateWithLifecycle()
    var importing by remember { mutableStateOf(false) }
    var toDelete by remember { mutableStateOf<WgProfileItem?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    ScreenScaffold(
        title = "WireGuard",
        floatingActionButton = {
            FloatingActionButton(onClick = { importing = true }) { Text("Import", Modifier.padding(horizontal = 20.dp)) }
        },
    ) {
        Column(Modifier.fillMaxSize()) {
            error?.let { ErrorCard(it, Modifier.padding(16.dp)) }
            if (profiles.isEmpty()) {
                EmptyState(
                    "No WireGuard profiles",
                    "Import a wg-quick configuration (for example a MikroTik client config) to reach hosts that are only available through a tunnel. The tunnel runs inside the app: no VPN permission and no administrator rights.",
                )
            } else {
                LazyColumn(Modifier.fillMaxSize()) {
                    items(profiles, key = { it.id }) { p ->
                        ListItem(
                            headlineContent = { Text(p.label) },
                            supportingContent = {
                                Text("Address ${p.address.ifEmpty { "-" }}, peer ${p.endpoint.ifEmpty { "-" }}. The private key is stored encrypted and is never shown.")
                            },
                            trailingContent = { TextButton(onClick = { toDelete = p }) { Text("Delete") } },
                        )
                        HorizontalDivider()
                    }
                }
            }
        }
    }

    if (importing) {
        ImportProfileDialog(
            container = container,
            onDone = { importing = false },
        )
    }
    toDelete?.let { p ->
        ConfirmDialog(
            title = "Delete ${p.label}?",
            text = "Hosts that use this profile will connect directly instead of through the tunnel until you pick another profile.",
            confirmLabel = "Delete",
            onConfirm = {
                toDelete = null
                scope.launch { error = vm.deleteProfile(p.id) }
            },
            onDismiss = { toDelete = null },
        )
    }
}

@Composable
private fun ImportProfileDialog(container: AppContainer, onDone: () -> Unit) {
    var label by remember { mutableStateOf("") }
    var text by remember { mutableStateOf("") }
    var errors by remember { mutableStateOf<List<String>>(emptyList()) }
    var busy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    AlertDialog(
        onDismissRequest = { if (!busy) onDone() },
        title = { Text("Import WireGuard profile") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "Paste the wg-quick configuration or choose a file. It needs [Interface] with PrivateKey and Address, and a [Peer] with PublicKey, Endpoint and AllowedIPs.",
                    style = MaterialTheme.typography.bodySmall,
                )
                TextInput(label, { label = it }, "Profile name")
                OutlinedButton(
                    onClick = {
                        container.platform.pickTextFile { picked ->
                            if (picked != null) text = picked else errors = listOf("The file could not be read.")
                        }
                    },
                ) { Text("Choose file...") }
                TextInput(
                    text,
                    { text = it },
                    "Configuration",
                    singleLine = false,
                    minLines = 6,
                )
                errors.forEach { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Default) }
            }
        },
        confirmButton = {
            TextButton(
                enabled = !busy,
                onClick = {
                    busy = true
                    scope.launch {
                        val r = container.hosts.importProfile(label, text)
                        busy = false
                        if (r.ok) {
                            text = ""
                            onDone()
                        } else {
                            errors = r.messages
                        }
                    }
                },
            ) { Text("Import") }
        },
        dismissButton = { TextButton(onClick = { if (!busy) onDone() }) { Text("Cancel") } },
    )
}
