// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.feature.app

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle

/** First launch: create a vault or join one from WebDAV. Later launches: unlock. */
@Composable
fun VaultGateScreen(vault: VaultViewModel) {
    val state by vault.state.collectAsStateWithLifecycle()
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Column(Modifier.widthIn(max = 480.dp).fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(AppInfo.NAME, style = MaterialTheme.typography.displaySmall)
            Text(
                "Pre-alpha: do not store real credentials yet.",
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.error,
            )
            if (state.phase == VaultPhase.Locked) UnlockForm(vault, state) else SetupForm(vault, state)
        }
    }
    state.joinPreview?.let { JoinConfirmDialog(it, vault) }
}

@Composable
private fun UnlockForm(vault: VaultViewModel, state: VaultUiState) {
    var password by remember { mutableStateOf("") }
    Text("Unlock your vault", style = MaterialTheme.typography.titleLarge)
    SecretField(password, { password = it }, "Vault password", error = state.error)
    if (state.busy) {
        BusyRow("Unlocking...")
    } else {
        Button(onClick = { vault.unlock(password) }, Modifier.fillMaxWidth()) { Text("Unlock") }
    }
    Text(
        "Unlocking derives the key from your password and can take a few seconds. Quick unlock with a fingerprint or " +
            "the system keychain is not part of this release.",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

@Composable
private fun SetupForm(vault: VaultViewModel, state: VaultUiState) {
    var join by remember { mutableStateOf(false) }
    Text("Welcome", style = MaterialTheme.typography.titleLarge)
    Text(
        "Your hosts, keys and WireGuard profiles live in an encrypted vault on this device. " +
            "Create a new vault, or join the one you already synced to a WebDAV server.",
        style = MaterialTheme.typography.bodyMedium,
    )
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        FilterChip(selected = !join, onClick = { join = false; vault.clearError() }, label = { Text("Create vault") })
        FilterChip(selected = join, onClick = { join = true; vault.clearError() }, label = { Text("Join from WebDAV") })
    }
    if (join) JoinForm(vault, state) else CreateForm(vault, state)
}

@Composable
private fun CreateForm(vault: VaultViewModel, state: VaultUiState) {
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    val strength = passwordStrength(password)
    SecretField(password, { password = it }, "Vault password", supporting = if (password.isEmpty()) null else strength.hint())
    SecretField(confirm, { confirm = it }, "Repeat the password", error = state.error)
    Text(
        "There is no way to recover the vault if you forget this password.",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    if (state.busy) {
        BusyRow("Creating the vault...")
    } else {
        Button(onClick = { vault.create(password, confirm) }, Modifier.fillMaxWidth()) { Text("Create vault") }
    }
}

@Composable
private fun JoinForm(vault: VaultViewModel, state: VaultUiState) {
    var url by remember { mutableStateOf("") }
    var user by remember { mutableStateOf("") }
    var davPassword by remember { mutableStateOf("") }
    var vaultPassword by remember { mutableStateOf("") }
    TextInput(url, { url = it }, "WebDAV address (https://...)", keyboardType = KeyboardType.Uri)
    TextInput(user, { user = it }, "WebDAV user name")
    SecretField(davPassword, { davPassword = it }, "WebDAV password")
    SecretField(vaultPassword, { vaultPassword = it }, "Vault password", error = state.error)
    if (state.busy) {
        BusyRow("Contacting the server...")
    } else {
        Button(onClick = { vault.startJoin(url, user, davPassword, vaultPassword) }, Modifier.fillMaxWidth()) {
            Text("Download and check")
        }
    }
}

@Composable
private fun JoinConfirmDialog(preview: JoinPreviewUi, vault: VaultViewModel) {
    var matches by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = { vault.cancelJoin() },
        title = { Text("Is this your vault?") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "Open TerminalMax on a device that already has this vault and compare. This check is the only " +
                        "protection against a server that serves an old or foreign vault.",
                )
                Text("Fingerprint", style = MaterialTheme.typography.labelLarge)
                Text(preview.fingerprint, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.titleMedium)
                Text("Revision ${preview.revision}, key epoch ${preview.keyEpoch}")
                if (preview.recordCounts.isNotEmpty()) {
                    Text(preview.recordCounts.entries.joinToString(", ") { "${it.value} ${it.key}" })
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = matches, onCheckedChange = { matches = it })
                    Text("The fingerprint matches, and the revision is at least the one that device last synced.")
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { vault.confirmJoin() }, enabled = matches) { Text("Join this vault") }
        },
        dismissButton = {
            OutlinedButton(onClick = { vault.cancelJoin() }) { Text("Cancel") }
        },
    )
}
