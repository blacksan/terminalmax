// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.feature.app

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Slider
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.launch

@Composable
fun SettingsScreen(container: AppContainer) {
    val theme by container.prefs.themeMode.collectAsStateWithLifecycle()
    val fontSp by container.prefs.terminalFontSp.collectAsStateWithLifecycle()
    var confirmLock by remember { mutableStateOf(false) }
    val openSessions by container.sessions.count.collectAsStateWithLifecycle()

    ScreenScaffold(
        title = "Settings",
        actions = { TextButton(onClick = { confirmLock = true }) { Text("Lock") } },
    ) {
        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("Appearance", style = MaterialTheme.typography.titleMedium)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                ThemeMode.entries.forEach { mode ->
                    FilterChip(selected = theme == mode, onClick = { container.prefs.setThemeMode(mode) }, label = { Text(mode.label) })
                }
            }
            Text("Terminal font size: $fontSp sp", style = MaterialTheme.typography.bodyLarge)
            Slider(
                value = fontSp.toFloat(),
                onValueChange = { container.prefs.setTerminalFontSp(it.toInt()) },
                valueRange = AppPrefs.MIN_FONT_SP.toFloat()..AppPrefs.MAX_FONT_SP.toFloat(),
                steps = AppPrefs.MAX_FONT_SP - AppPrefs.MIN_FONT_SP - 1,
            )
            HorizontalDivider()
            Text("Security", style = MaterialTheme.typography.titleMedium)
            Text(
                "Lock closes the vault and every open session. On Android the vault also locks by itself after 5 minutes in the background, as long as no session is open.",
                style = MaterialTheme.typography.bodyMedium,
            )
            Text(
                "Quick unlock (fingerprint, system keychain) is not part of this release: you always unlock with the vault password.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedButton(onClick = { confirmLock = true }) { Text("Lock now") }
            HorizontalDivider()
            ListItem(
                modifier = Modifier.clickable { container.navigator.push(Screen.SyncSettings) },
                headlineContent = { Text("Sync") },
                supportingContent = { Text("WebDAV server, sync now, backup") },
            )
            ListItem(
                modifier = Modifier.clickable { container.navigator.push(Screen.About) },
                headlineContent = { Text("About") },
                supportingContent = { Text("Version ${container.platform.appVersion}, licence, third-party notices") },
            )
        }
    }
    if (confirmLock) {
        ConfirmDialog(
            title = "Lock the vault?",
            text = if (openSessions > 0) "$openSessions open session(s) will be disconnected." else "You will need the vault password to unlock it again.",
            confirmLabel = "Lock",
            onConfirm = { confirmLock = false; container.vault.lock() },
            onDismiss = { confirmLock = false },
        )
    }
}

@Composable
fun SyncSettingsScreen(container: AppContainer) {
    val vm = container.sync
    val state by vm.state.collectAsStateWithLifecycle()
    val autoSync by container.prefs.autoSync.collectAsStateWithLifecycle()
    var url by remember(state.config.url) { mutableStateOf(state.config.url) }
    var user by remember(state.config.username) { mutableStateOf(state.config.username) }
    var password by remember(state.config.password) { mutableStateOf(state.config.password) }
    var saveMessage by remember { mutableStateOf<SyncMessage?>(null) }
    var backupMessage by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    fun save(after: () -> Unit = {}) {
        scope.launch {
            val error = vm.saveConfig(url, user, password)
            saveMessage = if (error == null) SyncMessage(MessageKind.Success, "Saved in the vault.") else SyncMessage(MessageKind.Error, error)
            if (error == null) after()
        }
    }

    ScreenScaffold(title = "Sync", onBack = { container.navigator.pop() }) {
        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(
                "Your vault is encrypted on this device. The WebDAV server only ever sees the encrypted file. Use an https address.",
                style = MaterialTheme.typography.bodyMedium,
            )
            TextInput(url, { url = it }, "WebDAV address", keyboardType = KeyboardType.Uri, supporting = "For example https://dav.example.org/terminalmax/")
            TextInput(user, { user = it }, "User name")
            SecretField(password, { password = it }, "Password", supporting = "Stored in the vault, encrypted like everything else.")
            saveMessage?.let { MessageCard(it) }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { save() }, enabled = !state.busy) { Text("Save") }
                OutlinedButton(onClick = { save { vm.testServer() } }, enabled = !state.busy) { Text("Test server") }
                Button(onClick = { save { vm.syncNow() } }, enabled = !state.busy) { Text("Sync now") }
            }
            if (state.busy) BusyRow("Working...")
            state.testMessage?.let { MessageCard(it) }
            state.lastResult?.let { MessageCard(it) }
            state.details.forEach { Text("• $it", style = MaterialTheme.typography.bodySmall) }

            HorizontalDivider()
            Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Switch(checked = autoSync, onCheckedChange = { container.prefs.setAutoSync(it) })
                Column(Modifier.weight(1f)) {
                    Text("Sync automatically", style = MaterialTheme.typography.bodyLarge)
                    Text(
                        "When the vault is unlocked and 10 seconds after an edit. Off by default.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            HorizontalDivider()
            Text("Backup", style = MaterialTheme.typography.titleMedium)
            Text(
                "A backup is the sealed vault file. It is as protected as the copy on the server: anyone who gets it can try to guess your password offline, so keep it somewhere safe.",
                style = MaterialTheme.typography.bodySmall,
            )
            OutlinedButton(onClick = {
                val bytes = vm.backupBytes()
                if (bytes == null) {
                    backupMessage = "The vault is locked."
                } else {
                    container.platform.saveFile("terminalmax-vault-backup.bin", bytes) { ok ->
                        backupMessage = if (ok) "Backup saved." else "The backup was not saved."
                    }
                }
            }) { Text("Export backup...") }
            backupMessage?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        }
    }
    state.decision?.let { DecisionDialog(container, it) }
}

@Composable
private fun DecisionDialog(container: AppContainer, decision: SyncDecision) {
    val vm = container.sync
    var password by remember(decision) { mutableStateOf("") }
    var confirmed by remember(decision) { mutableStateOf(false) }
    var backupNote by remember(decision) { mutableStateOf<String?>(null) }

    val needsPassword = decision is SyncDecision.Reopen || decision is SyncDecision.CompetingKey ||
        decision is SyncDecision.ReplaceRemote || decision is SyncDecision.PendingPasswordChange
    val needsCheckbox = decision is SyncDecision.CompetingKey || decision is SyncDecision.ReplaceRemote ||
        decision is SyncDecision.Rollback || decision is SyncDecision.LargeRemoteChange || decision is SyncDecision.RevisionJump

    val title: String
    val body: String
    val action: String
    val checkboxText: String
    when (decision) {
        is SyncDecision.LargeRemoteChange -> {
            title = "Apply a large change from the server?"
            body = "The server would change ${decision.changed} and delete ${decision.deleted} of your entries (and add ${decision.added}). " +
                (if (decision.knownHostsChanged > 0) "${decision.knownHostsChanged} of the changed entries are saved host keys: a changed host key can mean an interception. " else "") +
                "Nothing has been applied. If you apply it, deleted entries stay restorable from the vault history for a while."
            action = "Apply these changes"
            checkboxText = "I expected this change."
        }
        SyncDecision.Rollback -> {
            title = "Accept an older server copy?"
            body = "The server has an older revision of the vault than this device has already seen. This can happen after a server restore, or when a server serves old data on purpose. " +
                "Accepting merges it with your newer data; an older entry never replaces a newer one."
            action = "Accept for this sync"
            checkboxText = "I know why the server went back."
        }
        SyncDecision.RemoteMissing -> {
            title = "Upload the vault again?"
            body = "The vault file is gone from the server, although this device synced it before. If you did not delete it, someone else may have. Uploading puts this device's copy there again."
            action = "Upload this device's copy"
            checkboxText = ""
        }
        SyncDecision.RevisionJump -> {
            title = "Accept a very large revision jump?"
            body = "The server's vault is far ahead of anything this device has seen. A buggy or hostile writer could use this to make the vault impossible to edit. Accept only if another of your devices made lots of changes."
            action = "Accept for this sync"
            checkboxText = "I know where this revision comes from."
        }
        is SyncDecision.Reopen -> {
            title = "The vault key was changed"
            body = (if (decision.warnings.isEmpty()) "" else decision.warnings.joinToString("\n\n") + "\n\n") +
                "The password was changed on another device. Enter the vault password to follow it. " +
                "Type it yourself; the app never pre-fills it. If you did not change the password, stop and check your other devices first."
            action = "Continue"
            checkboxText = ""
        }
        is SyncDecision.CompetingKey -> {
            title = "Two devices changed the key at once"
            body = "Another device made a competing vault key. Its fingerprint is:\n\n${decision.fingerprint}\n\n" +
                "Open TerminalMax on another device of yours and compare it with that device's fingerprint. " +
                "If they differ, do NOT continue. Enter the vault password to adopt this key."
            action = "Adopt this key"
            checkboxText = "The fingerprint matches the one on my other device."
        }
        is SyncDecision.ReplaceRemote -> {
            title = "Replace the server copy?"
            body = decision.reason + "\n\n" +
                "Replacing uploads this device's vault as a new key epoch. Everything on the server is gone, including changes other devices made that this device never received. " +
                "Do this only if you did NOT change the password on another device. Other devices will need the vault password to follow. " +
                (if (decision.changeCredentialAdvice) "If you suspect someone else wrote to the share, also change the WebDAV password. " else "") +
                "Export a backup first if in doubt."
            action = "Replace server copy"
            checkboxText = "I understand that the server copy is replaced."
        }
        SyncDecision.PendingPasswordChange -> {
            title = "A password change was not finished"
            body = "A password change started on this device never reached the server. Until it is published, the OLD password is still the live one. " +
                "Enter the NEW password of that change to publish it, or close this and sync with the old password to drop it."
            action = "Finish the change"
            checkboxText = ""
        }
        is SyncDecision.Acknowledge -> {
            title = "Please read"
            body = decision.lines.joinToString("\n\n")
            action = "I have read this"
            checkboxText = ""
        }
    }
    val canConfirm = (!needsCheckbox || confirmed || checkboxText.isEmpty()) && (!needsPassword || password.isNotEmpty())

    AlertDialog(
        onDismissRequest = { vm.dismissDecision() },
        title = { Text(title) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(body, fontFamily = FontFamily.Default)
                if (decision is SyncDecision.ReplaceRemote) {
                    OutlinedButton(onClick = {
                        val bytes = vm.backupBytes()
                        if (bytes == null) {
                            backupNote = "The vault is locked."
                        } else {
                            container.platform.saveFile("terminalmax-vault-backup.bin", bytes) { ok ->
                                backupNote = if (ok) "Backup saved." else "The backup was not saved."
                            }
                        }
                    }) { Text("Export a backup first") }
                    backupNote?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                }
                if (needsPassword) SecretField(password, { password = it }, "Vault password")
                if (needsCheckbox && checkboxText.isNotEmpty()) {
                    Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                        Checkbox(checked = confirmed, onCheckedChange = { confirmed = it })
                        Text(checkboxText, style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }
        },
        confirmButton = {
            TextButton(enabled = canConfirm, onClick = { vm.resolve(password.ifEmpty { null }) }) { Text(action) }
        },
        dismissButton = { TextButton(onClick = { vm.dismissDecision() }) { Text(if (decision is SyncDecision.Acknowledge) "Later" else "Not now") } },
    )
}

@Composable
fun AboutScreen(container: AppContainer) {
    var licence by remember { mutableStateOf<String?>(null) }
    var notices by remember { mutableStateOf<String?>(null) }
    var show by remember { mutableStateOf("") }
    LaunchedEffect(Unit) {
        licence = container.platform.readLegalText("LICENSE")
        notices = container.platform.readLegalText("THIRD_PARTY_NOTICES.md")
    }
    ScreenScaffold(title = "About", onBack = { container.navigator.pop() }) {
        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(AppInfo.NAME, style = MaterialTheme.typography.headlineMedium)
            Text("Version ${container.platform.appVersion}")
            Text("Licence: ${AppInfo.LICENSE_ID}. TerminalMax is free software.")
            WarningCard("Pre-alpha. This software has not been audited and nothing has been tested on a wide range of devices. Do not store real credentials yet.")
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(selected = show == "licence", onClick = { show = if (show == "licence") "" else "licence" }, label = { Text("Licence text") })
                FilterChip(selected = show == "notices", onClick = { show = if (show == "notices") "" else "notices" }, label = { Text("Third-party notices") })
            }
            if (show.isNotEmpty()) {
                val text = if (show == "licence") licence else notices
                Text(
                    text ?: "This text is not bundled with this build.",
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }
    }
}
