// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.feature.app

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.ListItem
import androidx.compose.material3.LoadingIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEvent
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.input.key.isAltPressed
import androidx.compose.ui.input.key.isCtrlPressed
import androidx.compose.ui.input.key.isShiftPressed
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.onPreviewKeyEvent
import androidx.compose.ui.input.key.type
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.launch
import org.terminalmax.core.terminal.KeyModifiers
import org.terminalmax.core.terminal.TerminalEngine
import org.terminalmax.core.terminal.TerminalKey
import org.terminalmax.core.terminal.ui.TerminalView

@Composable
fun SessionsScreen(container: AppContainer) {
    val sessions by container.sessions.sessions.collectAsStateWithLifecycle()
    ScreenScaffold(title = "Sessions") {
        if (sessions.isEmpty()) {
            EmptyState("No open sessions", "Open a host from the Hosts tab. Sessions stay connected while you use other screens.")
        } else {
            LazyColumn(Modifier.fillMaxSize()) {
                items(sessions, key = { it.id }) { s ->
                    val state by s.state.collectAsStateWithLifecycle()
                    ListItem(
                        modifier = Modifier.clickable { container.navigator.push(Screen.Terminal(s.id)) },
                        headlineContent = { Text(s.host.label) },
                        supportingContent = { Text(s.host.subtitle + "  •  " + stateText(state)) },
                        trailingContent = { TextButton(onClick = { container.sessions.close(s.id) }) { Text("Close") } },
                    )
                    HorizontalDivider()
                }
            }
        }
    }
}

internal fun stateText(state: SessionState): String = when (state) {
    SessionState.Connecting -> "Connecting"
    is SessionState.Connected -> if (state.legacyCrypto) "Connected (legacy crypto)" else "Connected"
    is SessionState.NeedsTrust -> "Waiting for host key decision"
    is SessionState.KeyChanged -> "Host key changed"
    is SessionState.Failed -> "Failed"
    is SessionState.Ended -> "Ended"
}

@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Composable
fun TerminalScreen(container: AppContainer, sessionId: Long) {
    val all by container.sessions.sessions.collectAsStateWithLifecycle()
    val session = all.firstOrNull { it.id == sessionId }
    if (session == null) {
        LaunchedEffect(sessionId) { container.navigator.pop() }
        return
    }
    val state by session.state.collectAsStateWithLifecycle()
    val fontSp by container.prefs.terminalFontSp.collectAsStateWithLifecycle()
    val isAndroid = container.platform.isAndroid
    val scope = rememberCoroutineScope()
    val keyboard = LocalSoftwareKeyboardController.current
    val hiddenFocus = remember { FocusRequester() }
    var ctrl by remember { mutableStateOf(false) }
    var alt by remember { mutableStateOf(false) }
    var keyboardShown by remember { mutableStateOf(true) }

    fun send(bytes: ByteArray) = session.send(bytes)

    LaunchedEffect(state is SessionState.Connected) {
        if (isAndroid && state is SessionState.Connected) {
            runCatching { hiddenFocus.requestFocus() }
            keyboard?.show()
        }
    }

    ScreenScaffold(
        title = session.host.label,
        onBack = { container.navigator.pop() },
        actions = {
            if (isAndroid) {
                TextButton(onClick = {
                    if (keyboardShown) {
                        keyboard?.hide()
                    } else {
                        runCatching { hiddenFocus.requestFocus() }
                        keyboard?.show()
                    }
                    keyboardShown = !keyboardShown
                }) { Text("Keyboard") }
            }
            when (state) {
                is SessionState.Connected, SessionState.Connecting -> TextButton(onClick = { session.disconnect() }) { Text("Disconnect") }
                else -> TextButton(onClick = { session.connect() }) { Text("Reconnect") }
            }
            TextButton(onClick = {
                container.sessions.close(session.id)
                container.navigator.pop()
            }) { Text("Close") }
        },
    ) {
        Column(Modifier.fillMaxSize()) {
            if (!isAndroid && all.size > 1) {
                Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    all.forEach { s ->
                        FilterChip(
                            selected = s.id == sessionId,
                            onClick = { container.navigator.replaceTop(Screen.Terminal(s.id)) },
                            label = { Text(s.host.label) },
                        )
                    }
                }
            }
            val connected = state as? SessionState.Connected
            if (connected?.legacyCrypto == true) {
                WarningCard("This connection uses legacy cryptography. Do not rely on it on an untrusted network.", Modifier.padding(horizontal = 8.dp))
            }
            Box(
                Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .onFocusChanged { f ->
                        // A tap focuses the terminal canvas (hardware keys); on a phone the soft keyboard needs the hidden field.
                        if (isAndroid && f.hasFocus) {
                            scope.launch {
                                runCatching { hiddenFocus.requestFocus() }
                                keyboard?.show()
                                keyboardShown = true
                            }
                        }
                    },
            ) {
                TerminalView(
                    engine = session.engine,
                    modifier = Modifier.fillMaxSize(),
                    fontSize = fontSp.sp,
                    onInput = { send(it) },
                    onSizeChanged = { c, r -> session.resize(c, r) },
                )
                when (val st = state) {
                    SessionState.Connecting -> BusyRow("Connecting...", Modifier.align(Alignment.Center))
                    is SessionState.Failed -> StatusOverlay("Connection failed", st.message, "Reconnect") { session.connect() }
                    is SessionState.Ended -> StatusOverlay(
                        "Session ended",
                        st.exitStatus?.let { "The remote shell exited with status $it." } ?: "The connection is closed.",
                        "Reconnect",
                    ) { session.connect() }
                    else -> Unit
                }
            }
            if (isAndroid) {
                ExtraKeysRow(
                    ctrlActive = ctrl,
                    altActive = alt,
                    onKey = { key ->
                        when (key) {
                            ExtraKey.Ctrl -> ctrl = !ctrl
                            ExtraKey.Alt -> alt = !alt
                            else -> {
                                encodeExtraKey(key, ctrl, alt) { k, m -> session.engine.encodeKey(k, m) }?.let { send(it) }
                                ctrl = false
                                alt = false
                            }
                        }
                    },
                )
                HiddenKeyboardField(
                    engine = session.engine,
                    focusRequester = hiddenFocus,
                    ctrl = ctrl,
                    alt = alt,
                    onSend = { send(it) },
                    onModifiersUsed = { ctrl = false; alt = false },
                )
            }
        }
    }

    when (val st = state) {
        is SessionState.NeedsTrust -> HostKeyDialog(
            title = "Trust this host?",
            text = "This is the first connection to ${st.host}:${st.port}, or its key type is new. " +
                "Compare the fingerprint with the one on the device before you trust it.",
            keyType = st.keyType,
            fingerprint = st.fingerprint,
            danger = false,
            confirmLabel = "Trust and connect",
            onConfirm = { session.trustAndReconnect(replace = false) },
            onCancel = { session.disconnect() },
        )
        is SessionState.KeyChanged -> HostKeyDialog(
            title = "WARNING: the host key has changed",
            text = "The key of ${st.host}:${st.port} is different from the one you trusted before. " +
                "Someone may be intercepting the connection, or the device was reset or replaced. " +
                "Do not continue unless you know why the key changed.",
            keyType = st.keyType,
            fingerprint = st.fingerprint,
            danger = true,
            confirmLabel = "Replace stored key",
            onConfirm = { session.trustAndReconnect(replace = true) },
            onCancel = { session.disconnect() },
        )
        else -> Unit
    }
}

@Composable
private fun HostKeyDialog(
    title: String,
    text: String,
    keyType: String,
    fingerprint: String,
    danger: Boolean,
    confirmLabel: String,
    onConfirm: () -> Unit,
    onCancel: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text(title, color = if (danger) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(text)
                Text("Key type: $keyType")
                Text("SHA-256 fingerprint", style = MaterialTheme.typography.labelLarge)
                Text(fingerprint, fontFamily = FontFamily.Monospace)
            }
        },
        // Cancel is the default action; replacing a stored key needs a deliberate tap on the smaller text button.
        confirmButton = { Button(onClick = onCancel) { Text("Cancel") } },
        dismissButton = {
            if (danger) {
                TextButton(onClick = onConfirm) { Text(confirmLabel, color = MaterialTheme.colorScheme.error) }
            } else {
                OutlinedButton(onClick = onConfirm) { Text(confirmLabel) }
            }
        },
    )
}

@Composable
private fun StatusOverlay(title: String, text: String, action: String, onAction: () -> Unit) {
    Box(Modifier.fillMaxSize().background(MaterialTheme.colorScheme.scrim.copy(alpha = 0.55f)), contentAlignment = Alignment.Center) {
        Column(
            Modifier.background(MaterialTheme.colorScheme.surfaceContainerHigh, MaterialTheme.shapes.large).padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            Text(text, style = MaterialTheme.typography.bodyMedium)
            Button(onClick = onAction) { Text(action) }
        }
    }
}

@Composable
private fun ExtraKeysRow(ctrlActive: Boolean, altActive: Boolean, onKey: (ExtraKey) -> Unit) {
    Row(
        Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(horizontal = 4.dp, vertical = 2.dp),
        horizontalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        for (key in ExtraKey.entries) {
            val active = (key == ExtraKey.Ctrl && ctrlActive) || (key == ExtraKey.Alt && altActive)
            if (active) {
                Button(
                    onClick = { onKey(key) },
                    modifier = Modifier.height(40.dp).defaultMinSize(minWidth = 44.dp),
                    contentPadding = androidx.compose.foundation.layout.PaddingValues(horizontal = 10.dp),
                ) { Text(key.label) }
            } else {
                FilledTonalButton(
                    onClick = { onKey(key) },
                    modifier = Modifier.height(40.dp).defaultMinSize(minWidth = 44.dp),
                    contentPadding = androidx.compose.foundation.layout.PaddingValues(horizontal = 10.dp),
                ) { Text(key.label) }
            }
        }
    }
}

private const val SENTINEL = "  "

/**
 * An invisible text field that receives the soft keyboard. Its content is always reset to a two character
 * sentinel: characters typed after the sentinel are sent to the shell, a shorter text means Backspace.
 * Hardware keys that reach it (arrows, Enter, Esc, Ctrl+letter) are encoded by the terminal engine.
 */
@Composable
private fun HiddenKeyboardField(
    engine: TerminalEngine,
    focusRequester: FocusRequester,
    ctrl: Boolean,
    alt: Boolean,
    onSend: (ByteArray) -> Unit,
    onModifiersUsed: () -> Unit,
) {
    var value by remember { mutableStateOf(TextFieldValue(SENTINEL, TextRange(SENTINEL.length))) }
    BasicTextField(
        value = value,
        onValueChange = { next ->
            val t = next.text
            if (t.length < SENTINEL.length) {
                onSend(engine.encodeKey(TerminalKey.Backspace, KeyModifiers.None))
            } else if (t.length > SENTINEL.length) {
                val typed = if (t.startsWith(SENTINEL)) t.substring(SENTINEL.length) else t.replace(" ", "")
                if (typed.isNotEmpty()) {
                    onSend(encodeTypedText(typed, ctrl, alt))
                    if (ctrl || alt) onModifiersUsed()
                }
            }
            value = TextFieldValue(SENTINEL, TextRange(SENTINEL.length))
        },
        keyboardOptions = KeyboardOptions(
            keyboardType = KeyboardType.Password,
            imeAction = ImeAction.None,
            autoCorrectEnabled = false,
        ),
        modifier = Modifier
            .size(1.dp)
            .alpha(0f)
            .focusRequester(focusRequester)
            .onPreviewKeyEvent { event -> handleHardwareKey(event, engine, ctrl, alt, onSend, onModifiersUsed) },
    )
}

private fun terminalKeyFor(key: Key): TerminalKey? = when (key) {
    Key.Enter, Key.NumPadEnter -> TerminalKey.Enter
    Key.Backspace -> TerminalKey.Backspace
    Key.Tab -> TerminalKey.Tab
    Key.Escape -> TerminalKey.Escape
    Key.DirectionUp -> TerminalKey.Up
    Key.DirectionDown -> TerminalKey.Down
    Key.DirectionLeft -> TerminalKey.Left
    Key.DirectionRight -> TerminalKey.Right
    Key.MoveHome -> TerminalKey.Home
    Key.MoveEnd -> TerminalKey.End
    Key.PageUp -> TerminalKey.PageUp
    Key.PageDown -> TerminalKey.PageDown
    Key.Insert -> TerminalKey.Insert
    Key.Delete -> TerminalKey.Delete
    Key.F1 -> TerminalKey.F1
    Key.F2 -> TerminalKey.F2
    Key.F3 -> TerminalKey.F3
    Key.F4 -> TerminalKey.F4
    Key.F5 -> TerminalKey.F5
    Key.F6 -> TerminalKey.F6
    Key.F7 -> TerminalKey.F7
    Key.F8 -> TerminalKey.F8
    Key.F9 -> TerminalKey.F9
    Key.F10 -> TerminalKey.F10
    Key.F11 -> TerminalKey.F11
    Key.F12 -> TerminalKey.F12
    else -> null
}

private fun handleHardwareKey(
    event: KeyEvent,
    engine: TerminalEngine,
    stickyCtrl: Boolean,
    stickyAlt: Boolean,
    send: (ByteArray) -> Unit,
    modifiersUsed: () -> Unit,
): Boolean {
    val special = terminalKeyFor(event.key)
    val letter = event.key.letterOrNull()
    val ctrl = event.isCtrlPressed || stickyCtrl
    val alt = event.isAltPressed || stickyAlt
    val handled = special != null || (letter != null && event.isCtrlPressed)
    if (!handled) return false
    if (event.type != KeyEventType.KeyDown) return true
    if (special != null) {
        send(engine.encodeKey(special, KeyModifiers(ctrl = ctrl, alt = alt, shift = event.isShiftPressed)))
    } else if (letter != null) {
        send(encodeTypedText(letter.toString(), ctrl = true, alt = alt))
    }
    if (stickyCtrl || stickyAlt) modifiersUsed()
    return true
}

private fun Key.letterOrNull(): Char? = when (this) {
    Key.A -> 'a'; Key.B -> 'b'; Key.C -> 'c'; Key.D -> 'd'; Key.E -> 'e'; Key.F -> 'f'; Key.G -> 'g'
    Key.H -> 'h'; Key.I -> 'i'; Key.J -> 'j'; Key.K -> 'k'; Key.L -> 'l'; Key.M -> 'm'; Key.N -> 'n'
    Key.O -> 'o'; Key.P -> 'p'; Key.Q -> 'q'; Key.R -> 'r'; Key.S -> 's'; Key.T -> 't'; Key.U -> 'u'
    Key.V -> 'v'; Key.W -> 'w'; Key.X -> 'x'; Key.Y -> 'y'; Key.Z -> 'z'
    else -> null
}
