// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.feature.app

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import org.terminalmax.core.ssh.SshTransport
import org.terminalmax.core.ssh.SshjTransport
import org.terminalmax.core.sync.RemoteStore
import org.terminalmax.core.sync.WebDavStore
import org.terminalmax.core.vault.KdfParams
import org.terminalmax.core.wireguard.WireGuardBackend
import org.terminalmax.core.wireguard.createWireGuardBackend

/**
 * Manual constructor injection: one container per platform process wires the platform services to the view
 * models. (Hilt is Android-only, so a plain object graph is used on both targets.)
 */
class AppContainer(
    val platform: PlatformServices,
    val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Default),
    transport: SshTransport = SshjTransport(),
    wireGuardFactory: () -> WireGuardBackend = { createWireGuardBackend() },
    remoteFactory: (url: String, user: String, password: CharArray) -> RemoteStore =
        { url, user, password -> WebDavStore(url, user, password) },
    kdf: KdfParams = KdfParams.Default,
) {
    val navigator = Navigator()
    val prefs = AppPrefs(platform.prefsFile)

    // Declared before the vault view model, which refers to it through lambdas only.
    lateinit var vault: VaultViewModel
        private set

    val sessions = SessionManager(scope, transport, wireGuardFactory, vaultSession = { vault.session.value })

    init {
        vault = VaultViewModel(
            scope = scope,
            directory = platform.vaultDirectory,
            kdf = kdf,
            remoteFactory = remoteFactory,
            onLocked = {
                sessions.closeAll()
                navigator.switchTo(Screen.Hosts)
            },
            onUnlocked = { navigator.switchTo(Screen.Hosts) },
        )
    }

    val hosts = HostsViewModel(scope, vault)
    val sync = SyncViewModel(scope, vault, prefs, remoteFactory)
}
