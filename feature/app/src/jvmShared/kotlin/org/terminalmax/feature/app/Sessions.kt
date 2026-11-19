// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.feature.app

import java.util.concurrent.atomic.AtomicLong
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import org.terminalmax.core.ssh.AlgorithmProfile
import org.terminalmax.core.ssh.LoopbackPreamble
import org.terminalmax.core.ssh.PtyRequest
import org.terminalmax.core.ssh.SshAuth
import org.terminalmax.core.ssh.SshConnectOptions
import org.terminalmax.core.ssh.SshException
import org.terminalmax.core.ssh.SshSession
import org.terminalmax.core.ssh.SshShell
import org.terminalmax.core.ssh.SshTarget
import org.terminalmax.core.ssh.SshTransport
import org.terminalmax.core.sync.VaultSession
import org.terminalmax.core.terminal.TerminalEngine
import org.terminalmax.core.terminal.createTerminalEngine
import org.terminalmax.core.wireguard.WireGuardBackend
import org.terminalmax.core.wireguard.WireGuardException
import org.terminalmax.core.wireguard.WireGuardTunnel

/** Connection state of one terminal session. The classes carrying a host key hold the raw key for the trust prompt. */
sealed interface SessionState {
    data object Connecting : SessionState

    data class Connected(val legacyCrypto: Boolean, val summary: String) : SessionState

    /** The server's key is not stored yet: ask the user, then [TerminalSession.trustAndReconnect]. */
    class NeedsTrust(val host: String, val port: Int, val keyType: String, val fingerprint: String, val key: ByteArray) : SessionState

    /** The server's key differs from the stored one: show a warning, default action is cancel. */
    class KeyChanged(val host: String, val port: Int, val keyType: String, val fingerprint: String, val key: ByteArray) : SessionState

    data class Failed(val message: String) : SessionState

    data class Ended(val exitStatus: Int?) : SessionState
}

/** Opens and tracks terminal sessions and the WireGuard tunnels they share (one tunnel per profile). */
class SessionManager(
    private val scope: CoroutineScope,
    private val transport: SshTransport,
    private val wireGuardFactory: () -> WireGuardBackend,
    private val vaultSession: () -> VaultSession?,
    internal val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val engineFactory: (cols: Int, rows: Int) -> TerminalEngine = { c, r -> createTerminalEngine(c, r) },
) {
    private val nextId = AtomicLong(1)
    private val mutableSessions = MutableStateFlow<List<TerminalSession>>(emptyList())
    private val mutableCount = MutableStateFlow(0)

    val sessions: StateFlow<List<TerminalSession>> get() = mutableSessions

    /** Number of open sessions (the Android foreground service shows it). */
    val count: StateFlow<Int> get() = mutableCount

    private class TunnelEntry(val tunnel: WireGuardTunnel, var refs: Int)

    private val tunnelLock = Any()
    private val tunnels = HashMap<String, TunnelEntry>()
    private var backend: WireGuardBackend? = null

    fun open(host: HostItem): TerminalSession {
        val session = TerminalSession(nextId.getAndIncrement(), host, this, scope, transport, engineFactory(DEFAULT_COLS, DEFAULT_ROWS))
        mutableSessions.update { it + session }
        mutableCount.value = mutableSessions.value.size
        session.connect()
        return session
    }

    fun find(id: Long): TerminalSession? = mutableSessions.value.firstOrNull { it.id == id }

    fun close(id: Long) {
        val session = find(id) ?: return
        mutableSessions.update { list -> list.filterNot { it.id == id } }
        mutableCount.value = mutableSessions.value.size
        session.dispose()
    }

    fun closeAll() {
        val all = mutableSessions.value
        mutableSessions.value = emptyList()
        mutableCount.value = 0
        all.forEach { it.dispose() }
    }

    /** Makes every tunnel re-handshake now (network change, wake-up). Safe to call from any thread. */
    fun rebindAll() {
        val current = synchronized(tunnelLock) { tunnels.values.map { it.tunnel } }
        if (current.isEmpty()) return
        scope.launch(ioDispatcher) {
            for (t in current) {
                try {
                    t.rebind()
                } catch (_: Exception) {
                    // A tunnel that cannot rebind is reported by the sessions that use it.
                }
            }
        }
    }

    internal fun vaultSession(): VaultSession? = vaultSession.invoke()

    internal fun acquireTunnel(profileId: String, config: String): WireGuardTunnel {
        synchronized(tunnelLock) {
            val existing = tunnels[profileId]
            if (existing != null) {
                existing.refs++
                return existing.tunnel
            }
            val b = backend ?: wireGuardFactory().also { backend = it }
            val tunnel = b.start(config.toByteArray(Charsets.UTF_8))
            tunnels[profileId] = TunnelEntry(tunnel, 1)
            return tunnel
        }
    }

    internal fun releaseTunnel(profileId: String) {
        val toClose: WireGuardTunnel? = synchronized(tunnelLock) {
            val entry = tunnels[profileId] ?: return
            entry.refs--
            if (entry.refs <= 0) {
                tunnels.remove(profileId)
                entry.tunnel
            } else {
                null
            }
        }
        try {
            toClose?.close()
        } catch (_: Exception) {
            // Closing is idempotent and best effort.
        }
    }

    /** Forgets a tunnel that stopped working so that the next connect starts a fresh one. */
    internal fun dropTunnel(profileId: String) {
        val entry = synchronized(tunnelLock) { tunnels.remove(profileId) } ?: return
        try {
            entry.tunnel.close()
        } catch (_: Exception) {
            // Best effort.
        }
    }

    companion object {
        const val DEFAULT_COLS = 80
        const val DEFAULT_ROWS = 24
    }
}

/** One interactive shell on one host. Output goes to [engine]; use [send] for input bytes. */
class TerminalSession internal constructor(
    val id: Long,
    val host: HostItem,
    private val manager: SessionManager,
    private val scope: CoroutineScope,
    private val transport: SshTransport,
    val engine: TerminalEngine,
) {
    private val mutableState = MutableStateFlow<SessionState>(SessionState.Connecting)
    private val input = Channel<ByteArray>(INPUT_QUEUE)
    private var job: Job? = null

    @Volatile
    private var shell: SshShell? = null

    @Volatile
    private var cols = SessionManager.DEFAULT_COLS

    @Volatile
    private var rows = SessionManager.DEFAULT_ROWS

    @Volatile
    private var disposed = false

    val state: StateFlow<SessionState> get() = mutableState

    init {
        engine.onResponse = { send(it) }
    }

    /** Starts (or restarts) the connection. Any earlier attempt is cancelled first. */
    fun connect() {
        if (disposed) return
        val previous = job
        job = scope.launch(manager.ioDispatcher) {
            previous?.cancelAndJoin()
            run()
        }
    }

    fun send(bytes: ByteArray) {
        if (mutableState.value is SessionState.Connected) input.trySend(bytes)
    }

    /** Called by the view whenever the character grid changes size. */
    fun resize(newCols: Int, newRows: Int) {
        cols = newCols
        rows = newRows
        val s = shell ?: return
        scope.launch(manager.ioDispatcher) {
            try {
                s.resize(newCols.coerceIn(1, 1000), newRows.coerceIn(1, 500))
            } catch (_: Exception) {
                // The connection state reports a broken connection.
            }
        }
    }

    /** Ends the connection but keeps the session in the list so that it can be reconnected. */
    fun disconnect() {
        job?.cancel()
        mutableState.value = SessionState.Ended(null)
    }

    fun trustAndReconnect(replace: Boolean) {
        val st = mutableState.value
        val session = manager.vaultSession() ?: return
        val (h, p, type, fp, key) = when (st) {
            is SessionState.NeedsTrust -> HostKeyInfo(st.host, st.port, st.keyType, st.fingerprint, st.key)
            is SessionState.KeyChanged -> HostKeyInfo(st.host, st.port, st.keyType, st.fingerprint, st.key)
            else -> return
        }
        mutableState.value = SessionState.Connecting
        scope.launch(manager.ioDispatcher) {
            try {
                session.trustHostKey(h, p, type, fp, key, replace)
                connect()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                mutableState.value = SessionState.Failed("Could not save the host key: ${e.message ?: e::class.simpleName}")
            }
        }
    }

    private data class HostKeyInfo(val host: String, val port: Int, val keyType: String, val fingerprint: String, val key: ByteArray)

    internal fun dispose() {
        disposed = true
        job?.cancel()
        input.close()
        engine.onResponse = null
        runCatching { engine.close() }
    }

    private suspend fun run() {
        mutableState.value = SessionState.Connecting
        var tunnelProfile: String? = null
        var ssh: SshSession? = null
        var openShell: SshShell? = null
        var auth: SshAuth? = null
        var connected = false
        try {
            val vault = manager.vaultSession() ?: throw IllegalStateException("The vault is locked.")
            val content = vault.content.value
            auth = content.authFor(host) ?: throw IllegalStateException("No login is stored for this host. Edit the host and set a password or key.")

            var via: LoopbackPreamble? = null
            val profileId = host.wireGuardProfileId
            if (profileId != null) {
                val config = content.wireGuardConfig(profileId)
                    ?: throw IllegalStateException("The WireGuard profile of this host no longer exists.")
                try {
                    val tunnel = manager.acquireTunnel(profileId, config)
                    tunnelProfile = profileId
                    val forward = tunnel.openForward(host.address, host.port)
                    val token = forward.token
                    try {
                        via = LoopbackPreamble(forward.port, token)
                    } finally {
                        token.fill(0)
                        forward.wipe()
                    }
                } catch (e: WireGuardException) {
                    if (tunnelProfile != null) manager.dropTunnel(profileId)
                    tunnelProfile = null
                    throw e
                } catch (e: IllegalArgumentException) {
                    throw IllegalStateException("The WireGuard tunnel needs an IP address as the host address.", e)
                }
            }

            val verifier = knownHostVerifier(content.knownHosts().map { it.second })
            val options = SshConnectOptions(algorithms = if (host.legacy) AlgorithmProfile.Legacy else AlgorithmProfile.Modern)
            val connectedSession = transport.connect(
                SshTarget(host.address, host.port, host.sshUsername),
                auth,
                verifier,
                via,
                options,
            )
            ssh = connectedSession
            val pty = PtyRequest(cols = cols.coerceIn(1, 1000), rows = rows.coerceIn(1, 500))
            val s = connectedSession.openShell(pty)
            openShell = s
            shell = s
            connected = true
            val n = connectedSession.negotiated
            mutableState.value = SessionState.Connected(
                connectedSession.usesLegacyCrypto,
                "${n.kex} / ${n.cipherC2s} / host key ${n.hostKey}",
            )
            val writer = scope.launch(manager.ioDispatcher) {
                for (bytes in input) s.write(bytes)
            }
            try {
                s.output.collect { engine.feed(it) }
            } finally {
                writer.cancel()
            }
            val exit = try {
                s.awaitExit()
            } catch (_: Exception) {
                null
            }
            mutableState.value = SessionState.Ended(exit)
        } catch (e: CancellationException) {
            throw e
        } catch (e: SshException.HostKeyUnknown) {
            mutableState.value = SessionState.NeedsTrust(e.host, e.port, e.keyType, e.fingerprintSha256, e.key)
        } catch (e: SshException.HostKeyChanged) {
            mutableState.value = SessionState.KeyChanged(e.host, e.port, e.keyType, e.fingerprintSha256, e.key)
        } catch (e: Exception) {
            mutableState.value = SessionState.Failed(describeConnectionError(e, connected))
        } finally {
            shell = null
            runCatching { openShell?.close() }
            runCatching { ssh?.close() }
            (auth as? SshAuth.Password)?.password?.fill('\u0000')
            tunnelProfile?.let { manager.releaseTunnel(it) }
        }
    }

    private companion object {
        const val INPUT_QUEUE = 1024
    }
}

internal fun describeConnectionError(e: Throwable, wasConnected: Boolean): String = when (e) {
    is SshException.AuthFailed ->
        "Login failed. Check the user name, the password or key and, for RouterOS, the console options."
    is SshException.Timeout -> if (wasConnected) "The connection timed out." else "The host did not answer in time."
    is SshException.Unreachable ->
        "Could not reach the host. Check the address, port and network (or the WireGuard profile)."
    is SshException.Protocol -> if (wasConnected) {
        "The connection was lost: ${e.message}"
    } else {
        "The SSH handshake failed: ${e.message}. An older router may need the Legacy algorithm profile in the host settings."
    }
    is SshException -> e.message ?: "SSH error."
    is WireGuardException -> "WireGuard: ${e.message}"
    is IllegalStateException -> e.message ?: "Cannot connect."
    else -> "Unexpected error (${e::class.simpleName})."
}
