// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.wireguard

/**
 * Failure of a WireGuard bridge operation (bad configuration, tunnel start failure, closed
 * tunnel, missing native library, ...). Messages come from the native bridge, are printable
 * ASCII and never contain key material.
 */
class WireGuardException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * Userspace WireGuard (wireguard-go with a netstack TUN, no VPN service, no administrator
 * rights) behind the `libwgbridge` native library.
 *
 * All methods of the backend and of [WireGuardTunnel] are **blocking** and must be called off
 * the main thread (use `Dispatchers.IO`).
 */
interface WireGuardBackend {
    /** Version string of the native bridge, for diagnostics. */
    fun version(): String

    /**
     * Parses [configText] (a wg-quick style config as UTF-8 bytes, at most 1 MiB, no NUL bytes)
     * and starts a tunnel.
     *
     * This call **consumes** [configText]: the array is zero-filled before it returns, also when
     * it fails. Pass a copy if you still need the bytes.
     *
     * @throws WireGuardException if the configuration is invalid or the tunnel cannot start.
     */
    fun start(configText: ByteArray): WireGuardTunnel
}

/**
 * A running tunnel. Methods are blocking; call them off the main thread.
 *
 * Android duties of the app layer (the native Go runtime's timers stop while the CPU sleeps):
 * hold a `PARTIAL_WAKE_LOCK` while sessions are open, and call [rebind] on every network change
 * and when the device wakes.
 */
interface WireGuardTunnel : AutoCloseable {
    /**
     * Opens a one-connection loopback forwarder to [targetIp]:[port] through the tunnel. Open it
     * immediately before connecting: it expires after 5 s without a client, and the client has
     * 5 s to send the token. [targetIp] must be an IP literal (IPv4 or IPv6, without brackets).
     *
     * The tunnel wipes the token of every forward it handed out when it is closed (and of the
     * oldest ones once more than 64 are outstanding): read [LoopbackForward.token] right away.
     *
     * @throws IllegalArgumentException if [targetIp] is not an IP literal or [port] is not in 1..65535
     *   (checked before anything reaches the native bridge).
     * @throws WireGuardException if the tunnel is closed or the bridge cannot open the forwarder.
     */
    fun openForward(targetIp: String, port: Int): LoopbackForward

    /**
     * Handshake time and byte counters. **Poll sparingly**: at most every 5 s and only while
     * the UI is visible. Every call makes wireguard-go serialise its private and preshared keys
     * into an internal buffer.
     */
    fun stats(): TunnelStats

    /** Reopens the UDP socket so that the tunnel re-handshakes at once (network change, wake-up). */
    fun rebind()

    /** Stops the tunnel and its forwarders. Idempotent. */
    override fun close()
}

/**
 * A loopback listener on `127.0.0.1:[port]` that accepts one connection. The client must send
 * [token] (32 bytes) first; with `:core:ssh` pass both to `LoopbackPreamble(port, token)`.
 *
 * The token is copied on construction and on every read of [token]; call [wipe] when done (the
 * tunnel that created the forward also wipes it when the tunnel is closed). [toString] never
 * shows it.
 */
class LoopbackForward(val port: Int, token: ByteArray) {
    private val stored: ByteArray

    init {
        require(port in 1..65535) { "port must be in 1..65535" }
        require(token.size == TOKEN_SIZE) { "token must be $TOKEN_SIZE bytes" }
        stored = token.copyOf()
    }

    /** A fresh copy of the token on every call; callers should wipe it after use. */
    val token: ByteArray get() = stored.copyOf()

    /** Zero-fills the stored token. */
    fun wipe() {
        stored.fill(0)
    }

    override fun toString(): String = "LoopbackForward(port=$port, token=***)"

    companion object {
        const val TOKEN_SIZE = 32
    }
}

/**
 * @property lastHandshakeEpochSeconds time of the latest completed handshake, or null if none yet.
 * @property rxBytes bytes received through the tunnel (as counted by wireguard-go).
 * @property txBytes bytes sent through the tunnel.
 * @property lastForwardError most recent forwarder error (ASCII, at most 120 chars), if any.
 * @property lastDeviceError most recent error logged by wireguard-go (ASCII, at most 256 chars), if any.
 */
data class TunnelStats(
    val lastHandshakeEpochSeconds: Long?,
    val rxBytes: Long,
    val txBytes: Long,
    val lastForwardError: String?,
    val lastDeviceError: String?,
)

/**
 * Creates the platform backend. On Android this loads `libwgbridge.so` from the APK through
 * JNI; on the desktop it binds the shared library through JNA (see the module README for the
 * lookup rules). Loading happens once per process and the library is never unloaded.
 *
 * @throws WireGuardException if the native library cannot be found or loaded.
 */
expect fun createWireGuardBackend(): WireGuardBackend
