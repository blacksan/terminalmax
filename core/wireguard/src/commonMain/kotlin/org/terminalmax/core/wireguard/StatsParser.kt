// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.wireguard

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json

/** Wire format of `wgbStats`: see native/wgbridge/wgconf/stats.go (Stats.JSON). */
@Serializable
internal class RawStats(
    @SerialName("last_handshake_unix_ms") val lastHandshakeUnixMs: Long = 0,
    @SerialName("rx_bytes") val rxBytes: Long = 0,
    @SerialName("tx_bytes") val txBytes: Long = 0,
    @SerialName("last_forward_error") val lastForwardError: String? = null,
    @SerialName("last_device_error") val lastDeviceError: String? = null,
)

private val statsJson = Json { ignoreUnknownKeys = true }

/** Parses the bridge's stats JSON. A handshake time of 0 means "no handshake yet" (null). */
internal fun parseTunnelStats(json: String): TunnelStats {
    val raw = try {
        statsJson.decodeFromString(RawStats.serializer(), json)
    } catch (e: SerializationException) {
        throw WireGuardException("unparseable stats from the native bridge", e)
    } catch (e: IllegalArgumentException) {
        throw WireGuardException("unparseable stats from the native bridge", e)
    }
    return TunnelStats(
        lastHandshakeEpochSeconds = if (raw.lastHandshakeUnixMs > 0) raw.lastHandshakeUnixMs / 1000 else null,
        rxBytes = raw.rxBytes,
        txBytes = raw.txBytes,
        lastForwardError = raw.lastForwardError?.takeIf { it.isNotEmpty() },
        lastDeviceError = raw.lastDeviceError?.takeIf { it.isNotEmpty() },
    )
}

/** Largest config the bridge accepts (it rejects anything over 1 MiB). */
internal const val MAX_CONFIG_BYTES = 1 shl 20

/**
 * Validates an IP literal and a port and renders the `host:port` target of the bridge
 * (IPv6 in brackets). Accepts only characters that can occur in an IP literal; whether the
 * address is well-formed is decided by the native side.
 */
internal fun formatForwardTarget(targetIp: String, port: Int): String {
    if (targetIp.isEmpty() || targetIp.length > 64) {
        throw IllegalArgumentException("targetIp must be an IP literal")
    }
    for (c in targetIp) {
        val ok = c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F' || c == '.' || c == ':'
        if (!ok) throw IllegalArgumentException("targetIp must be an IP literal without brackets or zone")
    }
    if (port !in 1..65535) throw IllegalArgumentException("port must be in 1..65535")
    return if (targetIp.contains(':')) "[$targetIp]:$port" else "$targetIp:$port"
}
