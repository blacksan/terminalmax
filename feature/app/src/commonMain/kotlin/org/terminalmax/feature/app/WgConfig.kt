// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.feature.app

/** Non-secret facts of a WireGuard configuration. The private key is never part of this. */
data class WgConfigInfo(
    val address: String,
    val endpoint: String,
    val allowedIps: String,
    val peerCount: Int,
)

sealed interface WgValidation {
    data class Valid(val info: WgConfigInfo) : WgValidation
    data class Invalid(val errors: List<String>) : WgValidation
}

private const val MAX_WG_CONFIG_CHARS = 64 * 1024
private val WG_KEY = Regex("^[A-Za-z0-9+/]{43}=$")

private class Section(val name: String, val values: MutableMap<String, String> = LinkedHashMap())

/**
 * Minimal validation of a wg-quick style configuration: [Interface] needs PrivateKey and Address, every [Peer]
 * needs PublicKey, Endpoint and AllowedIPs. The native bridge does the full parse when a tunnel starts; this only
 * catches the usual paste mistakes early. Error messages never contain key material.
 */
fun validateWgConfig(text: String): WgValidation {
    val errors = ArrayList<String>()
    if (text.isBlank()) return WgValidation.Invalid(listOf("The configuration is empty."))
    if (text.length > MAX_WG_CONFIG_CHARS) return WgValidation.Invalid(listOf("The configuration is too large."))
    if (text.indexOf('\u0000') >= 0) return WgValidation.Invalid(listOf("The configuration contains binary data."))

    val sections = ArrayList<Section>()
    var current: Section? = null
    var lineNo = 0
    for (raw in text.lines()) {
        lineNo++
        val line = raw.substringBefore('#').trim()
        if (line.isEmpty()) continue
        if (line.startsWith("[")) {
            if (!line.endsWith("]")) {
                errors += "Line $lineNo: a section header must look like [Interface] or [Peer]."
                continue
            }
            val name = line.substring(1, line.length - 1).trim()
            current = Section(name.lowercase())
            sections += current
            continue
        }
        val eq = line.indexOf('=')
        if (eq <= 0) {
            errors += "Line $lineNo: expected 'Key = value'."
            continue
        }
        val section = current
        if (section == null) {
            errors += "Line $lineNo: this line is outside any section."
            continue
        }
        val key = line.substring(0, eq).trim().lowercase()
        val value = line.substring(eq + 1).trim()
        // Repeated keys (for example several AllowedIPs lines) are joined.
        val previous = section.values[key]
        section.values[key] = if (previous == null) value else "$previous, $value"
    }

    val interfaces = sections.filter { it.name == "interface" }
    val peers = sections.filter { it.name == "peer" }
    for (s in sections) {
        if (s.name != "interface" && s.name != "peer") errors += "Unknown section [${s.name}]."
    }
    if (interfaces.size != 1) errors += "Exactly one [Interface] section is required."
    if (peers.isEmpty()) errors += "At least one [Peer] section is required."

    var address = ""
    interfaces.firstOrNull()?.let { s ->
        val key = s.values["privatekey"]
        when {
            key.isNullOrEmpty() -> errors += "[Interface] needs a PrivateKey."
            !WG_KEY.matches(key) -> errors += "[Interface] PrivateKey is not a valid WireGuard key (44 characters of base64)."
        }
        address = s.values["address"].orEmpty()
        if (address.isEmpty()) errors += "[Interface] needs an Address."
    }
    var endpoint = ""
    var allowed = ""
    peers.forEachIndexed { index, s ->
        val label = if (peers.size > 1) "[Peer] #${index + 1}" else "[Peer]"
        val pub = s.values["publickey"]
        when {
            pub.isNullOrEmpty() -> errors += "$label needs a PublicKey."
            !WG_KEY.matches(pub) -> errors += "$label PublicKey is not a valid WireGuard key (44 characters of base64)."
        }
        val ep = s.values["endpoint"]
        if (ep.isNullOrEmpty()) {
            errors += "$label needs an Endpoint (host:port)."
        } else if (!isValidEndpoint(ep)) {
            errors += "$label Endpoint must look like host:port, for example 203.0.113.5:13231."
        }
        val ips = s.values["allowedips"]
        if (ips.isNullOrEmpty()) errors += "$label needs AllowedIPs."
        if (index == 0) {
            endpoint = ep.orEmpty()
            allowed = ips.orEmpty()
        }
    }
    return if (errors.isEmpty()) {
        WgValidation.Valid(WgConfigInfo(address, endpoint, allowed, peers.size))
    } else {
        WgValidation.Invalid(errors)
    }
}

internal fun isValidEndpoint(value: String): Boolean {
    val host: String
    val portText: String
    if (value.startsWith("[")) {
        val close = value.indexOf("]:")
        if (close < 0) return false
        host = value.substring(1, close)
        portText = value.substring(close + 2)
    } else {
        val colon = value.lastIndexOf(':')
        if (colon <= 0) return false
        host = value.substring(0, colon)
        portText = value.substring(colon + 1)
    }
    val port = portText.toIntOrNull() ?: return false
    return host.isNotBlank() && !host.any { it.isWhitespace() } && port in 1..65535
}
