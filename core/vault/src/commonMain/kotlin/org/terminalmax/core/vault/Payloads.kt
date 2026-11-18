// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.vault

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

/** Algorithm profile names stored in [HostPayload.algorithmProfile]. */
object AlgorithmProfiles {
    const val MODERN = "Modern"
    const val LEGACY = "Legacy"
}

@Serializable
data class HostPayload(
    val label: String,
    val address: String,
    val port: Int = 22,
    val username: String,
    val identityId: String? = null,
    val wireGuardProfileId: String? = null,
    val algorithmProfile: String = AlgorithmProfiles.MODERN,
    val routerOsConsoleOptions: String? = null,
)

@Serializable
data class IdentityPayload(
    val label: String,
    val username: String,
    val password: String? = null,
    val privateKeyId: String? = null,
)

@Serializable
data class PrivateKeyPayload(
    val label: String,
    val pem: String,
    val passphrase: String? = null,
)

@Serializable
data class WireGuardProfilePayload(
    val label: String,
    val configText: String,
)

@Serializable
data class KnownHostPayload(
    val host: String,
    val port: Int = 22,
    val keyType: String,
    val fingerprintSha256: String,
    val keyBase64: String,
)

@Serializable
data class SnippetPayload(
    val label: String,
    val text: String,
)

/** Conversions between typed payloads and the raw JSON stored in [VaultRecord.payload]. */
object Payloads {
    fun toJson(value: HostPayload): JsonObject = VaultJson.encodePayload(HostPayload.serializer(), value)
    fun toJson(value: IdentityPayload): JsonObject = VaultJson.encodePayload(IdentityPayload.serializer(), value)
    fun toJson(value: PrivateKeyPayload): JsonObject = VaultJson.encodePayload(PrivateKeyPayload.serializer(), value)
    fun toJson(value: WireGuardProfilePayload): JsonObject =
        VaultJson.encodePayload(WireGuardProfilePayload.serializer(), value)
    fun toJson(value: KnownHostPayload): JsonObject = VaultJson.encodePayload(KnownHostPayload.serializer(), value)
    fun toJson(value: SnippetPayload): JsonObject = VaultJson.encodePayload(SnippetPayload.serializer(), value)

    fun host(payload: JsonObject): HostPayload = VaultJson.decodePayload(HostPayload.serializer(), payload)
    fun identity(payload: JsonObject): IdentityPayload = VaultJson.decodePayload(IdentityPayload.serializer(), payload)
    fun privateKey(payload: JsonObject): PrivateKeyPayload =
        VaultJson.decodePayload(PrivateKeyPayload.serializer(), payload)
    fun wireGuardProfile(payload: JsonObject): WireGuardProfilePayload =
        VaultJson.decodePayload(WireGuardProfilePayload.serializer(), payload)
    fun knownHost(payload: JsonObject): KnownHostPayload =
        VaultJson.decodePayload(KnownHostPayload.serializer(), payload)
    fun snippet(payload: JsonObject): SnippetPayload = VaultJson.decodePayload(SnippetPayload.serializer(), payload)

    /** Field names the typed payload for [type] understands; empty for free-form or unknown types. */
    internal fun knownKeys(type: RecordType): Set<String> {
        val serializer: KSerializer<*>? = when (type) {
            RecordType.Host -> HostPayload.serializer()
            RecordType.Identity -> IdentityPayload.serializer()
            RecordType.PrivateKey -> PrivateKeyPayload.serializer()
            RecordType.WireGuardProfile -> WireGuardProfilePayload.serializer()
            RecordType.KnownHost -> KnownHostPayload.serializer()
            RecordType.Snippet -> SnippetPayload.serializer()
            RecordType.Settings, RecordType.Unknown -> null
        }
        return serializer?.descriptor?.let { d -> (0 until d.elementsCount).map { d.getElementName(it) }.toSet() }
            ?: emptySet()
    }
}
