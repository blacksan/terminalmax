// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.feature.app

import java.util.Base64
import org.terminalmax.core.ssh.HostKeyDecision
import org.terminalmax.core.ssh.HostKeyVerifier
import org.terminalmax.core.ssh.SshAuth
import org.terminalmax.core.sync.VaultSession
import org.terminalmax.core.vault.AlgorithmProfiles
import org.terminalmax.core.vault.HostPayload
import org.terminalmax.core.vault.IdentityPayload
import org.terminalmax.core.vault.KnownHostPayload
import org.terminalmax.core.vault.Payloads
import org.terminalmax.core.vault.PrivateKeyPayload
import org.terminalmax.core.vault.RecordType
import org.terminalmax.core.vault.VaultContent
import org.terminalmax.core.vault.VaultRecord
import org.terminalmax.core.vault.WireGuardProfilePayload

/** A host as the list shows it. Secrets are not part of it. */
data class HostItem(
    val id: String,
    val label: String,
    val address: String,
    val port: Int,
    val username: String,
    val identityId: String?,
    val wireGuardProfileId: String?,
    val legacy: Boolean,
    val consoleOptions: String?,
) {
    /** The name sent to the server: the user name plus the RouterOS console options (`admin+ct80w`). */
    val sshUsername: String get() = username + consoleOptions.orEmpty()
    val subtitle: String get() = "$username@$address:$port"
}

data class WgProfileItem(val id: String, val label: String, val address: String, val endpoint: String)

private fun VaultContent.live(type: RecordType): List<VaultRecord> =
    records.filter { it.type == type && !it.deleted }

private fun hostOf(record: VaultRecord): HostItem? = try {
    val p = Payloads.host(record.payload)
    HostItem(
        id = record.id,
        label = p.label,
        address = p.address,
        port = p.port,
        username = p.username,
        identityId = p.identityId,
        wireGuardProfileId = p.wireGuardProfileId,
        legacy = p.algorithmProfile == AlgorithmProfiles.LEGACY,
        consoleOptions = p.routerOsConsoleOptions?.takeIf { it.isNotEmpty() },
    )
} catch (_: Exception) {
    null
}

fun VaultContent.hosts(): List<HostItem> =
    live(RecordType.Host).mapNotNull { hostOf(it) }.sortedBy { it.label.lowercase() }

fun VaultContent.hostById(id: String): HostItem? = live(RecordType.Host).firstOrNull { it.id == id }?.let { hostOf(it) }

fun VaultContent.wireGuardProfiles(): List<WgProfileItem> = live(RecordType.WireGuardProfile).mapNotNull { r ->
    try {
        val p = Payloads.wireGuardProfile(r.payload)
        val info = (validateWgConfig(p.configText) as? WgValidation.Valid)?.info
        WgProfileItem(r.id, p.label, info?.address.orEmpty(), info?.endpoint.orEmpty())
    } catch (_: Exception) {
        null
    }
}.sortedBy { it.label.lowercase() }

fun VaultContent.wireGuardConfig(id: String): String? =
    live(RecordType.WireGuardProfile).firstOrNull { it.id == id }?.let {
        try {
            Payloads.wireGuardProfile(it.payload).configText
        } catch (_: Exception) {
            null
        }
    }

fun VaultContent.knownHosts(): List<Pair<String, KnownHostPayload>> = live(RecordType.KnownHost).mapNotNull { r ->
    try {
        r.id to Payloads.knownHost(r.payload)
    } catch (_: Exception) {
        null
    }
}

/** The SSH credentials of [host], or null if none are stored. The caller wipes the password after connecting. */
fun VaultContent.authFor(host: HostItem): SshAuth? {
    val identityRecord = host.identityId?.let { id -> live(RecordType.Identity).firstOrNull { it.id == id } } ?: return null
    val identity: IdentityPayload = try {
        Payloads.identity(identityRecord.payload)
    } catch (_: Exception) {
        return null
    }
    val keyId = identity.privateKeyId
    if (keyId != null) {
        val keyRecord = live(RecordType.PrivateKey).firstOrNull { it.id == keyId } ?: return null
        val key: PrivateKeyPayload = try {
            Payloads.privateKey(keyRecord.payload)
        } catch (_: Exception) {
            return null
        }
        return SshAuth.PrivateKey(key.pem, key.passphrase?.takeIf { it.isNotEmpty() }?.toCharArray())
    }
    return SshAuth.Password((identity.password ?: "").toCharArray())
}

/** Host-key trust store backed by the KnownHost records of one snapshot of the vault. */
fun knownHostVerifier(known: List<KnownHostPayload>): HostKeyVerifier = object : HostKeyVerifier {
    override fun check(host: String, port: Int, keyType: String, fingerprintSha256: String, key: ByteArray): HostKeyDecision {
        val forType = known.filter { it.host.equals(host, ignoreCase = true) && it.port == port && it.keyType == keyType }
        if (forType.isEmpty()) return HostKeyDecision.Unknown
        val encoded = Base64.getEncoder().encodeToString(key)
        return if (forType.any { it.keyBase64 == encoded }) HostKeyDecision.Trusted else HostKeyDecision.Mismatch
    }

    override fun knownKeyTypes(host: String, port: Int): List<String> =
        known.filter { it.host.equals(host, ignoreCase = true) && it.port == port }.map { it.keyType }.distinct()
}

/** Loads the editor draft of [hostId] (or an empty one). Secrets are not loaded. */
fun VaultContent.draftFor(hostId: String?): HostDraft {
    if (hostId == null) return HostDraft()
    val host = hostById(hostId) ?: return HostDraft()
    var kind = AuthKind.Password
    var storedPassword = false
    var storedKey = false
    val identityRecord = host.identityId?.let { id -> live(RecordType.Identity).firstOrNull { it.id == id } }
    if (identityRecord != null) {
        try {
            val identity = Payloads.identity(identityRecord.payload)
            if (identity.privateKeyId != null) {
                kind = AuthKind.Key
                storedKey = true
            } else {
                storedPassword = !identity.password.isNullOrEmpty()
            }
        } catch (_: Exception) {
            // Treat an unreadable identity as "nothing stored".
        }
    }
    return HostDraft(
        id = host.id,
        label = host.label,
        address = host.address,
        port = host.port.toString(),
        username = host.username,
        auth = kind,
        wireGuardProfileId = host.wireGuardProfileId,
        legacy = host.legacy,
        consoleOptions = host.consoleOptions.orEmpty(),
        hasStoredPassword = storedPassword,
        hasStoredKey = storedKey,
    )
}

/** Writes [draft] as Host + Identity (+ PrivateKey) records in one edit. [draft] must have passed [validateHostDraft]. */
suspend fun VaultSession.saveHost(draft: HostDraft) {
    edit { e ->
        val content = e.content
        val existingHost = draft.id?.let { id -> content.records.firstOrNull { it.id == id && !it.deleted && it.type == RecordType.Host } }
        val existingHostPayload = existingHost?.let { runCatching { Payloads.host(it.payload) }.getOrNull() }
        val identityId = existingHostPayload?.identityId
        val existingIdentityRecord = identityId?.let { id -> content.records.firstOrNull { it.id == id && !it.deleted && it.type == RecordType.Identity } }
        val existingIdentity = existingIdentityRecord?.let { runCatching { Payloads.identity(it.payload) }.getOrNull() }
        val existingKeyId = existingIdentity?.privateKeyId
        val existingKey = existingKeyId
            ?.let { id -> content.records.firstOrNull { it.id == id && !it.deleted && it.type == RecordType.PrivateKey } }
            ?.let { runCatching { Payloads.privateKey(it.payload) }.getOrNull() }

        val username = draft.username.trim()
        val savedIdentityId: String
        when (draft.auth) {
            AuthKind.Password -> {
                val password = when {
                    draft.password.isNotEmpty() -> draft.password
                    existingIdentity != null && existingIdentity.privateKeyId == null -> existingIdentity.password ?: ""
                    else -> ""
                }
                savedIdentityId = e.upsertIdentity(
                    IdentityPayload(label = draft.label.trim(), username = username, password = password, privateKeyId = null),
                    id = identityId,
                ).id
                if (existingKeyId != null) e.delete(existingKeyId)
            }
            AuthKind.Key -> {
                val replacing = draft.privateKeyPem.isNotBlank()
                val pem = if (replacing) draft.privateKeyPem.trim() + "\n" else existingKey?.pem.orEmpty()
                val passphrase = when {
                    draft.passphrase.isNotEmpty() -> draft.passphrase
                    replacing -> null
                    else -> existingKey?.passphrase
                }
                val keyRecord = e.upsertPrivateKey(
                    PrivateKeyPayload(label = draft.label.trim() + " key", pem = pem, passphrase = passphrase),
                    id = existingKeyId,
                )
                savedIdentityId = e.upsertIdentity(
                    IdentityPayload(label = draft.label.trim(), username = username, password = null, privateKeyId = keyRecord.id),
                    id = identityId,
                ).id
            }
        }
        e.upsertHost(
            HostPayload(
                label = draft.label.trim(),
                address = draft.address.trim(),
                port = draft.port.trim().toInt(),
                username = username,
                identityId = savedIdentityId,
                wireGuardProfileId = draft.wireGuardProfileId,
                algorithmProfile = if (draft.legacy) AlgorithmProfiles.LEGACY else AlgorithmProfiles.MODERN,
                routerOsConsoleOptions = normalizeConsoleOptions(draft.consoleOptions).takeIf { it.isNotEmpty() },
            ),
            id = draft.id,
        )
    }
}

/** Deletes a host together with the identity and key that belong to it. */
suspend fun VaultSession.deleteHost(hostId: String) {
    edit { e ->
        val content = e.content
        val host = content.records.firstOrNull { it.id == hostId && it.type == RecordType.Host && !it.deleted } ?: return@edit
        val payload = runCatching { Payloads.host(host.payload) }.getOrNull()
        val identityId = payload?.identityId
        if (identityId != null) {
            val identity = content.records.firstOrNull { it.id == identityId && it.type == RecordType.Identity && !it.deleted }
                ?.let { runCatching { Payloads.identity(it.payload) }.getOrNull() }
            identity?.privateKeyId?.let { e.delete(it) }
            e.delete(identityId)
        }
        e.delete(hostId)
    }
}

suspend fun VaultSession.importWireGuardProfile(label: String, configText: String) {
    edit { it.upsertWireGuardProfile(WireGuardProfilePayload(label = label, configText = configText)) }
}

/** Deletes a profile; hosts that used it keep working without a tunnel (their profile link is cleared). */
suspend fun VaultSession.deleteWireGuardProfile(profileId: String) {
    edit { e ->
        for (r in e.content.records.filter { it.type == RecordType.Host && !it.deleted }) {
            val p = runCatching { Payloads.host(r.payload) }.getOrNull() ?: continue
            if (p.wireGuardProfileId == profileId) e.upsertHost(p.copy(wireGuardProfileId = null), id = r.id)
        }
        e.delete(profileId)
    }
}

suspend fun VaultSession.trustHostKey(host: String, port: Int, keyType: String, fingerprint: String, key: ByteArray, replace: Boolean) {
    val encoded = Base64.getEncoder().encodeToString(key)
    edit { e ->
        var id: String? = null
        if (replace) {
            id = e.content.records.firstOrNull { r ->
                r.type == RecordType.KnownHost && !r.deleted &&
                    runCatching { Payloads.knownHost(r.payload) }.getOrNull()
                        ?.let { it.host.equals(host, ignoreCase = true) && it.port == port && it.keyType == keyType } == true
            }?.id
        }
        e.upsertKnownHost(KnownHostPayload(host, port, keyType, fingerprint, encoded), id = id)
    }
}
