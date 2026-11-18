// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.vault

import java.security.MessageDigest
import kotlin.io.encoding.Base64

/**
 * A decrypted vault: its [content] plus the (secret) data key needed to re-seal it. Call [close] when done; it
 * zeroes the key bytes this object holds. Instances produced by [withContent] and the codec's slot operations own
 * independent copies of the key and must be closed separately.
 *
 * [keyEpoch] counts data-key replacements (every change of the password slot is one); it is authenticated by the
 * file it was read from. The header of an open vault never changes within its key epoch.
 *
 * Note: [content] itself is ordinary heap data (strings) and cannot be zeroed, and the JCA and BouncyCastle keep
 * their own copies of key material while they work.
 */
class OpenVault internal constructor(
    val content: VaultContent,
    internal val header: VaultHeader,
    dataKey: ByteArray,
) : AutoCloseable {
    private val key: ByteArray = dataKey

    @Volatile
    private var closed = false

    val vaultId: String get() = header.vaultId

    /** Number of times the data key has been replaced (starts at 1). */
    val keyEpoch: Long get() = header.keyEpoch

    /** The key slots in the header (exactly one: the password slot). */
    val slots: List<SlotInfo> get() = header.slots.map { SlotInfo(it.id, it.type) }

    /** Ids of the key slots in the header. */
    val slotIds: List<String> get() = header.slots.map { it.id }

    /**
     * A short string for comparing this vault's key identity between devices out of band: the first 12 bytes of
     * `SHA-256(utf8(vaultId) || "|" || decimal(keyEpoch) || "|" || keyCommit)` as six groups of four upper-case hex
     * characters (`A1B2-C3D4-E5F6-0718-293A-4B5C`). It reveals nothing about the key (the commitment is public in
     * the header) and changes with every password change. Two devices that show the same value hold the same vault,
     * epoch and key.
     */
    val fingerprint: String
        get() {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(vaultId.toByteArray(Charsets.UTF_8))
            digest.update('|'.code.toByte())
            digest.update(keyEpoch.toString().toByteArray(Charsets.US_ASCII))
            digest.update('|'.code.toByte())
            digest.update(Base64.Default.decode(header.keyCommit))
            val hex = digest.digest().copyOf(12).joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
            return hex.uppercase().chunked(4).joinToString("-")
        }

    /** True when [other] holds the same data key (compared through the key commitments, in constant time). */
    fun hasSameKeyAs(other: OpenVault): Boolean =
        header.vaultId == other.header.vaultId && header.keyEpoch == other.header.keyEpoch &&
            MessageDigest.isEqual(Base64.Default.decode(header.keyCommit), Base64.Default.decode(other.header.keyCommit))

    /** A new [OpenVault] with the same key and header but different [newContent]. */
    fun withContent(newContent: VaultContent): OpenVault {
        require(newContent.vaultId == vaultId) { "Content belongs to a different vault" }
        return OpenVault(newContent, header, dataKey().copyOf())
    }

    /**
     * A small versioned binary blob that holds a copy of the current data key and its key epoch, for per-device
     * convenience unlock (biometrics, the OS keychain). Hand it to [VaultCodec.openWithLocalUnlockSecret] later.
     *
     * The blob is **the key itself**: the caller must store it only in platform secure storage (Android Keystore
     * wrapping, macOS Keychain, Windows DPAPI), never in the synced vault, a log or a backup, and must zero the
     * array after use (`fill(0)`). It stops working as soon as the vault is re-keyed (any password change), which is
     * how a device is revoked: the next unlock fails with [VaultException.KeyEpochMismatch] and the UI asks for the
     * password.
     */
    fun exportLocalUnlockSecret(): ByteArray = VaultCodec.encodeLocalUnlockSecret(vaultId, keyEpoch, dataKey())

    internal fun dataKey(): ByteArray {
        check(!closed) { "Vault is closed" }
        return key
    }

    override fun close() {
        closed = true
        key.fill(0)
    }

    override fun toString(): String = "OpenVault(vaultId=$vaultId, revision=${content.revision}, keyEpoch=$keyEpoch)"
}
