// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.vault

/**
 * A decrypted vault: its [content] plus the (secret) data key needed to re-seal it. Call [close] when done; it
 * zeroes the key bytes this object holds. Instances produced by [withContent] and the codec's slot operations own
 * independent copies of the key and must be closed separately.
 *
 * [keyEpoch] counts data-key replacements and [headerRevision] counts changes of the slot set; both are
 * authenticated by the file they were read from.
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

    /** Number of changes to the slot set (starts at 1). */
    val headerRevision: Long get() = header.headerRevision

    /** All key slots in the header. */
    val slots: List<SlotInfo> get() = header.slots.map { SlotInfo(it.id, it.type) }

    /** Ids of all key slots in the header. */
    val slotIds: List<String> get() = header.slots.map { it.id }

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
