// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.vault

/**
 * An X25519 key pair identifying one device. Keep [privateKey] in the platform key store (Android Keystore wrapping,
 * macOS Keychain, Windows DPAPI) and publish [publicKey] in the vault with [VaultCodec.addDeviceSlot].
 * [close] zeroes the private key bytes held here.
 */
class DeviceKeyPair(val publicKey: ByteArray, val privateKey: ByteArray) : AutoCloseable {
    init {
        require(publicKey.size == 32 && privateKey.size == 32) { "X25519 keys are 32 bytes" }
    }

    override fun close() {
        privateKey.fill(0)
    }

    override fun toString(): String = "DeviceKeyPair(publicKey=${publicKey.size} bytes)"
}
