// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.sync

import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * What a **holder of a data key** (a stolen local unlock secret, a compromised device, a malicious co-user) can do
 * to a vault file without any password: decrypt it and write it again under a header of its choosing. Written with
 * `javax.crypto` only, from FORMAT.md, so the tests do not depend on the codec's own helpers.
 */
internal object HostileFiles {
    /** The data key inside a local unlock secret (its last 32 bytes). */
    fun keyOf(secret: ByteArray): ByteArray = secret.copyOfRange(secret.size - 32, secret.size)

    fun headerText(file: ByteArray): String {
        val len = ((file[6].toInt() and 0xff) shl 24) or ((file[7].toInt() and 0xff) shl 16) or
            ((file[8].toInt() and 0xff) shl 8) or (file[9].toInt() and 0xff)
        return String(file, 10, len, Charsets.UTF_8)
    }

    /** The JSON object of the (only) password slot of [file]. */
    fun slotOf(file: ByteArray): String = Regex("\\{\"id\":\"pw-[0-9a-f]{16}\",\"type\":\"password\"[^{}]*\\}")
        .find(headerText(file))!!.value

    private fun mac(key: ByteArray, data: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").run { init(SecretKeySpec(key, "HmacSHA256")); doFinal(data) }

    private fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray): ByteArray {
        val prk = mac(salt, ikm)
        return mac(prk, info + byteArrayOf(1)) // one block is 32 bytes: enough
    }

    private fun u32(v: Long) = byteArrayOf((v shr 24).toByte(), (v shr 16).toByte(), (v shr 8).toByte(), v.toByte())

    private fun cipher(mode: Int, key: ByteArray, aad: ByteArray): Cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
        init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(128, ByteArray(12)))
        updateAAD(aad)
    }

    /** Decrypts [file] with [key], rewrites its header text with [transform] and encrypts it again (fresh write salt). */
    fun forge(file: ByteArray, key: ByteArray, writeSalt: ByteArray = ByteArray(32) { (0xA0 + it).toByte() }, transform: (String) -> String): ByteArray {
        val header = headerText(file)
        val epoch = Regex("\"keyEpoch\":(\\d+)").find(header)!!.groupValues[1].toLong()
        val oldSalt = Base64.getDecoder().decode(Regex("\"writeSalt\":\"([^\"]*)\"").find(header)!!.groupValues[1])
        val oldHeader = header.toByteArray(Charsets.UTF_8)
        val ciphertext = file.copyOfRange(10 + oldHeader.size, file.size)
        val plain = cipher(
            Cipher.DECRYPT_MODE, hkdf(key, oldSalt, "TMXV2 content".toByteArray() + u32(epoch)),
            file.copyOfRange(0, 6) + oldHeader,
        ).doFinal(ciphertext)
        val newHeader = transform(header)
            .replace(Regex("\"writeSalt\":\"[^\"]*\""), "\"writeSalt\":\"" + Base64.getEncoder().encodeToString(writeSalt) + "\"")
            .toByteArray(Charsets.UTF_8)
        val ct = cipher(
            Cipher.ENCRYPT_MODE, hkdf(key, writeSalt, "TMXV2 content".toByteArray() + u32(epoch)),
            file.copyOfRange(0, 6) + newHeader,
        ).doFinal(plain)
        return file.copyOfRange(0, 6) + u32(newHeader.size.toLong()) + newHeader + ct
    }
}
