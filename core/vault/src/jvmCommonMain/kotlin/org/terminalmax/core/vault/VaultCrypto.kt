// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.vault

import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.security.GeneralSecurityException
import java.security.SecureRandom
import java.text.Normalizer
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import org.bouncycastle.crypto.params.HKDFParameters

/**
 * Primitive operations of the vault format. BouncyCastle's lightweight API is used for Argon2id and HKDF-SHA-256 so
 * nothing depends on which JCA providers a platform ships; AES-256-GCM and HMAC-SHA-256 go through the platform JCA.
 *
 * Key hygiene is best effort: the `ByteArray`s this code creates are zeroed after use, but the JCA (`SecretKeySpec`,
 * `Cipher`) and BouncyCastle keep their own internal copies of key material that nothing here can wipe.
 */
internal object VaultCrypto {
    const val KEY_BYTES = 32
    const val NONCE_BYTES = 12
    const val SALT_BYTES = 16
    const val TAG_BYTES = 16

    private val random = SecureRandom()

    /** Test hook: called with the parameters of every Argon2id derivation, before any work is done. */
    @Volatile
    var kdfObserver: ((KdfParams) -> Unit)? = null

    fun randomBytes(n: Int): ByteArray = ByteArray(n).also { random.nextBytes(it) }

    fun randomHex(bytes: Int): String =
        randomBytes(bytes).joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }

    /**
     * Password bytes: NFC-normalised, then strictly encoded as UTF-8. An unpaired surrogate is rejected instead
     * of silently replaced (two different passwords must never derive the same key). Intermediate buffers are
     * zeroed; the `String` that [Normalizer] returns for a password that was not already NFC cannot be.
     *
     * @throws IllegalArgumentException when [chars] is not valid UTF-16
     */
    fun encodePassword(chars: CharArray): ByteArray {
        var normalized: CharArray? = null
        val source: CharArray = if (Normalizer.isNormalized(CharBuffer.wrap(chars), Normalizer.Form.NFC)) {
            chars
        } else {
            val n = Normalizer.normalize(CharBuffer.wrap(chars), Normalizer.Form.NFC).toCharArray()
            normalized = n
            n
        }
        val encoder = Charsets.UTF_8.newEncoder()
            .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
            .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
        val out = ByteBuffer.allocate(source.size * 3 + 4) // worst case for UTF-16 -> UTF-8
        try {
            if (encoder.encode(CharBuffer.wrap(source), out, true).isError || encoder.flush(out).isError) {
                throw IllegalArgumentException("Password is not valid Unicode")
            }
            out.flip()
            val bytes = ByteArray(out.remaining())
            out.get(bytes)
            return bytes
        } finally {
            out.array().fill(0)
            normalized?.fill('\u0000')
        }
    }

    /** Argon2id (version 0x13), 32-byte output. [params] must already be validated. */
    fun argon2id(password: CharArray, salt: ByteArray, params: KdfParams): ByteArray {
        params.validate()
        kdfObserver?.invoke(params)
        val passwordBytes = encodePassword(password)
        try {
            val argon = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withIterations(params.iterations)
                .withMemoryAsKB(params.memoryKiB)
                .withParallelism(params.parallelism)
                .withSalt(salt)
                .build()
            val generator = Argon2BytesGenerator()
            generator.init(argon)
            val out = ByteArray(KEY_BYTES)
            generator.generateBytes(passwordBytes, out, 0, out.size)
            return out
        } finally {
            passwordBytes.fill(0)
        }
    }

    /** HKDF-SHA-256 (RFC 5869). */
    fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        val generator = HKDFBytesGenerator(SHA256Digest())
        generator.init(HKDFParameters(ikm, salt, info))
        val out = ByteArray(length)
        generator.generateBytes(out, 0, length)
        return out
    }

    /** HMAC-SHA-256. */
    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    fun gcmEncrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BYTES * 8, nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(plaintext)
    }

    /** @throws GeneralSecurityException when authentication fails */
    fun gcmDecrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BYTES * 8, nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(ciphertext)
    }
}
