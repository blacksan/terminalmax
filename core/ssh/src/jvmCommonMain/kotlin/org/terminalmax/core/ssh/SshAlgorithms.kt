// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.ssh

import net.schmizz.keepalive.KeepAliveProvider
import net.schmizz.sshj.Config
import net.schmizz.sshj.DefaultConfig
import net.schmizz.sshj.common.Factory

/**
 * Explicit algorithm lists, in preference order. sshj's own defaults prefer aes128-cbc over
 * aes128-ctr, hmac-sha1 over hmac-sha2 and enable 1024-bit DH, DSA, RC4 and MD5, so the
 * defaults are never used as they are.
 *
 * The lists hold algorithm names. A name that this sshj build or the platform crypto does not
 * provide is skipped when the config is built.
 */
internal object SshAlgorithms {
    // "ext-info-c" must stay: it makes servers send server-sig-algs, which user authentication
    // needs to use rsa-sha2-* instead of ssh-rsa. Strict KEX (Terrapin mitigation) is added by sshj.
    val MODERN_KEX = listOf(
        "curve25519-sha256",
        "curve25519-sha256@libssh.org",
        "ecdh-sha2-nistp521",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp256",
        "diffie-hellman-group-exchange-sha256",
        "diffie-hellman-group18-sha512",
        "diffie-hellman-group16-sha512",
        "diffie-hellman-group14-sha256",
        "ext-info-c",
    )

    val MODERN_CIPHERS = listOf(
        "chacha20-poly1305@openssh.com",
        "aes256-gcm@openssh.com",
        "aes128-gcm@openssh.com",
        "aes256-ctr",
        "aes192-ctr",
        "aes128-ctr",
    )

    val MODERN_MACS = listOf(
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512-etm@openssh.com",
        "hmac-sha2-256",
        "hmac-sha2-512",
    )

    val MODERN_KEYS = listOf(
        "ssh-ed25519-cert-v01@openssh.com",
        "ssh-ed25519",
        "sk-ssh-ed25519@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com",
        "ecdsa-sha2-nistp521-cert-v01@openssh.com",
        "ecdsa-sha2-nistp521",
        "ecdsa-sha2-nistp384-cert-v01@openssh.com",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp256-cert-v01@openssh.com",
        "ecdsa-sha2-nistp256",
        "rsa-sha2-512",
        "rsa-sha2-256",
    )

    // Appended after the modern lists, so they are only chosen when the server has nothing better.
    // Never RC4 (arcfour*), MD5 (hmac-md5*) or "none".
    val LEGACY_KEX = listOf(
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1",
        "diffie-hellman-group1-sha1",
    )
    val LEGACY_CIPHERS = listOf("aes256-cbc", "aes192-cbc", "aes128-cbc", "3des-cbc")
    val LEGACY_MACS = listOf("hmac-sha1")
    val LEGACY_KEYS = listOf("ssh-rsa", "ssh-dss")

    private val AEAD_CIPHERS = setOf(
        "chacha20-poly1305@openssh.com",
        "aes256-gcm@openssh.com",
        "aes128-gcm@openssh.com",
    )

    private val modernKex = MODERN_KEX.toSet()
    private val modernCiphers = MODERN_CIPHERS.toSet()
    private val modernMacs = MODERN_MACS.toSet()
    private val modernKeys = MODERN_KEYS.toSet()

    fun isLegacy(negotiated: NegotiatedAlgorithms): Boolean {
        if (negotiated.kex !in modernKex) return true
        if (negotiated.hostKey !in modernKeys) return true
        if (negotiated.cipherC2s !in modernCiphers || negotiated.cipherS2c !in modernCiphers) return true
        // The MAC is not used with an AEAD cipher; sshj still reports one.
        if (negotiated.cipherC2s !in AEAD_CIPHERS && negotiated.macC2s !in modernMacs) return true
        if (negotiated.cipherS2c !in AEAD_CIPHERS && negotiated.macS2c !in modernMacs) return true
        return false
    }
}

/**
 * The two sshj configs, built once on first use (a [DefaultConfig] self-tests every cipher) and
 * shared by all connections. A [Config] is read-only after construction; everything that differs
 * per connection (timeouts, keep-alive interval, host-key verifier) is set on the client, not here.
 */
internal object SshjConfigs {
    private val modern: Config by lazy(LazyThreadSafetyMode.SYNCHRONIZED) { build(AlgorithmProfile.Modern) }
    private val legacy: Config by lazy(LazyThreadSafetyMode.SYNCHRONIZED) { build(AlgorithmProfile.Legacy) }

    /** Call after the security provider is installed. */
    fun forProfile(profile: AlgorithmProfile): Config = when (profile) {
        AlgorithmProfile.Modern -> modern
        AlgorithmProfile.Legacy -> legacy
    }

    private fun build(profile: AlgorithmProfile): Config {
        fun names(modern: List<String>, legacy: List<String>): List<String> =
            if (profile == AlgorithmProfile.Legacy) modern + legacy else modern

        val config = DefaultConfig()
        config.setKeyExchangeFactories(
            config.getKeyExchangeFactories()
                .pick("key exchange", names(SshAlgorithms.MODERN_KEX, SshAlgorithms.LEGACY_KEX)),
        )
        config.setCipherFactories(
            config.getCipherFactories()
                .pick("cipher", names(SshAlgorithms.MODERN_CIPHERS, SshAlgorithms.LEGACY_CIPHERS)),
        )
        config.setMACFactories(
            config.getMACFactories()
                .pick("MAC", names(SshAlgorithms.MODERN_MACS, SshAlgorithms.LEGACY_MACS)),
        )
        config.setKeyAlgorithms(
            config.getKeyAlgorithms()
                .pick("host key", names(SshAlgorithms.MODERN_KEYS, SshAlgorithms.LEGACY_KEYS)),
        )
        // HEARTBEAT (the default) sends SSH_MSG_IGNORE and expects no answer, so it can never
        // detect a dead peer. KEEP_ALIVE sends keepalive@openssh.com and counts missing replies.
        config.setKeepAliveProvider(KeepAliveProvider.KEEP_ALIVE)
        return config
    }

    /** The factories whose name is in [names], in the order of [names]. */
    private fun <T> List<Factory.Named<T>>.pick(kind: String, names: List<String>): List<Factory.Named<T>> {
        val picked = names.mapNotNull { name -> firstOrNull { it.name == name } }
        check(picked.isNotEmpty()) { "No usable $kind algorithm in this environment" }
        return picked
    }
}
