// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.ssh

import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider

/**
 * Android ships a cut-down provider registered as "BC". sshj needs the full BouncyCastle
 * (curve25519, ed25519, ...), so replace the platform one. Idempotent and thread-safe.
 */
object SshSecurity {
    @Synchronized
    fun install() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) is BouncyCastleProvider) return
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
        Security.insertProviderAt(BouncyCastleProvider(), 1)
    }
}

internal actual fun installSecurityProvider() = SshSecurity.install()
