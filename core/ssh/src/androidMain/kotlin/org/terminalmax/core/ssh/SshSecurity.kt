// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.ssh

import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider

/**
 * Android ships a cut-down provider registered as "BC". sshj needs the full BouncyCastle
 * (curve25519, ed25519, ...), so replace the platform one. Idempotent and thread-safe.
 *
 * The replacement is appended at the end of the provider list, not inserted at position 1:
 * sshj asks for its algorithms by provider name ("BC"), so its position does not matter to sshj,
 * while position 1 would change which provider answers every un-named JCA lookup in the process
 * and would push AndroidKeyStoreBCWorkaround out of the first position it relies on.
 */
object SshSecurity {
    @Synchronized
    fun install() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) is BouncyCastleProvider) return
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
        Security.addProvider(BouncyCastleProvider())
    }
}

internal actual fun installSecurityProvider() = SshSecurity.install()
