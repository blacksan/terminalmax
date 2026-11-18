// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.ssh

internal actual fun installSecurityProvider() {
    // No-op: sshj registers the BouncyCastle provider on its own on a regular JVM.
}
