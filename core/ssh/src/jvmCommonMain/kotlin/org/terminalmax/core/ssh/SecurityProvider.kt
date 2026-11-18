// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.ssh

/**
 * Prepares the JCA provider list before sshj is first used. Android needs the full
 * BouncyCastle provider; the desktop JVM needs nothing (sshj registers BouncyCastle itself).
 */
internal expect fun installSecurityProvider()
