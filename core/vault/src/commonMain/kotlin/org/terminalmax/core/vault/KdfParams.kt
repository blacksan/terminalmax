// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.vault

/** Argon2id cost parameters. Validated before use so a malicious file cannot force absurd work. */
data class KdfParams(val memoryKiB: Int, val iterations: Int, val parallelism: Int) {

    /** Work estimate used for the per-file budget: memory (KiB) times passes. */
    val cost: Long get() = memoryKiB.toLong() * iterations.toLong()

    /** @throws VaultException.KdfParamsOutOfRange when any value is outside the accepted bounds. */
    fun validate() {
        if (memoryKiB !in MIN_MEMORY_KIB..MAX_MEMORY_KIB) {
            throw VaultException.KdfParamsOutOfRange("memory must be between 8 MiB and 1 GiB")
        }
        if (iterations !in MIN_ITERATIONS..MAX_ITERATIONS) {
            throw VaultException.KdfParamsOutOfRange("iterations must be between $MIN_ITERATIONS and $MAX_ITERATIONS")
        }
        if (parallelism !in MIN_PARALLELISM..MAX_PARALLELISM) {
            throw VaultException.KdfParamsOutOfRange("parallelism must be between $MIN_PARALLELISM and $MAX_PARALLELISM")
        }
    }

    companion object {
        const val MIN_MEMORY_KIB = 8 * 1024
        const val MAX_MEMORY_KIB = 1024 * 1024
        const val MIN_ITERATIONS = 1
        const val MAX_ITERATIONS = 10
        const val MIN_PARALLELISM = 1
        const val MAX_PARALLELISM = 16

        /**
         * Default ceiling on the memory a reader is willing to spend on one password slot (128 MiB, twice the
         * default of 64 MiB). It is checked against the unauthenticated header before any key derivation, so a
         * foreign file cannot make a phone allocate more than this on its heap (the Argon2 implementation is pure
         * JVM and allocates the whole matrix up front).
         */
        const val PLATFORM_CEILING_KIB = 128 * 1024

        /** Largest sum of [cost] over all password slots of one file: four times the default cost (64 MiB, t=3). */
        const val MAX_TOTAL_COST: Long = 4L * 65_536L * 3L

        /** 64 MiB, t=3, p=4. */
        val Default = KdfParams(memoryKiB = 64 * 1024, iterations = 3, parallelism = 4)
    }
}
