// SPDX-License-Identifier: GPL-3.0-or-later
plugins {
    id("terminalmax.kmp.library")
    alias(libs.plugins.kotlin.serialization)
}

kotlin {
    android {
        namespace = "org.terminalmax.core.vault"
        compileSdk = libs.versions.compileSdk.get().toInt()
        minSdk = libs.versions.minSdk.get().toInt()
    }

    sourceSets {
        val commonMain = getByName("commonMain")

        // Intermediate source set shared by the android and desktop (JVM) targets (same DSL as
        // :core:ssh). Holds the JCA + BouncyCastle file codec.
        val jvmCommonMain = create("jvmCommonMain") {
            dependsOn(commonMain)
            dependencies {
                implementation(libs.bouncycastle.bcprov)
            }
        }
        getByName("androidMain").dependsOn(jvmCommonMain)
        getByName("desktopMain").dependsOn(jvmCommonMain)

        commonMain.dependencies {
            api(libs.kotlinx.serialization.json)
        }
    }
}
