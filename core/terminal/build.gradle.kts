// SPDX-License-Identifier: GPL-3.0-or-later
plugins {
    id("terminalmax.kmp.compose")
}

kotlin {
    android {
        namespace = "org.terminalmax.core.terminal"
        compileSdk = libs.versions.compileSdk.get().toInt()
        minSdk = libs.versions.minSdk.get().toInt()
    }

    sourceSets {
        val commonMain = getByName("commonMain")

        // Intermediate source set shared by the android and desktop (JVM) targets (same DSL as
        // :core:ssh). Holds the JediTerm adapter; expect/actual declarations live in commonMain
        // with actuals in androidMain/desktopMain.
        val jvmCommonMain = create("jvmCommonMain") {
            dependsOn(commonMain)
            dependencies {
                implementation(libs.jediterm.core)
            }
        }
        getByName("androidMain").dependsOn(jvmCommonMain)
        getByName("desktopMain").dependsOn(jvmCommonMain)

        commonMain.dependencies {
            api(libs.kotlinx.coroutines.core)
        }

        getByName("desktopTest").dependencies {
            // JediTerm logs through slf4j; silence it in tests only (apps bind slf4j-nop themselves).
            runtimeOnly(libs.slf4j.nop)
        }
    }
}
