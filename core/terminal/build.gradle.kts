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
        // Engine adapter shared by Android and desktop. A true intermediate source set between
        // androidMain and jvm("desktop") is unreliable with the AGP KMP library plugin (KT-80409:
        // the hierarchy-template group does not attach androidMain), so the same directory is
        // added as a source root of both JVM-like leaf source sets instead.
        val jvmCommonDir = "src/jvmCommonMain/kotlin"
        getByName("androidMain").kotlin.srcDir(jvmCommonDir)
        getByName("desktopMain").kotlin.srcDir(jvmCommonDir)

        commonMain.dependencies {
            api(libs.kotlinx.coroutines.core)
        }
        getByName("androidMain").dependencies {
            implementation(libs.jediterm.core)
            implementation(libs.slf4j.api)
        }
        getByName("desktopMain").dependencies {
            implementation(libs.jediterm.core)
            implementation(libs.slf4j.api)
        }
    }
}
