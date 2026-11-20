// SPDX-License-Identifier: GPL-3.0-or-later
plugins {
    id("terminalmax.kmp.compose")
}

kotlin {
    android {
        namespace = "org.terminalmax.feature.app"
        compileSdk = libs.versions.compileSdk.get().toInt()
        minSdk = libs.versions.minSdk.get().toInt()
    }

    sourceSets {
        commonMain.dependencies {
            api(projects.core.designsystem)
            api(projects.core.terminal)
            api(projects.core.ssh)
            api(projects.core.wireguard)
            api(projects.core.vault)
            api(projects.core.sync)
            api(libs.kotlinx.coroutines.core)
            implementation(libs.kotlinx.serialization.json)
            implementation(libs.androidx.lifecycle.runtime.compose)
        }

        // Everything that touches the JVM-only APIs of :core:sync (VaultSession), :core:ssh (SshjTransport) and
        // :core:wireguard is compiled into BOTH leaf targets from one directory. A consumer's intermediate
        // "jvmCommonMain" source set cannot see another module's jvmCommonMain declarations, but each leaf
        // target sees the full platform variant of its dependencies.
        getByName("androidMain").kotlin.srcDir("src/jvmShared/kotlin")
        getByName("desktopMain").kotlin.srcDir("src/jvmShared/kotlin")

        getByName("desktopTest").dependencies {
            runtimeOnly(libs.slf4j.nop)
        }
    }
}
