// SPDX-License-Identifier: GPL-3.0-or-later
plugins {
    id("terminalmax.kmp.library")
}

kotlin {
    android {
        namespace = "org.terminalmax.core.sync"
        compileSdk = libs.versions.compileSdk.get().toInt()
        minSdk = libs.versions.minSdk.get().toInt()
    }

    sourceSets {
        val commonMain = getByName("commonMain")

        // Intermediate source set shared by the android and desktop (JVM) targets (same DSL as :core:ssh).
        val jvmCommonMain = create("jvmCommonMain") {
            dependsOn(commonMain)
        }
        getByName("androidMain").dependsOn(jvmCommonMain)
        getByName("desktopMain").dependsOn(jvmCommonMain)

        commonMain.dependencies {
            api(projects.core.vault)
            api(libs.kotlinx.coroutines.core)
            api(libs.kotlinx.serialization.json)
        }

        // OkHttp is a Kotlin Multiplatform library published with Gradle module metadata (android and jvm
        // variants). It is declared on each leaf source set (not on jvmCommonMain) so variant selection never
        // depends on how the shared intermediate source set is resolved.
        getByName("androidMain").dependencies {
            implementation(libs.okhttp)
        }
        getByName("desktopMain").dependencies {
            implementation(libs.okhttp)
        }
    }
}
