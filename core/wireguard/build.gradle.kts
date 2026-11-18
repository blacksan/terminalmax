plugins {
    id("terminalmax.kmp.library")
    alias(libs.plugins.kotlin.serialization)
}

kotlin {
    android {
        namespace = "org.terminalmax.core.wireguard"
        compileSdk = libs.versions.compileSdk.get().toInt()
        minSdk = libs.versions.minSdk.get().toInt()

        // JNI natives of WgBridgeNative must keep their names; R8 would otherwise be free to rename them.
        optimization {
            consumerKeepRules.publish = true
            consumerKeepRules.files.add(project.file("consumer-rules.pro"))
        }
    }

    sourceSets {
        val commonMain = getByName("commonMain")

        // Intermediate source set shared by the android and desktop (JVM) targets: the
        // native-bridge-agnostic backend (locking, validation, zero-filling).
        val jvmCommonMain = create("jvmCommonMain") {
            dependsOn(commonMain)
        }
        getByName("androidMain").dependsOn(jvmCommonMain)
        getByName("desktopMain").dependsOn(jvmCommonMain)

        commonMain.dependencies {
            implementation(libs.kotlinx.serialization.json)
        }

        getByName("desktopMain").dependencies {
            // JNA binds libwgbridge on the desktop; Android uses JNI (see WgBridgeNative).
            implementation(libs.jna)
        }
    }
}
