plugins {
    id("terminalmax.kmp.library")
}

kotlin {
    android {
        namespace = "org.terminalmax.core.ssh"
        compileSdk = libs.versions.compileSdk.get().toInt()
        minSdk = libs.versions.minSdk.get().toInt()

        // Consumer R8 rules for sshj / BouncyCastle (reflection-based factories).
        optimization {
            consumerKeepRules.publish = true
            consumerKeepRules.files.add(project.file("consumer-rules.pro"))
        }
    }

    sourceSets {
        val commonMain = getByName("commonMain")

        // Intermediate source set shared by the android and desktop (JVM) targets.
        val jvmCommonMain = create("jvmCommonMain") {
            dependsOn(commonMain)
            dependencies {
                implementation(libs.sshj)
                implementation(libs.bouncycastle.bcprov)
                implementation(libs.bouncycastle.bcpkix)
            }
        }
        getByName("androidMain").dependsOn(jvmCommonMain)
        getByName("desktopMain").dependsOn(jvmCommonMain)

        commonMain.dependencies {
            api(libs.kotlinx.coroutines.core)
        }

        getByName("desktopTest").dependencies {
            implementation(libs.mina.sshd.core)
            // sshj and MINA SSHD both log through slf4j; silence it in tests only.
            runtimeOnly(libs.slf4j.nop)
        }
    }
}
