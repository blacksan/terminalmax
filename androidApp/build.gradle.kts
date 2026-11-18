plugins {
    id("terminalmax.android.application")
}

android {
    namespace = "org.terminalmax.app"

    defaultConfig {
        applicationId = "org.terminalmax.app"
        versionCode = 1
        versionName = "0.1.0-proof"

        // libwgbridge.so is built for these two ABIs only (no 32-bit library exists).
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }
}

dependencies {
    implementation(projects.core.designsystem)
    implementation(projects.feature.proof)
    // Not referenced by the proof UI yet; listed so R8 (consumer rules) and packaging see the SSH module.
    implementation(projects.core.ssh)
    // libwgbridge.so is copied into src/main/jniLibs/<abi>/ by CI (see .github/workflows/ci.yml).
    implementation(projects.core.wireguard)
    implementation(libs.androidx.activity.compose)
    // Explicit slf4j binding: terminal output and SSH details must never reach a logger by accident.
    runtimeOnly(libs.slf4j.nop)
}
