plugins {
    id("terminalmax.android.application")
}

android {
    namespace = "org.terminalmax.app"

    defaultConfig {
        applicationId = "org.terminalmax.app"
        versionCode = 1
        versionName = "0.1.0-proof"
    }
}

dependencies {
    implementation(projects.core.designsystem)
    implementation(projects.feature.proof)
    // Not referenced by the proof UI yet; listed so R8 (consumer rules) and packaging see the SSH module.
    implementation(projects.core.ssh)
    implementation(libs.androidx.activity.compose)
    // Explicit slf4j binding: terminal output and SSH details must never reach a logger by accident.
    runtimeOnly(libs.slf4j.nop)
}
