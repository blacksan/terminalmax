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
    implementation(libs.androidx.activity.compose)
}
