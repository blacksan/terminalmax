plugins {
    id("terminalmax.kmp.compose")
}

kotlin {
    android {
        namespace = "org.terminalmax.core.designsystem"
        compileSdk = libs.versions.compileSdk.get().toInt()
        minSdk = libs.versions.minSdk.get().toInt()
    }
}
