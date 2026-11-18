plugins {
    id("terminalmax.kmp.library")
}

kotlin {
    android {
        namespace = "org.terminalmax.core.model"
        compileSdk = libs.versions.compileSdk.get().toInt()
        minSdk = libs.versions.minSdk.get().toInt()
    }
}
