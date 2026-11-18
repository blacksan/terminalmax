plugins {
    id("terminalmax.kmp.compose")
}

kotlin {
    android {
        namespace = "org.terminalmax.feature.proof"
        compileSdk = libs.versions.compileSdk.get().toInt()
        minSdk = libs.versions.minSdk.get().toInt()
    }

    sourceSets {
        commonMain.dependencies {
            implementation(projects.core.designsystem)
            implementation(projects.core.model)
        }
    }
}
