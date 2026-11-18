import org.jetbrains.compose.desktop.application.dsl.TargetFormat
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.compose.compiler)
    alias(libs.plugins.compose.multiplatform)
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    implementation(projects.core.designsystem)
    implementation(projects.feature.proof)
    // Not referenced by the proof UI yet; listed so desktop packaging sees the SSH module.
    implementation(projects.core.ssh)
    implementation(compose.desktop.currentOs)
    implementation(libs.kotlinx.coroutines.swing)
    // Explicit slf4j binding: terminal output and SSH details must never reach a logger by accident.
    runtimeOnly(libs.slf4j.nop)
}

compose.desktop {
    application {
        mainClass = "org.terminalmax.desktop.MainKt"

        nativeDistributions {
            targetFormats(TargetFormat.Dmg, TargetFormat.Msi)
            packageName = "TerminalMax"
            // dmg/msi require MAJOR > 0, so this is independent of the app versionName.
            packageVersion = "1.0.0"
            licenseFile.set(rootProject.file("LICENSE"))
            macOS {
                bundleID = "org.terminalmax.desktop"
            }
            windows {
                upgradeUuid = "9c8d68eb-000c-4de1-a782-854e37af6cb7"
                menu = true
                shortcut = true
            }
        }
    }
}
