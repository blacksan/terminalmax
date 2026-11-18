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
    // JNA binding of libwgbridge; the library itself is bundled from resources/<os>-<arch>/.
    implementation(projects.core.wireguard)
    implementation(compose.desktop.currentOs)
    implementation(libs.kotlinx.coroutines.swing)
    // Explicit slf4j binding: terminal output and SSH details must never reach a logger by accident.
    runtimeOnly(libs.slf4j.nop)
}

// JNA's own native stub (jnidispatch) is shipped next to libwgbridge so that JNA never extracts it to a
// temp directory or searches for it (see core/wireguard/README.md). It is taken from the very JNA jar
// that the app runs with, so the versions always match.
val jnaDispatchJar by configurations.creating {
    isCanBeConsumed = false
    isCanBeResolved = true
}

dependencies {
    add(jnaDispatchJar.name, "net.java.dev.jna:jna:${libs.versions.jna.get()}")
}

// Copies into the same resources/<os>-<arch>/ folders that CI fills with the bridge. Only the two
// shipped platforms exist. A Copy (not Sync) task: it must never delete the bridge next to it.
val bundleJnaDispatch by tasks.registering(Copy::class) {
    description = "Copies JNA's jnidispatch for macOS arm64 and Windows x64 into the app resources."
    // singleFile: the jna jar has no dependencies. Resolved while configuring (configuration cache friendly).
    from(zipTree(jnaDispatchJar.singleFile)) {
        include(
            "com/sun/jna/darwin-aarch64/libjnidispatch.jnilib",
            "com/sun/jna/win32-x86-64/jnidispatch.dll",
        )
        eachFile {
            path = (if (sourcePath.contains("darwin-aarch64")) "macos-arm64/" else "windows-x64/") + name
        }
    }
    includeEmptyDirs = false
    into(layout.projectDirectory.dir("resources"))
}

// Packaging, the runnable distribution and `run` all read resources/; make sure the stub is there first.
tasks.matching {
    it.name == "prepareAppResources" || it.name == "run" ||
        it.name.startsWith("package") || it.name.startsWith("createDistributable")
}.configureEach {
    dependsOn(bundleJnaDispatch)
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
            // CI copies the freshly built libwgbridge.dylib / wgbridge.dll into
            // resources/macos-arm64/ and resources/windows-x64/ before packaging; bundleJnaDispatch
            // (above) adds JNA's jnidispatch next to them. The app finds both only through the
            // compose.application.resources.dir system property (no search path, no temp extraction).
            appResourcesRootDir.set(project.layout.projectDirectory.dir("resources"))
            // JNA needs sun.misc.Unsafe-style access (jdk.unsupported) and java.logging in the jlink image.
            modules("jdk.unsupported", "java.logging")
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
