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
    implementation(projects.feature.app)
    implementation(projects.core.ssh)
    implementation(projects.core.sync)
    implementation(projects.core.vault)
    // JNA binding of libwgbridge; the library itself is bundled from resources/<os>-<arch>/.
    implementation(projects.core.wireguard)
    implementation(compose.desktop.currentOs)
    implementation(libs.kotlinx.coroutines.swing)
    // Explicit slf4j binding: terminal output and SSH details must never reach a logger by accident.
    runtimeOnly(libs.slf4j.nop)
}

// JNA's own native stub (jnidispatch) is shipped next to libwgbridge so that JNA never extracts it to a
// temp directory or searches for it (see core/wireguard/README.md). It is taken from the JNA jar of the
// catalog version, and the app's runtime classpath is constrained to exactly that version (`strictly`):
// if conflict resolution ever wanted another JNA, resolution fails instead of silently pairing a stub
// with a different jar.
dependencies {
    constraints {
        add("implementation", "net.java.dev.jna:jna") {
            version { strictly(libs.versions.jna.get()) }
        }
    }
}

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

// The licence and the third-party notices travel inside the installed app: resources/common/ is
// merged into $APPDIR/resources on every OS. Copy (not Sync): never delete the native libraries.
val bundleLegalNotices by tasks.registering(Copy::class) {
    description = "Copies LICENSE and THIRD_PARTY_NOTICES.md into the app resources (common/)."
    from(rootProject.layout.projectDirectory.file("LICENSE"))
    from(rootProject.layout.projectDirectory.file("THIRD_PARTY_NOTICES.md"))
    into(layout.projectDirectory.dir("resources/common"))
}

// Packaging, the runnable distribution and `run` all read resources/; make sure the stub and the
// notices are there first.
tasks.matching {
    it.name == "prepareAppResources" || it.name == "run" ||
        it.name.startsWith("package") || it.name.startsWith("createDistributable")
}.configureEach {
    dependsOn(bundleJnaDispatch, bundleLegalNotices)
}

compose.desktop {
    application {
        mainClass = "org.terminalmax.desktop.MainKt"

        // JNA reads these once, in the static initialiser of com.sun.jna.Native, so they must exist
        // before any class loads: they are launcher JVM arguments, not something the backend sets
        // "early enough". jpackage expands $APPDIR (the app/ directory of the installed app) in
        // java-options; Compose passes -Dcompose.application.resources.dir=$APPDIR/resources the same
        // way. The loader (core/wireguard) re-sets them as a fallback for `./gradlew run`, where
        // $APPDIR is NOT expanded (the loader overrides jna.boot.library.path with the real path), and
        // verifies after loading that JNA really used the bundled stub (`jnidispatch.path`).
        // All of these properties exist in JNA 5.19.1 (Native.loadNativeDispatchLibrary).
        jvmArgs += listOf(
            "-Djna.nosys=true",
            "-Djna.nounpack=true",
            "-Djna.noclasspath=true",
            "-Djna.boot.library.path=\$APPDIR/resources",
        )

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
