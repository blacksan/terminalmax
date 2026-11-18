plugins {
    id("terminalmax.android.application")
}

// Copies the licence and the third-party notices (repository root) into a generated assets directory,
// so that they are inside the APK as assets/LICENSE and assets/THIRD_PARTY_NOTICES.md. This uses AGP's
// generated-source API (a task with an @OutputDirectory, registered per variant): it is configuration
// cache safe, carries the task dependency into mergeAssets/lint automatically, needs no git-ignored
// directory under src/ and no `dependsOn` wiring by name.
abstract class GenerateLegalAssets : DefaultTask() {
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.NAME_ONLY)
    abstract val legalFiles: ConfigurableFileCollection

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @TaskAction
    fun generate() {
        val out = outputDir.get().asFile
        out.deleteRecursively()
        out.mkdirs()
        legalFiles.files.forEach { it.copyTo(File(out, it.name), overwrite = true) }
    }
}

val generateLegalAssets = tasks.register<GenerateLegalAssets>("generateLegalAssets") {
    legalFiles.from(
        rootProject.layout.projectDirectory.file("LICENSE"),
        rootProject.layout.projectDirectory.file("THIRD_PARTY_NOTICES.md"),
    )
    outputDir.set(layout.buildDirectory.dir("generated/legalAssets"))
}

androidComponents {
    onVariants { variant ->
        variant.sources.assets?.addGeneratedSourceDirectory(generateLegalAssets, GenerateLegalAssets::outputDir)
    }
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
