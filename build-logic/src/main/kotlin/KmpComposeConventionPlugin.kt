import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.configure
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension

/** [KmpLibraryConventionPlugin] + Compose compiler + Compose Multiplatform plugin and common deps. */
class KmpComposeConventionPlugin : Plugin<Project> {
    override fun apply(target: Project) {
        with(target) {
            pluginManager.apply("terminalmax.kmp.library")
            pluginManager.apply("org.jetbrains.kotlin.plugin.compose")
            pluginManager.apply("org.jetbrains.compose")

            extensions.configure<KotlinMultiplatformExtension> {
                sourceSets.getByName("commonMain").dependencies {
                    // api: composable signatures expose Compose types to dependents.
                    api(libs.findLibrary("compose-runtime").get())
                    api(libs.findLibrary("compose-foundation").get())
                    api(libs.findLibrary("compose-ui").get())
                    api(libs.findLibrary("compose-material3").get())
                    implementation(libs.findLibrary("compose-ui-tooling-preview").get())
                }
            }
        }
    }
}
