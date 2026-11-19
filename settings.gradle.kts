pluginManagement {
    includeBuild("build-logic")
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode = RepositoriesMode.FAIL_ON_PROJECT_REPOS
    repositories {
        google()
        mavenCentral()
        // JediTerm's emulator core is published only to the JetBrains repository. exclusiveContent
        // means this group is resolved from that repository only (never probed on google() or
        // mavenCentral()), and nothing else is resolved from it.
        exclusiveContent {
            forRepository {
                maven { url = uri("https://packages.jetbrains.team/maven/p/ij/intellij-dependencies") }
            }
            filter { includeGroup("org.jetbrains.jediterm") }
        }
    }
}

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

rootProject.name = "terminalmax"

include(":androidApp")
include(":desktopApp")
include(":core:model")
include(":core:ssh")
include(":core:vault")
include(":core:sync")
include(":core:designsystem")
include(":core:terminal")
include(":feature:app")
include(":core:wireguard")
include(":integration-tests")
