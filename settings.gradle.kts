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
        // JediTerm's emulator core is published only to the JetBrains repository.
        maven {
            url = uri("https://packages.jetbrains.team/maven/p/ij/intellij-dependencies")
            content { includeGroup("org.jetbrains.jediterm") }
        }
    }
}

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

rootProject.name = "terminalmax"

include(":androidApp")
include(":desktopApp")
include(":core:model")
include(":core:ssh")
include(":core:designsystem")
include(":core:terminal")
include(":feature:proof")
