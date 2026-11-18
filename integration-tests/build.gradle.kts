import org.jetbrains.kotlin.gradle.dsl.JvmTarget

// End-to-end tests of the product's core path (kernel WireGuard peer -> wgbridge -> SSH). Test-only
// module: it has no main code and is skipped unless TMX_E2E=1 (see README.md).
plugins {
    alias(libs.plugins.kotlin.jvm)
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
    // Consuming a KMP library from a plain JVM project selects its desktop (jvm) variant.
    testImplementation(projects.core.ssh)
    testImplementation(projects.core.wireguard)
    testImplementation(libs.kotlin.test)
    testImplementation(libs.kotlinx.coroutines.core)
    testImplementation(libs.mina.sshd.core)
    testRuntimeOnly(libs.slf4j.nop)
}

tasks.test {
    useJUnit()
    // Never reuse a cached or up-to-date result: the outcome depends on the runner's network setup.
    outputs.upToDateWhen { false }
    outputs.cacheIf { false }
    testLogging {
        events("failed", "standardOut")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
        showCauses = true
        showStackTraces = true
    }
}
