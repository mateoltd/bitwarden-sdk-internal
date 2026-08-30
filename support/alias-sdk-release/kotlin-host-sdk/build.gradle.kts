plugins {
    kotlin("jvm") version "2.1.0"
    `java-library`
}

repositories {
    mavenCentral()
}

val generatedSources = providers.gradleProperty("generatedSources").get()
val licenseFile = providers.gradleProperty("licenseFile").get()
val releaseVersion = providers.gradleProperty("releaseVersion").get()

sourceSets {
    main {
        kotlin.srcDir(generatedSources)
    }
}

dependencies {
    api("net.java.dev.jna:jna:5.17.0")
    api("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.1")
}

kotlin {
    jvmToolchain(17)
}

tasks.jar {
    archiveBaseName = "bitwarden-alias-sdk-kotlin-host"
    archiveVersion = releaseVersion
    from(licenseFile) {
        into("META-INF")
        rename { "LICENSE_GPL.txt" }
    }
}
