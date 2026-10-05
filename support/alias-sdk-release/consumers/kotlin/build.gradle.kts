plugins {
    kotlin("jvm") version "2.1.0"
    application
}

repositories {
    mavenCentral()
}

val sdkJar = providers.gradleProperty("sdkJar").get()
val sdkNativeDirectory = providers.gradleProperty("sdkNativeDirectory").get()

dependencies {
    implementation(files(sdkJar))
    implementation("net.java.dev.jna:jna:5.17.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.1")
}

application {
    mainClass = "consumer.AliasReleaseConsumerKt"
    applicationDefaultJvmArgs = listOf(
        "-Djava.library.path=$sdkNativeDirectory",
        "-Djna.library.path=$sdkNativeDirectory",
    )
}

kotlin {
    jvmToolchain(17)
}
