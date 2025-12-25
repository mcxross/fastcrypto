plugins {
    id("org.jetbrains.kotlin.jvm")
    application
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation(project(":lib"))
}

application {
    mainClass.set("xyz.mcxross.fastkrypto.samples.MainKt")
}
