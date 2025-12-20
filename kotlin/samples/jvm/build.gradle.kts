plugins {
    id("org.jetbrains.kotlin.jvm")
    application
}

dependencies {
    implementation(project(":lib"))
}

application {
    mainClass.set("xyz.mcxross.fastkrypto.samples.MainKt")
}
