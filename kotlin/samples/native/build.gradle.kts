plugins {
    alias(libs.plugins.kotlinMultiplatform)
}

kotlin {
    macosX64()
    macosArm64()

    sourceSets {
        val commonMain by getting {
            kotlin.srcDir("src/main/kotlin")
            dependencies {
                implementation(project(":lib"))
            }
        }
    }

    targets.withType<org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget>().configureEach {
        binaries.executable {
            entryPoint = "xyz.mcxross.fastkrypto.samples.main"
        }
    }
}

tasks.register("run") {
    val arch = System.getProperty("os.arch").lowercase()
    val isArm64 = arch.contains("aarch64") || arch.contains("arm64")
    val runTask = if (isArm64) "runDebugExecutableMacosArm64" else "runDebugExecutableMacosX64"
    dependsOn(runTask)
}
