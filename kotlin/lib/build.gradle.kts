import fastkrypto.buildlogic.BuildJvmNativeLibsTask
import fastkrypto.buildlogic.PrepareJvmNativeResourcesTask
import gobley.gradle.cargo.dsl.linux
import gobley.gradle.cargo.dsl.mingw
import gobley.gradle.cargo.tasks.CargoTask
import gobley.gradle.rust.dsl.RustExtension
import java.io.File
import org.gradle.internal.os.OperatingSystem
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
  alias(libs.plugins.kotlinMultiplatform)
  alias(libs.plugins.androidLibrary)
  id("dev.gobley.rust")
  alias(libs.plugins.gobleyCargo)
  alias(libs.plugins.gobleyUniffi)
  alias(libs.plugins.kotlinAtomicfu)
  alias(libs.plugins.maven.publish)
}

group = (project.findProperty("fastkrypto.group") as String?) ?: "xyz.mcxross.fastkrypto"

version = (project.findProperty("fastkrypto.version") as String?) ?: "0.2.0-SNAPSHOT"

uniffi {
  generateFromLibrary {
    packageName.set("xyz.mcxross.fastkrypto")
  }
}

kotlin {
  jvmToolchain(17)

  jvm {
    compilerOptions {
      jvmTarget.set(JvmTarget.JVM_17)
    }
  }

  androidTarget {
    publishLibraryVariants("release")
    compilerOptions {
      jvmTarget.set(JvmTarget.JVM_11)
    }
  }

  iosX64()
  iosArm64()
  iosSimulatorArm64()
  macosX64()
  macosArm64()
  linuxX64()
  linuxArm64()

  sourceSets {
    val commonTest by getting {
      dependencies {
        implementation(libs.kotlin.test)
      }
    }
  }

  targets.withType<org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget>().configureEach {
    if (konanTarget.family.isAppleFamily) {
      binaries.framework {
        baseName = "FastKrypto"
        isStatic = true
      }
    }
  }

  sourceSets.named("jvmMain") {
    resources.srcDir(layout.buildDirectory.dir("generated/jvmNativeResources"))
  }
}

val cleanUniffiBindings =
  tasks.register<Delete>("cleanUniffiBindings") {
    delete(layout.buildDirectory.dir("generated/uniffi"))
  }

tasks.withType<gobley.gradle.uniffi.tasks.BuildUniffiBindingsTask>().configureEach {
  dependsOn(cleanUniffiBindings)
  outputs.cacheIf { false }
}

val jvmNativeTargets =
  listOf(
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-gnu",
  )

val jvmNativeResourceDirs =
  mapOf(
    "aarch64-apple-darwin" to "darwin-aarch64",
    "x86_64-apple-darwin" to "darwin-x86-64",
    "aarch64-unknown-linux-gnu" to "linux-aarch64",
    "x86_64-unknown-linux-gnu" to "linux-x86-64",
  )

val jvmNativeLibNames =
  mapOf(
    "aarch64-apple-darwin" to "libfastkrypto_uniffi.dylib",
    "x86_64-apple-darwin" to "libfastkrypto_uniffi.dylib",
    "aarch64-unknown-linux-gnu" to "libfastkrypto_uniffi.so",
    "x86_64-unknown-linux-gnu" to "libfastkrypto_uniffi.so",
  )

fun hostRustTarget(): String {
  val os = OperatingSystem.current()
  val arch = System.getProperty("os.arch").lowercase()
  return when {
    os.isMacOsX ->
      if (arch.contains("aarch64") || arch.contains("arm64")) {
        "aarch64-apple-darwin"
      } else {
        "x86_64-apple-darwin"
      }
    os.isLinux ->
      if (arch.contains("aarch64") || arch.contains("arm64")) {
        "aarch64-unknown-linux-gnu"
      } else {
        "x86_64-unknown-linux-gnu"
      }
    os.isWindows -> "x86_64-pc-windows-gnu"
    else -> error("Unsupported host OS for Rust target detection: ${os.name}")
  }
}

val configuredJvmTargets =
  providers
    .gradleProperty("fastkrypto.jvmNativeTargets")
    .map { value ->
      value.split(',').map { it.trim() }.filter { it.isNotEmpty() }
    }
    .orElse(jvmNativeTargets)

// Gobley otherwise discovers the first `cargo` binary on PATH. That can bypass the
// workspace's rust-toolchain file when a system Cargo is also installed. Resolve
// through Rustup so its selected toolchain is used consistently for metadata,
// UniFFI generation, and the JVM-native library build.
val resolvedCargoPath =
  providers
    .gradleProperty("fastkrypto.cargoPath")
    .orElse(
      providers
        .exec {
          workingDir = rootProject.projectDir.parentFile
          commandLine("rustup", "which", "cargo")
        }
        .standardOutput
        .asText
        .map { it.trim() }
    )

val resolvedRustcPath = resolvedCargoPath.map { File(it).parentFile.resolve("rustc").absolutePath }

extensions.configure<RustExtension> {
  toolchainDirectory.set(resolvedCargoPath.map { File(it).parentFile })
}

val buildJvmNativeLibs =
  tasks.register<BuildJvmNativeLibsTask>("buildJvmNativeLibs") {
    group = "build"
    description = "Builds Rust cdylib(s) for JVM JNA loading."
    targets.set(configuredJvmTargets)
    workingDir.set(layout.projectDirectory)
    cargoPath.set(resolvedCargoPath)
    rustcPath.set(resolvedRustcPath)
    notCompatibleWithConfigurationCache("Executes cargo builds.")
  }

val prepareJvmNativeResources =
  tasks.register<PrepareJvmNativeResourcesTask>("prepareJvmNativeResources") {
    dependsOn(buildJvmNativeLibs)
    targets.set(configuredJvmTargets)
    resourceDirs.set(jvmNativeResourceDirs)
    libNames.set(jvmNativeLibNames)
    projectDir.set(layout.projectDirectory)
    outputDir.set(layout.buildDirectory.dir("generated/jvmNativeResources"))
    // The custom Cargo task intentionally has no declared outputs. Always refresh the resources so
    // a same-version local/publication build cannot pair new UniFFI Kotlin bindings with an older
    // native library (which otherwise fails at runtime with a missing checksum symbol).
    outputs.upToDateWhen { false }
    notCompatibleWithConfigurationCache("Copies native artifacts.")
  }

tasks.named("jvmProcessResources") {
  dependsOn(prepareJvmNativeResources)
}

tasks.named<org.gradle.jvm.tasks.Jar>("jvmJar") {
  dependsOn(prepareJvmNativeResources)
}

val zigWrapperDir = layout.projectDirectory.dir(".cargo")
val zigAarch64WrapperName = providers.provider { "zig-cc-aarch64-linux-gnu" }
val zigX86WrapperName = providers.provider { "zig-cc-x86_64-linux-gnu" }

tasks.withType<CargoTask>().configureEach {
  cargo.set(resolvedCargoPath.map(::File))
  additionalEnvironment.put("RUSTC", resolvedRustcPath)
  additionalEnvironmentPath.add(zigWrapperDir.asFile)
  // Keep C dependencies and rustc on the same deployment target across Xcode versions.
  additionalEnvironment.put("IPHONEOS_DEPLOYMENT_TARGET", "13.0")
  additionalEnvironment.put("MACOSX_DEPLOYMENT_TARGET", "11.0")
  additionalEnvironment.put("CC_aarch64_unknown_linux_gnu", zigAarch64WrapperName)
  additionalEnvironment.put("CXX_aarch64_unknown_linux_gnu", zigAarch64WrapperName)
  additionalEnvironment.put("CC_x86_64_unknown_linux_gnu", zigX86WrapperName)
  additionalEnvironment.put("CXX_x86_64_unknown_linux_gnu", zigX86WrapperName)
  additionalEnvironment.put("CC_aarch64-unknown-linux-gnu", zigAarch64WrapperName)
  additionalEnvironment.put("CXX_aarch64-unknown-linux-gnu", zigAarch64WrapperName)
  additionalEnvironment.put("CC_x86_64-unknown-linux-gnu", zigX86WrapperName)
  additionalEnvironment.put("CXX_x86_64-unknown-linux-gnu", zigX86WrapperName)
}

cargo {
  builds.linux {
    embedRustLibrary.set(false)
  }
  builds.mingw {
    embedRustLibrary.set(false)
  }
}

android {
  namespace = "xyz.mcxross.fastkrypto"
  compileSdk = libs.versions.android.compileSdk.get().toInt()

  defaultConfig {
    minSdk = libs.versions.android.minSdk.get().toInt()
  }

  compileOptions {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
  }

  sourceSets["main"].manifest.srcFile("src/androidMain/AndroidManifest.xml")
}

mavenPublishing {
  val enableSigning =
    providers.gradleProperty("enableSigning").orNull?.toBooleanStrictOrNull() ?: true

  coordinates(
    group.toString(),
    "fastkrypto",
    version.toString(),
  )

  pom {
    name.set("FastKrypto")
    description.set("Kotlin Multiplatform bindings for fastcrypto via Gobley UniFFI")
    inceptionYear.set("2023")
    url.set("https://github.com/mcxross/fastcrypto")

    licenses {
      license {
        name.set("The Apache License, Version 2.0")
        url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
        distribution.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
      }
    }

    developers {
      developer {
        id.set("mcxross")
        name.set("Mcxross")
        email.set("oss@mcxross.xyz")
      }
    }

    scm {
      url.set("https://github.com/mcxross/fastcrypto")
      connection.set("scm:git:ssh://github.com/mcxross/fastcrypto.git")
      developerConnection.set("scm:git:ssh://github.com/mcxross/fastcrypto.git")
    }
  }

  publishToMavenCentral(automaticRelease = true)

  if (enableSigning) {
    signAllPublications()
  }
}
