package fastkrypto.buildlogic

import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.FileSystemOperations
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.MapProperty
import org.gradle.api.provider.Property
import org.gradle.process.ExecOperations
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.TaskAction
import java.io.File
import javax.inject.Inject

abstract class BuildJvmNativeLibsTask : DefaultTask() {
    @get:Input
    abstract val targets: ListProperty<String>

    @get:Internal
    abstract val workingDir: DirectoryProperty

    @get:Input
    abstract val cargoPath: Property<String>

    @get:Inject
    abstract val execOperations: ExecOperations

    @TaskAction
    fun runBuilds() {
        val cargoExecutable = cargoPath.get()
        val wrapperDir = workingDir.get().asFile.resolve(".cargo")
        val zigAarch64 = wrapperDir.resolve("zig-cc-aarch64-linux-gnu").absolutePath
        val zigX86 = wrapperDir.resolve("zig-cc-x86_64-linux-gnu").absolutePath
        val pathSeparator = File.pathSeparator
        val existingPath = System.getenv("PATH") ?: ""
        targets.get().forEach { target ->
            execOperations.exec {
                workingDir = this@BuildJvmNativeLibsTask.workingDir.get().asFile
                executable = cargoExecutable
                args("build", "--release", "--target", target)
                environment("PATH", listOf(wrapperDir.absolutePath, existingPath).joinToString(pathSeparator))
                environment("CC_aarch64_unknown_linux_gnu", zigAarch64)
                environment("CXX_aarch64_unknown_linux_gnu", zigAarch64)
                environment("CC_x86_64_unknown_linux_gnu", zigX86)
                environment("CXX_x86_64_unknown_linux_gnu", zigX86)
                environment("CC_aarch64-unknown-linux-gnu", zigAarch64)
                environment("CXX_aarch64-unknown-linux-gnu", zigAarch64)
                environment("CC_x86_64-unknown-linux-gnu", zigX86)
                environment("CXX_x86_64-unknown-linux-gnu", zigX86)
                environment("CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER", zigAarch64)
                environment("CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER", zigX86)
            }
        }
    }
}

abstract class PrepareJvmNativeResourcesTask : DefaultTask() {
    @get:Input
    abstract val targets: ListProperty<String>

    @get:Input
    abstract val resourceDirs: MapProperty<String, String>

    @get:Input
    abstract val libNames: MapProperty<String, String>

    @get:Internal
    abstract val projectDir: DirectoryProperty

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @get:Inject
    abstract val fs: FileSystemOperations

    @TaskAction
    fun copyResources() {
        val selected = targets.get().toSet()
        val dirs = resourceDirs.get()
        val libs = libNames.get()
        fs.delete { delete(outputDir) }
        selected.forEach { target ->
            val resourceDir = dirs[target] ?: return@forEach
            val libName = libs[target] ?: return@forEach
            // Cargo workspace builds may place artifacts in a higher-level target directory.
            val targetRoots = listOfNotNull(
                projectDir.asFile.get().resolve("target"),
                projectDir.asFile.get().parentFile?.resolve("target"),
                projectDir.asFile.get().parentFile?.parentFile?.resolve("target"),
            )
            val libFile = targetRoots
                .asSequence()
                .map { it.resolve("$target/release/$libName") }
                .firstOrNull { it.exists() }
                ?: projectDir.asFile.get().resolve("target/$target/release/$libName")
            fs.copy {
                from(libFile)
                into(outputDir.dir(resourceDir))
            }
        }
    }
}
