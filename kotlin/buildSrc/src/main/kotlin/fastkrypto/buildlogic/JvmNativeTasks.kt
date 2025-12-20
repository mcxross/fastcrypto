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
        targets.get().forEach { target ->
            execOperations.exec {
                workingDir = this@BuildJvmNativeLibsTask.workingDir.get().asFile
                executable = cargoExecutable
                args("build", "--release", "--target", target)
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
