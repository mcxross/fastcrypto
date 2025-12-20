plugins {
    alias(libs.plugins.androidApplication) apply false
    alias(libs.plugins.androidLibrary) apply false
    alias(libs.plugins.composeMultiplatform) apply false
    alias(libs.plugins.composeCompiler) apply false
    alias(libs.plugins.kotlinMultiplatform) apply false
    alias(libs.plugins.kotlinJvm) apply false
    alias(libs.plugins.gobleyCargo) apply false
    alias(libs.plugins.gobleyUniffi) apply false
    alias(libs.plugins.kotlinAtomicfu) apply false
    alias(libs.plugins.maven.publish) apply false
}
