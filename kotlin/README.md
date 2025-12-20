# FastCrypto Kotlin samples

These samples use the UniFFI-generated Kotlin bindings produced by Gobley.

## JVM

```sh
cd kotlin
./gradlew -PincludeSamples=true :samples:jvm:run
```

## Native (macOS)

```sh
cd kotlin
./gradlew -PincludeSamples=true :samples:native:runDebugExecutableMacosArm64
```

## Compose Multiplatform (Android/iOS/Desktop)

Open `kotlin/samples/fastcrypto-kmp-sample` in Android Studio or run Gradle from that directory to
launch the Compose Multiplatform sample.
