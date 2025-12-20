package org.example.project

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.safeContentPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.jetbrains.compose.resources.painterResource
import org.jetbrains.compose.ui.tooling.preview.Preview
import org.example.project.generated.resources.Res
import org.example.project.generated.resources.compose_multiplatform
import xyz.mcxross.fastkrypto.ed25519GenerateKeypair
import xyz.mcxross.fastkrypto.ed25519Sign
import xyz.mcxross.fastkrypto.ed25519Verify
import xyz.mcxross.fastkrypto.sha256

@Composable
@Preview
fun App() {
    MaterialTheme {
        var showContent by remember { mutableStateOf(false) }
        var cryptoResult by remember { mutableStateOf<String?>(null) }
        Column(
            modifier = Modifier
                .background(MaterialTheme.colorScheme.primaryContainer)
                .safeContentPadding()
                .fillMaxSize(),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Button(onClick = {
                showContent = !showContent
                if (showContent) {
                    val keypair = ed25519GenerateKeypair()
                    val message = "fastcrypto compose".encodeToByteArray()
                    val signature = ed25519Sign(keypair.privateKey, message)
                    val verified = ed25519Verify(keypair.publicKey, message, signature)
                    val digest = sha256(message)
                    cryptoResult = "ed25519 verified=$verified\nsha256=${digest.toHex()}"
                }
            }) {
                Text("Click me!")
            }
            AnimatedVisibility(showContent) {
                val greeting = remember { Greeting().greet() }
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Image(painterResource(Res.drawable.compose_multiplatform), null)
                    Text("Compose: $greeting")
                    cryptoResult?.let {
                        Text(it, modifier = Modifier.padding(top = 12.dp))
                    }
                }
            }
        }
    }
}

private fun ByteArray.toHex(): String =
    joinToString(separator = "") { it.toUByte().toString(16).padStart(2, '0') }
