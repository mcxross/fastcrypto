package xyz.mcxross.fastkrypto.samples

import xyz.mcxross.fastkrypto.ed25519GenerateKeypair
import xyz.mcxross.fastkrypto.ed25519Sign
import xyz.mcxross.fastkrypto.ed25519Verify
import xyz.mcxross.fastkrypto.sha256

fun main() {
    val keypair = ed25519GenerateKeypair()
    val message = "fastcrypto compose".encodeToByteArray()

    val signature = ed25519Sign(keypair.privateKey, message)
    val verified = ed25519Verify(keypair.publicKey, message, signature)

    val digest = sha256(message)

    println("ed25519 verified=$verified")
    println("sha256=${digest.joinToString("") { it.toUByte().toString(16).padStart(2, '0') }}")
}
