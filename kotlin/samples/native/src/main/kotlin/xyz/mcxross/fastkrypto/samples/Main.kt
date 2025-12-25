package xyz.mcxross.fastkrypto.samples

import xyz.mcxross.fastkrypto.secp256k1GenerateKeypair
import xyz.mcxross.fastkrypto.secp256k1Sign
import xyz.mcxross.fastkrypto.secp256k1Verify

fun main() {
    val keypair = secp256k1GenerateKeypair()
    val message = "fastcrypto compose".encodeToByteArray()

    val signature = secp256k1Sign(keypair.privateKey, message)
    val verified = secp256k1Verify(keypair.publicKey, message, signature)

    println("secp256k1 verified=$verified")
}
