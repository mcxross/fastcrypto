package xyz.mcxross.fastkrypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class FastKryptoBindingsTest {
    private val testMnemonic =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    private val ed25519Path = "m/44H/784H/0H/0H/0H"
    private val secpPath = "m/44'/784'/0'/0/0"

    @Test
    fun ed25519KeypairSignVerifyRoundtrip() {
        val keypair = ed25519GenerateKeypair()
        val message = "fastkrypto".encodeToByteArray()
        val signature = ed25519Sign(keypair.privateKey, message)

        assertTrue(ed25519Verify(keypair.publicKey, message, signature))
        assertEquals(32, keypair.privateKey.size)
        assertEquals(32, keypair.publicKey.size)
        assertEquals(64, signature.size)
    }

    @Test
    fun secp256k1KeypairSignVerifyRoundtrip() {
        val keypair = secp256k1GenerateKeypair()
        val message = "fastkrypto".encodeToByteArray()
        val signature = secp256k1Sign(keypair.privateKey, message)

        assertTrue(secp256k1Verify(keypair.publicKey, message, signature))
        assertEquals(32, keypair.privateKey.size)
        assertEquals(33, keypair.publicKey.size)
        assertEquals(64, signature.size)
    }

    @Test
    fun secp256r1KeypairSignVerifyRoundtrip() {
        val keypair = secp256r1GenerateKeypair()
        val message = "fastkrypto".encodeToByteArray()
        val signature = secp256r1Sign(keypair.privateKey, message)

        assertTrue(secp256r1Verify(keypair.publicKey, message, signature))
        assertEquals(32, keypair.privateKey.size)
        assertEquals(33, keypair.publicKey.size)
        assertEquals(64, signature.size)
    }

    @Test
    fun mnemonicGenerationAndValidation() {
        val wordCounts = listOf(12u, 15u, 18u, 21u, 24u)
        for (count in wordCounts) {
            val phrase = mnemonicGenerate(count)
            assertTrue(mnemonicValidate(phrase))
        }

        assertFailsWith<FastCryptoFfiException> { mnemonicGenerate(11u) }
        assertFailsWith<FastCryptoFfiException> { mnemonicGenerate(13u) }
        assertFalse(mnemonicValidate("not a valid mnemonic"))
    }

    @Test
    fun mnemonicSeedLength() {
        val seed = mnemonicToSeed(testMnemonic, "")
        assertEquals(64, seed.size)
    }

    @Test
    fun mnemonicDerivationAllSchemes() {
        val edPrivate =
            mnemonicDerivePrivateKey(testMnemonic, "", SignatureScheme.ED25519, ed25519Path)
        val edPublic =
            mnemonicDerivePublicKey(testMnemonic, "", SignatureScheme.ED25519, ed25519Path)
        assertEquals(32, edPrivate.size)
        assertEquals(32, edPublic.size)

        val k1Private =
            mnemonicDerivePrivateKey(testMnemonic, "", SignatureScheme.SECP256K1, secpPath)
        val k1Public =
            mnemonicDerivePublicKey(testMnemonic, "", SignatureScheme.SECP256K1, secpPath)
        assertEquals(32, k1Private.size)
        assertEquals(33, k1Public.size)

        val r1Private =
            mnemonicDerivePrivateKey(testMnemonic, "", SignatureScheme.SECP256R1, secpPath)
        val r1Public =
            mnemonicDerivePublicKey(testMnemonic, "", SignatureScheme.SECP256R1, secpPath)
        assertEquals(32, r1Private.size)
        assertEquals(33, r1Public.size)
    }

    @Test
    fun mnemonicDeriveKeypairMatchesPublicKey() {
        val keypair =
            mnemonicDeriveKeypair(testMnemonic, "", SignatureScheme.ED25519, ed25519Path)
        val derivedPublic = ed25519PublicKeyFromPrivate(keypair.privateKey)
        assertTrue(derivedPublic.contentEquals(keypair.publicKey))
    }

    @Test
    fun ed25519RejectsNonHardenedPath() {
        assertFailsWith<FastCryptoFfiException> {
            mnemonicDerivePrivateKey(testMnemonic, "", SignatureScheme.ED25519, secpPath)
        }
    }
}
