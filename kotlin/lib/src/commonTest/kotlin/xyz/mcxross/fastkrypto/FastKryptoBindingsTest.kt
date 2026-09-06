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

  private fun String.hexToBytes(): ByteArray {
    require(length % 2 == 0)
    return ByteArray(length / 2) { index ->
      substring(index * 2, index * 2 + 2).toInt(16).toByte()
    }
  }

  @Test
  fun bn254PoseidonMatchesKnownAptosVectors() {
    val one = ByteArray(32).also { it[0] = 1 }
    val two = ByteArray(32).also { it[0] = 2 }

    assertTrue(
      bn254PoseidonHash(listOf(one))
        .contentEquals(
          "33018202c57d898b84338b16d1a4960e133c6a4d656cfec1bd62a9ea00611729".hexToBytes()
        )
    )
    assertTrue(
      bn254PoseidonHash(listOf(one, two))
        .contentEquals(
          "9a1817447a60199e51453274f217362acfe962966b4cf63d4190d6e7f5c05c11".hexToBytes()
        )
    )
    assertFailsWith<FastCryptoFfiException> { bn254PoseidonHash(emptyList()) }
    assertFailsWith<FastCryptoFfiException> { bn254PoseidonHash(listOf(ByteArray(31))) }
    assertFailsWith<FastCryptoFfiException> {
      bn254PoseidonHash(listOf(ByteArray(32) { 0xff.toByte() }))
    }
  }

  @Test
  fun bn254Groth16VerifiesOfficialFastCryptoRegressionVector() {
    val preparedKey =
      Bn254PreparedVerifyingKeyBytes(
        gammaAbcG1 =
          "df35140d037b211901de04f62a417c53c304328304d738bcc4ff623b1e65698765c6fa5f804bac35ce67f2c26e37bd0cba6f8a944a6c8c17a2417c7b88254f000f87f4f3b509521fbd63e8460ef9082880ada8f342803fd2188e5ce75bbb0d06"
            .hexToBytes(),
        alphaG1BetaG2 =
          "b51f110c1840d39a3185436f5307ad47b375ff892acd78cfa2939556eb46d22112f76ffdd8f3be5fabcc44df3a6750edaaf65af3218f58988afedf6b4202b41066a18f1a8e6b06194838ab7331524da9389802cfd1cc87ef800cbf927fe65e1009fd4d603bf4790371ea2272d17f9a1d98f790b04af2fef1f35889b7e54cc210ce1e47a6ecece6f9d20e8c4514db8f74b96db01cd3528e49faf67d40b7e18f12cd4aadf7698d3fbca9d5a660f677a8c9bba800d3a125c9431e151fa9120c9d07c80d5f662fd6630f1c7441ce7c2f65cad89898222976d519fcadcd9a9beb7120625ee32258e4436e31b4661521c68dbd78027a0935423f2f3b74087c3dcc4b15f8c23a499e1b2e0e456d24274eb7e5c2a0ca3338c5e4ec4d31fd3392c32c790e05142edd5fe2e671260f33318826f2ce0e0cbadb2d347a1644d14824a1f2f402c2740188daef879da5139d06160b1bd44788a272e92d33553631cbc9db991f18606ba945064aff9ec7c0d6d0fde961d834783008718783f67c778dd952b1270f"
            .hexToBytes(),
        gammaG2NegPc =
          "04d7dbe72328896134ed56890042202827ce6805cd384ab00afa0997b26a8d0905b8d48c57bcbc7e9d8a2ff6771a50f90d96970636a9e7d89aaf7369ce7e4d9f"
            .hexToBytes(),
        deltaG2NegPc =
          "06639a71c443532e6c7797e0b18926ea09962bd2fdad9a7130df397463afd315b4bfda26cbef66c4f62f6e65a90d70f058df1f57216846e93890f9b2be68ce85"
            .hexToBytes(),
      )
    val publicInputs =
      "7b00000000000000000000000000000000000000000000000000000000000000c801000000000000000000000000000000000000000000000000000000000000"
        .hexToBytes()
    val proof =
      "537a1b8ba0fc0f2b456c59769a58f22fbf9228311f5cc9070e7358e28c51d2033984c58d47b747c7e07bc87520f14e19029042259a21a910040b87533bf3c32613261dbeffd2913f3627895532b49e9cf623fdfa94e4ef9c040086b397ad640c54c165811c46fa50a880a7b8616d2165848b8f631db25b1b1ebf7fe021f4a11a"
        .hexToBytes()

    assertTrue(bn254VerifyGroth16(preparedKey, publicInputs, proof))
    assertFalse(
      bn254VerifyGroth16(
        preparedKey,
        publicInputs.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() },
        proof,
      )
    )
    assertFailsWith<FastCryptoFfiException> {
      bn254VerifyGroth16(preparedKey, ByteArray(31), proof)
    }
  }

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
  fun secp256r1Sha3KeypairSignVerifyRoundtrip() {
    val keypair = secp256r1GenerateKeypair()
    val message = "aptos-secp256r1".encodeToByteArray()
    val signature = secp256r1SignSha3256(keypair.privateKey, message)

    assertTrue(secp256r1VerifySha3256(keypair.publicKey, message, signature))
    assertFalse(secp256r1Verify(keypair.publicKey, message, signature))
    assertEquals(64, signature.size)
  }

  @Test
  fun secp256r1NormalizesCompressedAndUncompressedPublicKeys() {
    val keypair = secp256r1GenerateKeypair()
    val uncompressed = secp256r1NormalizePublicKey(keypair.publicKey, false)

    assertEquals(65, uncompressed.size)
    assertTrue(secp256r1NormalizePublicKey(uncompressed, true).contentEquals(keypair.publicKey))
  }

  @Test
  fun aptosBatchEncryptionRejectsMalformedKeysAcrossTheFfiBoundary() {
    assertFailsWith<FastCryptoFfiException> {
      aptosBatchEncrypt(
        encryptionKeyBcs = byteArrayOf(0, 1),
        plaintextBcs = byteArrayOf(2),
        associatedDataBcs = byteArrayOf(3),
      )
    }
  }

  @Test
  fun aptosConfidentialTwistedElGamalAndDiscreteLogRoundTrip() {
    val keyPair = twistedEd25519GenerateKeypair()
    val encrypted =
      twistedElgamalEncrypt(
        publicKey = keyPair.publicKey,
        amount = 65_535uL,
        randomness = null,
      )

    assertEquals(32, keyPair.privateKey.size)
    assertEquals(32, keyPair.publicKey.size)
    assertEquals(32, encrypted.commitment.size)
    assertEquals(32, encrypted.handle.size)
    assertEquals(32, encrypted.randomness.size)
    assertEquals(
      65_535uL,
      twistedElgamalDecrypt(
        privateKey = keyPair.privateKey,
        commitment = encrypted.commitment,
        handle = encrypted.handle,
        bitWidth = 16u.toUByte(),
      ),
    )
  }

  @Test
  fun aptosConfidentialBatchRangeProofUsesOnChainParameters() {
    val keyPair = twistedEd25519GenerateKeypair()
    val values = listOf(0uL, 1uL, 42uL, 65_535uL)
    val encrypted = values.map { value ->
      twistedElgamalEncrypt(
        publicKey = keyPair.publicKey,
        amount = value,
        randomness = null,
      )
    }
    val range =
      aptosConfidentialRangeProve(
        values = values,
        blindings = encrypted.map { it.randomness },
      )

    assertEquals(encrypted.size, range.commitments.size)
    range.commitments.zip(encrypted).forEach { (commitment, ciphertext) ->
      assertTrue(commitment.contentEquals(ciphertext.commitment))
    }
    assertTrue(
      aptosConfidentialRangeVerify(
        proof = range.proof,
        commitments = range.commitments,
      )
    )
    assertFalse(
      aptosConfidentialRangeVerify(
        proof = range.proof,
        commitments =
          range.commitments.mapIndexed { index, commitment ->
            if (index == 0) twistedElgamalEncryptZeroRandomness(1uL).commitment else commitment
          },
      )
    )
  }

  @Test
  fun aptosConfidentialSigmaBindingsRegisterAndRotateKeys() {
    val sender = ByteArray(32).also { it[31] = 7 }
    val token = ByteArray(32).also { it[31] = 9 }
    val current = twistedEd25519GenerateKeypair()
    val next = twistedEd25519GenerateKeypair()
    val registration =
      aptosConfidentialRegistrationProve(
        privateKey = current.privateKey,
        senderAddress = sender,
        tokenAddress = token,
        chainId = 2u,
      )

    assertTrue(
      aptosConfidentialRegistrationVerify(
        publicKey = current.publicKey,
        senderAddress = sender,
        tokenAddress = token,
        chainId = 2u,
        proof = registration,
      )
    )

    val oldHandles =
      List(8) { index ->
        twistedElgamalEncrypt(
            publicKey = current.publicKey,
            amount = index.toULong(),
            randomness = null,
          )
          .handle
      }
    val rotation =
      aptosConfidentialKeyRotationProve(
        currentPrivateKey = current.privateKey,
        newPrivateKey = next.privateKey,
        oldHandles = oldHandles,
        senderAddress = sender,
        tokenAddress = token,
        chainId = 2u,
      )

    assertTrue(rotation.newPublicKey.contentEquals(next.publicKey))
    assertTrue(
      aptosConfidentialKeyRotationVerify(
        oldPublicKey = current.publicKey,
        newPublicKey = rotation.newPublicKey,
        oldHandles = oldHandles,
        newHandles = rotation.newHandles,
        senderAddress = sender,
        tokenAddress = token,
        chainId = 2u,
        proof = rotation.proof,
      )
    )
  }

  @Test
  fun secureRandomBytesUsesTheRequestedLength() {
    val first = secureRandomBytes(32u)
    val second = secureRandomBytes(32u)

    assertEquals(32, first.size)
    assertEquals(32, second.size)
    assertFalse(first.contentEquals(second))
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
    val edPrivate = mnemonicDerivePrivateKey(testMnemonic, "", SignatureScheme.ED25519, ed25519Path)
    val edPublic = mnemonicDerivePublicKey(testMnemonic, "", SignatureScheme.ED25519, ed25519Path)
    assertEquals(32, edPrivate.size)
    assertEquals(32, edPublic.size)

    val k1Private = mnemonicDerivePrivateKey(testMnemonic, "", SignatureScheme.SECP256K1, secpPath)
    val k1Public = mnemonicDerivePublicKey(testMnemonic, "", SignatureScheme.SECP256K1, secpPath)
    assertEquals(32, k1Private.size)
    assertEquals(33, k1Public.size)

    val r1Private = mnemonicDerivePrivateKey(testMnemonic, "", SignatureScheme.SECP256R1, secpPath)
    val r1Public = mnemonicDerivePublicKey(testMnemonic, "", SignatureScheme.SECP256R1, secpPath)
    assertEquals(32, r1Private.size)
    assertEquals(33, r1Public.size)
  }

  @Test
  fun mnemonicDeriveKeypairMatchesPublicKey() {
    val keypair = mnemonicDeriveKeypair(testMnemonic, "", SignatureScheme.ED25519, ed25519Path)
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
