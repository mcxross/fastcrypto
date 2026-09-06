use ark_bn254::{G1Affine as Bn254G1Affine, G2Affine as Bn254G2Affine};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bip39::{Language, Mnemonic};
use fastcrypto::ed25519::{
    Ed25519KeyPair, Ed25519PublicKey, Ed25519Signature, ED25519_PRIVATE_KEY_LENGTH,
    ED25519_PUBLIC_KEY_LENGTH, ED25519_SIGNATURE_LENGTH,
};
use fastcrypto::error::FastCryptoError;
use fastcrypto::hash::HashFunction;
use fastcrypto::hash::{Blake2b256, Keccak256, Sha256, Sha3_256, Sha3_512, Sha512};
use fastcrypto::hmac::{hkdf_sha3_256, hmac_sha3_256, HkdfIkm, HmacKey};
use fastcrypto::secp256k1::recoverable::{
    Secp256k1RecoverableSignature, SECP256K1_RECOVERABLE_SIGNATURE_SIZE,
};
use fastcrypto::secp256k1::{
    Secp256k1KeyPair, Secp256k1PublicKey, Secp256k1Signature, SECP256K1_PRIVATE_KEY_LENGTH,
    SECP256K1_PUBLIC_KEY_LENGTH, SECP256K1_SIGNATURE_LENGTH,
};
use fastcrypto::secp256r1::recoverable::{
    Secp256r1RecoverableSignature, SECP256R1_RECOVERABLE_SIGNATURE_LENGTH,
};
use fastcrypto::secp256r1::{
    Secp256r1KeyPair, Secp256r1PublicKey, Secp256r1Signature, SECP256R1_PRIVATE_KEY_LENGTH,
    SECP256R1_PUBLIC_KEY_LENGTH, SECP256R1_SIGNATURE_LENTH,
};
use fastcrypto::traits::{
    KeyPair, RecoverableSignature, RecoverableSigner, Signer, ToFromBytes, VerifyingKey,
};
use fastcrypto_zkp::bn254::{api as bn254_groth16, poseidon as bn254_poseidon};
use hmac::{Hmac, Mac};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::{NonZeroScalar, PrimeField};
use k256::{FieldBytes as K256FieldBytes, PublicKey as K256PublicKey, Scalar as K256Scalar};
use p256::PublicKey as P256PublicKey;
use rand::{thread_rng, RngCore};
use sha2::Sha512 as Sha512Digest;
use subtle::CtOption;
use zeroize::Zeroize;

mod aptos_batch_encryption;
mod confidential_assets;

pub use confidential_assets::*;

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FastCryptoFfiError {
    #[error("Invalid input")]
    InvalidInput,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Input too short: expected at least {0}")]
    InputTooShort(u64),
    #[error("Input too long: expected at most {0}")]
    InputTooLong(u64),
    #[error("Input length wrong: expected {0}")]
    InputLengthWrong(u64),
    #[error("General error: {0}")]
    General(String),
}

#[derive(Copy, Clone, Debug, uniffi::Enum)]
pub enum SignatureScheme {
    Ed25519,
    Secp256k1,
    Secp256r1,
}

impl From<FastCryptoError> for FastCryptoFfiError {
    fn from(err: FastCryptoError) -> Self {
        match err {
            FastCryptoError::InvalidInput => Self::InvalidInput,
            FastCryptoError::InvalidSignature => Self::InvalidSignature,
            FastCryptoError::InputTooShort(len) => Self::InputTooShort(len as u64),
            FastCryptoError::InputTooLong(len) => Self::InputTooLong(len as u64),
            FastCryptoError::InputLengthWrong(len) => Self::InputLengthWrong(len as u64),
            FastCryptoError::GeneralError(msg) => Self::General(msg),
            FastCryptoError::GeneralOpaqueError => {
                Self::General("Opaque cryptographic error".to_string())
            }
            other => Self::General(other.to_string()),
        }
    }
}

#[derive(uniffi::Record)]
pub struct KeyPairBytes {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

/// Byte-oriented prepared BN254 Groth16 verifying key components.
///
/// Keeping the curve representation opaque prevents Arkworks types and implementation details
/// from leaking through the Kotlin API while retaining the exact FastCrypto serialization.
#[derive(Clone, Debug, uniffi::Record)]
pub struct Bn254PreparedVerifyingKeyBytes {
    pub gamma_abc_g1: Vec<u8>,
    pub alpha_g1_beta_g2: Vec<u8>,
    pub gamma_g2_neg_pc: Vec<u8>,
    pub delta_g2_neg_pc: Vec<u8>,
}

fn ensure_len(actual: usize, expected: usize) -> Result<(), FastCryptoFfiError> {
    if actual != expected {
        return Err(FastCryptoFfiError::InputLengthWrong(expected as u64));
    }
    Ok(())
}

/// Encrypts already-BCS-encoded Aptos transaction plaintext and associated data with the
/// node-advertised BCS encryption key. The returned bytes are the exact Aptos `Ciphertext` BCS
/// record consumed by encrypted transaction payloads.
#[uniffi::export]
pub fn aptos_batch_encrypt(
    encryption_key_bcs: Vec<u8>,
    plaintext_bcs: Vec<u8>,
    associated_data_bcs: Vec<u8>,
) -> Result<Vec<u8>, FastCryptoFfiError> {
    aptos_batch_encryption::encrypt(&encryption_key_bcs, &plaintext_bcs, &associated_data_bcs)
}

/// Computes the BN254 Poseidon hash used by Aptos Keyless.
///
/// Each input must be one canonical 32-byte little-endian BN254 scalar. Poseidon accepts between
/// one and sixteen inputs.
#[uniffi::export]
pub fn bn254_poseidon_hash(inputs: Vec<Vec<u8>>) -> Result<Vec<u8>, FastCryptoFfiError> {
    if inputs.is_empty() || inputs.len() > 16 {
        return Err(FastCryptoFfiError::InvalidInput);
    }
    if inputs.iter().any(|input| input.len() != 32) {
        return Err(FastCryptoFfiError::InputLengthWrong(32));
    }
    Ok(bn254_poseidon::poseidon_bytes(&inputs)?.to_vec())
}

/// Converts a compressed BN254 Groth16 verifying key into FastCrypto's verification-only form.
#[uniffi::export]
pub fn bn254_prepare_groth16_verifying_key(
    verifying_key: Vec<u8>,
) -> Result<Bn254PreparedVerifyingKeyBytes, FastCryptoFfiError> {
    const MAX_VERIFYING_KEY_BYTES: usize = 1024 * 1024;
    if verifying_key.is_empty() {
        return Err(FastCryptoFfiError::InvalidInput);
    }
    if verifying_key.len() > MAX_VERIFYING_KEY_BYTES {
        return Err(FastCryptoFfiError::InputTooLong(
            MAX_VERIFYING_KEY_BYTES as u64,
        ));
    }

    let components = bn254_groth16::prepare_pvk_bytes(&verifying_key)?;
    let [gamma_abc_g1, alpha_g1_beta_g2, gamma_g2_neg_pc, delta_g2_neg_pc]: [Vec<u8>; 4] =
        components
            .try_into()
            .map_err(|_| FastCryptoFfiError::InvalidInput)?;
    Ok(Bn254PreparedVerifyingKeyBytes {
        gamma_abc_g1,
        alpha_g1_beta_g2,
        gamma_g2_neg_pc,
        delta_g2_neg_pc,
    })
}

/// Prepares an Aptos on-chain BN254 Groth16 verifying key from its compressed point fields.
#[uniffi::export]
pub fn bn254_prepare_groth16_verifying_key_components(
    alpha_g1: Vec<u8>,
    beta_g2: Vec<u8>,
    gamma_g2: Vec<u8>,
    delta_g2: Vec<u8>,
    gamma_abc_g1: Vec<Vec<u8>>,
) -> Result<Bn254PreparedVerifyingKeyBytes, FastCryptoFfiError> {
    ensure_len(alpha_g1.len(), 32)?;
    ensure_len(beta_g2.len(), 64)?;
    ensure_len(gamma_g2.len(), 64)?;
    ensure_len(delta_g2.len(), 64)?;
    if gamma_abc_g1.is_empty() || gamma_abc_g1.len() > 1024 {
        return Err(FastCryptoFfiError::InvalidInput);
    }
    if gamma_abc_g1.iter().any(|point| point.len() != 32) {
        return Err(FastCryptoFfiError::InputLengthWrong(32));
    }

    fn g1(bytes: &[u8]) -> Result<Bn254G1Affine, FastCryptoFfiError> {
        Bn254G1Affine::deserialize_compressed(bytes).map_err(|_| FastCryptoFfiError::InvalidInput)
    }
    fn g2(bytes: &[u8]) -> Result<Bn254G2Affine, FastCryptoFfiError> {
        Bn254G2Affine::deserialize_compressed(bytes).map_err(|_| FastCryptoFfiError::InvalidInput)
    }

    let verifying_key = ark_groth16::VerifyingKey::<ark_bn254::Bn254> {
        alpha_g1: g1(&alpha_g1)?,
        beta_g2: g2(&beta_g2)?,
        gamma_g2: g2(&gamma_g2)?,
        delta_g2: g2(&delta_g2)?,
        gamma_abc_g1: gamma_abc_g1
            .iter()
            .map(|point| g1(point))
            .collect::<Result<Vec<_>, _>>()?,
    };
    let mut bytes = Vec::new();
    verifying_key
        .serialize_compressed(&mut bytes)
        .map_err(|_| FastCryptoFfiError::InvalidInput)?;
    bn254_prepare_groth16_verifying_key(bytes)
}

/// Verifies a compressed BN254 Groth16 proof against a previously prepared verifying key.
#[uniffi::export]
pub fn bn254_verify_groth16(
    prepared_key: Bn254PreparedVerifyingKeyBytes,
    public_inputs: Vec<u8>,
    proof: Vec<u8>,
) -> Result<bool, FastCryptoFfiError> {
    const COMPRESSED_PROOF_BYTES: usize = 128;
    const MAX_PUBLIC_INPUT_BYTES: usize = 1024 * 1024;
    if public_inputs.len() > MAX_PUBLIC_INPUT_BYTES {
        return Err(FastCryptoFfiError::InputTooLong(
            MAX_PUBLIC_INPUT_BYTES as u64,
        ));
    }
    if public_inputs.len() % bn254_groth16::SCALAR_SIZE != 0 {
        return Err(FastCryptoFfiError::InputLengthWrong(
            bn254_groth16::SCALAR_SIZE as u64,
        ));
    }
    ensure_len(proof.len(), COMPRESSED_PROOF_BYTES)?;

    Ok(bn254_groth16::verify_groth16_in_bytes(
        &prepared_key.gamma_abc_g1,
        &prepared_key.alpha_g1_beta_g2,
        &prepared_key.gamma_g2_neg_pc,
        &prepared_key.delta_g2_neg_pc,
        &public_inputs,
        &proof,
    )?)
}

fn normalize_secp256r1_public_key(
    public_key: &[u8],
    compressed: bool,
) -> Result<Vec<u8>, FastCryptoFfiError> {
    if public_key.len() != SECP256R1_PUBLIC_KEY_LENGTH && public_key.len() != 65 {
        return Err(FastCryptoFfiError::InputLengthWrong(
            SECP256R1_PUBLIC_KEY_LENGTH as u64,
        ));
    }
    let public_key =
        P256PublicKey::from_sec1_bytes(public_key).map_err(|_| FastCryptoFfiError::InvalidInput)?;
    Ok(public_key.to_encoded_point(compressed).as_bytes().to_vec())
}

fn ensure_mnemonic_word_count(word_count: usize) -> Result<usize, FastCryptoFfiError> {
    if (12..=24).contains(&word_count) && word_count % 3 == 0 {
        Ok(word_count)
    } else {
        Err(FastCryptoFfiError::InvalidInput)
    }
}

fn parse_mnemonic(phrase: &str) -> Result<Mnemonic, FastCryptoFfiError> {
    Mnemonic::parse_in_normalized(Language::English, phrase)
        .map_err(|_| FastCryptoFfiError::InvalidInput)
}

fn parse_derivation_path(path: &str) -> Result<Vec<(u32, bool)>, FastCryptoFfiError> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err(FastCryptoFfiError::InvalidInput);
    }
    let mut work = trimmed;
    if work.starts_with("m/") || work.starts_with("M/") {
        work = &work[2..];
    } else if work == "m" || work == "M" {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    for part in work.split('/') {
        if part.is_empty() {
            return Err(FastCryptoFfiError::InvalidInput);
        }
        let hardened = part.ends_with('\'') || part.ends_with('H') || part.ends_with('h');
        let index_str = if hardened {
            &part[..part.len() - 1]
        } else {
            part
        };
        let index: u32 = index_str
            .parse()
            .map_err(|_| FastCryptoFfiError::InvalidInput)?;
        if index >= 0x8000_0000 {
            return Err(FastCryptoFfiError::InvalidInput);
        }
        out.push((index, hardened));
    }
    Ok(out)
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> Result<[u8; 64], FastCryptoFfiError> {
    type HmacSha512 = Hmac<Sha512Digest>;
    let mut mac = HmacSha512::new_from_slice(key).map_err(|_| FastCryptoFfiError::InvalidInput)?;
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    Ok(out)
}

fn ed25519_master_key(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), FastCryptoFfiError> {
    let i = hmac_sha512(b"ed25519 seed", seed)?;
    Ok((i[0..32].to_vec(), i[32..64].to_vec()))
}

fn ed25519_derive_child(
    key: &[u8],
    chaincode: &[u8],
    index: u32,
) -> Result<(Vec<u8>, Vec<u8>), FastCryptoFfiError> {
    let mut data = Vec::with_capacity(1 + key.len() + 4);
    data.push(0u8);
    data.extend_from_slice(key);
    data.extend_from_slice(&index.to_be_bytes());
    let i = hmac_sha512(chaincode, &data)?;
    Ok((i[0..32].to_vec(), i[32..64].to_vec()))
}

fn ed25519_derive_private_key(seed: &[u8], path: &str) -> Result<Vec<u8>, FastCryptoFfiError> {
    let steps = parse_derivation_path(path)?;
    let (mut key, mut chaincode) = ed25519_master_key(seed)?;
    for (index, hardened) in steps {
        if !hardened {
            return Err(FastCryptoFfiError::InvalidInput);
        }
        let hardened_index = index | 0x8000_0000;
        let (child_key, child_chain) = ed25519_derive_child(&key, &chaincode, hardened_index)?;
        key = child_key;
        chaincode = child_chain;
    }
    Ok(key)
}

fn ct_option_to_result<T>(value: CtOption<T>) -> Result<T, FastCryptoFfiError> {
    Option::<T>::from(value).ok_or(FastCryptoFfiError::InvalidInput)
}

fn bip32_master_key(seed: &[u8]) -> Result<(K256Scalar, [u8; 32]), FastCryptoFfiError> {
    let i = hmac_sha512(b"Bitcoin seed", seed)?;
    let il = &i[0..32];
    let ir = &i[32..64];
    let mut il_bytes = [0u8; 32];
    il_bytes.copy_from_slice(il);
    let scalar = ct_option_to_result(K256Scalar::from_repr(K256FieldBytes::from(il_bytes)))?;
    let mut chaincode = [0u8; 32];
    chaincode.copy_from_slice(ir);
    Ok((scalar, chaincode))
}

fn bip32_derive_child(
    parent_key: K256Scalar,
    chaincode: [u8; 32],
    index: u32,
    hardened: bool,
) -> Result<(K256Scalar, [u8; 32]), FastCryptoFfiError> {
    let mut data = Vec::with_capacity(37);
    let child_index = if hardened { index | 0x8000_0000 } else { index };
    if hardened {
        data.push(0u8);
        data.extend_from_slice(&parent_key.to_bytes());
    } else {
        let nonzero = ct_option_to_result(NonZeroScalar::new(parent_key))?;
        let public = K256PublicKey::from_secret_scalar(&nonzero);
        let encoded = public.to_encoded_point(true);
        data.extend_from_slice(encoded.as_bytes());
    }
    data.extend_from_slice(&child_index.to_be_bytes());
    let i = hmac_sha512(&chaincode, &data)?;
    let il = &i[0..32];
    let ir = &i[32..64];
    let mut il_bytes = [0u8; 32];
    il_bytes.copy_from_slice(il);
    let il_scalar = ct_option_to_result(K256Scalar::from_repr(K256FieldBytes::from(il_bytes)))?;
    let child_key = il_scalar + parent_key;
    if bool::from(child_key.is_zero()) {
        return Err(FastCryptoFfiError::InvalidInput);
    }
    let mut child_chaincode = [0u8; 32];
    child_chaincode.copy_from_slice(ir);
    Ok((child_key, child_chaincode))
}

fn bip32_derive_private_key(seed: &[u8], path: &str) -> Result<Vec<u8>, FastCryptoFfiError> {
    let steps = parse_derivation_path(path)?;
    let (mut key, mut chaincode) = bip32_master_key(seed)?;
    for (index, hardened) in steps {
        let (child_key, child_chaincode) = bip32_derive_child(key, chaincode, index, hardened)?;
        key = child_key;
        chaincode = child_chaincode;
    }
    Ok(key.to_bytes().to_vec())
}

#[uniffi::export]
pub fn ed25519_generate_keypair() -> KeyPairBytes {
    let kp = Ed25519KeyPair::generate(&mut thread_rng());
    KeyPairBytes {
        public_key: kp.public().as_ref().to_vec(),
        private_key: kp.as_ref().to_vec(),
    }
}

#[uniffi::export]
pub fn ed25519_public_key_from_private(
    private_key: Vec<u8>,
) -> Result<Vec<u8>, FastCryptoFfiError> {
    ensure_len(private_key.len(), ED25519_PRIVATE_KEY_LENGTH)?;
    let mut private_key = private_key;
    let kp = Ed25519KeyPair::from_bytes(&private_key)?;
    private_key.zeroize();
    Ok(kp.public().as_ref().to_vec())
}

#[uniffi::export]
pub fn ed25519_sign(private_key: Vec<u8>, message: Vec<u8>) -> Result<Vec<u8>, FastCryptoFfiError> {
    ensure_len(private_key.len(), ED25519_PRIVATE_KEY_LENGTH)?;
    let mut private_key = private_key;
    let kp = Ed25519KeyPair::from_bytes(&private_key)?;
    let sig = kp.sign(&message);
    private_key.zeroize();
    Ok(sig.as_ref().to_vec())
}

#[uniffi::export]
pub fn ed25519_verify(
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
) -> Result<bool, FastCryptoFfiError> {
    ensure_len(public_key.len(), ED25519_PUBLIC_KEY_LENGTH)?;
    ensure_len(signature.len(), ED25519_SIGNATURE_LENGTH)?;
    let pk = Ed25519PublicKey::from_bytes(&public_key)?;
    let sig = Ed25519Signature::from_bytes(&signature)?;
    Ok(pk.verify(&message, &sig).is_ok())
}

#[uniffi::export]
pub fn secp256k1_generate_keypair() -> KeyPairBytes {
    let kp = Secp256k1KeyPair::generate(&mut thread_rng());
    KeyPairBytes {
        public_key: kp.public().as_ref().to_vec(),
        private_key: kp.as_ref().to_vec(),
    }
}

#[uniffi::export]
pub fn secp256k1_public_key_from_private(
    private_key: Vec<u8>,
) -> Result<Vec<u8>, FastCryptoFfiError> {
    ensure_len(private_key.len(), SECP256K1_PRIVATE_KEY_LENGTH)?;
    let mut private_key = private_key;
    let kp = Secp256k1KeyPair::from_bytes(&private_key)?;
    private_key.zeroize();
    Ok(kp.public().as_ref().to_vec())
}

#[uniffi::export]
pub fn secp256k1_sign(
    private_key: Vec<u8>,
    message: Vec<u8>,
) -> Result<Vec<u8>, FastCryptoFfiError> {
    ensure_len(private_key.len(), SECP256K1_PRIVATE_KEY_LENGTH)?;
    let mut private_key = private_key;
    let kp = Secp256k1KeyPair::from_bytes(&private_key)?;
    let sig = kp.sign(&message);
    private_key.zeroize();
    Ok(sig.as_ref().to_vec())
}

#[uniffi::export]
pub fn secp256k1_verify(
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
) -> Result<bool, FastCryptoFfiError> {
    ensure_len(public_key.len(), SECP256K1_PUBLIC_KEY_LENGTH)?;
    ensure_len(signature.len(), SECP256K1_SIGNATURE_LENGTH)?;
    let pk = Secp256k1PublicKey::from_bytes(&public_key)?;
    let sig = Secp256k1Signature::from_bytes(&signature)?;
    Ok(pk.verify(&message, &sig).is_ok())
}

#[uniffi::export]
pub fn secp256k1_sign_recoverable(
    private_key: Vec<u8>,
    message: Vec<u8>,
) -> Result<Vec<u8>, FastCryptoFfiError> {
    ensure_len(private_key.len(), SECP256K1_PRIVATE_KEY_LENGTH)?;
    let mut private_key = private_key;
    let kp = Secp256k1KeyPair::from_bytes(&private_key)?;
    let sig = kp.sign_recoverable(&message);
    private_key.zeroize();
    Ok(sig.as_ref().to_vec())
}

#[uniffi::export]
pub fn secp256k1_recover_public_key(
    message: Vec<u8>,
    signature: Vec<u8>,
) -> Result<Vec<u8>, FastCryptoFfiError> {
    ensure_len(signature.len(), SECP256K1_RECOVERABLE_SIGNATURE_SIZE)?;
    let sig = Secp256k1RecoverableSignature::from_bytes(&signature)?;
    let pk = sig.recover(&message)?;
    Ok(pk.as_ref().to_vec())
}

#[uniffi::export]
pub fn secp256r1_generate_keypair() -> KeyPairBytes {
    let kp = Secp256r1KeyPair::generate(&mut thread_rng());
    KeyPairBytes {
        public_key: kp.public().as_ref().to_vec(),
        private_key: kp.as_ref().to_vec(),
    }
}

#[uniffi::export]
pub fn secp256r1_public_key_from_private(
    private_key: Vec<u8>,
) -> Result<Vec<u8>, FastCryptoFfiError> {
    ensure_len(private_key.len(), SECP256R1_PRIVATE_KEY_LENGTH)?;
    let mut private_key = private_key;
    let kp = Secp256r1KeyPair::from_bytes(&private_key)?;
    private_key.zeroize();
    Ok(kp.public().as_ref().to_vec())
}

/// Validates and converts a compressed or uncompressed SEC1 P-256 public key.
#[uniffi::export]
pub fn secp256r1_normalize_public_key(
    public_key: Vec<u8>,
    compressed: bool,
) -> Result<Vec<u8>, FastCryptoFfiError> {
    normalize_secp256r1_public_key(&public_key, compressed)
}

#[uniffi::export]
pub fn secp256r1_sign(
    private_key: Vec<u8>,
    message: Vec<u8>,
) -> Result<Vec<u8>, FastCryptoFfiError> {
    ensure_len(private_key.len(), SECP256R1_PRIVATE_KEY_LENGTH)?;
    let mut private_key = private_key;
    let kp = Secp256r1KeyPair::from_bytes(&private_key)?;
    let sig = kp.sign(&message);
    private_key.zeroize();
    Ok(sig.as_ref().to_vec())
}

/// Aptos' P-256 convention hashes transaction and message bytes with SHA3-256.
///
/// This operation is deliberately separate from [`secp256r1_sign`], whose SHA-256 behavior is
/// retained for standards such as WebAuthn.
#[uniffi::export]
pub fn secp256r1_sign_sha3_256(
    private_key: Vec<u8>,
    message: Vec<u8>,
) -> Result<Vec<u8>, FastCryptoFfiError> {
    ensure_len(private_key.len(), SECP256R1_PRIVATE_KEY_LENGTH)?;
    let mut private_key = private_key;
    let kp = Secp256r1KeyPair::from_bytes(&private_key)?;
    let sig = kp.sign_with_hash::<Sha3_256>(&message);
    private_key.zeroize();
    Ok(sig.as_ref().to_vec())
}

#[uniffi::export]
pub fn mnemonic_generate(word_count: u32) -> Result<String, FastCryptoFfiError> {
    let count = ensure_mnemonic_word_count(word_count as usize)?;
    let mnemonic = Mnemonic::generate_in(Language::English, count)
        .map_err(|_| FastCryptoFfiError::InvalidInput)?;
    Ok(mnemonic.to_string())
}

#[uniffi::export]
pub fn mnemonic_validate(phrase: String) -> bool {
    Mnemonic::parse_in_normalized(Language::English, &phrase).is_ok()
}

#[uniffi::export]
pub fn mnemonic_to_seed(phrase: String, passphrase: String) -> Result<Vec<u8>, FastCryptoFfiError> {
    let mnemonic = parse_mnemonic(&phrase)?;
    let seed = mnemonic.to_seed(passphrase);
    Ok(seed.to_vec())
}

#[uniffi::export]
pub fn mnemonic_derive_private_key(
    phrase: String,
    passphrase: String,
    scheme: SignatureScheme,
    path: String,
) -> Result<Vec<u8>, FastCryptoFfiError> {
    let mnemonic = parse_mnemonic(&phrase)?;
    let seed = mnemonic.to_seed(passphrase);
    match scheme {
        SignatureScheme::Ed25519 => ed25519_derive_private_key(seed.as_ref(), &path),
        SignatureScheme::Secp256k1 | SignatureScheme::Secp256r1 => {
            bip32_derive_private_key(seed.as_ref(), &path)
        }
    }
}

#[uniffi::export]
pub fn mnemonic_derive_public_key(
    phrase: String,
    passphrase: String,
    scheme: SignatureScheme,
    path: String,
) -> Result<Vec<u8>, FastCryptoFfiError> {
    let private_key = mnemonic_derive_private_key(phrase, passphrase, scheme, path)?;
    match scheme {
        SignatureScheme::Ed25519 => ed25519_public_key_from_private(private_key),
        SignatureScheme::Secp256k1 => secp256k1_public_key_from_private(private_key),
        SignatureScheme::Secp256r1 => secp256r1_public_key_from_private(private_key),
    }
}

#[uniffi::export]
pub fn mnemonic_derive_keypair(
    phrase: String,
    passphrase: String,
    scheme: SignatureScheme,
    path: String,
) -> Result<KeyPairBytes, FastCryptoFfiError> {
    let private_key = mnemonic_derive_private_key(phrase, passphrase, scheme, path)?;
    let public_key = match scheme {
        SignatureScheme::Ed25519 => ed25519_public_key_from_private(private_key.clone())?,
        SignatureScheme::Secp256k1 => secp256k1_public_key_from_private(private_key.clone())?,
        SignatureScheme::Secp256r1 => secp256r1_public_key_from_private(private_key.clone())?,
    };
    Ok(KeyPairBytes {
        public_key,
        private_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Bn254, Fr};
    use ark_ff::UniformRand;
    use ark_groth16::Groth16;
    use ark_serialize::CanonicalSerialize;
    use ark_snark::SNARK;
    use ark_std::rand::thread_rng;
    use fastcrypto::ed25519::{
        ED25519_PRIVATE_KEY_LENGTH, ED25519_PUBLIC_KEY_LENGTH, ED25519_SIGNATURE_LENGTH,
    };
    use fastcrypto::secp256k1::{
        SECP256K1_PRIVATE_KEY_LENGTH, SECP256K1_PUBLIC_KEY_LENGTH, SECP256K1_SIGNATURE_LENGTH,
    };
    use fastcrypto::secp256r1::{
        SECP256R1_PRIVATE_KEY_LENGTH, SECP256R1_PUBLIC_KEY_LENGTH, SECP256R1_SIGNATURE_LENTH,
    };
    use fastcrypto_zkp::dummy_circuits::DummyCircuit;

    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn bn254_poseidon_matches_known_aptos_vectors() {
        let mut one = vec![0u8; 32];
        one[0] = 1;
        let mut two = vec![0u8; 32];
        two[0] = 2;

        assert_eq!(
            hex::encode(bn254_poseidon_hash(vec![one.clone()]).unwrap()),
            "33018202c57d898b84338b16d1a4960e133c6a4d656cfec1bd62a9ea00611729"
        );
        assert_eq!(
            hex::encode(bn254_poseidon_hash(vec![one, two]).unwrap()),
            "9a1817447a60199e51453274f217362acfe962966b4cf63d4190d6e7f5c05c11"
        );
        assert!(bn254_poseidon_hash(vec![]).is_err());
        assert!(bn254_poseidon_hash(vec![vec![0u8; 31]]).is_err());
        assert!(bn254_poseidon_hash(vec![vec![0xff; 32]]).is_err());
    }

    #[test]
    fn bn254_groth16_prepare_and_verify_roundtrip() {
        let rng = &mut thread_rng();
        let circuit = DummyCircuit::<Fr> {
            a: Some(Fr::rand(rng)),
            b: Some(Fr::rand(rng)),
            num_variables: 16,
            num_constraints: 4,
        };
        let (proving_key, verifying_key) =
            Groth16::<Bn254>::circuit_specific_setup(circuit, rng).unwrap();
        let proof = Groth16::<Bn254>::prove(&proving_key, circuit, rng).unwrap();
        let public_input = circuit.a.unwrap() * circuit.b.unwrap();

        let mut verifying_key_bytes = Vec::new();
        verifying_key
            .serialize_compressed(&mut verifying_key_bytes)
            .unwrap();
        let prepared = bn254_prepare_groth16_verifying_key(verifying_key_bytes).unwrap();

        let mut public_input_bytes = Vec::new();
        public_input
            .serialize_compressed(&mut public_input_bytes)
            .unwrap();
        let mut proof_bytes = Vec::new();
        proof.a.serialize_compressed(&mut proof_bytes).unwrap();
        proof.b.serialize_compressed(&mut proof_bytes).unwrap();
        proof.c.serialize_compressed(&mut proof_bytes).unwrap();
        assert_eq!(proof_bytes.len(), 128);

        assert!(bn254_verify_groth16(
            prepared.clone(),
            public_input_bytes.clone(),
            proof_bytes.clone(),
        )
        .unwrap());

        public_input_bytes[0] ^= 1;
        assert!(!bn254_verify_groth16(prepared, public_input_bytes, proof_bytes).unwrap());
    }

    #[test]
    fn ed25519_keypair_sign_verify_roundtrip() {
        let message = b"fastcrypto-ed25519".to_vec();
        let kp = ed25519_generate_keypair();
        assert_eq!(kp.public_key.len(), ED25519_PUBLIC_KEY_LENGTH);
        assert_eq!(kp.private_key.len(), ED25519_PRIVATE_KEY_LENGTH);

        let signature = ed25519_sign(kp.private_key.clone(), message.clone()).unwrap();
        assert_eq!(signature.len(), ED25519_SIGNATURE_LENGTH);
        let verified = ed25519_verify(kp.public_key.clone(), message, signature).unwrap();
        assert!(verified);
    }

    #[test]
    fn secp256k1_keypair_sign_verify_roundtrip() {
        let message = b"fastcrypto-secp256k1".to_vec();
        let kp = secp256k1_generate_keypair();
        assert_eq!(kp.public_key.len(), SECP256K1_PUBLIC_KEY_LENGTH);
        assert_eq!(kp.private_key.len(), SECP256K1_PRIVATE_KEY_LENGTH);

        let signature = secp256k1_sign(kp.private_key.clone(), message.clone()).unwrap();
        assert_eq!(signature.len(), SECP256K1_SIGNATURE_LENGTH);
        let verified = secp256k1_verify(kp.public_key.clone(), message, signature).unwrap();
        assert!(verified);
    }

    #[test]
    fn secp256r1_keypair_sign_verify_roundtrip() {
        let message = b"fastcrypto-secp256r1".to_vec();
        let kp = secp256r1_generate_keypair();
        assert_eq!(kp.public_key.len(), SECP256R1_PUBLIC_KEY_LENGTH);
        assert_eq!(kp.private_key.len(), SECP256R1_PRIVATE_KEY_LENGTH);

        let signature = secp256r1_sign(kp.private_key.clone(), message.clone()).unwrap();
        assert_eq!(signature.len(), SECP256R1_SIGNATURE_LENTH);
        let verified = secp256r1_verify(kp.public_key.clone(), message, signature).unwrap();
        assert!(verified);
    }

    #[test]
    fn secp256r1_sha3_sign_verify_roundtrip() {
        let message = b"aptos-secp256r1".to_vec();
        let kp = secp256r1_generate_keypair();

        let signature = secp256r1_sign_sha3_256(kp.private_key.clone(), message.clone()).unwrap();
        assert_eq!(signature.len(), SECP256R1_SIGNATURE_LENTH);
        assert!(secp256r1_verify_sha3_256(
            kp.public_key.clone(),
            message.clone(),
            signature.clone(),
        )
        .unwrap());
        assert!(!secp256r1_verify(kp.public_key, message, signature).unwrap());
    }

    #[test]
    fn secp256r1_public_key_normalization_accepts_both_sec1_forms() {
        let kp = secp256r1_generate_keypair();
        let uncompressed = secp256r1_normalize_public_key(kp.public_key.clone(), false).unwrap();
        assert_eq!(uncompressed.len(), 65);
        let compressed = secp256r1_normalize_public_key(uncompressed, true).unwrap();
        assert_eq!(compressed, kp.public_key);
    }

    #[test]
    fn mnemonic_generation_and_validation() {
        for &count in &[12u32, 15, 18, 21, 24] {
            let phrase = mnemonic_generate(count).unwrap();
            assert!(mnemonic_validate(phrase));
        }

        assert!(mnemonic_generate(11).is_err());
        assert!(mnemonic_generate(13).is_err());
        assert!(!mnemonic_validate("not a valid mnemonic".to_string()));
    }

    #[test]
    fn mnemonic_seed_length() {
        let seed = mnemonic_to_seed(TEST_MNEMONIC.to_string(), "".to_string()).unwrap();
        assert_eq!(seed.len(), 64);
    }

    #[test]
    fn mnemonic_derive_keys_all_schemes() {
        let path = "m/44'/784'/0'/0'/0'".to_string();

        let ed_priv = mnemonic_derive_private_key(
            TEST_MNEMONIC.to_string(),
            "".to_string(),
            SignatureScheme::Ed25519,
            path.clone(),
        )
        .unwrap();
        assert_eq!(ed_priv.len(), ED25519_PRIVATE_KEY_LENGTH);
        let ed_pub = mnemonic_derive_public_key(
            TEST_MNEMONIC.to_string(),
            "".to_string(),
            SignatureScheme::Ed25519,
            path.clone(),
        )
        .unwrap();
        assert_eq!(ed_pub.len(), ED25519_PUBLIC_KEY_LENGTH);

        let k1_priv = mnemonic_derive_private_key(
            TEST_MNEMONIC.to_string(),
            "".to_string(),
            SignatureScheme::Secp256k1,
            "m/44'/0'/0'/0/0".to_string(),
        )
        .unwrap();
        assert_eq!(k1_priv.len(), SECP256K1_PRIVATE_KEY_LENGTH);
        let k1_pub = mnemonic_derive_public_key(
            TEST_MNEMONIC.to_string(),
            "".to_string(),
            SignatureScheme::Secp256k1,
            "m/44'/0'/0'/0/0".to_string(),
        )
        .unwrap();
        assert_eq!(k1_pub.len(), SECP256K1_PUBLIC_KEY_LENGTH);

        let r1_priv = mnemonic_derive_private_key(
            TEST_MNEMONIC.to_string(),
            "".to_string(),
            SignatureScheme::Secp256r1,
            "m/44'/0'/0'/0/1".to_string(),
        )
        .unwrap();
        assert_eq!(r1_priv.len(), SECP256R1_PRIVATE_KEY_LENGTH);
        let r1_pub = mnemonic_derive_public_key(
            TEST_MNEMONIC.to_string(),
            "".to_string(),
            SignatureScheme::Secp256r1,
            "m/44'/0'/0'/0/1".to_string(),
        )
        .unwrap();
        assert_eq!(r1_pub.len(), SECP256R1_PUBLIC_KEY_LENGTH);
    }

    #[test]
    fn ed25519_rejects_non_hardened_path() {
        let result = mnemonic_derive_private_key(
            TEST_MNEMONIC.to_string(),
            "".to_string(),
            SignatureScheme::Ed25519,
            "m/44'/784'/0'/0/0".to_string(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn mnemonic_keypair_matches_public_key() {
        let path = "m/44'/784'/0'/0'/0'".to_string();
        let keypair = mnemonic_derive_keypair(
            TEST_MNEMONIC.to_string(),
            "".to_string(),
            SignatureScheme::Ed25519,
            path,
        )
        .unwrap();
        let derived_pub = ed25519_public_key_from_private(keypair.private_key.clone()).unwrap();
        assert_eq!(derived_pub, keypair.public_key);
    }
}

#[uniffi::export]
pub fn secp256r1_verify(
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
) -> Result<bool, FastCryptoFfiError> {
    ensure_len(signature.len(), SECP256R1_SIGNATURE_LENTH)?;
    let normalized_public_key = normalize_secp256r1_public_key(&public_key, true)?;
    let pk = Secp256r1PublicKey::from_bytes(&normalized_public_key)?;
    let sig = Secp256r1Signature::from_bytes(&signature)?;
    Ok(pk.verify(&message, &sig).is_ok())
}

/// Verifies an Aptos-style P-256 signature using SHA3-256 over the exact message bytes.
#[uniffi::export]
pub fn secp256r1_verify_sha3_256(
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
) -> Result<bool, FastCryptoFfiError> {
    ensure_len(signature.len(), SECP256R1_SIGNATURE_LENTH)?;
    let normalized_public_key = normalize_secp256r1_public_key(&public_key, true)?;
    let pk = Secp256r1PublicKey::from_bytes(&normalized_public_key)?;
    let sig = Secp256r1Signature::from_bytes(&signature)?;
    Ok(pk.verify_with_hash::<Sha3_256>(&message, &sig).is_ok())
}

#[uniffi::export]
pub fn secp256r1_sign_recoverable(
    private_key: Vec<u8>,
    message: Vec<u8>,
) -> Result<Vec<u8>, FastCryptoFfiError> {
    ensure_len(private_key.len(), SECP256R1_PRIVATE_KEY_LENGTH)?;
    let mut private_key = private_key;
    let kp = Secp256r1KeyPair::from_bytes(&private_key)?;
    let sig = kp.sign_recoverable(&message);
    private_key.zeroize();
    Ok(sig.as_ref().to_vec())
}

#[uniffi::export]
pub fn secp256r1_recover_public_key(
    message: Vec<u8>,
    signature: Vec<u8>,
) -> Result<Vec<u8>, FastCryptoFfiError> {
    ensure_len(signature.len(), SECP256R1_RECOVERABLE_SIGNATURE_LENGTH)?;
    let sig = Secp256r1RecoverableSignature::from_bytes(&signature)?;
    let pk = sig.recover(&message)?;
    Ok(pk.as_ref().to_vec())
}

#[uniffi::export]
pub fn sha256(message: Vec<u8>) -> Vec<u8> {
    Sha256::digest(&message).digest.to_vec()
}

#[uniffi::export]
pub fn sha3_256(message: Vec<u8>) -> Vec<u8> {
    Sha3_256::digest(&message).digest.to_vec()
}

/// Returns bytes from the platform cryptographically secure random generator.
#[uniffi::export]
pub fn secure_random_bytes(length: u32) -> Result<Vec<u8>, FastCryptoFfiError> {
    const MAX_RANDOM_BYTES: u32 = 1024 * 1024;
    if length > MAX_RANDOM_BYTES {
        return Err(FastCryptoFfiError::InputTooLong(MAX_RANDOM_BYTES as u64));
    }
    let mut output = vec![0u8; length as usize];
    thread_rng().fill_bytes(&mut output);
    Ok(output)
}

#[uniffi::export]
pub fn sha512(message: Vec<u8>) -> Vec<u8> {
    Sha512::digest(&message).digest.to_vec()
}

#[uniffi::export]
pub fn sha3_512(message: Vec<u8>) -> Vec<u8> {
    Sha3_512::digest(&message).digest.to_vec()
}

#[uniffi::export]
pub fn keccak256(message: Vec<u8>) -> Vec<u8> {
    Keccak256::digest(&message).digest.to_vec()
}

#[uniffi::export]
pub fn blake2b256(message: Vec<u8>) -> Vec<u8> {
    Blake2b256::digest(&message).digest.to_vec()
}

#[uniffi::export]
pub fn hmac_sha3_256_digest(key: Vec<u8>, message: Vec<u8>) -> Result<Vec<u8>, FastCryptoFfiError> {
    let key = HmacKey::from_bytes(&key)?;
    Ok(hmac_sha3_256(&key, &message).digest.to_vec())
}

#[uniffi::export]
pub fn hkdf_sha3_256_expand(
    ikm: Vec<u8>,
    salt: Vec<u8>,
    info: Vec<u8>,
    output_length: u32,
) -> Result<Vec<u8>, FastCryptoFfiError> {
    let ikm = HkdfIkm::from_bytes(&ikm)?;
    Ok(hkdf_sha3_256(&ikm, &salt, &info, output_length as usize)?)
}
mod seal;
