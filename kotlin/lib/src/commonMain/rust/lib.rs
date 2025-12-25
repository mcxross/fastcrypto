use fastcrypto::ed25519::{
    Ed25519KeyPair, Ed25519PublicKey, Ed25519Signature, ED25519_PRIVATE_KEY_LENGTH,
    ED25519_PUBLIC_KEY_LENGTH, ED25519_SIGNATURE_LENGTH,
};
use fastcrypto::error::FastCryptoError;
use fastcrypto::hash::{Blake2b256, Keccak256, Sha256, Sha3_256, Sha3_512, Sha512};
use fastcrypto::hash::HashFunction;
use fastcrypto::hmac::{hmac_sha3_256, hkdf_sha3_256, HkdfIkm, HmacKey};
use fastcrypto::secp256k1::{
    Secp256k1KeyPair, Secp256k1PublicKey, Secp256k1Signature,
    SECP256K1_PRIVATE_KEY_LENGTH, SECP256K1_PUBLIC_KEY_LENGTH, SECP256K1_SIGNATURE_LENGTH,
};
use fastcrypto::secp256k1::recoverable::{
    Secp256k1RecoverableSignature, SECP256K1_RECOVERABLE_SIGNATURE_SIZE,
};
use fastcrypto::secp256r1::{
    Secp256r1KeyPair, Secp256r1PublicKey, Secp256r1Signature, SECP256R1_PRIVATE_KEY_LENGTH,
    SECP256R1_PUBLIC_KEY_LENGTH, SECP256R1_SIGNATURE_LENTH,
};
use fastcrypto::secp256r1::recoverable::{
    Secp256r1RecoverableSignature, SECP256R1_RECOVERABLE_SIGNATURE_LENGTH,
};
use fastcrypto::traits::{
    KeyPair, RecoverableSignature, RecoverableSigner, Signer, ToFromBytes, VerifyingKey,
};
use bip39::{Language, Mnemonic};
use hmac::{Hmac, Mac};
use k256::{
    FieldBytes as K256FieldBytes,
    PublicKey as K256PublicKey,
    Scalar as K256Scalar,
};
use k256::elliptic_curve::{PrimeField, NonZeroScalar};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use subtle::CtOption;
use sha2::Sha512 as Sha512Digest;
use rand::thread_rng;
use zeroize::Zeroize;

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
            FastCryptoError::GeneralOpaqueError => Self::General("Opaque cryptographic error".to_string()),
            other => Self::General(other.to_string()),
        }
    }
}

#[derive(uniffi::Record)]
pub struct KeyPairBytes {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

fn ensure_len(actual: usize, expected: usize) -> Result<(), FastCryptoFfiError> {
    if actual != expected {
        return Err(FastCryptoFfiError::InputLengthWrong(expected as u64));
    }
    Ok(())
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
        let index_str = if hardened { &part[..part.len() - 1] } else { part };
        let index: u32 = index_str.parse().map_err(|_| FastCryptoFfiError::InvalidInput)?;
        if index >= 0x8000_0000 {
            return Err(FastCryptoFfiError::InvalidInput);
        }
        out.push((index, hardened));
    }
    Ok(out)
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> Result<[u8; 64], FastCryptoFfiError> {
    type HmacSha512 = Hmac<Sha512Digest>;
    let mut mac = HmacSha512::new_from_slice(key)
        .map_err(|_| FastCryptoFfiError::InvalidInput)?;
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
    let scalar = ct_option_to_result(
        K256Scalar::from_repr(K256FieldBytes::from(il_bytes)),
    )?;
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
    let il_scalar = ct_option_to_result(
        K256Scalar::from_repr(K256FieldBytes::from(il_bytes)),
    )?;
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
pub fn ed25519_sign(
    private_key: Vec<u8>,
    message: Vec<u8>,
) -> Result<Vec<u8>, FastCryptoFfiError> {
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
    use fastcrypto::ed25519::{
        ED25519_PRIVATE_KEY_LENGTH, ED25519_PUBLIC_KEY_LENGTH, ED25519_SIGNATURE_LENGTH,
    };
    use fastcrypto::secp256k1::{
        SECP256K1_PRIVATE_KEY_LENGTH, SECP256K1_PUBLIC_KEY_LENGTH, SECP256K1_SIGNATURE_LENGTH,
    };
    use fastcrypto::secp256r1::{
        SECP256R1_PRIVATE_KEY_LENGTH, SECP256R1_PUBLIC_KEY_LENGTH, SECP256R1_SIGNATURE_LENTH,
    };

    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

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
    ensure_len(public_key.len(), SECP256R1_PUBLIC_KEY_LENGTH)?;
    ensure_len(signature.len(), SECP256R1_SIGNATURE_LENTH)?;
    let pk = Secp256r1PublicKey::from_bytes(&public_key)?;
    let sig = Secp256r1Signature::from_bytes(&signature)?;
    Ok(pk.verify(&message, &sig).is_ok())
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
pub fn hmac_sha3_256_digest(
    key: Vec<u8>,
    message: Vec<u8>,
) -> Result<Vec<u8>, FastCryptoFfiError> {
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
