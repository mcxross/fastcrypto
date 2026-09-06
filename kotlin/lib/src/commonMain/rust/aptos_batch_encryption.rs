// Copyright 2026 McXross
// SPDX-License-Identifier: Apache-2.0

//! Aptos batch encryption for encrypted transaction payloads.
//!
//! This is intentionally separate from the Sui Seal implementation. The construction and domain
//! separators mirror `aptos_batch_encryption::shared::{ciphertext,symmetric,ids}`.

use crate::FastCryptoFfiError;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Nonce,
};
use aptos_ark_bls12_381::{
    g1::Config as G1Config, Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective,
};
use aptos_ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    pairing::Pairing,
    AffineRepr, CurveGroup,
};
use aptos_ark_ff::field_hashers::{DefaultFieldHasher, HashToField};
use aptos_ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use aptos_ark_std::UniformRand;
use fastcrypto::{
    ed25519::{Ed25519KeyPair, ED25519_PRIVATE_KEY_LENGTH},
    traits::{KeyPair, Signer, ToFromBytes},
};
use hmac::{Hmac, Mac};
use rand::{thread_rng, RngCore};
use sha2::Sha256;
use zeroize::Zeroize;

const G2_LENGTH: usize = 96;
const FR_LENGTH: usize = 32;
const SYMMETRIC_KEY_LENGTH: usize = 16;
const GCM_NONCE_LENGTH: usize = 12;
const HKDF_SALT: &[u8] = b"APTOS_BATCH_ENCRYPTION_OTP";
const ID_HASH_DST: &[u8] = b"APTOS_BATCH_ENCRYPTION_HASH_ID";
const HASH_G2_ELEMENT_DST: &[u8] = b"APTOS_BATCH_ENCRYPTION_HASH_G2_ELEMENT";

type G1Hasher = MapToCurveBasedHasher<G1Projective, DefaultFieldHasher<Sha256>, WBMap<G1Config>>;

pub(crate) fn encrypt(
    encryption_key_bcs: &[u8],
    plaintext_bcs: &[u8],
    associated_data_bcs: &[u8],
) -> Result<Vec<u8>, FastCryptoFfiError> {
    if plaintext_bcs.is_empty() || associated_data_bcs.is_empty() {
        return Err(FastCryptoFfiError::InvalidInput);
    }
    let (sig_mpk_g2, tau_g2) = parse_encryption_key(encryption_key_bcs)?;
    let mut rng = thread_rng();

    let mut signing_key_bytes = [0u8; ED25519_PRIVATE_KEY_LENGTH];
    rng.fill_bytes(&mut signing_key_bytes);
    let signing_key = Ed25519KeyPair::from_bytes(&signing_key_bytes)?;
    signing_key_bytes.zeroize();
    let verification_key = signing_key.public().as_ref().to_vec();

    let mut id_preimage = Vec::with_capacity(verification_key.len() + associated_data_bcs.len());
    id_preimage.extend_from_slice(&verification_key);
    id_preimage.extend_from_slice(associated_data_bcs);
    let id = hash_to_fr(&id_preimage);

    let r = [Fr::rand(&mut rng), Fr::rand(&mut rng)];
    let hashed_encryption_key = hash_g2_element(&sig_mpk_g2)?;
    let generator = G2Affine::generator();
    let ct_g2 = [
        (generator * r[0] + sig_mpk_g2 * r[1]).into_affine(),
        ((generator * id - G2Projective::from(tau_g2)) * r[0]).into_affine(),
        (-(generator * r[1])).into_affine(),
    ];

    let otp_source = -Bls12_381::pairing(hashed_encryption_key, sig_mpk_g2) * r[1];
    let otp_source_bytes = canonical_bytes(&otp_source)?;
    let otp = derive_otp(&otp_source_bytes)?;

    let mut symmetric_key = [0u8; SYMMETRIC_KEY_LENGTH];
    rng.fill_bytes(&mut symmetric_key);
    let mut padded_key = [0u8; SYMMETRIC_KEY_LENGTH];
    for index in 0..SYMMETRIC_KEY_LENGTH {
        padded_key[index] = symmetric_key[index] ^ otp[index];
    }

    let mut nonce = [0u8; GCM_NONCE_LENGTH];
    rng.fill_bytes(&mut nonce);
    let cipher =
        Aes128Gcm::new_from_slice(&symmetric_key).map_err(|_| FastCryptoFfiError::InvalidInput)?;
    let body = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext_bcs)
        .map_err(|_| FastCryptoFfiError::General("Aptos batch encryption failed".to_string()))?;
    symmetric_key.zeroize();

    let id_bytes = canonical_bytes(&id)?;
    if id_bytes.len() != FR_LENGTH {
        return Err(FastCryptoFfiError::General(
            "Unexpected BLS12-381 scalar encoding".to_string(),
        ));
    }
    let mut points_bytes = Vec::with_capacity(G2_LENGTH * 3);
    for point in &ct_g2 {
        let encoded = canonical_bytes(point)?;
        if encoded.len() != G2_LENGTH {
            return Err(FastCryptoFfiError::General(
                "Unexpected BLS12-381 G2 encoding".to_string(),
            ));
        }
        points_bytes.extend_from_slice(&encoded);
    }

    let mut bibe_ciphertext = Vec::new();
    write_bcs_bytes(&mut bibe_ciphertext, &id_bytes)?;
    write_bcs_bytes(&mut bibe_ciphertext, &points_bytes)?;
    bibe_ciphertext.extend_from_slice(&padded_key);
    bibe_ciphertext.extend_from_slice(&nonce);
    write_bcs_bytes(&mut bibe_ciphertext, &body)?;

    // Rust signs BCS(&(bibe_ct, associated_data_bytes)). The tuple is encoded by concatenation.
    let mut to_sign = bibe_ciphertext.clone();
    write_bcs_bytes(&mut to_sign, associated_data_bcs)?;
    let signature = signing_key.sign(&to_sign);

    let mut ciphertext = Vec::new();
    write_bcs_bytes(&mut ciphertext, &verification_key)?;
    ciphertext.extend_from_slice(&bibe_ciphertext);
    write_bcs_bytes(&mut ciphertext, associated_data_bcs)?;
    ciphertext.extend_from_slice(signature.as_ref());
    Ok(ciphertext)
}

fn parse_encryption_key(input: &[u8]) -> Result<(G2Affine, G2Affine), FastCryptoFfiError> {
    let mut offset = 0usize;
    let sig_mpk_bytes = read_bcs_bytes(input, &mut offset)?;
    let tau_bytes = read_bcs_bytes(input, &mut offset)?;
    if offset != input.len() || sig_mpk_bytes.len() != G2_LENGTH || tau_bytes.len() != G2_LENGTH {
        return Err(FastCryptoFfiError::InvalidInput);
    }
    let sig_mpk = G2Affine::deserialize_compressed(sig_mpk_bytes)
        .map_err(|_| FastCryptoFfiError::InvalidInput)?;
    let tau = G2Affine::deserialize_compressed(tau_bytes)
        .map_err(|_| FastCryptoFfiError::InvalidInput)?;
    Ok((sig_mpk, tau))
}

fn hash_to_fr(input: &[u8]) -> Fr {
    let hasher = <DefaultFieldHasher<Sha256> as HashToField<Fr>>::new(ID_HASH_DST);
    hasher.hash_to_field::<1>(input)[0]
}

fn hash_g2_element(point: &G2Affine) -> Result<G1Affine, FastCryptoFfiError> {
    let bytes = canonical_bytes(point)?;
    let hasher = G1Hasher::new(HASH_G2_ELEMENT_DST).map_err(|_| {
        FastCryptoFfiError::General("Unable to initialize Aptos hash-to-curve".to_string())
    })?;
    hasher
        .hash(&bytes)
        .map_err(|_| FastCryptoFfiError::General("Aptos hash-to-curve failed".to_string()))
}

fn canonical_bytes(value: &impl CanonicalSerialize) -> Result<Vec<u8>, FastCryptoFfiError> {
    let mut output = Vec::new();
    value
        .serialize_compressed(&mut output)
        .map_err(|_| FastCryptoFfiError::InvalidInput)?;
    Ok(output)
}

fn derive_otp(source: &[u8]) -> Result<[u8; SYMMETRIC_KEY_LENGTH], FastCryptoFfiError> {
    type HmacSha256 = Hmac<Sha256>;
    let mut extract = <HmacSha256 as Mac>::new_from_slice(HKDF_SALT)
        .map_err(|_| FastCryptoFfiError::InvalidInput)?;
    extract.update(source);
    let prk = extract.finalize().into_bytes();

    let mut expand =
        <HmacSha256 as Mac>::new_from_slice(&prk).map_err(|_| FastCryptoFfiError::InvalidInput)?;
    expand.update(&[1]);
    let okm = expand.finalize().into_bytes();
    let mut result = [0u8; SYMMETRIC_KEY_LENGTH];
    result.copy_from_slice(&okm[..SYMMETRIC_KEY_LENGTH]);
    Ok(result)
}

fn write_bcs_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), FastCryptoFfiError> {
    write_uleb128(output, bytes.len())?;
    output.extend_from_slice(bytes);
    Ok(())
}

fn write_uleb128(output: &mut Vec<u8>, value: usize) -> Result<(), FastCryptoFfiError> {
    let mut remaining =
        u32::try_from(value).map_err(|_| FastCryptoFfiError::InputTooLong(u32::MAX as u64))?;
    loop {
        let mut byte = (remaining & 0x7f) as u8;
        remaining >>= 7;
        if remaining != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if remaining == 0 {
            return Ok(());
        }
    }
}

fn read_bcs_bytes<'a>(input: &'a [u8], offset: &mut usize) -> Result<&'a [u8], FastCryptoFfiError> {
    let length = read_uleb128(input, offset)?;
    let end = offset
        .checked_add(length)
        .ok_or(FastCryptoFfiError::InvalidInput)?;
    if end > input.len() {
        return Err(FastCryptoFfiError::InvalidInput);
    }
    let result = &input[*offset..end];
    *offset = end;
    Ok(result)
}

fn read_uleb128(input: &[u8], offset: &mut usize) -> Result<usize, FastCryptoFfiError> {
    let mut value = 0u32;
    for shift in (0..=28).step_by(7) {
        let byte = *input.get(*offset).ok_or(FastCryptoFfiError::InvalidInput)?;
        *offset += 1;
        let digit = (byte & 0x7f) as u32;
        if shift == 28 && digit > 0x0f {
            return Err(FastCryptoFfiError::InvalidInput);
        }
        value |= digit << shift;
        if byte & 0x80 == 0 {
            if shift > 0 && digit == 0 {
                return Err(FastCryptoFfiError::InvalidInput);
            }
            return Ok(value as usize);
        }
    }
    Err(FastCryptoFfiError::InvalidInput)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastcrypto::{
        ed25519::{Ed25519PublicKey, Ed25519Signature},
        traits::VerifyingKey,
    };

    fn testing_encryption_key() -> Vec<u8> {
        let sig_mpk = G2Affine::generator();
        let tau = (G2Affine::generator() * Fr::from(2u64)).into_affine();
        let mut output = Vec::new();
        write_bcs_bytes(&mut output, &canonical_bytes(&sig_mpk).unwrap()).unwrap();
        write_bcs_bytes(&mut output, &canonical_bytes(&tau).unwrap()).unwrap();
        output
    }

    #[test]
    fn id_hash_matches_aptos_core_consensus_vector() {
        // Generated with Aptos Core 7b4738d6e776ec1abe60394408bab11dea06214c.
        // Upstream Arkworks 0.4/0.5 produces a different scalar for this preimage.
        let input = (0u8..99).collect::<Vec<_>>();
        assert_eq!(
            hex::encode(canonical_bytes(&hash_to_fr(&input)).unwrap()),
            "edcaab659d3d8daaa6c6bd899775e63fc80ae6bf0046d5be8785180f4b348a5b"
        );
    }

    #[test]
    fn ciphertext_has_exact_aptos_bcs_shape_and_valid_signature() {
        let associated_data = vec![0, 1, 2, 3];
        let ciphertext = encrypt(&testing_encryption_key(), &[4, 5, 6], &associated_data).unwrap();
        let mut offset = 0;
        let verification_key = read_bcs_bytes(&ciphertext, &mut offset).unwrap();
        assert_eq!(verification_key.len(), 32);

        let bibe_start = offset;
        assert_eq!(
            read_bcs_bytes(&ciphertext, &mut offset).unwrap().len(),
            FR_LENGTH
        );
        assert_eq!(
            read_bcs_bytes(&ciphertext, &mut offset).unwrap().len(),
            G2_LENGTH * 3
        );
        offset += SYMMETRIC_KEY_LENGTH + GCM_NONCE_LENGTH;
        let body = read_bcs_bytes(&ciphertext, &mut offset).unwrap();
        assert_eq!(body.len(), 3 + 16); // AES-GCM appends its 16-byte tag.
        let bibe_end = offset;
        assert_eq!(
            read_bcs_bytes(&ciphertext, &mut offset).unwrap(),
            associated_data
        );
        let signature_bytes = &ciphertext[offset..];
        assert_eq!(signature_bytes.len(), 64);

        let mut signed = ciphertext[bibe_start..bibe_end].to_vec();
        write_bcs_bytes(&mut signed, &associated_data).unwrap();
        let public_key = Ed25519PublicKey::from_bytes(verification_key).unwrap();
        let signature = Ed25519Signature::from_bytes(signature_bytes).unwrap();
        public_key.verify(&signed, &signature).unwrap();
    }

    #[test]
    fn rejects_malformed_or_noncanonical_encryption_keys() {
        assert!(encrypt(&[0, 1], &[1], &[1]).is_err());
        let mut invalid = testing_encryption_key();
        invalid.push(0);
        assert!(encrypt(&invalid, &[1], &[1]).is_err());
    }
}
