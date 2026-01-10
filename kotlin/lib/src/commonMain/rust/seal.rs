use blst::*;
use crate::FastCryptoFfiError;
use sha3::{Digest, Sha3_256};
use rand::{RngCore, SeedableRng};
use rand::rngs::StdRng;
use std::ptr;

const DST_POP: &[u8] = b"SUI-SEAL-IBE-BLS12381-POP-00";
const BLS_SIG_DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
const DST_ID: &[u8] = b"SUI-SEAL-IBE-BLS12381-00";
const DST_KDF: &[u8] = b"SUI-SEAL-IBE-BLS12381-H2-00";
const DST_DERIVE_KEY: &[u8] = b"SUI-SEAL-IBE-BLS12381-H3-00";

const SUI_ADDRESS_LENGTH: usize = 32;

fn from_hex(hex: &str) -> Result<Vec<u8>, FastCryptoFfiError> {
    let hex = hex.trim_start_matches("0x");
    hex::decode(hex).map_err(|_| FastCryptoFfiError::InvalidInput)
}

fn hash_to_g1(id: &[u8]) -> blst_p1 {
    let mut msg = Vec::new();
    msg.extend_from_slice(DST_ID);
    msg.extend_from_slice(id);
    
    let mut p1 = blst_p1::default();
    unsafe {
        blst_hash_to_g1(
            &mut p1,
            msg.as_ptr(),
            msg.len(),
            BLS_SIG_DST.as_ptr(),
            BLS_SIG_DST.len(),
            ptr::null(),
            0,
        );
    }
    p1
}


fn sha3_256(data: &[&[u8]]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    for d in data {
        hasher.update(d);
    }
    hasher.finalize().to_vec()
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

fn kdf(element: &blst_fp12, nonce: &blst_p2, id: &[u8], object_id: &str, index: u32) -> Result<Vec<u8>, FastCryptoFfiError> {
    let object_id_bytes = from_hex(object_id)?;
    if object_id_bytes.len() != SUI_ADDRESS_LENGTH {
        return Err(FastCryptoFfiError::InputLengthWrong(SUI_ADDRESS_LENGTH as u64));
    }
    
    let element_bytes = unsafe {
        let mut out = [0u8; 576];
        blst_bendian_from_fp12(out.as_mut_ptr(), element);
        out
    };

    let mut nonce_bytes = [0u8; 96];
    unsafe {
        blst_p2_compress(nonce_bytes.as_mut_ptr(), nonce);
    }
    
    let p1 = hash_to_g1(id);
    let mut gid_bytes = [0u8; 48];
    unsafe {
        blst_p1_compress(gid_bytes.as_mut_ptr(), &p1);
    }
    
    let index_byte = [index as u8];
    
    Ok(sha3_256(&[
        DST_KDF,
        &element_bytes,
        &nonce_bytes,
        &gid_bytes,
        &object_id_bytes,
        &index_byte
    ]))
}

fn derive_key(
    purpose: u8,
    base_key: &[u8],
    encrypted_shares: &[Vec<u8>],
    threshold: u32,
    key_servers: &[String],
) -> Result<Vec<u8>, FastCryptoFfiError> {
    if encrypted_shares.len() != key_servers.len() {
        return Err(FastCryptoFfiError::InvalidInput);
    }
    let mut hash_input = Vec::new();
    hash_input.push(DST_DERIVE_KEY);
    hash_input.push(base_key);
    let purpose_byte = [purpose];
    hash_input.push(&purpose_byte);
    let threshold_byte = [threshold as u8];
    hash_input.push(&threshold_byte);
    
    for share in encrypted_shares {
        hash_input.push(share);
    }
    
    let mut server_bytes = Vec::new();
    for server in key_servers {
        server_bytes.push(from_hex(server)?);
    }
    for sb in &server_bytes {
        hash_input.push(sb);
    }
    
    Ok(sha3_256(&hash_input))
}

#[uniffi::export]
pub fn seal_derive_key(
    purpose: u8,
    base_key: Vec<u8>,
    encrypted_shares: Vec<Vec<u8>>,
    threshold: u32,
    key_servers: Vec<String>,
) -> Result<Vec<u8>, FastCryptoFfiError> {
    derive_key(purpose, &base_key, &encrypted_shares, threshold, &key_servers)
}

#[uniffi::export]
pub fn seal_verify_pop(
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
) -> Result<bool, FastCryptoFfiError> {
    if public_key.len() != 96 || signature.len() != 48 {
        return Err(FastCryptoFfiError::InvalidInput);
    }

    let mut pk_affine = blst_p2_affine::default();
    unsafe {
        if blst_p2_uncompress(&mut pk_affine, public_key.as_ptr()) != BLST_ERROR::BLST_SUCCESS {
            return Err(FastCryptoFfiError::InvalidInput);
        }
    }

    let mut sig_affine = blst_p1_affine::default();
    unsafe {
        if blst_p1_uncompress(&mut sig_affine, signature.as_ptr()) != BLST_ERROR::BLST_SUCCESS {
            return Err(FastCryptoFfiError::InvalidSignature);
        }
    }
    
    let mut full_msg = Vec::new();
    full_msg.extend_from_slice(DST_POP);
    full_msg.extend_from_slice(&public_key);
    full_msg.extend_from_slice(&message);
    
    let res = unsafe {
        blst_core_verify_pk_in_g2(
            &pk_affine,
            &sig_affine,
            true, // hash_or_encode
            full_msg.as_ptr(),
            full_msg.len(),
            BLS_SIG_DST.as_ptr(),
            BLS_SIG_DST.len(),
            ptr::null(),
            0
        )
    };
    
    Ok(res == BLST_ERROR::BLST_SUCCESS)
}

#[derive(uniffi::Record)]
pub struct IBEEncryptionResult {
    pub nonce: Vec<u8>,
    pub encrypted_shares: Vec<Vec<u8>>,
    pub encrypted_randomness: Vec<u8>,
}

#[uniffi::export]
pub fn seal_ibe_encrypt(
    public_keys: Vec<Vec<u8>>,
    id: Vec<u8>,
    shares: Vec<Vec<u8>>,
    indices: Vec<u32>,
    base_key: Vec<u8>,
    threshold: u32,
    object_ids: Vec<String>,
) -> Result<IBEEncryptionResult, FastCryptoFfiError> {
    if public_keys.len() != shares.len() || public_keys.len() != object_ids.len() || public_keys.len() != indices.len() {
        return Err(FastCryptoFfiError::InvalidInput);
    }
    
    let mut rng = StdRng::from_entropy();
    let mut r_bytes = [0u8; 32];
    rng.fill_bytes(&mut r_bytes);
    
    let mut r_scalar = blst_scalar::default();
    unsafe {
        blst_scalar_from_be_bytes(&mut r_scalar, r_bytes.as_ptr(), 32);
    }
    
    // Nonce: g2 * r
    let mut nonce_p2 = blst_p2::default();
    unsafe {
        let mut gen_p2 = blst_p2::default();
        blst_p2_from_affine(&mut gen_p2, &BLS12_381_G2);
        
        blst_p2_mult(&mut nonce_p2, &gen_p2, r_scalar.b.as_ptr(), 255);
    }
    
    // gid^r
    let mut gid_r = blst_p1::default();
    unsafe {
        let p1 = hash_to_g1(&id);
        blst_p1_mult(&mut gid_r, &p1, r_scalar.b.as_ptr(), 255);
    }
    
    let mut encrypted_shares = Vec::new();
    for i in 0..public_keys.len() {
        let mut pk_affine = blst_p2_affine::default();
        unsafe {
            if blst_p2_uncompress(&mut pk_affine, public_keys[i].as_ptr()) != BLST_ERROR::BLST_SUCCESS {
                return Err(FastCryptoFfiError::InvalidInput);
            }
        }
        
        let mut key_gt = blst_fp12::default();
        unsafe {
            let mut gid_r_affine = blst_p1_affine::default();
            blst_p1_to_affine(&mut gid_r_affine, &gid_r);
            blst_miller_loop(&mut key_gt, &pk_affine, &gid_r_affine);
            blst_final_exp(&mut key_gt, &key_gt);
        }
        
        let kdf_key = kdf(&key_gt, &nonce_p2, &id, &object_ids[i], indices[i])?;
        
        let encrypted_share = xor(&shares[i], &kdf_key);
        encrypted_shares.push(encrypted_share);
    }
    
    let randomness_key = derive_key(0, &base_key, &encrypted_shares, threshold, &object_ids)?;
    
    let encrypted_randomness = xor(&r_bytes, &randomness_key);
    
    let mut nonce_bytes = [0u8; 96];
    unsafe {
        blst_p2_compress(nonce_bytes.as_mut_ptr(), &nonce_p2);
    }
    
    Ok(IBEEncryptionResult {
        nonce: nonce_bytes.to_vec(),
        encrypted_shares,
        encrypted_randomness,
    })
}

#[uniffi::export]
pub fn seal_ibe_decrypt(
    nonce: Vec<u8>,
    sk: Vec<u8>,
    ciphertext: Vec<u8>,
    id: Vec<u8>,
    object_id: String,
    index: u32,
) -> Result<Vec<u8>, FastCryptoFfiError> {
    if nonce.len() != 96 || sk.len() != 48 {
        return Err(FastCryptoFfiError::InvalidInput);
    }

    let mut nonce_p2 = blst_p2::default();
    let mut nonce_affine = blst_p2_affine::default();
    unsafe {
        if blst_p2_uncompress(&mut nonce_affine, nonce.as_ptr()) != BLST_ERROR::BLST_SUCCESS {
            return Err(FastCryptoFfiError::InvalidInput);
        }
        blst_p2_from_affine(&mut nonce_p2, &nonce_affine);
    }
    
    let mut sk_affine = blst_p1_affine::default();
    unsafe {
        if blst_p1_uncompress(&mut sk_affine, sk.as_ptr()) != BLST_ERROR::BLST_SUCCESS {
            return Err(FastCryptoFfiError::InvalidInput);
        }
    }
    
    let mut key_gt = blst_fp12::default();
    unsafe {
        blst_miller_loop(&mut key_gt, &nonce_affine, &sk_affine);
        blst_final_exp(&mut key_gt, &key_gt);
    }
    
    let kdf_key = kdf(&key_gt, &nonce_p2, &id, &object_id, index)?;
    Ok(xor(&ciphertext, &kdf_key))
}

#[uniffi::export]
pub fn seal_verify_user_secret_key(
    sk: Vec<u8>,
    id: Vec<u8>,
    pk: Vec<u8>,
) -> Result<bool, FastCryptoFfiError> {
    if sk.len() != 48 || pk.len() != 96 {
        return Err(FastCryptoFfiError::InvalidInput);
    }

    let mut sk_affine = blst_p1_affine::default();
    unsafe {
        if blst_p1_uncompress(&mut sk_affine, sk.as_ptr()) != BLST_ERROR::BLST_SUCCESS {
            return Err(FastCryptoFfiError::InvalidInput);
        }
    }
    
    let mut pk_affine = blst_p2_affine::default();
    unsafe {
        if blst_p2_uncompress(&mut pk_affine, pk.as_ptr()) != BLST_ERROR::BLST_SUCCESS {
            return Err(FastCryptoFfiError::InvalidInput);
        }
    }
    
    let mut lhs = blst_fp12::default();
    unsafe {
        blst_miller_loop(&mut lhs, &BLS12_381_G2, &sk_affine);
        blst_final_exp(&mut lhs, &lhs);
    }
    
    let mut rhs = blst_fp12::default();
    unsafe {
        let p1 = hash_to_g1(&id);
        let mut p1_affine = blst_p1_affine::default();
        blst_p1_to_affine(&mut p1_affine, &p1);
        blst_miller_loop(&mut rhs, &pk_affine, &p1_affine);
        blst_final_exp(&mut rhs, &rhs);
    }
    
    unsafe {
        Ok(blst_fp12_is_equal(&lhs, &rhs))
    }
}

// Helper to derive a Public Key (G2) from a Secret Key (Scalar) for testing
#[uniffi::export]
pub fn seal_derive_pk(scalar_bytes: Vec<u8>) -> Result<Vec<u8>, FastCryptoFfiError> {
    if scalar_bytes.len() != 32 {
        return Err(FastCryptoFfiError::InputLengthWrong(32));
    }
    
    let mut scalar = blst_scalar::default();
    unsafe {
        blst_scalar_from_be_bytes(&mut scalar, scalar_bytes.as_ptr(), 32);
    }
    
    let mut pk_p2 = blst_p2::default();
    unsafe {
        let mut gen_p2 = blst_p2::default();
        blst_p2_from_affine(&mut gen_p2, &BLS12_381_G2);
        blst_p2_mult(&mut pk_p2, &gen_p2, scalar.b.as_ptr(), 255);
    }
    
    let mut pk_bytes = [0u8; 96];
    unsafe {
        blst_p2_compress(pk_bytes.as_mut_ptr(), &pk_p2);
    }
    
    Ok(pk_bytes.to_vec())
}

#[uniffi::export]
pub fn seal_derive_pk_g1(scalar_bytes: Vec<u8>) -> Result<Vec<u8>, FastCryptoFfiError> {
    if scalar_bytes.len() != 32 {
        return Err(FastCryptoFfiError::InputLengthWrong(32));
    }
    
    let mut scalar = blst_scalar::default();
    unsafe {
        blst_scalar_from_be_bytes(&mut scalar, scalar_bytes.as_ptr(), 32);
    }
    
    let mut pk_p1 = blst_p1::default();
    unsafe {
        let mut gen_p1 = blst_p1::default();
        blst_p1_from_affine(&mut gen_p1, &BLS12_381_G1);
        blst_p1_mult(&mut pk_p1, &gen_p1, scalar.b.as_ptr(), 255);
    }
    
    let mut pk_bytes = [0u8; 48];
    unsafe {
        blst_p1_compress(pk_bytes.as_mut_ptr(), &pk_p1);
    }
    
    Ok(pk_bytes.to_vec())
}

#[uniffi::export]
pub fn seal_elgamal_decrypt(
    secret_key: Vec<u8>,
    c0: Vec<u8>,
    c1: Vec<u8>
) -> Result<Vec<u8>, FastCryptoFfiError> {
    if secret_key.len() != 32 || c0.len() != 48 || c1.len() != 48 {
        return Err(FastCryptoFfiError::InvalidInput);
    }
    
    let mut scalar = blst_scalar::default();
    unsafe {
        blst_scalar_from_be_bytes(&mut scalar, secret_key.as_ptr(), 32);
    }
    
    let mut c0_p1 = blst_p1::default();
    unsafe {
        let mut c0_affine = blst_p1_affine::default();
        if blst_p1_uncompress(&mut c0_affine, c0.as_ptr()) != BLST_ERROR::BLST_SUCCESS {
            return Err(FastCryptoFfiError::InvalidInput);
        }
        blst_p1_from_affine(&mut c0_p1, &c0_affine);
    }
    
    let mut c1_p1 = blst_p1::default();
    unsafe {
        let mut c1_affine = blst_p1_affine::default();
        if blst_p1_uncompress(&mut c1_affine, c1.as_ptr()) != BLST_ERROR::BLST_SUCCESS {
            return Err(FastCryptoFfiError::InvalidInput);
        }
        blst_p1_from_affine(&mut c1_p1, &c1_affine);
    }
    
    // Decrypt: M = C1 - sk * C0
    // sk * C0
    let mut sk_c0 = blst_p1::default();
    unsafe {
        blst_p1_mult(&mut sk_c0, &c0_p1, scalar.b.as_ptr(), 255);
    }
    
    // C1 - (sk * C0) => C1 + -(sk * C0)
    unsafe {
        blst_p1_cneg(&mut sk_c0, true);
        blst_p1_add_or_double(&mut c1_p1, &c1_p1, &sk_c0);
    }
    
    let mut res_bytes = [0u8; 48];
    unsafe {
        blst_p1_compress(res_bytes.as_mut_ptr(), &c1_p1);
    }
    
    Ok(res_bytes.to_vec())
}

// Helper to extract User Secret Key (G1) from Master Secret Key (Scalar) and ID for testing
#[uniffi::export]
pub fn seal_extract_usk(master_sk_bytes: Vec<u8>, id: Vec<u8>) -> Result<Vec<u8>, FastCryptoFfiError> {
    if master_sk_bytes.len() != 32 {
        return Err(FastCryptoFfiError::InputLengthWrong(32));
    }
    
    let mut scalar = blst_scalar::default();
    unsafe {
        blst_scalar_from_be_bytes(&mut scalar, master_sk_bytes.as_ptr(), 32);
    }
    
    let mut usk_p1 = blst_p1::default();
    unsafe {
        let p1 = hash_to_g1(&id);
        blst_p1_mult(&mut usk_p1, &p1, scalar.b.as_ptr(), 255);
    }
    
    let mut usk_bytes = [0u8; 48];
    unsafe {
        blst_p1_compress(usk_bytes.as_mut_ptr(), &usk_p1);
    }
    
    Ok(usk_bytes.to_vec())
}

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce
};

#[uniffi::export]
pub fn seal_aes_gcm_encrypt(
    key: Vec<u8>,
    nonce: Vec<u8>,
    data: Vec<u8>,
    aad: Vec<u8>
) -> Result<Vec<u8>, FastCryptoFfiError> {
    if key.len() != 32 { return Err(FastCryptoFfiError::InputLengthWrong(32)); }
    
    let key_ga = aes_gcm::Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(key_ga);
    // Aes256Gcm standard nonce is 96-bit (12 bytes). 
    if nonce.len() != 12 { return Err(FastCryptoFfiError::InputLengthWrong(12)); }
    let nonce_ga = Nonce::from_slice(&nonce);
    
    let payload = Payload {
        msg: &data,
        aad: &aad,
    };
    
    cipher.encrypt(nonce_ga, payload)
        .map_err(|_| FastCryptoFfiError::General("Encryption failed".into()))
}

#[uniffi::export]
pub fn seal_aes_gcm_decrypt(
    key: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    aad: Vec<u8>
) -> Result<Vec<u8>, FastCryptoFfiError> {
    if key.len() != 32 { return Err(FastCryptoFfiError::InputLengthWrong(32)); }
    if nonce.len() != 12 { return Err(FastCryptoFfiError::InputLengthWrong(12)); }
    
    let key_ga = aes_gcm::Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(key_ga);
    let nonce_ga = Nonce::from_slice(&nonce);
    
    let payload = Payload {
        msg: &ciphertext,
        aad: &aad,
    };
    
    cipher.decrypt(nonce_ga, payload)
        .map_err(|_| FastCryptoFfiError::General("Decryption failed".into()))
}
