use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek_ng::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};
use merlin::Transcript;
use rand::thread_rng;
use sha2::{Digest, Sha512};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
};
use zeroize::Zeroize;

use crate::FastCryptoFfiError;

const POINT_BYTES: usize = 32;
const SCALAR_BYTES: usize = 32;
const WIDE_SCALAR_BYTES: usize = 64;
const APTOS_RANGE_BITS: usize = 16;
const APTOS_RANGE_DOMAIN: &[u8] = b"AptosConfidentialAsset/BulletproofRangeProof";
const APTOS_FRAMEWORK_ADDRESS: [u8; 32] = {
    let mut address = [0; 32];
    address[31] = 1;
    address
};
const HASH_BASE_POINT_HEX: &str =
    "8c9240b456a9e6dc65c377a1048d745f94a08cdb7f44cbcd7b46f34048871134";

#[derive(Clone, Debug, uniffi::Record)]
pub struct TwistedEd25519KeyPairBytes {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct TwistedElGamalCiphertextBytes {
    pub commitment: Vec<u8>,
    pub handle: Vec<u8>,
    /// Canonical little-endian scalar. It is a proof witness and must be treated as secret.
    pub randomness: Vec<u8>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct AptosConfidentialRangeProofBytes {
    pub proof: Vec<u8>,
    pub commitments: Vec<Vec<u8>>,
}

/// Byte-oriented representation of an Aptos confidential-asset sigma proof.
#[derive(Clone, Debug, uniffi::Record)]
pub struct AptosConfidentialSigmaProofBytes {
    pub commitment: Vec<Vec<u8>>,
    pub response: Vec<Vec<u8>>,
}

/// Outputs produced while authorizing an encryption-key rotation.
#[derive(Clone, Debug, uniffi::Record)]
pub struct AptosConfidentialKeyRotationProofBytes {
    pub new_public_key: Vec<u8>,
    pub new_handles: Vec<Vec<u8>>,
    pub proof: AptosConfidentialSigmaProofBytes,
}

/// Secret and public inputs for the Aptos withdrawal/normalization sigma prover.
#[derive(Clone, Debug, uniffi::Record)]
pub struct AptosConfidentialWithdrawProofInputBytes {
    pub private_key: Vec<u8>,
    pub sender_address: Vec<u8>,
    pub token_address: Vec<u8>,
    pub chain_id: u8,
    /// The public withdrawal amount. Use zero for normalization.
    pub amount: u64,
    pub old_commitments: Vec<Vec<u8>>,
    pub old_handles: Vec<Vec<u8>>,
    pub new_commitments: Vec<Vec<u8>>,
    pub new_handles: Vec<Vec<u8>>,
    pub new_amount_chunks: Vec<u64>,
    pub new_randomness: Vec<Vec<u8>>,
    pub auditor_public_key: Option<Vec<u8>>,
    pub new_auditor_handles: Vec<Vec<u8>>,
}

/// Public statement for verifying an Aptos withdrawal/normalization sigma proof.
#[derive(Clone, Debug, uniffi::Record)]
pub struct AptosConfidentialWithdrawStatementBytes {
    pub sender_address: Vec<u8>,
    pub token_address: Vec<u8>,
    pub chain_id: u8,
    pub amount: u64,
    pub public_key: Vec<u8>,
    pub old_commitments: Vec<Vec<u8>>,
    pub old_handles: Vec<Vec<u8>>,
    pub new_commitments: Vec<Vec<u8>>,
    pub new_handles: Vec<Vec<u8>>,
    pub auditor_public_key: Option<Vec<u8>>,
    pub new_auditor_handles: Vec<Vec<u8>>,
}

/// Secret and public inputs for the Aptos confidential transfer sigma prover.
#[derive(Clone, Debug, uniffi::Record)]
pub struct AptosConfidentialTransferProofInputBytes {
    pub private_key: Vec<u8>,
    pub sender_address: Vec<u8>,
    pub recipient_address: Vec<u8>,
    pub token_address: Vec<u8>,
    pub chain_id: u8,
    pub recipient_public_key: Vec<u8>,
    pub old_commitments: Vec<Vec<u8>>,
    pub old_handles: Vec<Vec<u8>>,
    pub new_commitments: Vec<Vec<u8>>,
    pub new_handles: Vec<Vec<u8>>,
    pub new_amount_chunks: Vec<u64>,
    pub new_randomness: Vec<Vec<u8>>,
    pub transfer_commitments: Vec<Vec<u8>>,
    pub transfer_sender_handles: Vec<Vec<u8>>,
    pub transfer_recipient_handles: Vec<Vec<u8>>,
    pub transfer_amount_chunks: Vec<u64>,
    pub transfer_randomness: Vec<Vec<u8>>,
    pub has_effective_auditor: bool,
    /// Voluntary auditor keys first and the effective auditor key last, when present.
    pub auditor_public_keys: Vec<Vec<u8>>,
    /// Effective-auditor new-balance handles only; empty when no effective auditor exists.
    pub effective_new_balance_handles: Vec<Vec<u8>>,
    /// Auditor-major flattened transfer handles: `auditor_count * transfer_chunk_count`.
    pub auditor_transfer_handles: Vec<Vec<u8>>,
}

/// Public statement for verifying an Aptos confidential transfer sigma proof.
#[derive(Clone, Debug, uniffi::Record)]
pub struct AptosConfidentialTransferStatementBytes {
    pub sender_address: Vec<u8>,
    pub recipient_address: Vec<u8>,
    pub token_address: Vec<u8>,
    pub chain_id: u8,
    pub sender_public_key: Vec<u8>,
    pub recipient_public_key: Vec<u8>,
    pub old_commitments: Vec<Vec<u8>>,
    pub old_handles: Vec<Vec<u8>>,
    pub new_commitments: Vec<Vec<u8>>,
    pub new_handles: Vec<Vec<u8>>,
    pub transfer_commitments: Vec<Vec<u8>>,
    pub transfer_sender_handles: Vec<Vec<u8>>,
    pub transfer_recipient_handles: Vec<Vec<u8>>,
    pub has_effective_auditor: bool,
    pub auditor_public_keys: Vec<Vec<u8>>,
    pub effective_new_balance_handles: Vec<Vec<u8>>,
    pub auditor_transfer_handles: Vec<Vec<u8>>,
}

#[derive(Clone)]
struct SigmaStatement {
    points: Vec<RistrettoPoint>,
    compressed_points: Vec<Vec<u8>>,
    scalars: Vec<Vec<u8>>,
}

fn uleb128(mut value: usize, output: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            return;
        }
    }
}

fn bcs_bytes(bytes: &[u8], output: &mut Vec<u8>) {
    uleb128(bytes.len(), output);
    output.extend_from_slice(bytes);
}

fn bcs_byte_vectors(values: &[Vec<u8>], output: &mut Vec<u8>) {
    uleb128(values.len(), output);
    for value in values {
        bcs_bytes(value, output);
    }
}

fn bcs_domain_separator(chain_id: u8, protocol_id: &[u8], session_id: &[u8], output: &mut Vec<u8>) {
    uleb128(0, output); // DomainSeparator::V1
    output.extend_from_slice(&APTOS_FRAMEWORK_ADDRESS);
    output.push(chain_id);
    bcs_bytes(protocol_id, output);
    bcs_bytes(session_id, output);
}

fn bcs_session(
    addresses: &[&[u8]],
    u64s: &[u64],
    bools: &[bool],
) -> Result<Vec<u8>, FastCryptoFfiError> {
    let mut output = Vec::new();
    for address in addresses {
        if address.len() != 32 {
            return Err(FastCryptoFfiError::InputLengthWrong(32));
        }
        output.extend_from_slice(address);
    }
    for value in u64s {
        output.extend_from_slice(&value.to_le_bytes());
    }
    for value in bools {
        output.push(u8::from(*value));
    }
    Ok(output)
}

fn sigma_challenge(
    chain_id: u8,
    protocol_id: &str,
    session_id: &[u8],
    type_name: &str,
    statement: &SigmaStatement,
    commitment: &[Vec<u8>],
    witness_count: usize,
) -> Result<Scalar, FastCryptoFfiError> {
    if commitment.is_empty() {
        return Err(FastCryptoFfiError::InvalidInput);
    }
    let mut inputs = Vec::new();
    bcs_domain_separator(chain_id, protocol_id.as_bytes(), session_id, &mut inputs);
    bcs_bytes(type_name.as_bytes(), &mut inputs);
    inputs.extend_from_slice(&(witness_count as u64).to_le_bytes());
    bcs_byte_vectors(&statement.compressed_points, &mut inputs);
    bcs_byte_vectors(&statement.scalars, &mut inputs);
    bcs_byte_vectors(commitment, &mut inputs);

    let seed = Sha512::digest(&inputs);
    let mut challenge_input = Vec::with_capacity(seed.len() + 1);
    challenge_input.extend_from_slice(&seed);
    challenge_input.push(0);
    let hash = Sha512::digest(&challenge_input);
    Ok(Scalar::from_bytes_mod_order_wide(&fixed::<64>(&hash)?))
}

fn sigma_prove<F>(
    chain_id: u8,
    protocol_id: &str,
    session_id: &[u8],
    type_name: &str,
    statement: &SigmaStatement,
    witness: &[Scalar],
    psi: F,
) -> Result<AptosConfidentialSigmaProofBytes, FastCryptoFfiError>
where
    F: Fn(&SigmaStatement, &[Scalar]) -> Vec<RistrettoPoint>,
{
    if witness.is_empty() {
        return Err(FastCryptoFfiError::InvalidInput);
    }
    let alpha = (0..witness.len())
        .map(|_| Scalar::random(&mut thread_rng()))
        .collect::<Vec<_>>();
    let commitment = psi(statement, &alpha)
        .into_iter()
        .map(|value| value.compress().to_bytes().to_vec())
        .collect::<Vec<_>>();
    let challenge = sigma_challenge(
        chain_id,
        protocol_id,
        session_id,
        type_name,
        statement,
        &commitment,
        witness.len(),
    )?;
    let response = alpha
        .iter()
        .zip(witness)
        .map(|(alpha, witness)| (alpha + challenge * witness).to_bytes().to_vec())
        .collect();
    Ok(AptosConfidentialSigmaProofBytes {
        commitment,
        response,
    })
}

fn sigma_verify<F, T>(
    chain_id: u8,
    protocol_id: &str,
    session_id: &[u8],
    type_name: &str,
    statement: &SigmaStatement,
    proof: &AptosConfidentialSigmaProofBytes,
    psi: F,
    transform: T,
) -> Result<bool, FastCryptoFfiError>
where
    F: Fn(&SigmaStatement, &[Scalar]) -> Vec<RistrettoPoint>,
    T: Fn(&SigmaStatement) -> Vec<RistrettoPoint>,
{
    if proof.commitment.is_empty() || proof.response.is_empty() {
        return Ok(false);
    }
    let commitment = proof
        .commitment
        .iter()
        .map(|value| point(value))
        .collect::<Result<Vec<_>, _>>()?;
    let response = proof
        .response
        .iter()
        .map(|value| canonical_scalar(value))
        .collect::<Result<Vec<_>, _>>()?;
    let challenge = sigma_challenge(
        chain_id,
        protocol_id,
        session_id,
        type_name,
        statement,
        &proof.commitment,
        response.len(),
    )?;
    let left = psi(statement, &response);
    let targets = transform(statement);
    if left.len() != commitment.len() || targets.len() != commitment.len() {
        return Ok(false);
    }
    Ok(left
        .iter()
        .zip(commitment.iter().zip(targets))
        .all(|(left, (commitment, target))| *left == commitment + target * challenge))
}

fn statement(
    compressed_points: Vec<Vec<u8>>,
    scalars: Vec<Vec<u8>>,
) -> Result<SigmaStatement, FastCryptoFfiError> {
    let points = compressed_points
        .iter()
        .map(|value| point(value))
        .collect::<Result<Vec<_>, _>>()?;
    for scalar in &scalars {
        canonical_scalar(scalar)?;
    }
    Ok(SigmaStatement {
        points,
        compressed_points,
        scalars,
    })
}

const REGISTRATION_PROTOCOL: &str = "AptosConfidentialAsset/RegistrationV1";
const REGISTRATION_TYPE: &str = "0x1::sigma_protocol_registration::Registration";

fn registration_psi(statement: &SigmaStatement, witness: &[Scalar]) -> Vec<RistrettoPoint> {
    vec![statement.points[1] * witness[0]]
}

/// Proves knowledge of the decryption key for an Aptos confidential-asset registration.
#[uniffi::export]
pub fn aptos_confidential_registration_prove(
    mut private_key: Vec<u8>,
    sender_address: Vec<u8>,
    token_address: Vec<u8>,
    chain_id: u8,
) -> Result<AptosConfidentialSigmaProofBytes, FastCryptoFfiError> {
    let result = (|| {
        let private = nonzero_canonical_scalar(&private_key)?;
        let public = hash_base_point() * private.invert();
        let stmt = statement(
            vec![
                hash_base_point().compress().to_bytes().to_vec(),
                public.compress().to_bytes().to_vec(),
            ],
            vec![],
        )?;
        let session = bcs_session(&[&sender_address, &token_address], &[], &[])?;
        sigma_prove(
            chain_id,
            REGISTRATION_PROTOCOL,
            &session,
            REGISTRATION_TYPE,
            &stmt,
            &[private],
            registration_psi,
        )
    })();
    private_key.zeroize();
    result
}

/// Verifies an Aptos confidential-asset registration proof.
#[uniffi::export]
pub fn aptos_confidential_registration_verify(
    public_key: Vec<u8>,
    sender_address: Vec<u8>,
    token_address: Vec<u8>,
    chain_id: u8,
    proof: AptosConfidentialSigmaProofBytes,
) -> Result<bool, FastCryptoFfiError> {
    let stmt = statement(
        vec![hash_base_point().compress().to_bytes().to_vec(), public_key],
        vec![],
    )?;
    let session = bcs_session(&[&sender_address, &token_address], &[], &[])?;
    sigma_verify(
        chain_id,
        REGISTRATION_PROTOCOL,
        &session,
        REGISTRATION_TYPE,
        &stmt,
        &proof,
        registration_psi,
        |statement| vec![statement.points[0]],
    )
}

const KEY_ROTATION_PROTOCOL: &str = "AptosConfidentialAsset/KeyRotationV1";
const KEY_ROTATION_TYPE: &str = "0x1::sigma_protocol_key_rotation::KeyRotation";

fn key_rotation_psi(statement: &SigmaStatement, witness: &[Scalar]) -> Vec<RistrettoPoint> {
    let chunk_count = (statement.points.len() - 3) / 2;
    let mut output = vec![
        statement.points[1] * witness[0],
        statement.points[1] * witness[1],
        statement.points[2] * witness[2],
    ];
    for old_handle in &statement.points[3..3 + chunk_count] {
        output.push(old_handle * witness[1]);
    }
    output
}

fn key_rotation_transform(statement: &SigmaStatement) -> Vec<RistrettoPoint> {
    let chunk_count = (statement.points.len() - 3) / 2;
    let mut output = vec![
        statement.points[0],
        statement.points[2],
        statement.points[1],
    ];
    output.extend_from_slice(&statement.points[3 + chunk_count..]);
    output
}

/// Re-encrypts balance handles and proves an Aptos confidential encryption-key rotation.
#[uniffi::export]
pub fn aptos_confidential_key_rotation_prove(
    mut current_private_key: Vec<u8>,
    mut new_private_key: Vec<u8>,
    old_handles: Vec<Vec<u8>>,
    sender_address: Vec<u8>,
    token_address: Vec<u8>,
    chain_id: u8,
) -> Result<AptosConfidentialKeyRotationProofBytes, FastCryptoFfiError> {
    let result = (|| {
        if old_handles.is_empty() {
            return Err(FastCryptoFfiError::InvalidInput);
        }
        let current_private = nonzero_canonical_scalar(&current_private_key)?;
        let new_private = nonzero_canonical_scalar(&new_private_key)?;
        let delta = current_private * new_private.invert();
        let delta_inverse = delta.invert();
        let current_public = hash_base_point() * current_private.invert();
        let new_public = current_public * delta;
        let old_points = old_handles
            .iter()
            .map(|value| point(value))
            .collect::<Result<Vec<_>, _>>()?;
        let new_points = old_points
            .iter()
            .map(|value| value * delta)
            .collect::<Vec<_>>();
        let mut compressed = vec![
            hash_base_point().compress().to_bytes().to_vec(),
            current_public.compress().to_bytes().to_vec(),
            new_public.compress().to_bytes().to_vec(),
        ];
        compressed.extend(old_handles);
        let new_handles = new_points
            .iter()
            .map(|value| value.compress().to_bytes().to_vec())
            .collect::<Vec<_>>();
        compressed.extend(new_handles.clone());
        let stmt = statement(compressed, vec![])?;
        let session = bcs_session(
            &[&sender_address, &token_address],
            &[new_handles.len() as u64],
            &[],
        )?;
        let proof = sigma_prove(
            chain_id,
            KEY_ROTATION_PROTOCOL,
            &session,
            KEY_ROTATION_TYPE,
            &stmt,
            &[current_private, delta, delta_inverse],
            key_rotation_psi,
        )?;
        Ok(AptosConfidentialKeyRotationProofBytes {
            new_public_key: new_public.compress().to_bytes().to_vec(),
            new_handles,
            proof,
        })
    })();
    current_private_key.zeroize();
    new_private_key.zeroize();
    result
}

/// Verifies an Aptos confidential encryption-key-rotation proof.
#[uniffi::export]
pub fn aptos_confidential_key_rotation_verify(
    old_public_key: Vec<u8>,
    new_public_key: Vec<u8>,
    old_handles: Vec<Vec<u8>>,
    new_handles: Vec<Vec<u8>>,
    sender_address: Vec<u8>,
    token_address: Vec<u8>,
    chain_id: u8,
    proof: AptosConfidentialSigmaProofBytes,
) -> Result<bool, FastCryptoFfiError> {
    if old_handles.is_empty() || old_handles.len() != new_handles.len() {
        return Ok(false);
    }
    let mut compressed = vec![
        hash_base_point().compress().to_bytes().to_vec(),
        old_public_key,
        new_public_key,
    ];
    compressed.extend(old_handles);
    compressed.extend(new_handles);
    let stmt = statement(compressed, vec![])?;
    let session = bcs_session(
        &[&sender_address, &token_address],
        &[((stmt.points.len() - 3) / 2) as u64],
        &[],
    )?;
    sigma_verify(
        chain_id,
        KEY_ROTATION_PROTOCOL,
        &session,
        KEY_ROTATION_TYPE,
        &stmt,
        &proof,
        key_rotation_psi,
        key_rotation_transform,
    )
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], FastCryptoFfiError> {
    bytes
        .try_into()
        .map_err(|_| FastCryptoFfiError::InputLengthWrong(N as u64))
}

fn point(bytes: &[u8]) -> Result<RistrettoPoint, FastCryptoFfiError> {
    if bytes.len() != POINT_BYTES {
        return Err(FastCryptoFfiError::InputLengthWrong(POINT_BYTES as u64));
    }
    CompressedRistretto::from_slice(bytes)
        .decompress()
        .ok_or(FastCryptoFfiError::InvalidInput)
}

fn canonical_scalar(bytes: &[u8]) -> Result<Scalar, FastCryptoFfiError> {
    Scalar::from_canonical_bytes(fixed::<SCALAR_BYTES>(bytes)?)
        .ok_or(FastCryptoFfiError::InvalidInput)
}

fn nonzero_canonical_scalar(bytes: &[u8]) -> Result<Scalar, FastCryptoFfiError> {
    let scalar = canonical_scalar(bytes)?;
    if scalar == Scalar::zero() {
        return Err(FastCryptoFfiError::InvalidInput);
    }
    Ok(scalar)
}

fn hash_base_point() -> RistrettoPoint {
    static HASH_BASE_POINT: OnceLock<RistrettoPoint> = OnceLock::new();
    *HASH_BASE_POINT.get_or_init(|| {
        let bytes = hex::decode(HASH_BASE_POINT_HEX).expect("valid Aptos hash-base hex");
        point(&bytes).expect("valid Aptos hash-base point")
    })
}

fn bulletproof_generators() -> &'static BulletproofGens {
    static GENERATORS: OnceLock<BulletproofGens> = OnceLock::new();
    GENERATORS.get_or_init(|| BulletproofGens::new(64, 16))
}

fn pedersen_generators() -> PedersenGens {
    PedersenGens {
        B: RISTRETTO_BASEPOINT_POINT,
        B_blinding: hash_base_point(),
    }
}

fn valid_batch_size(size: usize) -> bool {
    matches!(size, 1 | 2 | 4 | 8 | 16)
}

/// Generates a canonical twisted Ed25519 decryption/encryption key pair.
#[uniffi::export]
pub fn twisted_ed25519_generate_keypair() -> TwistedEd25519KeyPairBytes {
    let mut rng = thread_rng();
    let private_key = loop {
        let candidate = Scalar::random(&mut rng);
        if candidate != Scalar::zero() {
            break candidate;
        }
    };
    let public_key = hash_base_point() * private_key.invert();
    TwistedEd25519KeyPairBytes {
        public_key: public_key.compress().to_bytes().to_vec(),
        private_key: private_key.to_bytes().to_vec(),
    }
}

/// Derives the Aptos twisted Ed25519 encryption key `H / dk` from a 32-byte decryption key.
#[uniffi::export]
pub fn twisted_ed25519_public_key_from_private(
    mut private_key: Vec<u8>,
) -> Result<Vec<u8>, FastCryptoFfiError> {
    let result = nonzero_canonical_scalar(&private_key).map(|dk| {
        (hash_base_point() * dk.invert())
            .compress()
            .to_bytes()
            .to_vec()
    });
    private_key.zeroize();
    result
}

/// Derives an Aptos confidential-asset decryption key by reducing an Ed25519 signature modulo l.
#[uniffi::export]
pub fn twisted_ed25519_private_key_from_signature(
    mut signature: Vec<u8>,
) -> Result<Vec<u8>, FastCryptoFfiError> {
    let result = (|| {
        let scalar = Scalar::from_bytes_mod_order_wide(&fixed::<WIDE_SCALAR_BYTES>(&signature)?);
        if scalar == Scalar::zero() {
            return Err(FastCryptoFfiError::InvalidInput);
        }
        Ok(scalar.to_bytes().to_vec())
    })();
    signature.zeroize();
    result
}

/// Encrypts one unsigned amount as `(C = amount*G + r*H, D = r*ek)`.
#[uniffi::export]
pub fn twisted_elgamal_encrypt(
    public_key: Vec<u8>,
    amount: u64,
    randomness: Option<Vec<u8>>,
) -> Result<TwistedElGamalCiphertextBytes, FastCryptoFfiError> {
    let encryption_key = point(&public_key)?;
    let random = match randomness.as_deref() {
        Some(bytes) => canonical_scalar(bytes)?,
        None => Scalar::random(&mut thread_rng()),
    };
    let commitment = RISTRETTO_BASEPOINT_POINT * Scalar::from(amount) + hash_base_point() * random;
    let handle = encryption_key * random;
    Ok(TwistedElGamalCiphertextBytes {
        commitment: commitment.compress().to_bytes().to_vec(),
        handle: handle.compress().to_bytes().to_vec(),
        randomness: random.to_bytes().to_vec(),
    })
}

/// Deterministic zero-randomness encryption used for public homomorphic adjustments.
#[uniffi::export]
pub fn twisted_elgamal_encrypt_zero_randomness(amount: u64) -> TwistedElGamalCiphertextBytes {
    TwistedElGamalCiphertextBytes {
        commitment: (RISTRETTO_BASEPOINT_POINT * Scalar::from(amount))
            .compress()
            .to_bytes()
            .to_vec(),
        handle: RistrettoPoint::identity().compress().to_bytes().to_vec(),
        randomness: Scalar::zero().to_bytes().to_vec(),
    }
}

/// Adds or subtracts two canonical twisted ElGamal ciphertexts.
#[uniffi::export]
pub fn twisted_elgamal_combine(
    left_commitment: Vec<u8>,
    left_handle: Vec<u8>,
    right_commitment: Vec<u8>,
    right_handle: Vec<u8>,
    subtract: bool,
) -> Result<TwistedElGamalCiphertextBytes, FastCryptoFfiError> {
    let left_c = point(&left_commitment)?;
    let left_d = point(&left_handle)?;
    let right_c = point(&right_commitment)?;
    let right_d = point(&right_handle)?;
    let (commitment, handle) = if subtract {
        (left_c - right_c, left_d - right_d)
    } else {
        (left_c + right_c, left_d + right_d)
    };
    Ok(TwistedElGamalCiphertextBytes {
        commitment: commitment.compress().to_bytes().to_vec(),
        handle: handle.compress().to_bytes().to_vec(),
        randomness: Vec::new(),
    })
}

type BsgsTable = HashMap<[u8; POINT_BYTES], u32>;

fn bsgs_tables() -> &'static Mutex<HashMap<u8, Arc<BsgsTable>>> {
    static TABLES: OnceLock<Mutex<HashMap<u8, Arc<BsgsTable>>>> = OnceLock::new();
    TABLES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn bsgs_table(bit_width: u8) -> Result<Arc<BsgsTable>, FastCryptoFfiError> {
    if !matches!(bit_width, 16 | 32) {
        return Err(FastCryptoFfiError::InvalidInput);
    }
    if let Some(table) = bsgs_tables()
        .lock()
        .map_err(|_| FastCryptoFfiError::General("Discrete-log cache is poisoned".into()))?
        .get(&bit_width)
        .cloned()
    {
        return Ok(table);
    }

    let half_bits = (bit_width as u32 + 1) / 2;
    let size = 1u32 << half_bits;
    let mut table = HashMap::with_capacity(size as usize);
    let mut point = RistrettoPoint::identity();
    for value in 0..size {
        table.insert(point.compress().to_bytes(), value);
        point += RISTRETTO_BASEPOINT_POINT;
    }
    let table = Arc::new(table);
    bsgs_tables()
        .lock()
        .map_err(|_| FastCryptoFfiError::General("Discrete-log cache is poisoned".into()))?
        .insert(bit_width, table.clone());
    Ok(table)
}

/// Solves `value * G = point` in the bounded 16- or 32-bit Aptos amount domain.
#[uniffi::export]
pub fn ristretto_solve_bounded_discrete_log(
    compressed_point: Vec<u8>,
    bit_width: u8,
) -> Result<u64, FastCryptoFfiError> {
    let target = point(&compressed_point)?;
    if target == RistrettoPoint::identity() {
        return Ok(0);
    }
    let table = bsgs_table(bit_width)?;
    let half_bits = (bit_width as u32 + 1) / 2;
    let size = 1u64 << half_bits;
    let giant_step = RISTRETTO_BASEPOINT_POINT * Scalar::from(size);
    let rounds = 1u64 << (bit_width as u32 - half_bits);
    let mut candidate = target;
    let limit = 1u64 << bit_width;
    for giant in 0..rounds {
        if let Some(baby) = table.get(&candidate.compress().to_bytes()) {
            let value = giant * size + *baby as u64;
            if value < limit {
                return Ok(value);
            }
        }
        candidate -= giant_step;
    }
    Err(FastCryptoFfiError::General(
        "Discrete logarithm is outside the requested range".into(),
    ))
}

/// Decrypts an Aptos twisted ElGamal ciphertext in a bounded 16- or 32-bit range.
#[uniffi::export]
pub fn twisted_elgamal_decrypt(
    mut private_key: Vec<u8>,
    commitment: Vec<u8>,
    handle: Vec<u8>,
    bit_width: u8,
) -> Result<u64, FastCryptoFfiError> {
    let result = (|| {
        let dk = nonzero_canonical_scalar(&private_key)?;
        let message_point = point(&commitment)? - point(&handle)? * dk;
        ristretto_solve_bounded_discrete_log(
            message_point.compress().to_bytes().to_vec(),
            bit_width,
        )
    })();
    private_key.zeroize();
    result
}

/// Generates the exact batch Bulletproof accepted by Aptos Confidential Assets.
#[uniffi::export]
pub fn aptos_confidential_range_prove(
    values: Vec<u64>,
    mut blindings: Vec<Vec<u8>>,
) -> Result<AptosConfidentialRangeProofBytes, FastCryptoFfiError> {
    let result = (|| {
        if values.len() != blindings.len() || !valid_batch_size(values.len()) {
            return Err(FastCryptoFfiError::InvalidInput);
        }
        if values
            .iter()
            .any(|value| *value >= (1u64 << APTOS_RANGE_BITS))
        {
            return Err(FastCryptoFfiError::InvalidInput);
        }
        let blindings = blindings
            .iter()
            .map(|bytes| canonical_scalar(bytes))
            .collect::<Result<Vec<_>, _>>()?;
        let mut transcript = Transcript::new(APTOS_RANGE_DOMAIN);
        let (proof, commitments) = RangeProof::prove_multiple(
            bulletproof_generators(),
            &pedersen_generators(),
            &mut transcript,
            &values,
            &blindings,
            APTOS_RANGE_BITS,
        )
        .map_err(|_| FastCryptoFfiError::General("Bulletproof generation failed".into()))?;
        Ok(AptosConfidentialRangeProofBytes {
            proof: proof.to_bytes(),
            commitments: commitments
                .iter()
                .map(|commitment| commitment.as_bytes().to_vec())
                .collect(),
        })
    })();
    blindings.iter_mut().for_each(Zeroize::zeroize);
    result
}

/// Verifies the exact batch Bulletproof accepted by Aptos Confidential Assets.
#[uniffi::export]
pub fn aptos_confidential_range_verify(
    proof: Vec<u8>,
    commitments: Vec<Vec<u8>>,
) -> Result<bool, FastCryptoFfiError> {
    if !valid_batch_size(commitments.len()) {
        return Err(FastCryptoFfiError::InvalidInput);
    }
    let commitments = commitments
        .iter()
        .map(|bytes| {
            point(bytes)?;
            Ok(CompressedRistretto::from_slice(bytes))
        })
        .collect::<Result<Vec<_>, FastCryptoFfiError>>()?;
    let proof = RangeProof::from_bytes(&proof).map_err(|_| FastCryptoFfiError::InvalidInput)?;
    let mut transcript = Transcript::new(APTOS_RANGE_DOMAIN);
    Ok(proof
        .verify_multiple(
            bulletproof_generators(),
            &pedersen_generators(),
            &mut transcript,
            &commitments,
            APTOS_RANGE_BITS,
        )
        .is_ok())
}

const WITHDRAW_PROTOCOL: &str = "AptosConfidentialAsset/WithdrawalV1";
const WITHDRAW_TYPE: &str = "0x1::sigma_protocol_withdraw::Withdrawal";

fn chunk_powers(count: usize) -> Vec<Scalar> {
    let base = Scalar::from(1u64 << 16);
    let mut value = Scalar::one();
    (0..count)
        .map(|_| {
            let current = value;
            value *= base;
            current
        })
        .collect()
}

fn withdraw_psi(
    statement: &SigmaStatement,
    witness: &[Scalar],
    chunk_count: usize,
    has_auditor: bool,
) -> Vec<RistrettoPoint> {
    let private = witness[0];
    let amounts = &witness[1..1 + chunk_count];
    let randomness = &witness[1 + chunk_count..1 + 2 * chunk_count];
    let base = statement.points[0];
    let hash_base = statement.points[1];
    let public = statement.points[2];
    let old_handles_start = 3 + chunk_count;
    let mut output = vec![public * private];
    for index in 0..chunk_count {
        output.push(base * amounts[index] + hash_base * randomness[index]);
    }
    for random in randomness {
        output.push(public * random);
    }
    if has_auditor {
        let auditor_public = statement.points[3 + 4 * chunk_count];
        for random in randomness {
            output.push(auditor_public * random);
        }
    }
    let powers = chunk_powers(chunk_count);
    let mut balance = RistrettoPoint::identity();
    for index in 0..chunk_count {
        balance += statement.points[old_handles_start + index] * (private * powers[index]);
        balance += base * (amounts[index] * powers[index]);
    }
    output.push(balance);
    output
}

fn withdraw_transform(
    statement: &SigmaStatement,
    chunk_count: usize,
    has_auditor: bool,
    amount: u64,
) -> Vec<RistrettoPoint> {
    let new_commitments_start = 3 + 2 * chunk_count;
    let new_handles_start = 3 + 3 * chunk_count;
    let mut output = vec![statement.points[1]];
    output.extend_from_slice(
        &statement.points[new_commitments_start..new_commitments_start + chunk_count],
    );
    output.extend_from_slice(&statement.points[new_handles_start..new_handles_start + chunk_count]);
    if has_auditor {
        let auditor_handles_start = 3 + 4 * chunk_count + 1;
        output.extend_from_slice(
            &statement.points[auditor_handles_start..auditor_handles_start + chunk_count],
        );
    }
    let powers = chunk_powers(chunk_count);
    let mut target = RistrettoPoint::identity();
    for index in 0..chunk_count {
        target += statement.points[3 + index] * powers[index];
    }
    target -= statement.points[0] * Scalar::from(amount);
    output.push(target);
    output
}

#[allow(clippy::too_many_arguments)]
fn withdraw_statement(
    public_key: Vec<u8>,
    old_commitments: Vec<Vec<u8>>,
    old_handles: Vec<Vec<u8>>,
    new_commitments: Vec<Vec<u8>>,
    new_handles: Vec<Vec<u8>>,
    auditor_public_key: Option<Vec<u8>>,
    new_auditor_handles: Vec<Vec<u8>>,
    amount: u64,
) -> Result<(SigmaStatement, usize, bool), FastCryptoFfiError> {
    let chunk_count = old_commitments.len();
    if chunk_count == 0
        || old_handles.len() != chunk_count
        || new_commitments.len() != chunk_count
        || new_handles.len() != chunk_count
    {
        return Err(FastCryptoFfiError::InvalidInput);
    }
    let has_auditor = auditor_public_key.is_some();
    if (has_auditor && new_auditor_handles.len() != chunk_count)
        || (!has_auditor && !new_auditor_handles.is_empty())
    {
        return Err(FastCryptoFfiError::InvalidInput);
    }
    let mut compressed = vec![
        RISTRETTO_BASEPOINT_POINT.compress().to_bytes().to_vec(),
        hash_base_point().compress().to_bytes().to_vec(),
        public_key,
    ];
    compressed.extend(old_commitments);
    compressed.extend(old_handles);
    compressed.extend(new_commitments);
    compressed.extend(new_handles);
    if let Some(auditor_public_key) = auditor_public_key {
        compressed.push(auditor_public_key);
        compressed.extend(new_auditor_handles);
    }
    Ok((
        statement(compressed, vec![Scalar::from(amount).to_bytes().to_vec()])?,
        chunk_count,
        has_auditor,
    ))
}

/// Generates the exact Aptos withdrawal sigma proof; amount zero is normalization.
#[uniffi::export]
pub fn aptos_confidential_withdraw_prove(
    mut input: AptosConfidentialWithdrawProofInputBytes,
) -> Result<AptosConfidentialSigmaProofBytes, FastCryptoFfiError> {
    let result = (|| {
        let private = nonzero_canonical_scalar(&input.private_key)?;
        let public_key = (hash_base_point() * private.invert())
            .compress()
            .to_bytes()
            .to_vec();
        let (stmt, chunk_count, has_auditor) = withdraw_statement(
            public_key,
            input.old_commitments,
            input.old_handles,
            input.new_commitments,
            input.new_handles,
            input.auditor_public_key,
            input.new_auditor_handles,
            input.amount,
        )?;
        if input.new_amount_chunks.len() != chunk_count
            || input.new_randomness.len() != chunk_count
            || input
                .new_amount_chunks
                .iter()
                .any(|value| *value >= (1u64 << APTOS_RANGE_BITS))
        {
            return Err(FastCryptoFfiError::InvalidInput);
        }
        let mut witness = Vec::with_capacity(1 + 2 * chunk_count);
        witness.push(private);
        witness.extend(
            input
                .new_amount_chunks
                .iter()
                .map(|value| Scalar::from(*value)),
        );
        witness.extend(
            input
                .new_randomness
                .iter()
                .map(|value| canonical_scalar(value))
                .collect::<Result<Vec<_>, _>>()?,
        );
        let session = bcs_session(
            &[&input.sender_address, &input.token_address],
            &[chunk_count as u64],
            &[has_auditor],
        )?;
        sigma_prove(
            input.chain_id,
            WITHDRAW_PROTOCOL,
            &session,
            WITHDRAW_TYPE,
            &stmt,
            &witness,
            |statement, witness| withdraw_psi(statement, witness, chunk_count, has_auditor),
        )
    })();
    input.private_key.zeroize();
    input.new_randomness.iter_mut().for_each(Zeroize::zeroize);
    input.new_amount_chunks.zeroize();
    result
}

/// Verifies an Aptos withdrawal or normalization sigma proof.
#[uniffi::export]
pub fn aptos_confidential_withdraw_verify(
    input: AptosConfidentialWithdrawStatementBytes,
    proof: AptosConfidentialSigmaProofBytes,
) -> Result<bool, FastCryptoFfiError> {
    let (stmt, chunk_count, has_auditor) = withdraw_statement(
        input.public_key,
        input.old_commitments,
        input.old_handles,
        input.new_commitments,
        input.new_handles,
        input.auditor_public_key,
        input.new_auditor_handles,
        input.amount,
    )?;
    let session = bcs_session(
        &[&input.sender_address, &input.token_address],
        &[chunk_count as u64],
        &[has_auditor],
    )?;
    sigma_verify(
        input.chain_id,
        WITHDRAW_PROTOCOL,
        &session,
        WITHDRAW_TYPE,
        &stmt,
        &proof,
        |statement, witness| withdraw_psi(statement, witness, chunk_count, has_auditor),
        |statement| withdraw_transform(statement, chunk_count, has_auditor, input.amount),
    )
}

const TRANSFER_PROTOCOL: &str = "AptosConfidentialAsset/TransferV1";
const TRANSFER_TYPE: &str = "0x1::sigma_protocol_transfer::Transfer";

fn transfer_session(
    sender: &[u8],
    recipient: &[u8],
    token: &[u8],
    available_chunks: usize,
    transfer_chunks: usize,
    has_effective_auditor: bool,
    voluntary_auditors: usize,
) -> Result<Vec<u8>, FastCryptoFfiError> {
    for address in [sender, recipient, token] {
        if address.len() != 32 {
            return Err(FastCryptoFfiError::InputLengthWrong(32));
        }
    }
    let mut output = Vec::new();
    output.extend_from_slice(sender);
    output.extend_from_slice(recipient);
    output.extend_from_slice(token);
    output.extend_from_slice(&(available_chunks as u64).to_le_bytes());
    output.extend_from_slice(&(transfer_chunks as u64).to_le_bytes());
    output.push(u8::from(has_effective_auditor));
    output.extend_from_slice(&(voluntary_auditors as u64).to_le_bytes());
    Ok(output)
}

fn transfer_psi(
    statement: &SigmaStatement,
    witness: &[Scalar],
    available_chunks: usize,
    transfer_chunks: usize,
    has_effective_auditor: bool,
    voluntary_auditors: usize,
) -> Vec<RistrettoPoint> {
    let private = witness[0];
    let new_amounts = &witness[1..1 + available_chunks];
    let new_randomness = &witness[1 + available_chunks..1 + 2 * available_chunks];
    let transfer_amounts =
        &witness[1 + 2 * available_chunks..1 + 2 * available_chunks + transfer_chunks];
    let transfer_randomness = &witness[1 + 2 * available_chunks + transfer_chunks
        ..1 + 2 * available_chunks + 2 * transfer_chunks];
    let base = statement.points[0];
    let hash_base = statement.points[1];
    let sender_public = statement.points[2];
    let recipient_public = statement.points[3];
    let old_handles_start = 4 + available_chunks;
    let effective_start = 4 + 4 * available_chunks + 3 * transfer_chunks;
    let voluntary_start = effective_start
        + if has_effective_auditor {
            1 + available_chunks + transfer_chunks
        } else {
            0
        };

    let mut output = vec![sender_public * private];
    for index in 0..available_chunks {
        output.push(base * new_amounts[index] + hash_base * new_randomness[index]);
    }
    for random in new_randomness {
        output.push(sender_public * random);
    }
    if has_effective_auditor {
        let effective_public = statement.points[effective_start];
        for random in new_randomness {
            output.push(effective_public * random);
        }
    }

    let available_powers = chunk_powers(available_chunks);
    let transfer_powers = chunk_powers(transfer_chunks);
    let mut balance = RistrettoPoint::identity();
    for index in 0..available_chunks {
        balance +=
            statement.points[old_handles_start + index] * (private * available_powers[index]);
        balance += base * (new_amounts[index] * available_powers[index]);
    }
    for index in 0..transfer_chunks {
        balance += base * (transfer_amounts[index] * transfer_powers[index]);
    }
    output.push(balance);

    for index in 0..transfer_chunks {
        output.push(base * transfer_amounts[index] + hash_base * transfer_randomness[index]);
    }
    for random in transfer_randomness {
        output.push(sender_public * random);
    }
    for random in transfer_randomness {
        output.push(recipient_public * random);
    }
    if has_effective_auditor {
        let effective_public = statement.points[effective_start];
        for random in transfer_randomness {
            output.push(effective_public * random);
        }
    }
    for auditor in 0..voluntary_auditors {
        let public = statement.points[voluntary_start + auditor * (1 + transfer_chunks)];
        for random in transfer_randomness {
            output.push(public * random);
        }
    }
    output
}

fn transfer_transform(
    statement: &SigmaStatement,
    available_chunks: usize,
    transfer_chunks: usize,
    has_effective_auditor: bool,
    voluntary_auditors: usize,
) -> Vec<RistrettoPoint> {
    let new_commitments_start = 4 + 2 * available_chunks;
    let new_handles_start = 4 + 3 * available_chunks;
    let transfer_commitments_start = 4 + 4 * available_chunks;
    let sender_handles_start = transfer_commitments_start + transfer_chunks;
    let recipient_handles_start = sender_handles_start + transfer_chunks;
    let effective_start = recipient_handles_start + transfer_chunks;
    let voluntary_start = effective_start
        + if has_effective_auditor {
            1 + available_chunks + transfer_chunks
        } else {
            0
        };
    let mut output = vec![statement.points[1]];
    output.extend_from_slice(
        &statement.points[new_commitments_start..new_commitments_start + available_chunks],
    );
    output.extend_from_slice(
        &statement.points[new_handles_start..new_handles_start + available_chunks],
    );
    if has_effective_auditor {
        output.extend_from_slice(
            &statement.points[effective_start + 1..effective_start + 1 + available_chunks],
        );
    }
    let powers = chunk_powers(available_chunks);
    let mut balance = RistrettoPoint::identity();
    for index in 0..available_chunks {
        balance += statement.points[4 + index] * powers[index];
    }
    output.push(balance);
    output.extend_from_slice(
        &statement.points[transfer_commitments_start..transfer_commitments_start + transfer_chunks],
    );
    output.extend_from_slice(
        &statement.points[sender_handles_start..sender_handles_start + transfer_chunks],
    );
    output.extend_from_slice(
        &statement.points[recipient_handles_start..recipient_handles_start + transfer_chunks],
    );
    if has_effective_auditor {
        let handles_start = effective_start + 1 + available_chunks;
        output.extend_from_slice(&statement.points[handles_start..handles_start + transfer_chunks]);
    }
    for auditor in 0..voluntary_auditors {
        let handles_start = voluntary_start + auditor * (1 + transfer_chunks) + 1;
        output.extend_from_slice(&statement.points[handles_start..handles_start + transfer_chunks]);
    }
    output
}

#[allow(clippy::too_many_arguments)]
fn transfer_statement(
    sender_public_key: Vec<u8>,
    recipient_public_key: Vec<u8>,
    old_commitments: Vec<Vec<u8>>,
    old_handles: Vec<Vec<u8>>,
    new_commitments: Vec<Vec<u8>>,
    new_handles: Vec<Vec<u8>>,
    transfer_commitments: Vec<Vec<u8>>,
    transfer_sender_handles: Vec<Vec<u8>>,
    transfer_recipient_handles: Vec<Vec<u8>>,
    has_effective_auditor: bool,
    auditor_public_keys: Vec<Vec<u8>>,
    effective_new_balance_handles: Vec<Vec<u8>>,
    auditor_transfer_handles: Vec<Vec<u8>>,
) -> Result<(SigmaStatement, usize, usize, usize), FastCryptoFfiError> {
    let available_chunks = old_commitments.len();
    let transfer_chunks = transfer_commitments.len();
    if available_chunks == 0
        || transfer_chunks == 0
        || old_handles.len() != available_chunks
        || new_commitments.len() != available_chunks
        || new_handles.len() != available_chunks
        || transfer_sender_handles.len() != transfer_chunks
        || transfer_recipient_handles.len() != transfer_chunks
        || (has_effective_auditor && auditor_public_keys.is_empty())
        || (has_effective_auditor && effective_new_balance_handles.len() != available_chunks)
        || (!has_effective_auditor && !effective_new_balance_handles.is_empty())
        || auditor_transfer_handles.len() != auditor_public_keys.len() * transfer_chunks
    {
        return Err(FastCryptoFfiError::InvalidInput);
    }
    let voluntary_auditors = auditor_public_keys.len() - usize::from(has_effective_auditor);
    let mut compressed = vec![
        RISTRETTO_BASEPOINT_POINT.compress().to_bytes().to_vec(),
        hash_base_point().compress().to_bytes().to_vec(),
        sender_public_key,
        recipient_public_key,
    ];
    compressed.extend(old_commitments);
    compressed.extend(old_handles);
    compressed.extend(new_commitments);
    compressed.extend(new_handles);
    compressed.extend(transfer_commitments);
    compressed.extend(transfer_sender_handles);
    compressed.extend(transfer_recipient_handles);
    if has_effective_auditor {
        let effective = auditor_public_keys.len() - 1;
        compressed.push(auditor_public_keys[effective].clone());
        compressed.extend(effective_new_balance_handles);
        compressed.extend_from_slice(
            &auditor_transfer_handles
                [effective * transfer_chunks..(effective + 1) * transfer_chunks],
        );
    }
    for auditor in 0..voluntary_auditors {
        compressed.push(auditor_public_keys[auditor].clone());
        compressed.extend_from_slice(
            &auditor_transfer_handles[auditor * transfer_chunks..(auditor + 1) * transfer_chunks],
        );
    }
    Ok((
        statement(compressed, vec![])?,
        available_chunks,
        transfer_chunks,
        voluntary_auditors,
    ))
}

/// Generates the exact Aptos confidential transfer sigma proof for all auditor modes.
#[uniffi::export]
pub fn aptos_confidential_transfer_prove(
    mut input: AptosConfidentialTransferProofInputBytes,
) -> Result<AptosConfidentialSigmaProofBytes, FastCryptoFfiError> {
    let result = (|| {
        let private = nonzero_canonical_scalar(&input.private_key)?;
        let sender_public = (hash_base_point() * private.invert())
            .compress()
            .to_bytes()
            .to_vec();
        let (stmt, available_chunks, transfer_chunks, voluntary_auditors) = transfer_statement(
            sender_public,
            input.recipient_public_key,
            input.old_commitments,
            input.old_handles,
            input.new_commitments,
            input.new_handles,
            input.transfer_commitments,
            input.transfer_sender_handles,
            input.transfer_recipient_handles,
            input.has_effective_auditor,
            input.auditor_public_keys,
            input.effective_new_balance_handles,
            input.auditor_transfer_handles,
        )?;
        if input.new_amount_chunks.len() != available_chunks
            || input.new_randomness.len() != available_chunks
            || input.transfer_amount_chunks.len() != transfer_chunks
            || input.transfer_randomness.len() != transfer_chunks
            || input
                .new_amount_chunks
                .iter()
                .chain(&input.transfer_amount_chunks)
                .any(|value| *value >= (1u64 << APTOS_RANGE_BITS))
        {
            return Err(FastCryptoFfiError::InvalidInput);
        }
        let mut witness = Vec::with_capacity(1 + 2 * available_chunks + 2 * transfer_chunks);
        witness.push(private);
        witness.extend(
            input
                .new_amount_chunks
                .iter()
                .map(|value| Scalar::from(*value)),
        );
        witness.extend(
            input
                .new_randomness
                .iter()
                .map(|value| canonical_scalar(value))
                .collect::<Result<Vec<_>, _>>()?,
        );
        witness.extend(
            input
                .transfer_amount_chunks
                .iter()
                .map(|value| Scalar::from(*value)),
        );
        witness.extend(
            input
                .transfer_randomness
                .iter()
                .map(|value| canonical_scalar(value))
                .collect::<Result<Vec<_>, _>>()?,
        );
        let session = transfer_session(
            &input.sender_address,
            &input.recipient_address,
            &input.token_address,
            available_chunks,
            transfer_chunks,
            input.has_effective_auditor,
            voluntary_auditors,
        )?;
        sigma_prove(
            input.chain_id,
            TRANSFER_PROTOCOL,
            &session,
            TRANSFER_TYPE,
            &stmt,
            &witness,
            |statement, witness| {
                transfer_psi(
                    statement,
                    witness,
                    available_chunks,
                    transfer_chunks,
                    input.has_effective_auditor,
                    voluntary_auditors,
                )
            },
        )
    })();
    input.private_key.zeroize();
    input.new_randomness.iter_mut().for_each(Zeroize::zeroize);
    input
        .transfer_randomness
        .iter_mut()
        .for_each(Zeroize::zeroize);
    input.new_amount_chunks.zeroize();
    input.transfer_amount_chunks.zeroize();
    result
}

/// Verifies an Aptos confidential transfer sigma proof.
#[uniffi::export]
pub fn aptos_confidential_transfer_verify(
    input: AptosConfidentialTransferStatementBytes,
    proof: AptosConfidentialSigmaProofBytes,
) -> Result<bool, FastCryptoFfiError> {
    let (stmt, available_chunks, transfer_chunks, voluntary_auditors) = transfer_statement(
        input.sender_public_key,
        input.recipient_public_key,
        input.old_commitments,
        input.old_handles,
        input.new_commitments,
        input.new_handles,
        input.transfer_commitments,
        input.transfer_sender_handles,
        input.transfer_recipient_handles,
        input.has_effective_auditor,
        input.auditor_public_keys,
        input.effective_new_balance_handles,
        input.auditor_transfer_handles,
    )?;
    let session = transfer_session(
        &input.sender_address,
        &input.recipient_address,
        &input.token_address,
        available_chunks,
        transfer_chunks,
        input.has_effective_auditor,
        voluntary_auditors,
    )?;
    sigma_verify(
        input.chain_id,
        TRANSFER_PROTOCOL,
        &session,
        TRANSFER_TYPE,
        &stmt,
        &proof,
        |statement, witness| {
            transfer_psi(
                statement,
                witness,
                available_chunks,
                transfer_chunks,
                input.has_effective_auditor,
                voluntary_auditors,
            )
        },
        |statement| {
            transfer_transform(
                statement,
                available_chunks,
                transfer_chunks,
                input.has_effective_auditor,
                voluntary_auditors,
            )
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(last: u8) -> Vec<u8> {
        let mut value = vec![0; 32];
        value[31] = last;
        value
    }

    fn random_scalars(count: usize) -> Vec<Scalar> {
        (0..count)
            .map(|_| Scalar::random(&mut thread_rng()))
            .collect()
    }

    fn commitments(values: &[u64], randomness: &[Scalar]) -> Vec<Vec<u8>> {
        values
            .iter()
            .zip(randomness)
            .map(|(value, random)| {
                (RISTRETTO_BASEPOINT_POINT * Scalar::from(*value) + hash_base_point() * random)
                    .compress()
                    .to_bytes()
                    .to_vec()
            })
            .collect()
    }

    fn handles(public_key: &[u8], randomness: &[Scalar]) -> Vec<Vec<u8>> {
        let public = point(public_key).unwrap();
        randomness
            .iter()
            .map(|random| (public * random).compress().to_bytes().to_vec())
            .collect()
    }

    #[test]
    fn aptos_registration_fiat_shamir_matches_official_sdk_vector() {
        let sender = address(7);
        let token = address(9);
        let session = bcs_session(&[&sender, &token], &[], &[]).unwrap();
        let statement = statement(
            vec![
                hash_base_point().compress().to_bytes().to_vec(),
                RISTRETTO_BASEPOINT_POINT.compress().to_bytes().to_vec(),
            ],
            vec![],
        )
        .unwrap();
        let commitment = vec![(RISTRETTO_BASEPOINT_POINT * Scalar::from(2u64))
            .compress()
            .to_bytes()
            .to_vec()];

        let challenge = sigma_challenge(
            2,
            REGISTRATION_PROTOCOL,
            &session,
            REGISTRATION_TYPE,
            &statement,
            &commitment,
            1,
        )
        .unwrap();

        assert_eq!(
            challenge.to_bytes(),
            [
                0x41, 0x9b, 0xf7, 0x28, 0x73, 0xc4, 0xc5, 0x90, 0xa2, 0xfb, 0xd0, 0x08, 0x68, 0xc1,
                0x7a, 0xa4, 0xbc, 0xed, 0xa1, 0x11, 0xd0, 0xff, 0xfa, 0x3f, 0xac, 0x71, 0x59, 0x43,
                0xdb, 0x96, 0x3b, 0x0f,
            ],
        );
    }

    #[test]
    fn twisted_elgamal_round_trip_and_homomorphism() {
        let pair = twisted_ed25519_generate_keypair();
        let encrypted = twisted_elgamal_encrypt(pair.public_key.clone(), 12_345, None).unwrap();
        assert_eq!(
            twisted_elgamal_decrypt(
                pair.private_key.clone(),
                encrypted.commitment.clone(),
                encrypted.handle.clone(),
                16,
            )
            .unwrap(),
            12_345,
        );

        let delta = twisted_elgamal_encrypt_zero_randomness(55);
        let combined = twisted_elgamal_combine(
            encrypted.commitment,
            encrypted.handle,
            delta.commitment,
            delta.handle,
            false,
        )
        .unwrap();
        assert_eq!(
            twisted_elgamal_decrypt(pair.private_key, combined.commitment, combined.handle, 16,)
                .unwrap(),
            12_400,
        );
    }

    #[test]
    fn aptos_range_proof_round_trip() {
        let values = vec![1, 2, 65_535, 0];
        let blindings = (0..values.len())
            .map(|_| Scalar::random(&mut thread_rng()).to_bytes().to_vec())
            .collect();
        let range = aptos_confidential_range_prove(values, blindings).unwrap();
        assert!(aptos_confidential_range_verify(range.proof.clone(), range.commitments).unwrap());

        let mut invalid = range.proof;
        let middle = invalid.len() / 2;
        invalid[middle] ^= 1;
        assert!(!aptos_confidential_range_verify(
            invalid,
            vec![
                twisted_elgamal_encrypt_zero_randomness(1).commitment,
                twisted_elgamal_encrypt_zero_randomness(2).commitment,
                twisted_elgamal_encrypt_zero_randomness(65_535).commitment,
                twisted_elgamal_encrypt_zero_randomness(0).commitment,
            ],
        )
        .unwrap_or(false));
    }

    #[test]
    fn aptos_registration_and_key_rotation_sigma_round_trip() {
        let current = twisted_ed25519_generate_keypair();
        let next = twisted_ed25519_generate_keypair();
        let sender = address(7);
        let token = address(9);

        let registration = aptos_confidential_registration_prove(
            current.private_key.clone(),
            sender.clone(),
            token.clone(),
            2,
        )
        .unwrap();
        assert!(aptos_confidential_registration_verify(
            current.public_key.clone(),
            sender.clone(),
            token.clone(),
            2,
            registration.clone(),
        )
        .unwrap());
        assert!(!aptos_confidential_registration_verify(
            current.public_key.clone(),
            sender.clone(),
            address(10),
            2,
            registration,
        )
        .unwrap());

        let old_randomness = random_scalars(8);
        let old_handles = handles(&current.public_key, &old_randomness);
        let rotation = aptos_confidential_key_rotation_prove(
            current.private_key,
            next.private_key,
            old_handles.clone(),
            sender.clone(),
            token.clone(),
            2,
        )
        .unwrap();
        assert_eq!(rotation.new_public_key, next.public_key);
        assert!(aptos_confidential_key_rotation_verify(
            current.public_key,
            rotation.new_public_key,
            old_handles,
            rotation.new_handles,
            sender,
            token,
            2,
            rotation.proof,
        )
        .unwrap());
    }

    #[test]
    fn aptos_withdraw_sigma_round_trip_with_auditor() {
        let sender_pair = twisted_ed25519_generate_keypair();
        let auditor_pair = twisted_ed25519_generate_keypair();
        let sender = address(11);
        let token = address(12);
        let old_values = vec![100, 1];
        let new_values = vec![99, 1];
        let old_randomness = random_scalars(2);
        let new_randomness = random_scalars(2);
        let old_commitments = commitments(&old_values, &old_randomness);
        let old_handles = handles(&sender_pair.public_key, &old_randomness);
        let new_commitments = commitments(&new_values, &new_randomness);
        let new_handles = handles(&sender_pair.public_key, &new_randomness);
        let auditor_handles = handles(&auditor_pair.public_key, &new_randomness);

        let proof = aptos_confidential_withdraw_prove(AptosConfidentialWithdrawProofInputBytes {
            private_key: sender_pair.private_key,
            sender_address: sender.clone(),
            token_address: token.clone(),
            chain_id: 2,
            amount: 1,
            old_commitments: old_commitments.clone(),
            old_handles: old_handles.clone(),
            new_commitments: new_commitments.clone(),
            new_handles: new_handles.clone(),
            new_amount_chunks: new_values,
            new_randomness: new_randomness
                .iter()
                .map(|value| value.to_bytes().to_vec())
                .collect(),
            auditor_public_key: Some(auditor_pair.public_key.clone()),
            new_auditor_handles: auditor_handles.clone(),
        })
        .unwrap();
        assert!(aptos_confidential_withdraw_verify(
            AptosConfidentialWithdrawStatementBytes {
                sender_address: sender,
                token_address: token,
                chain_id: 2,
                amount: 1,
                public_key: sender_pair.public_key,
                old_commitments,
                old_handles,
                new_commitments,
                new_handles,
                auditor_public_key: Some(auditor_pair.public_key),
                new_auditor_handles: auditor_handles,
            },
            proof,
        )
        .unwrap());
    }

    #[test]
    fn aptos_transfer_sigma_round_trip_with_effective_and_voluntary_auditors() {
        let sender_pair = twisted_ed25519_generate_keypair();
        let recipient_pair = twisted_ed25519_generate_keypair();
        let voluntary_pair = twisted_ed25519_generate_keypair();
        let effective_pair = twisted_ed25519_generate_keypair();
        let old_values = vec![100, 1];
        let new_values = vec![90, 1];
        let transfer_values = vec![10, 0];
        let old_randomness = random_scalars(2);
        let new_randomness = random_scalars(2);
        let transfer_randomness = random_scalars(2);
        let old_commitments = commitments(&old_values, &old_randomness);
        let old_handles = handles(&sender_pair.public_key, &old_randomness);
        let new_commitments = commitments(&new_values, &new_randomness);
        let new_handles = handles(&sender_pair.public_key, &new_randomness);
        let transfer_commitments = commitments(&transfer_values, &transfer_randomness);
        let transfer_sender_handles = handles(&sender_pair.public_key, &transfer_randomness);
        let transfer_recipient_handles = handles(&recipient_pair.public_key, &transfer_randomness);
        let effective_new_handles = handles(&effective_pair.public_key, &new_randomness);
        let mut auditor_transfer_handles =
            handles(&voluntary_pair.public_key, &transfer_randomness);
        auditor_transfer_handles.extend(handles(&effective_pair.public_key, &transfer_randomness));
        let auditor_public_keys = vec![
            voluntary_pair.public_key.clone(),
            effective_pair.public_key.clone(),
        ];
        let sender = address(13);
        let recipient = address(14);
        let token = address(15);

        let proof = aptos_confidential_transfer_prove(AptosConfidentialTransferProofInputBytes {
            private_key: sender_pair.private_key,
            sender_address: sender.clone(),
            recipient_address: recipient.clone(),
            token_address: token.clone(),
            chain_id: 2,
            recipient_public_key: recipient_pair.public_key.clone(),
            old_commitments: old_commitments.clone(),
            old_handles: old_handles.clone(),
            new_commitments: new_commitments.clone(),
            new_handles: new_handles.clone(),
            new_amount_chunks: new_values,
            new_randomness: new_randomness
                .iter()
                .map(|value| value.to_bytes().to_vec())
                .collect(),
            transfer_commitments: transfer_commitments.clone(),
            transfer_sender_handles: transfer_sender_handles.clone(),
            transfer_recipient_handles: transfer_recipient_handles.clone(),
            transfer_amount_chunks: transfer_values,
            transfer_randomness: transfer_randomness
                .iter()
                .map(|value| value.to_bytes().to_vec())
                .collect(),
            has_effective_auditor: true,
            auditor_public_keys: auditor_public_keys.clone(),
            effective_new_balance_handles: effective_new_handles.clone(),
            auditor_transfer_handles: auditor_transfer_handles.clone(),
        })
        .unwrap();
        assert!(aptos_confidential_transfer_verify(
            AptosConfidentialTransferStatementBytes {
                sender_address: sender,
                recipient_address: recipient,
                token_address: token,
                chain_id: 2,
                sender_public_key: sender_pair.public_key,
                recipient_public_key: recipient_pair.public_key,
                old_commitments,
                old_handles,
                new_commitments,
                new_handles,
                transfer_commitments,
                transfer_sender_handles,
                transfer_recipient_handles,
                has_effective_auditor: true,
                auditor_public_keys,
                effective_new_balance_handles: effective_new_handles,
                auditor_transfer_handles,
            },
            proof,
        )
        .unwrap());
    }
}
