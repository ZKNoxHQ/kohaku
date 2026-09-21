//! The APDU protocol of the ZKNOX Railgun Ledger app.
//!
//! This module is the single source of truth for the host side of the wire format; the
//! device app must mirror it exactly.
//!
//! ## Commands
//!
//! All commands use class byte [`CLA`]. Paths are serialized in the standard Ledger form:
//! one byte component count, then each component as a big-endian `u32` (hardened components
//! have the high bit set).
//!
//! | INS | P1 | Data | Response |
//! |-----|----|------|----------|
//! | [`INS_GET_VERSION`] | 0 | empty | 3 bytes: major, minor, patch |
//! | [`INS_GET_SPENDING_PUBLIC_KEY`] | 0 silent, 1 display | path | 64 bytes: BabyJubJub A.x ‖ A.y, 32-byte big-endian each, uncompressed |
//! | [`INS_EXPORT_VIEWING_KEY`] | 0 silent, 1 display | path | 32 bytes: the raw ed25519 **seed** (not an expanded scalar) |
//! | [`INS_SIGN_HASH`] | 0 | path ‖ 32-byte big-endian BN254 field element | 96 bytes: R8.x ‖ R8.y ‖ s, 32-byte big-endian each |
//!
//! The signed message is the already-poseidon-hashed transaction digest
//! (`poseidon(merkleroot, boundParamsHash, nullifiers…, commitments…)`), computed host-side.
//! The signature must verify under circomlib's `EdDSAPoseidonVerifier`, i.e. match
//! the deterministic Poseidon-EdDSA of the reference software implementation.

use ruint::aliases::U256;
use thiserror::Error;

use railgun::crypto::keys::{HexKey, SpendingPublicKey, SpendingSignature, ViewingKey};

use crate::transport::{Apdu, Exchange, TransportError};

pub const CLA: u8 = 0xE0;

pub const INS_GET_VERSION: u8 = 0x01;
pub const INS_GET_SPENDING_PUBLIC_KEY: u8 = 0x02;
pub const INS_EXPORT_VIEWING_KEY: u8 = 0x04;
pub const INS_SIGN_HASH: u8 = 0x06;

/// Show the requested material on the device screen for user verification.
pub const P1_DISPLAY: u8 = 0x01;

pub const STATUS_OK: u16 = 0x9000;

const HARDENED: u32 = 0x8000_0000;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error("device status {status:#06x}: {}", status_name(*status))]
    Status { status: u16 },
    #[error("unexpected response length: expected {expected}, got {got}")]
    ResponseLength { expected: usize, got: usize },
    #[error("invalid key material in response: {0}")]
    Key(String),
}

fn status_name(status: u16) -> &'static str {
    match status {
        0x5515 => "device locked",
        0x6985 => "denied by user",
        0x6a86 => "wrong P1/P2",
        0x6a87 => "wrong data length",
        0x6d00 => "instruction not supported (wrong app?)",
        0x6e00 => "class not supported (wrong app?)",
        _ => "unknown status",
    }
}

/// BIP-32 path of the Railgun spending key, all components hardened:
/// `m/44'/1984'/0'/0'/index'`, as in the Railgun engine.
pub fn spending_path(index: u32) -> [u32; 5] {
    [
        44 | HARDENED,
        1984 | HARDENED,
        HARDENED,
        HARDENED,
        index | HARDENED,
    ]
}

/// BIP-32 path of the Railgun viewing key, all components hardened:
/// `m/420'/1984'/0'/0'/index'`, as in the Railgun engine.
pub fn viewing_path(index: u32) -> [u32; 5] {
    [
        420 | HARDENED,
        1984 | HARDENED,
        HARDENED,
        HARDENED,
        index | HARDENED,
    ]
}

/// Standard Ledger path framing: count byte, then big-endian `u32` components.
fn serialize_path(path: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 * path.len());
    out.push(path.len() as u8);
    for component in path {
        out.extend_from_slice(&component.to_be_bytes());
    }
    out
}

async fn call<E: Exchange>(
    device: &E,
    ins: u8,
    p1: u8,
    data: Vec<u8>,
    expected_len: usize,
) -> Result<Vec<u8>, ProtocolError> {
    let response = device
        .exchange(&Apdu {
            cla: CLA,
            ins,
            p1,
            p2: 0,
            data,
        })
        .await?;
    if response.status != STATUS_OK {
        return Err(ProtocolError::Status {
            status: response.status,
        });
    }
    if response.data.len() != expected_len {
        return Err(ProtocolError::ResponseLength {
            expected: expected_len,
            got: response.data.len(),
        });
    }
    Ok(response.data)
}

/// The app version, `(major, minor, patch)`.
pub async fn get_version<E: Exchange>(device: &E) -> Result<(u8, u8, u8), ProtocolError> {
    let data = call(device, INS_GET_VERSION, 0, Vec::new(), 3).await?;
    Ok((data[0], data[1], data[2]))
}

/// The BabyJubJub spending public key at `m/44'/1984'/0'/0'/index'`.
pub async fn get_spending_public_key<E: Exchange>(
    device: &E,
    index: u32,
    display: bool,
) -> Result<SpendingPublicKey, ProtocolError> {
    let p1 = if display { P1_DISPLAY } else { 0 };
    let path = serialize_path(&spending_path(index));
    let data = call(device, INS_GET_SPENDING_PUBLIC_KEY, p1, path, 64).await?;

    let x: [u8; 32] = data[..32].try_into().expect("length checked");
    let y: [u8; 32] = data[32..].try_into().expect("length checked");
    Ok(SpendingPublicKey::new(x, y))
}

/// The ed25519 viewing seed at `m/420'/1984'/0'/0'/index'`.
///
/// This must be the raw 32-byte seed: the host uses it as an ed25519 seed for the viewing
/// public key, hashed-and-clamped for note-decryption ECDH, and as the poseidon preimage of
/// the nullifying key.
pub async fn export_viewing_key<E: Exchange>(
    device: &E,
    index: u32,
) -> Result<ViewingKey, ProtocolError> {
    let data = call(device, INS_EXPORT_VIEWING_KEY, 0, serialize_path(&viewing_path(index)), 32)
        .await?;
    ViewingKey::from_hex(&hex::encode(&data)).map_err(|e| ProtocolError::Key(e.to_string()))
}

/// Poseidon-EdDSA signature over an already-hashed BN254 field element.
///
/// One call is one user confirmation on the device.
pub async fn sign_hash<E: Exchange>(
    device: &E,
    index: u32,
    hash: U256,
) -> Result<SpendingSignature, ProtocolError> {
    let mut data = serialize_path(&spending_path(index));
    data.extend_from_slice(&hash.to_be_bytes::<32>());
    let response = call(device, INS_SIGN_HASH, 0, data, 96).await?;

    Ok(SpendingSignature {
        r8_x: U256::from_be_slice(&response[..32]),
        r8_y: U256::from_be_slice(&response[32..64]),
        s: U256::from_be_slice(&response[64..]),
    })
}
