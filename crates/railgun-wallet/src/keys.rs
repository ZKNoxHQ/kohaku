//! Key derivation from a BIP-39 mnemonic.
//!
//! Two schemes are supported because they yield different 0zk addresses for the same mnemonic:
//!
//! * [`Derivation::Railgun`]: Railgun engine scheme (`engine/src/key-derivation/bip32.ts`).
//!   SLIP-0010-like, hardened-only, HMAC-SHA512 keyed with `"babyjubjub seed"`. This is what
//!   Railway and every Railgun community wallet use.
//! * [`Derivation::Kohaku`]: standard secp256k1 BIP-32 private key at the same paths, as done by
//!   kohaku's `MnemonicKeystore` (`packages/plugins/src/host/mnemonic-keystore.ts`).

use std::str::FromStr;

use anyhow::{Context, Result, anyhow};
use hmac::{Hmac, Mac};
use railgun::{
    account::signer::{spending_key_path, viewing_key_path},
    crypto::keys::{HexKey, SpendingKey, ViewingKey},
};
use serde::{Deserialize, Serialize};
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

const RAILGUN_CURVE_SEED: &[u8] = b"babyjubjub seed";
const HARDENED: u32 = 0x8000_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Derivation {
    #[default]
    Railgun,
    Kohaku,
}

pub struct RailgunKeys {
    pub spending: SpendingKey,
    pub viewing: ViewingKey,
}

/// Derives the Railgun spending and viewing keys at `index` from a BIP-39 mnemonic.
pub fn derive(mnemonic: &str, index: u32, scheme: Derivation) -> Result<RailgunKeys> {
    let mnemonic = bip39::Mnemonic::parse_normalized(mnemonic.trim())
        .map_err(|e| anyhow!("invalid mnemonic: {e}"))?;
    let seed = mnemonic.to_seed("");

    let spending_path = spending_key_path(index);
    let viewing_path = viewing_key_path(index);

    let (spending, viewing) = match scheme {
        Derivation::Railgun => (
            railgun_derive(&seed, &spending_path)?,
            railgun_derive(&seed, &viewing_path)?,
        ),
        Derivation::Kohaku => (
            bip32_derive(&seed, &spending_path)?,
            bip32_derive(&seed, &viewing_path)?,
        ),
    };

    keys_from_bytes(spending, viewing)
}

/// Parses raw hex spending / viewing keys (32 bytes each, optional 0x prefix).
pub fn from_hex(spending: &str, viewing: &str) -> Result<RailgunKeys> {
    keys_from_bytes(
        parse32(spending).context("spending key")?,
        parse32(viewing).context("viewing key")?,
    )
}

// `ByteKey` is crate-private upstream, the public constructor goes through hex.
fn keys_from_bytes(spending: [u8; 32], viewing: [u8; 32]) -> Result<RailgunKeys> {
    Ok(RailgunKeys {
        spending: SpendingKey::from_hex(&hex::encode(spending))
            .map_err(|e| anyhow!("spending key: {e}"))?,
        viewing: ViewingKey::from_hex(&hex::encode(viewing))
            .map_err(|e| anyhow!("viewing key: {e}"))?,
    })
}

fn parse32(s: &str) -> Result<[u8; 32]> {
    let s = s.trim().trim_start_matches("0x");
    let bytes = hex::decode(s)?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("expected 32 bytes of hex"))
}

fn hmac512(key: &[u8], data: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut mac = HmacSha512::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut l = [0u8; 32];
    let mut r = [0u8; 32];
    l.copy_from_slice(&out[..32]);
    r.copy_from_slice(&out[32..]);
    (l, r)
}

fn railgun_derive(seed: &[u8], path: &str) -> Result<[u8; 32]> {
    let (mut key, mut chain_code) = hmac512(RAILGUN_CURVE_SEED, seed);
    for segment in parse_hardened_path(path)? {
        let mut data = Vec::with_capacity(37);
        data.push(0u8);
        data.extend_from_slice(&key);
        data.extend_from_slice(&(segment | HARDENED).to_be_bytes());
        (key, chain_code) = hmac512(&chain_code, &data);
    }
    Ok(key)
}

fn parse_hardened_path(path: &str) -> Result<Vec<u32>> {
    let mut segments = path.split('/');
    if segments.next() != Some("m") {
        return Err(anyhow!("derivation path must start with m/"));
    }
    segments
        .map(|s| {
            let s = s
                .strip_suffix('\'')
                .ok_or_else(|| anyhow!("railgun derivation only supports hardened segments"))?;
            let n = u32::from_str(s)?;
            if n >= HARDENED {
                return Err(anyhow!("path segment out of range"));
            }
            Ok(n)
        })
        .collect()
}

fn bip32_derive(seed: &[u8], path: &str) -> Result<[u8; 32]> {
    let path = bip32::DerivationPath::from_str(path).map_err(|e| anyhow!("bad path: {e}"))?;
    let xprv = bip32::XPrv::derive_from_path(seed, &path).map_err(|e| anyhow!("bip32: {e}"))?;
    Ok(xprv.private_key().to_bytes().into())
}

#[cfg(test)]
mod tests {
    use railgun::account::{chain::ChainId, signer::{PrivateKeySigner, RailgunSigner}};

    use super::*;

    const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";

    /// Vector from the Railgun engine test-suite (chain-agnostic address of the hardhat mnemonic,
    /// index 0).
    #[test]
    fn railgun_scheme_matches_engine_vector() {
        let keys = derive(TEST_MNEMONIC, 0, Derivation::Railgun).unwrap();
        let signer = PrivateKeySigner::new(keys.spending, keys.viewing, ChainId::All);
        assert_eq!(
            signer.address().to_string(),
            "0zk1qyk9nn28x0u3rwn5pknglda68wrn7gw6anjw8gg94mcj6eq5u48tlrv7j6fe3z53lama02nutwtcqc979wnce0qwly4y7w4rls5cq040g7z8eagshxrw5ajy990"
        );
    }

    #[test]
    fn schemes_differ() {
        let a = derive(TEST_MNEMONIC, 0, Derivation::Railgun).unwrap();
        let b = derive(TEST_MNEMONIC, 0, Derivation::Kohaku).unwrap();
        assert_ne!(a.spending.to_hex(), b.spending.to_hex());
    }
}
