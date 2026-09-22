//! Credentials accepted by the viewer.
//!
//! * a BIP-39 mnemonic: both keys are derived (`railgun-wallet::keys`, same schemes as the wallet);
//! * a viewing private key plus the 0zk address: view-only, the address carries the master key;
//! * the Railgun engine "shareable viewing key" (`hex(msgpack({vpriv, spub}))`): view-only, the
//!   spending public key is unpacked from it.

use anyhow::{Context, Result, anyhow, bail};
use ark_ff::{BigInteger, Field, PrimeField};
use railgun::{
    account::address::RailgunAddress,
    crypto::keys::{HexKey, MasterPublicKey, SpendingKey, SpendingPublicKey, ViewingKey},
};
use railgun_wallet::keys::{self as wallet_keys, Derivation};
use serde::Deserialize;

#[derive(Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Credentials {
    pub mnemonic: Option<String>,
    #[serde(default)]
    pub index: u32,
    #[serde(default)]
    pub derivation: Derivation,
    pub viewing_key: Option<String>,
    /// 0zk address, needed with a bare viewing key (master public key).
    pub address: Option<String>,
    /// Railgun engine shareable viewing key.
    pub shareable_key: Option<String>,
}

pub enum Resolved {
    Full {
        spending: SpendingKey,
        viewing: ViewingKey,
        scheme: &'static str,
    },
    /// Viewing key plus spending public key: master key computed by the SDK.
    ViewOnlySpub {
        viewing: ViewingKey,
        spending_pub: SpendingPublicKey,
    },
    /// Viewing key plus master public key taken from the 0zk address.
    ViewOnlyMaster {
        viewing: ViewingKey,
        master: MasterPublicKey,
    },
}

impl Resolved {
    pub fn mode(&self) -> &'static str {
        match self {
            Resolved::Full { .. } => "full",
            Resolved::ViewOnlySpub { .. } | Resolved::ViewOnlyMaster { .. } => "view-only",
        }
    }
}

fn non_empty(s: &Option<String>) -> Option<&str> {
    s.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

fn parse32(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s.trim().trim_start_matches("0x"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("expected 32 bytes of hex"))
}

pub fn resolve(c: &Credentials) -> Result<Resolved> {
    if let Some(m) = non_empty(&c.mnemonic) {
        let keys = wallet_keys::derive(m, c.index, c.derivation)?;
        return Ok(Resolved::Full {
            spending: keys.spending,
            viewing: keys.viewing,
            scheme: match c.derivation {
                Derivation::Railgun => "railgun",
                Derivation::Kohaku => "kohaku",
            },
        });
    }
    if let Some(k) = non_empty(&c.shareable_key) {
        let (viewing, spending_pub) = decode_shareable(k)?;
        return Ok(Resolved::ViewOnlySpub {
            viewing,
            spending_pub,
        });
    }
    if let Some(v) = non_empty(&c.viewing_key) {
        let viewing = ViewingKey::from_hex(&hex::encode(parse32(v).context("viewing key")?))
            .map_err(|e| anyhow!("viewing key: {e}"))?;
        let Some(addr) = non_empty(&c.address) else {
            bail!(
                "a bare viewing key needs the 0zk address as well (it carries the master public \
                 key; the viewing key alone cannot recompute note public keys)"
            );
        };
        let address: RailgunAddress = addr
            .parse()
            .map_err(|e| anyhow!("0zk address: {e}"))?;
        if address.viewing_pubkey() != viewing.public_key() {
            bail!("the viewing key does not match the viewing public key of that 0zk address");
        }
        return Ok(Resolved::ViewOnlyMaster {
            viewing,
            master: address.master_key(),
        });
    }
    bail!("provide a mnemonic, or a viewing key with the 0zk address, or a shareable viewing key")
}

#[derive(Deserialize)]
struct Shareable {
    vpriv: String,
    spub: String,
}

/// `hex(msgpack({vpriv, spub}))` as produced by `getWalletShareableViewingKey` in the Railgun
/// engine; `spub` is the BabyJubJub spending public key packed circomlib-style.
pub fn decode_shareable(hex_key: &str) -> Result<(ViewingKey, SpendingPublicKey)> {
    let bytes = hex::decode(hex_key.trim().trim_start_matches("0x")).context("shareable key hex")?;
    let s: Shareable = rmp_serde::from_slice(&bytes).context("shareable key is not msgpack {vpriv, spub}")?;
    let viewing = ViewingKey::from_hex(&hex::encode(parse32(&s.vpriv).context("vpriv")?))
        .map_err(|e| anyhow!("vpriv: {e}"))?;
    let packed = parse32(&s.spub).context("spub")?;
    let (x, y) = unpack_point(&packed)?;
    Ok((viewing, SpendingPublicKey::new(x, y)))
}

/// circomlib `unpackPoint`: y little-endian, sign of x in the top bit of the last byte,
/// x recovered from the twisted Edwards equation `a x^2 + y^2 = 1 + d x^2 y^2`.
pub fn unpack_point(packed: &[u8; 32]) -> Result<([u8; 32], [u8; 32])> {
    use ark_bn254::Fr;
    let mut buf = *packed;
    let sign = buf[31] & 0x80 != 0;
    buf[31] &= 0x7f;
    let y = Fr::from_le_bytes_mod_order(&buf);
    let a = Fr::from(168700u64);
    let d = Fr::from(168696u64);
    let y2 = y.square();
    let denom = a - d * y2;
    let x2 = (Fr::ONE - y2) * denom.inverse().ok_or_else(|| anyhow!("degenerate packed point"))?;
    let x = x2.sqrt().ok_or_else(|| anyhow!("packed point is not on BabyJubJub"))?;
    let half = Fr::MODULUS_MINUS_ONE_DIV_TWO;
    let small = if x.into_bigint() > half { -x } else { x };
    let x = if sign { -small } else { small };
    Ok((to_be32(x), to_be32(y)))
}

fn to_be32(f: ark_bn254::Fr) -> [u8; 32] {
    let bytes = f.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use railgun::crypto::keys::HexKey;

    #[test]
    fn packed_point_roundtrip() {
        // Pack a known public key the circomlib way and check it unpacks to the same point.
        let sk = SpendingKey::from_hex(
            "039b3b11110e49d7340cbe7171791972e3c0d94ef31b18d6ab93d7ace62d278a",
        )
        .unwrap();
        let pk = sk.public_key();
        let mut x = [0u8; 32];
        x.copy_from_slice(&hex::decode(pk.x_hex()).unwrap());
        let mut y = [0u8; 32];
        y.copy_from_slice(&hex::decode(pk.y_hex()).unwrap());
        let mut packed = y;
        packed.reverse();
        let x_fr = ark_bn254::Fr::from_be_bytes_mod_order(&x);
        if x_fr.into_bigint() > ark_bn254::Fr::MODULUS_MINUS_ONE_DIV_TWO {
            packed[31] |= 0x80;
        }
        let (ux, uy) = unpack_point(&packed).unwrap();
        assert_eq!(ux, x);
        assert_eq!(uy, y);
    }
}
