//! End-to-end test of the signer over a mock device that implements the ZKNOX APDU
//! protocol in software. Proves the wire format round-trips: a `LedgerSigner` must be
//! indistinguishable from a `PrivateKeySigner` holding the same keys.

use async_trait::async_trait;
use ruint::aliases::U256;

use railgun::{
    account::{
        chain::ChainId,
        signer::{PrivateKeySigner, RailgunSigner},
    },
    crypto::keys::{HexKey, SpendingKey, ViewingKey},
};
use railgun_ledger::{
    Apdu, ApduResponse, Exchange, LedgerSigner, TransportError,
    protocol::{
        CLA, INS_EXPORT_VIEWING_KEY, INS_GET_SPENDING_PUBLIC_KEY, INS_GET_VERSION, INS_SIGN_HASH,
        spending_path, viewing_path,
    },
};

const SPENDING_HEX: &str = "039b3b11110e49d7340cbe7171791972e3c0d94ef31b18d6ab93d7ace62d278a";
const VIEWING_HEX: &str = "d345b2cc2f414aa93413b9572fa2b26e0e869e9274b006415a8d62ab1fa2dcb1";
const ACCOUNT_INDEX: u32 = 0;

/// A software model of the device app: checks the APDU framing byte-for-byte and answers
/// with the same key material a real device would hold.
struct MockDevice {
    spending: SpendingKey,
    viewing: ViewingKey,
    deny_signing: bool,
}

impl MockDevice {
    fn new() -> Self {
        Self {
            spending: SpendingKey::from_hex(SPENDING_HEX).unwrap(),
            viewing: ViewingKey::from_hex(VIEWING_HEX).unwrap(),
            deny_signing: false,
        }
    }

    fn expected_path(path: &[u32; 5]) -> Vec<u8> {
        let mut out = vec![5u8];
        for c in path {
            out.extend_from_slice(&c.to_be_bytes());
        }
        out
    }
}

#[async_trait]
impl Exchange for MockDevice {
    async fn exchange(&self, apdu: &Apdu) -> Result<ApduResponse, TransportError> {
        assert_eq!(apdu.cla, CLA);
        assert_eq!(apdu.p2, 0);

        let ok = |data: Vec<u8>| Ok(ApduResponse { data, status: 0x9000 });
        match apdu.ins {
            INS_GET_VERSION => {
                assert!(apdu.data.is_empty());
                ok(vec![0, 1, 0])
            }
            INS_GET_SPENDING_PUBLIC_KEY => {
                assert_eq!(apdu.data, Self::expected_path(&spending_path(ACCOUNT_INDEX)));
                let pubkey = self.spending.public_key();
                let mut data = pubkey.x_u256().to_be_bytes::<32>().to_vec();
                data.extend_from_slice(&pubkey.y_u256().to_be_bytes::<32>());
                ok(data)
            }
            INS_EXPORT_VIEWING_KEY => {
                assert_eq!(apdu.data, Self::expected_path(&viewing_path(ACCOUNT_INDEX)));
                ok(hex::decode(self.viewing.to_hex()).unwrap())
            }
            INS_SIGN_HASH => {
                if self.deny_signing {
                    return Ok(ApduResponse { data: Vec::new(), status: 0x6985 });
                }
                let expected_path = Self::expected_path(&spending_path(ACCOUNT_INDEX));
                assert_eq!(&apdu.data[..expected_path.len()], expected_path);
                let hash = U256::from_be_slice(&apdu.data[expected_path.len()..]);
                let signature = self.spending.sign(hash);
                let mut data = signature.r8_x.to_be_bytes::<32>().to_vec();
                data.extend_from_slice(&signature.r8_y.to_be_bytes::<32>());
                data.extend_from_slice(&signature.s.to_be_bytes::<32>());
                ok(data)
            }
            ins => panic!("unexpected instruction {ins:#04x}"),
        }
    }
}

fn software_signer() -> std::sync::Arc<PrivateKeySigner> {
    PrivateKeySigner::new(
        SpendingKey::from_hex(SPENDING_HEX).unwrap(),
        ViewingKey::from_hex(VIEWING_HEX).unwrap(),
        ChainId::All,
    )
}

#[tokio::test]
async fn ledger_signer_matches_software_signer() {
    let ledger = LedgerSigner::connect(MockDevice::new(), ChainId::All, ACCOUNT_INDEX)
        .await
        .unwrap();
    let software = software_signer();

    // Same address, hence same master and viewing public keys.
    assert_eq!(ledger.address(), software.address());

    // Deterministic EdDSA: the signature through the APDU layer is bit-identical.
    let message = U256::from(42u64);
    let from_device = ledger.sign(message).await.unwrap();
    let from_software = software.sign(message).await.unwrap();
    assert_eq!(from_device.r8_x, from_software.r8_x);
    assert_eq!(from_device.r8_y, from_software.r8_y);
    assert_eq!(from_device.s, from_software.s);
}

#[tokio::test]
async fn user_denial_is_an_error_not_a_panic() {
    let mut device = MockDevice::new();
    device.deny_signing = true;
    let ledger = LedgerSigner::connect(device, ChainId::All, ACCOUNT_INDEX)
        .await
        .unwrap();

    let err = ledger.sign(U256::from(1u64)).await.unwrap_err();
    assert!(err.to_string().contains("denied by user"), "got: {err}");
}
