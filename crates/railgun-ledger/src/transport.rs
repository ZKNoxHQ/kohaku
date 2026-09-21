//! Transport abstraction: anything that can exchange APDUs with a Ledger device.

use common::MaybeSend;
use thiserror::Error;

/// A raw APDU command, transport-agnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Apdu {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: Vec<u8>,
}

/// A raw APDU response: payload plus the trailing status word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApduResponse {
    pub data: Vec<u8>,
    pub status: u16,
}

#[derive(Debug, Error)]
#[error("Ledger transport error: {0}")]
pub struct TransportError(pub String);

/// A duplex channel to a Ledger device.
///
/// The only integration point a transport has to provide. Implementations exist for USB HID
/// (feature `usb`); BLE or browser WebHID transports slot in here without touching the
/// protocol or signer layers.
#[cfg_attr(native, async_trait::async_trait)]
#[cfg_attr(wasm, async_trait::async_trait(?Send))]
pub trait Exchange: MaybeSend {
    async fn exchange(&self, apdu: &Apdu) -> Result<ApduResponse, TransportError>;
}

/// USB HID transport over `coins-ledger`.
#[cfg(all(native, feature = "usb"))]
pub mod usb {
    use coins_ledger::{
        common::{APDUCommand, APDUData},
        transports::{Ledger, LedgerAsync},
    };

    use super::{Apdu, ApduResponse, Exchange, TransportError};

    /// A USB-connected Ledger. [`UsbLedger::init`] picks the first device found.
    pub struct UsbLedger(Ledger);

    impl UsbLedger {
        pub async fn init() -> Result<Self, TransportError> {
            let ledger = Ledger::init()
                .await
                .map_err(|e| TransportError(e.to_string()))?;
            Ok(Self(ledger))
        }
    }

    #[async_trait::async_trait]
    impl Exchange for UsbLedger {
        async fn exchange(&self, apdu: &Apdu) -> Result<ApduResponse, TransportError> {
            let command = APDUCommand {
                cla: apdu.cla,
                ins: apdu.ins,
                p1: apdu.p1,
                p2: apdu.p2,
                data: APDUData::new(&apdu.data),
                response_len: None,
            };
            let answer = self
                .0
                .exchange(&command)
                .await
                .map_err(|e| TransportError(e.to_string()))?;
            Ok(ApduResponse {
                status: answer.retcode(),
                data: answer.data().unwrap_or_default().to_vec(),
            })
        }
    }
}
