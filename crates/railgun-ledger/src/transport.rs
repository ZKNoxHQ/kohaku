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

    /// Re-establish the channel after it went stale. A Ledger re-enumerates on USB whenever
    /// an app is opened or closed (and on lock), which invalidates any open handle; callers
    /// retry a failed exchange once after a successful reconnect.
    async fn reconnect(&self) -> Result<(), TransportError> {
        Err(TransportError(
            "transport does not support reconnection".into(),
        ))
    }
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
    ///
    /// The handle sits behind a mutex so [`Exchange::reconnect`] can replace it in place:
    /// a Ledger re-enumerates on USB whenever an app opens or closes, killing old handles.
    pub struct UsbLedger(tokio::sync::Mutex<Ledger>);

    impl UsbLedger {
        pub async fn init() -> Result<Self, TransportError> {
            let ledger = Ledger::init()
                .await
                .map_err(|e| TransportError(e.to_string()))?;
            Ok(Self(tokio::sync::Mutex::new(ledger)))
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
                .lock()
                .await
                .exchange(&command)
                .await
                .map_err(|e| TransportError(e.to_string()))?;
            Ok(ApduResponse {
                status: answer.retcode(),
                data: answer.data().unwrap_or_default().to_vec(),
            })
        }

        async fn reconnect(&self) -> Result<(), TransportError> {
            let fresh = Ledger::init()
                .await
                .map_err(|e| TransportError(e.to_string()))?;
            *self.0.lock().await = fresh;
            Ok(())
        }
    }
}

/// Bluetooth LE transport over `btleplug`, for Flex / Stax / Nano X.
///
/// Implements Ledger's APDU-over-BLE framing (the same protocol as the JS
/// `@ledgerhq/devices` BLE transport): a 5-byte MTU handshake, then APDUs
/// chunked into `0x05`-tagged frames across a GATT write characteristic, with
/// the response reassembled from notify-characteristic frames.
#[cfg(all(native, feature = "ble"))]
pub mod ble {
    use std::pin::Pin;
    use std::time::Duration;

    use btleplug::api::{
        Central, CharPropFlags, Characteristic, Manager as _, Peripheral as _, ScanFilter,
        ValueNotification, WriteType,
    };
    use btleplug::platform::{Adapter, Manager, Peripheral};
    use futures::{FutureExt, Stream, StreamExt};
    use tokio::sync::Mutex;
    use tokio::time::{sleep, timeout};
    use uuid::Uuid;

    use super::{Apdu, ApduResponse, Exchange, TransportError};

    const TAG_APDU: u8 = 0x05;
    const TAG_MTU: u8 = 0x08;
    const DEFAULT_MTU: usize = 23;

    /// Ledger BLE GATT service UUIDs. Flex/Stax/Nano X share the same framing;
    /// only the third group's high nibble differs per model.
    fn ledger_services() -> [Uuid; 3] {
        [
            Uuid::from_u128(0x13d63400_2c97_3004_0000_4c6564676572), // Flex
            Uuid::from_u128(0x13d63400_2c97_6004_0000_4c6564676572), // Stax
            Uuid::from_u128(0x13d63400_2c97_0004_0000_4c6564676572), // Nano X
        ]
    }

    fn err(e: impl std::fmt::Display) -> TransportError {
        TransportError(e.to_string())
    }

    type NotifyStream = Pin<Box<dyn Stream<Item = ValueNotification> + Send>>;

    /// A Bluetooth-connected Ledger. [`BleLedger::connect`] scans, connects and
    /// negotiates the MTU. One APDU exchange holds the notification stream for
    /// the duration of the request/response so frames are not interleaved.
    pub struct BleLedger {
        peripheral: Peripheral,
        write_char: Characteristic,
        write_type: WriteType,
        notify_uuid: Uuid,
        mtu: usize,
        notifications: Mutex<NotifyStream>,
    }

    impl BleLedger {
        /// Scan for a Ledger (Flex/Stax/Nano X), connect, and negotiate MTU.
        pub async fn connect() -> Result<Self, TransportError> {
            Self::connect_timeout(Duration::from_secs(20)).await
        }

        pub async fn connect_timeout(scan_timeout: Duration) -> Result<Self, TransportError> {
            let manager = Manager::new().await.map_err(err)?;
            let adapter = manager
                .adapters()
                .await
                .map_err(err)?
                .into_iter()
                .next()
                .ok_or_else(|| TransportError("no Bluetooth adapter found".into()))?;

            let services = ledger_services().to_vec();
            adapter
                .start_scan(ScanFilter { services: services.clone() })
                .await
                .map_err(err)?;

            let peripheral = timeout(scan_timeout, find_ledger(&adapter, &services))
                .await
                .map_err(|_| {
                    TransportError(
                        "no Ledger found over BLE (device unlocked, Bluetooth on, app open?)".into(),
                    )
                })??;
            let _ = adapter.stop_scan().await;

            peripheral.connect().await.map_err(err)?;
            peripheral.discover_services().await.map_err(err)?;

            let chars = peripheral.characteristics();
            let notify = chars
                .iter()
                .find(|c| {
                    services.contains(&c.service_uuid)
                        && c.properties.contains(CharPropFlags::NOTIFY)
                })
                .cloned()
                .ok_or_else(|| TransportError("Ledger BLE notify characteristic not found".into()))?;
            let write_char = chars
                .iter()
                .find(|c| {
                    services.contains(&c.service_uuid) && c.properties.contains(CharPropFlags::WRITE)
                })
                .cloned()
                .ok_or_else(|| TransportError("Ledger BLE write characteristic not found".into()))?;

            peripheral.subscribe(&notify).await.map_err(err)?;
            let notifications = peripheral.notifications().await.map_err(err)?;

            let mut me = Self {
                peripheral,
                write_char,
                write_type: WriteType::WithResponse,
                notify_uuid: notify.uuid,
                mtu: DEFAULT_MTU,
                notifications: Mutex::new(notifications),
            };
            me.negotiate_mtu().await?;
            Ok(me)
        }

        /// Ledger MTU handshake: write `[0x08,0,0,0,0]`, read the `0x08` reply
        /// whose byte 5 is the frame MTU. Skips any stray frame before it so
        /// the reply is never left in the buffer for the first APDU to trip on.
        async fn negotiate_mtu(&mut self) -> Result<(), TransportError> {
            let mut stream = self.notifications.lock().await;
            self.peripheral
                .write(&self.write_char, &[TAG_MTU, 0, 0, 0, 0], self.write_type)
                .await
                .map_err(err)?;
            for _ in 0..8 {
                let frame = next_frame(&mut stream, self.notify_uuid).await?;
                if frame.first() == Some(&TAG_MTU) {
                    if frame.len() >= 6 {
                        self.mtu = (frame[5] as usize).max(DEFAULT_MTU);
                    }
                    return Ok(());
                }
                // Not the MTU reply (a spurious/keepalive frame): keep looking.
            }
            // No 0x08 reply seen; keep the conservative default MTU.
            Ok(())
        }

        async fn write_apdu(&self, raw: &[u8]) -> Result<(), TransportError> {
            let mut seq: u16 = 0;
            let mut offset = 0;
            while offset < raw.len() {
                let header_len = if seq == 0 { 5 } else { 3 };
                let chunk_len = self.mtu.saturating_sub(header_len).min(raw.len() - offset);
                if chunk_len == 0 {
                    return Err(TransportError("BLE MTU too small to frame APDU".into()));
                }
                let mut frame = Vec::with_capacity(header_len + chunk_len);
                frame.push(TAG_APDU);
                frame.extend_from_slice(&seq.to_be_bytes());
                if seq == 0 {
                    frame.extend_from_slice(&(raw.len() as u16).to_be_bytes());
                }
                frame.extend_from_slice(&raw[offset..offset + chunk_len]);
                self.peripheral
                    .write(&self.write_char, &frame, self.write_type)
                    .await
                    .map_err(err)?;
                offset += chunk_len;
                seq += 1;
            }
            Ok(())
        }

        async fn read_apdu(&self, stream: &mut NotifyStream) -> Result<Vec<u8>, TransportError> {
            // First (header) frame: seq 0, tag 0x05, 2-byte total length. Tolerate
            // a bounded number of stray leading frames (e.g. a late 0x08 MTU reply
            // or a keepalive) before it rather than failing outright.
            let mut header = None;
            let mut skipped: Vec<String> = Vec::new();
            for _ in 0..8 {
                let frame = next_frame(stream, self.notify_uuid).await?;
                if frame.first() == Some(&TAG_APDU) {
                    header = Some(frame);
                    break;
                }
                skipped.push(hex::encode(&frame));
            }
            let header = header.ok_or_else(|| {
                TransportError(format!(
                    "no BLE APDU frame received; got only: [{}]",
                    skipped.join(", ")
                ))
            })?;
            if header.len() < 5 {
                return Err(TransportError(format!(
                    "short BLE header frame: {}",
                    hex::encode(&header)
                )));
            }
            if u16::from_be_bytes([header[1], header[2]]) != 0 {
                return Err(TransportError("first BLE frame is not sequence 0".into()));
            }
            let total = u16::from_be_bytes([header[3], header[4]]) as usize;
            let mut data: Vec<u8> = header[5..].to_vec();

            // Continuation frames: strict tag/sequence checking.
            let mut expected_seq: u16 = 1;
            while data.len() < total {
                let frame = next_frame(stream, self.notify_uuid).await?;
                if frame.first() != Some(&TAG_APDU) || frame.len() < 3 {
                    return Err(TransportError(format!(
                        "malformed BLE continuation frame: {}",
                        hex::encode(&frame)
                    )));
                }
                let seq = u16::from_be_bytes([frame[1], frame[2]]);
                if seq != expected_seq {
                    return Err(TransportError(format!(
                        "BLE frame out of sequence: expected {expected_seq}, got {seq}"
                    )));
                }
                data.extend_from_slice(&frame[3..]);
                expected_seq = expected_seq.wrapping_add(1);
            }
            data.truncate(total);
            Ok(data)
        }
    }

    /// Poll the adapter until a peripheral advertising a Ledger service appears.
    async fn find_ledger(adapter: &Adapter, services: &[Uuid]) -> Result<Peripheral, TransportError> {
        loop {
            for p in adapter.peripherals().await.map_err(err)? {
                if let Ok(Some(props)) = p.properties().await {
                    if props.services.iter().any(|s| services.contains(s)) {
                        return Ok(p);
                    }
                }
            }
            sleep(Duration::from_millis(300)).await;
        }
    }

    /// Next notification value on the notify characteristic, skipping others.
    async fn next_frame(
        stream: &mut NotifyStream,
        notify_uuid: Uuid,
    ) -> Result<Vec<u8>, TransportError> {
        loop {
            let n = stream
                .next()
                .await
                .ok_or_else(|| TransportError("BLE notification stream ended".into()))?;
            // Ignore notifications on other characteristics and spurious empty
            // frames some BLE stacks deliver on subscribe.
            if n.uuid == notify_uuid && !n.value.is_empty() {
                return Ok(n.value);
            }
        }
    }

    #[async_trait::async_trait]
    impl Exchange for BleLedger {
        async fn exchange(&self, apdu: &Apdu) -> Result<ApduResponse, TransportError> {
            // Raw APDU: CLA INS P1 P2 Lc data (1-byte Lc, as Ledger uses).
            let mut raw = Vec::with_capacity(5 + apdu.data.len());
            raw.extend_from_slice(&[apdu.cla, apdu.ins, apdu.p1, apdu.p2, apdu.data.len() as u8]);
            raw.extend_from_slice(&apdu.data);

            // Hold the notification stream for the whole request/response so a
            // concurrent exchange cannot steal our response frames.
            let mut stream = self.notifications.lock().await;

            // Drain frames buffered before this request: MTU keepalives the
            // device emits between exchanges, and duplicate response frames the
            // bluez stack can re-deliver on a re-paired link. Such an echo can
            // arrive a beat *after* the previous response, so settle briefly
            // first, then drain. This is safe: any frame present before we write
            // the current command is by definition stale — the real response
            // only arrives after the write below.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            while stream.next().now_or_never().flatten().is_some() {}

            self.write_apdu(&raw).await?;
            let resp = self.read_apdu(&mut stream).await?;
            if resp.len() < 2 {
                return Err(TransportError("BLE response shorter than status word".into()));
            }
            let split = resp.len() - 2;
            let status = u16::from_be_bytes([resp[split], resp[split + 1]]);
            Ok(ApduResponse { data: resp[..split].to_vec(), status })
        }
    }
}
