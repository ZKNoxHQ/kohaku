//! Transport whose Waku node runs somewhere else, typically js-waku in the wallet's browser tab.
//!
//! The remote node calls [`BrowserBridge::exchange`] about once a second: it hands over what it
//! received and takes what has to be published. There is no mature Waku light client in Rust,
//! while js-waku is what every Railgun web wallet uses against the fleet's wss peers.
//!
//! The link is only alive while the remote node keeps calling. When it stops (tab closed), the
//! transport reports itself unreachable instead of queueing forever: a transact request is only
//! worth sending within the validity of its fee quote.

use std::{
    collections::VecDeque,
    sync::Mutex,
    time::{Duration, Instant},
};

use async_trait::async_trait;

use super::{TransportError, WakuMessage, WakuTransport};

/// Without an exchange for this long, the remote node is considered gone.
const LINK_TIMEOUT: Duration = Duration::from_secs(8);

/// A queued publish older than this is dropped rather than sent late.
const OUTBOUND_TTL: Duration = Duration::from_secs(30);

const MAX_INBOX: usize = 2_000;

#[derive(Debug, Clone)]
pub struct Outbound {
    pub content_topic: String,
    pub payload: Vec<u8>,
}

/// What the remote node says about itself at each exchange.
#[derive(Debug, Clone, Default)]
pub struct RemoteStatus {
    /// True once it is connected to peers and subscribed.
    pub connected: bool,
    pub peers: usize,
    /// Free text: "connecting", "light push refused…".
    pub detail: Option<String>,
}

#[derive(Default)]
struct State {
    inbox: Vec<WakuMessage>,
    outbox: VecDeque<(Instant, Outbound)>,
    last_exchange: Option<Instant>,
    remote: RemoteStatus,
}

#[derive(Default)]
pub struct BrowserBridge {
    state: Mutex<State>,
}

impl BrowserBridge {
    pub fn new() -> Self {
        Self::default()
    }

    /// One round trip with the remote node: stores `received`, returns what it must publish.
    pub fn exchange(&self, status: RemoteStatus, received: Vec<WakuMessage>) -> Vec<Outbound> {
        let mut state = self.state.lock().unwrap();
        state.last_exchange = Some(Instant::now());
        state.remote = status;
        state.inbox.extend(received);
        let overflow = state.inbox.len().saturating_sub(MAX_INBOX);
        if overflow > 0 {
            state.inbox.drain(..overflow);
        }
        let now = Instant::now();
        state
            .outbox
            .drain(..)
            .filter(|(queued, _)| now.duration_since(*queued) <= OUTBOUND_TTL)
            .map(|(_, message)| message)
            .collect()
    }

    fn link(&self) -> Result<(), TransportError> {
        let state = self.state.lock().unwrap();
        let alive = state
            .last_exchange
            .is_some_and(|t| t.elapsed() <= LINK_TIMEOUT);
        if !alive {
            return Err(TransportError::Remote(
                "no wallet tab is running the Waku node (open the wallet page and keep it open)"
                    .into(),
            ));
        }
        if !state.remote.connected {
            return Err(TransportError::Remote(format!(
                "the Waku node in the wallet tab is not connected yet ({})",
                state.remote.detail.as_deref().unwrap_or("starting")
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl WakuTransport for BrowserBridge {
    async fn subscribe(&self) -> Result<(), TransportError> {
        // The remote node subscribes on its own; this only reports whether it is there.
        self.link()
    }

    async fn poll(&self) -> Result<Vec<WakuMessage>, TransportError> {
        self.link()?;
        Ok(std::mem::take(&mut self.state.lock().unwrap().inbox))
    }

    async fn publish(&self, content_topic: &str, payload: &[u8]) -> Result<(), TransportError> {
        self.link()?;
        self.state.lock().unwrap().outbox.push_back((
            Instant::now(),
            Outbound {
                content_topic: content_topic.to_string(),
                payload: payload.to_vec(),
            },
        ));
        Ok(())
    }

    async fn peer_count(&self) -> Option<usize> {
        Some(self.state.lock().unwrap().remote.peers)
    }
}
