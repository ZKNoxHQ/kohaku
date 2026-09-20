//! Waku access, reduced to what the broadcaster protocol needs: publish a payload on a content
//! topic and drain what arrived on a set of content topics.
//!
//! No mature Rust Waku node exists. The default implementation talks to a local nwaku node over
//! its REST API; an in-memory hub backs the tests. A libwaku or js-waku bridge would implement
//! the same trait.

use async_trait::async_trait;
use thiserror::Error;

pub mod bridge;
#[cfg(any(test, feature = "testing"))]
pub mod memory;
pub mod nwaku_rest;

#[derive(Debug, Clone)]
pub struct WakuMessage {
    pub content_topic: String,
    pub payload: Vec<u8>,
    /// Nanoseconds since the epoch when the node provides it.
    pub timestamp_ns: Option<u64>,
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("waku node unreachable at {url}: {source}")]
    Unreachable {
        url: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("waku node answered {status}: {body}")]
    Node { status: u16, body: String },
    /// The Waku node runs elsewhere (wallet tab) and is absent or not ready.
    #[error("{0}")]
    Remote(String),
    #[error("malformed waku message: {0}")]
    Malformed(String),
}

#[async_trait]
pub trait WakuTransport: Send + Sync {
    /// Makes sure the node relays the Railgun shard. Idempotent.
    async fn subscribe(&self) -> Result<(), TransportError>;

    /// Returns the messages received since the previous call, on any content topic. The caller
    /// filters: one drain serves the fee monitor and the response wait.
    async fn poll(&self) -> Result<Vec<WakuMessage>, TransportError>;

    async fn publish(&self, content_topic: &str, payload: &[u8]) -> Result<(), TransportError>;

    /// Number of connected peers, when the node can tell. Diagnostic only.
    async fn peer_count(&self) -> Option<usize> {
        None
    }
}
