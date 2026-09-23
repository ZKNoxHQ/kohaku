//! Runtime seam: the node logic spawns, sleeps, times out and reads the clock only through this
//! module, so that a browser build (wasm32, no tokio timer, no `std::time::Instant`) can supply
//! its own implementation without touching the protocols. Native builds use tokio, as before.

use std::{future::Future, time::Duration};

use futures::future::{AbortHandle, Abortable};
/// `std::time` on native targets, `performance.now()` / `Date.now()` in a browser.
pub use web_time::{Instant, SystemTime, UNIX_EPOCH};

/// `Send` where tasks may move between threads (native), nothing in a browser, where futures
/// built on JS objects are not `Send` and everything runs on one thread.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSend: Send {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send> MaybeSend for T {}

/// A spawned task. Aborting drops its future at the next poll; the task is woken to notice.
pub struct Task(AbortHandle);

impl Task {
    pub fn abort(&self) {
        self.0.abort();
    }
}

/// Spawns on the ambient runtime. Abortion goes through `futures::Abortable`, which works the
/// same on every executor, instead of an executor-specific join handle.
pub fn spawn<F>(future: F) -> Task
where
    F: Future<Output = ()> + MaybeSend + 'static,
{
    let (handle, registration) = AbortHandle::new_pair();
    let task = Abortable::new(future, registration);
    #[cfg(not(target_arch = "wasm32"))]
    tokio::spawn(async move {
        let _ = task.await;
    });
    Task(handle)
}

pub async fn sleep(duration: Duration) {
    #[cfg(not(target_arch = "wasm32"))]
    tokio::time::sleep(duration).await;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elapsed;

pub async fn timeout<F: Future>(duration: Duration, future: F) -> Result<F::Output, Elapsed> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        tokio::time::timeout(duration, future).await.map_err(|_| Elapsed)
    }
}

/// Periodic tick; the first `tick` completes at once, as tokio's interval does.
pub struct Interval {
    #[cfg(not(target_arch = "wasm32"))]
    inner: tokio::time::Interval,
}

impl Interval {
    pub fn new(period: Duration) -> Self {
        Self {
            #[cfg(not(target_arch = "wasm32"))]
            inner: tokio::time::interval(period),
        }
    }

    pub async fn tick(&mut self) {
        #[cfg(not(target_arch = "wasm32"))]
        self.inner.tick().await;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    #[tokio::test]
    async fn abort_stops_a_task() {
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        let task = spawn(async move {
            let mut tick = Interval::new(Duration::from_millis(10));
            loop {
                tick.tick().await;
                h.fetch_add(1, Ordering::SeqCst);
            }
        });
        sleep(Duration::from_millis(55)).await;
        task.abort();
        sleep(Duration::from_millis(20)).await;
        let frozen = hits.load(Ordering::SeqCst);
        assert!(frozen >= 3, "ticked {frozen} times");
        sleep(Duration::from_millis(50)).await;
        assert_eq!(hits.load(Ordering::SeqCst), frozen, "no tick after abort");
    }

    #[tokio::test]
    async fn timeout_reports_elapsed() {
        assert_eq!(timeout(Duration::from_millis(10), sleep(Duration::from_secs(5))).await, Err(Elapsed));
        assert_eq!(timeout(Duration::from_secs(5), async { 7 }).await, Ok(7));
    }
}
