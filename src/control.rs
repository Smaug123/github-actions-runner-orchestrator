// Loopback HTTP control endpoint: pause/resume claiming and report status.
//
// "Pause" stops the supervisor claiming *new* jobs (they wait in new/);
// in-flight VMs and the GC keep running. The primary use is a clean
// shutdown/migration: pause, wait for `in_flight` to reach 0, then stop the
// daemon — so no in-flight VM is orphaned.
//
// No auth: the endpoint must bind a loopback address (enforced in Config), so
// the host boundary is the trust boundary. Pausing is the only state it can
// change, and it can't exfiltrate anything sensitive.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};

#[derive(Clone)]
pub struct ControlState {
    /// Drives the supervisor's pause gate; `true` = stop claiming new jobs.
    pub pause: watch::Sender<bool>,
    /// Shared with the supervisor so `in_flight` reflects live permit usage.
    pub permits: Arc<Semaphore>,
    pub max_concurrency: usize,
}

#[derive(Serialize)]
struct Status {
    paused: bool,
    in_flight: usize,
    max_concurrency: usize,
}

impl ControlState {
    fn status(&self) -> Status {
        // A claimed/running job holds a permit; available_permits() is what's
        // free, so the difference is what's in flight.
        let in_flight = self
            .max_concurrency
            .saturating_sub(self.permits.available_permits());
        Status {
            paused: *self.pause.borrow(),
            in_flight,
            max_concurrency: self.max_concurrency,
        }
    }
}

async fn get_status(State(s): State<ControlState>) -> Json<Status> {
    Json(s.status())
}

async fn pause(State(s): State<ControlState>) -> Json<Status> {
    // send() only errors if every receiver is gone, i.e. the supervisor has
    // exited; nothing useful to do then, and status still reflects the flag.
    let _ = s.pause.send(true);
    Json(s.status())
}

async fn resume(State(s): State<ControlState>) -> Json<Status> {
    let _ = s.pause.send(false);
    Json(s.status())
}

fn router(state: ControlState) -> Router {
    Router::new()
        .route("/status", get(get_status))
        .route("/pause", post(pause))
        .route("/resume", post(resume))
        .with_state(state)
}

/// Bind the loopback control listener. Separate from `serve` so the caller can
/// fail startup when the port is unavailable, rather than discovering it inside
/// a detached task. The caller has already validated `addr` is loopback (Config).
pub async fn bind(addr: SocketAddr) -> Result<TcpListener> {
    TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind control server on {addr}"))
}

/// Serve the control endpoints on an already-bound listener until exit.
pub async fn serve(listener: TcpListener, state: ControlState) -> Result<()> {
    axum::serve(listener, router(state))
        .await
        .context("control server")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Return the receiver too; a watch::Sender::send errors if every receiver
    // is dropped, and in production the supervisor holds one for the daemon's
    // life. Keep it alive for the test the same way.
    fn state(max: usize) -> (ControlState, watch::Receiver<bool>) {
        let (pause, rx) = watch::channel(false);
        let state = ControlState {
            pause,
            permits: Arc::new(Semaphore::new(max)),
            max_concurrency: max,
        };
        (state, rx)
    }

    #[test]
    fn in_flight_tracks_held_permits() {
        let (s, _rx) = state(4);
        assert_eq!(s.status().in_flight, 0);
        let _p1 = s.permits.clone().try_acquire_owned().unwrap();
        let _p2 = s.permits.clone().try_acquire_owned().unwrap();
        assert_eq!(s.status().in_flight, 2);
    }

    #[test]
    fn pause_flag_reflects_in_status() {
        let (s, _rx) = state(2);
        assert!(!s.status().paused);
        s.pause.send(true).unwrap();
        assert!(s.status().paused);
        s.pause.send(false).unwrap();
        assert!(!s.status().paused);
    }

    // Exercise the real HTTP wiring (routes + JSON), not just the state logic.
    #[tokio::test]
    async fn http_pause_resume_roundtrip() {
        let (s, _rx) = state(2); // keep _rx alive so pause/resume sends succeed
        let listener = bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { serve(listener, s).await.unwrap() });

        let base = format!("http://{addr}");
        let http = reqwest::Client::new();
        let get = |p: String| {
            let http = http.clone();
            async move {
                http.get(p)
                    .send()
                    .await
                    .unwrap()
                    .json::<serde_json::Value>()
                    .await
                    .unwrap()
            }
        };
        let post = |p: String| {
            let http = http.clone();
            async move {
                http.post(p)
                    .send()
                    .await
                    .unwrap()
                    .json::<serde_json::Value>()
                    .await
                    .unwrap()
            }
        };

        let v = get(format!("{base}/status")).await;
        assert_eq!(v["paused"], serde_json::json!(false));
        assert_eq!(v["max_concurrency"], serde_json::json!(2));

        let v = post(format!("{base}/pause")).await;
        assert_eq!(v["paused"], serde_json::json!(true));

        let v = post(format!("{base}/resume")).await;
        assert_eq!(v["paused"], serde_json::json!(false));
    }
}
