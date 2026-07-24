//! In-memory topic-based event pub/sub hub for Hush streaming handlers.
//!
//! Mirrors [`hush-go/server/stream.go`](https://github.com/feralbureau/hush-go/blob/main/server/stream.go).

use std::collections::HashMap;
use std::sync::Mutex;
use tokio::sync::broadcast;

use crate::tlv;

// ── Event ──────────────────────────────────────────────────

/// An event delivered to subscribers.
#[derive(Debug, Clone)]
pub struct Event {
    pub topic: String,
    pub payload: tlv::Map,
    pub time: u64, // unix millis
}

// ── Hub ─────────────────────────────────────────────────────

/// Topic-based in-memory event bus.
///
/// Each topic has a broadcast channel. Subscribers get a receiver and
/// publishers send to the channel. Messages are delivered to all active
/// subscribers; slow consumers silently drop messages.
pub struct Hub {
    topics: Mutex<HashMap<String, broadcast::Sender<Event>>>,
}

impl Hub {
    /// Create a new empty hub.
    pub fn new() -> Self {
        Hub {
            topics: Mutex::new(HashMap::new()),
        }
    }

    /// Subscribe to a topic. Returns a broadcast receiver.
    pub fn subscribe(&self, topic: &str) -> broadcast::Receiver<Event> {
        let mut topics = self.topics.lock().unwrap();
        topics
            .entry(topic.to_string())
            .or_insert_with(|| {
                let (tx, _) = broadcast::channel(64);
                tx
            })
            .subscribe()
    }

    /// Unsubscribe is automatic when the receiver is dropped.
    /// This method exists for API compatibility.
    pub fn unsubscribe(&self, topic: &str) {
        let mut topics = self.topics.lock().unwrap();
        if let Some(tx) = topics.get(topic) {
            if tx.receiver_count() == 0 {
                topics.remove(topic);
            }
        }
    }

    /// Publish an event to all subscribers of a topic.
    pub fn publish(&self, topic: &str, payload: tlv::Map) -> usize {
        let evt = Event {
            topic: topic.to_string(),
            payload,
            time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        };

        let maybe_tx = {
            let topics = self.topics.lock().unwrap();
            topics.get(topic).cloned()
        };

        match maybe_tx {
            Some(tx) => {
                let count = tx.receiver_count();
                let _ = tx.send(evt);
                count
            }
            None => 0,
        }
    }

    /// List all active topics.
    pub fn topics(&self) -> Vec<String> {
        let topics = self.topics.lock().unwrap();
        topics.keys().cloned().collect()
    }

    /// Number of subscribers for a topic.
    pub fn subscriber_count(&self, topic: &str) -> usize {
        let topics = self.topics.lock().unwrap();
        topics
            .get(topic)
            .map(|tx| tx.receiver_count())
            .unwrap_or(0)
    }
}

impl Default for Hub {
    fn default() -> Self {
        Self::new()
    }
}
