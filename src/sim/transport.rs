//! In-process "network": one `mpsc` inbox per node, with traffic accounting.
//!
//! The sender's identity is stamped by its own [`Endpoint`], never taken from
//! message contents, which models the *authenticated* channels FROST needs
//! for identifiable aborts. Every message crosses the channel as encoded
//! bytes and is decoded with full validation on receipt.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde::Serialize;

use crate::ciphersuite::Ciphersuite;
use crate::error::Error;
use crate::wire::{Decode, Encode, Message};

/// A node in the simulated deployment.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum NodeId {
    /// The trusted dealer (trusted-dealer key generation only).
    Dealer,
    /// The signing coordinator.
    Coordinator,
    /// Participant with the given identifier.
    Participant(u16),
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeId::Dealer => f.write_str("dealer"),
            NodeId::Coordinator => f.write_str("coordinator"),
            NodeId::Participant(i) => write!(f, "P{i}"),
        }
    }
}

/// Raw bytes in flight, stamped with the authenticated sender.
#[derive(Debug)]
struct Envelope {
    from: NodeId,
    bytes: Vec<u8>,
}

/// Message and byte counts for one message label.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct TrafficCount {
    /// Messages sent.
    pub messages: u64,
    /// Encoded bytes sent.
    pub bytes: u64,
}

/// Traffic per message label (e.g. `sign/round2-share`).
pub type TrafficStats = BTreeMap<&'static str, TrafficCount>;

/// Why a receive did not yield a message.
#[derive(Debug, PartialEq, Eq)]
pub enum RecvError {
    /// Nothing arrived before the deadline.
    Timeout,
    /// Every sender is gone.
    Disconnected,
    /// Bytes arrived but failed validation.
    Malformed {
        /// Authenticated sender.
        from: NodeId,
        /// Decoder error.
        error: Error,
    },
}

/// One node's view of the network.
#[derive(Debug)]
pub struct Endpoint {
    id: NodeId,
    inbox: Receiver<Envelope>,
    routes: Arc<BTreeMap<NodeId, Sender<Envelope>>>,
    stats: Arc<Mutex<TrafficStats>>,
}

impl Endpoint {
    /// This node's identity.
    pub fn id(&self) -> NodeId {
        self.id
    }

    /// Encode and send `msg` to `to`. Returns `false` if `to` is unknown or
    /// has already shut down.
    pub fn send<C: Ciphersuite>(&self, to: NodeId, msg: &Message<C>) -> bool {
        let bytes = msg.to_bytes();
        self.send_bytes(to, msg.label(), bytes)
    }

    /// Send pre-encoded bytes (used by tests to inject malformed traffic).
    pub fn send_bytes(&self, to: NodeId, label: &'static str, bytes: Vec<u8>) -> bool {
        {
            let mut stats = self.stats.lock().unwrap_or_else(PoisonError::into_inner);
            let entry = stats.entry(label).or_default();
            entry.messages += 1;
            entry.bytes += bytes.len() as u64;
        }
        match self.routes.get(&to) {
            Some(tx) => tx.send(Envelope { from: self.id, bytes }).is_ok(),
            None => false,
        }
    }

    /// Receive and decode the next message, waiting at most `timeout`.
    pub fn recv<C: Ciphersuite>(&self, timeout: Duration) -> Result<(NodeId, Message<C>), RecvError> {
        let env = self.inbox.recv_timeout(timeout).map_err(|e| match e {
            RecvTimeoutError::Timeout => RecvError::Timeout,
            RecvTimeoutError::Disconnected => RecvError::Disconnected,
        })?;
        Message::<C>::from_bytes(&env.bytes)
            .map(|m| (env.from, m))
            .map_err(|error| RecvError::Malformed { from: env.from, error })
    }
}

/// Build a fully connected network over `nodes`; returns one endpoint per
/// node and the shared traffic counters.
pub fn network(nodes: &[NodeId]) -> (BTreeMap<NodeId, Endpoint>, Arc<Mutex<TrafficStats>>) {
    let stats = Arc::new(Mutex::new(TrafficStats::new()));
    let mut senders = BTreeMap::new();
    let mut receivers = Vec::new();
    for id in nodes {
        let (tx, rx) = channel();
        senders.insert(*id, tx);
        receivers.push((*id, rx));
    }
    let routes = Arc::new(senders);
    let endpoints = receivers
        .into_iter()
        .map(|(id, inbox)| {
            (id, Endpoint { id, inbox, routes: Arc::clone(&routes), stats: Arc::clone(&stats) })
        })
        .collect();
    (endpoints, stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ciphersuite::Ed25519Sha512;

    #[test]
    fn delivers_with_authenticated_sender_and_counts_traffic() {
        let (mut eps, stats) = network(&[NodeId::Coordinator, NodeId::Participant(1)]);
        let p1 = eps.remove(&NodeId::Participant(1)).unwrap();
        let co = eps.remove(&NodeId::Coordinator).unwrap();
        assert!(co.send::<Ed25519Sha512>(NodeId::Participant(1), &Message::CommitRequest { session: 3 }));
        let (from, msg) = p1.recv::<Ed25519Sha512>(Duration::from_secs(1)).unwrap();
        assert_eq!(from, NodeId::Coordinator);
        assert_eq!(msg, Message::CommitRequest { session: 3 });
        let s = stats.lock().unwrap();
        assert_eq!(s["sign/commit-request"], TrafficCount { messages: 1, bytes: 9 });
    }

    #[test]
    fn reports_timeouts_malformed_bytes_and_unknown_routes() {
        let (mut eps, _) = network(&[NodeId::Coordinator, NodeId::Participant(1)]);
        let p1 = eps.remove(&NodeId::Participant(1)).unwrap();
        let co = eps.remove(&NodeId::Coordinator).unwrap();
        assert_eq!(p1.recv::<Ed25519Sha512>(Duration::from_millis(5)).unwrap_err(), RecvError::Timeout);
        co.send_bytes(NodeId::Participant(1), "junk", vec![1, 2, 3]);
        assert!(matches!(
            p1.recv::<Ed25519Sha512>(Duration::from_secs(1)),
            Err(RecvError::Malformed { from: NodeId::Coordinator, .. })
        ));
        assert!(!co.send::<Ed25519Sha512>(NodeId::Participant(9), &Message::Shutdown));
        assert_eq!(co.id(), NodeId::Coordinator);
        assert_eq!(NodeId::Participant(4).to_string(), "P4");
        assert_eq!(NodeId::Dealer.to_string(), "dealer");
    }
}
