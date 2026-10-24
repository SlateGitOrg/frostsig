//! The coordinator role (plus the dealer, when one is used): drives key
//! setup and signing sessions, aggregates, verifies, and excludes
//! participants identified as misbehaving.

use std::collections::{BTreeMap, BTreeSet};
use std::thread;

use super::participant::{self, KeySource, ParticipantSpec};
use super::transport::{network, Endpoint, NodeId, RecvError};
use super::{
    AttemptReport, KeygenMode, KeygenOutcome, Preloaded, SessionReport, SimConfig, SimOutput, SimReport,
    TrafficRow,
};
use crate::ciphersuite::Ciphersuite;
use crate::dealer::trusted_dealer_keygen;
use crate::error::{Error, Result};
use crate::identifier::Identifier;
use crate::keys::PublicKeyPackage;
use crate::signing::{aggregate, SignatureShare, SigningCommitments, SigningPackage};
use crate::wire::Message;

/// Retry budget per session: each failed attempt excludes its culprits.
const MAX_ATTEMPTS: u32 = 3;

pub(super) fn run<C: Ciphersuite>(
    config: &SimConfig,
    preloaded: Option<Preloaded<C>>,
) -> Result<SimOutput<C>> {
    let participants: Vec<u16> = match &preloaded {
        Some(p) => p.keys.keys().copied().collect(),
        None => (1..=config.max_signers).collect(),
    };
    let mut nodes = vec![NodeId::Dealer, NodeId::Coordinator];
    nodes.extend(participants.iter().map(|i| NodeId::Participant(*i)));
    let (mut endpoints, stats) = network(&nodes);
    let coordinator =
        endpoints.remove(&NodeId::Coordinator).ok_or_else(|| Error::Config("no coordinator".into()))?;
    let dealer = endpoints.remove(&NodeId::Dealer).ok_or_else(|| Error::Config("no dealer".into()))?;
    let keygen_label = match (&preloaded, config.keygen) {
        (Some(_), _) => "preloaded",
        (None, KeygenMode::TrustedDealer) => "trusted-dealer",
        (None, KeygenMode::Dkg) => "dkg",
    };

    let mut preloaded_keys = preloaded.map(|p| (p.keys, p.public));
    let mut specs = Vec::new();
    for id in &participants {
        let source = match &mut preloaded_keys {
            Some((keys, public)) => match keys.remove(id) {
                Some(k) => KeySource::Preloaded(Box::new((k, public.clone()))),
                None => return Err(Error::Config(format!("no key for participant {id}"))),
            },
            None if config.keygen == KeygenMode::Dkg => KeySource::Dkg,
            None => KeySource::Dealer,
        };
        let ep = endpoints
            .remove(&NodeId::Participant(*id))
            .ok_or_else(|| Error::Config(format!("no endpoint for {id}")))?;
        specs.push((
            ep,
            ParticipantSpec::<C> {
                id: *id,
                min_signers: config.min_signers,
                max_signers: config.max_signers,
                source,
                fault: config.faults.get(id).copied(),
                rng: config.rng_for("participant", *id),
                timeout: config.timeout,
            },
        ));
    }

    let (setup, sessions, keys) = thread::scope(|scope| -> Result<_> {
        let handles: Vec<_> = specs
            .into_iter()
            .map(|(ep, spec)| {
                let id = spec.id;
                (id, scope.spawn(move || participant::run::<C>(ep, spec)))
            })
            .collect();

        let setup = (|| -> Result<(KeygenOutcome, Option<PublicKeyPackage<C>>)> {
            if keygen_label == "trusted-dealer" {
                deal::<C>(&dealer, config)?;
            }
            Ok(collect_key_setup::<C>(&coordinator, config, &participants))
        })();
        let sessions = match &setup {
            Ok((KeygenOutcome::Ok, Some(public))) => {
                let mut c = Coordinator { ep: &coordinator, config, public, excluded: BTreeSet::new() };
                config
                    .messages
                    .iter()
                    .enumerate()
                    .map(|(k, m)| c.session(u32::try_from(k).unwrap_or(u32::MAX), m, &participants))
                    .collect()
            }
            _ => Vec::new(),
        };
        for id in &participants {
            coordinator.send::<C>(NodeId::Participant(*id), &Message::Shutdown);
        }
        let mut keys = BTreeMap::new();
        for (id, h) in handles {
            match h.join() {
                Ok(Some(k)) => {
                    keys.insert(id, k);
                }
                Ok(None) => {}
                Err(_) => return Err(Error::Config(format!("participant {id} thread panicked"))),
            }
        }
        Ok((setup?, sessions, keys))
    })?;

    let (keygen_outcome, public) = setup;
    let group_public_key = match &public {
        Some(p) => Some(hex::encode(p.verifying_key().serialize()?)),
        None => None,
    };
    let traffic = stats
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .map(|(label, count)| TrafficRow { label: (*label).to_string(), count: *count })
        .collect();
    let report = SimReport {
        suite: C::NAME.to_string(),
        min_signers: config.min_signers,
        max_signers: config.max_signers,
        keygen: keygen_label.to_string(),
        faults: config.faults.clone(),
        group_public_key,
        keygen_outcome,
        sessions,
        traffic,
    };
    Ok(SimOutput { report, keys, public })
}

fn deal<C: Ciphersuite>(dealer: &Endpoint, config: &SimConfig) -> Result<()> {
    let mut rng = config.rng_for("dealer", 0);
    let (shares, _public) = trusted_dealer_keygen::<C, _>(config.min_signers, config.max_signers, &mut rng)?;
    for (id, share) in shares {
        let to = NodeId::Participant(id.to_u16().unwrap_or(0));
        dealer.send(to, &Message::DealerShare(share));
    }
    log::info!("dealer distributed {} shares", config.max_signers);
    Ok(())
}

fn collect_key_setup<C: Ciphersuite>(
    ep: &Endpoint,
    config: &SimConfig,
    participants: &[u16],
) -> (KeygenOutcome, Option<PublicKeyPackage<C>>) {
    let mut ready: BTreeMap<u16, PublicKeyPackage<C>> = BTreeMap::new();
    let mut complaints: BTreeMap<u16, (Vec<u16>, String)> = BTreeMap::new();
    let pending = |ready: &BTreeMap<u16, _>, complaints: &BTreeMap<u16, _>| {
        participants.iter().filter(|i| !ready.contains_key(*i) && !complaints.contains_key(*i)).count()
    };
    while pending(&ready, &complaints) > 0 {
        match ep.recv::<C>(config.timeout * 8) {
            Ok((NodeId::Participant(i), Message::KeysReady(p))) => {
                ready.insert(i, p);
            }
            Ok((NodeId::Participant(i), Message::Abort { culprits, reason })) => {
                let accused = culprits.iter().filter_map(Identifier::to_u16).collect();
                complaints.insert(i, (accused, reason));
            }
            Ok(_) | Err(RecvError::Malformed { .. }) => {}
            Err(RecvError::Timeout | RecvError::Disconnected) => {
                for i in participants {
                    if !ready.contains_key(i) && !complaints.contains_key(i) {
                        complaints.insert(*i, (vec![], "no key-setup report (timed out)".into()));
                    }
                }
            }
        }
    }
    if !complaints.is_empty() {
        let culprits: BTreeSet<u16> = complaints.values().flat_map(|(a, _)| a.iter().copied()).collect();
        log::warn!("key setup aborted; culprits {culprits:?}");
        return (KeygenOutcome::Aborted { complaints, culprits: culprits.into_iter().collect() }, None);
    }
    let mut views: BTreeMap<String, Vec<u16>> = BTreeMap::new();
    for (i, p) in &ready {
        let key = p.verifying_key().serialize().map(hex::encode).unwrap_or_else(|_| "<invalid>".into());
        views.entry(key).or_default().push(*i);
    }
    let mut packages = ready.into_values();
    match packages.next() {
        Some(p) if views.len() == 1 && packages.all(|v| v == p) => (KeygenOutcome::Ok, Some(p)),
        _ => {
            log::warn!("participants hold {} different group views", views.len());
            (KeygenOutcome::Inconsistent { views }, None)
        }
    }
}

struct Coordinator<'a, C: Ciphersuite> {
    ep: &'a Endpoint,
    config: &'a SimConfig,
    public: &'a PublicKeyPackage<C>,
    excluded: BTreeSet<u16>,
}

enum Gather<T> {
    All(BTreeMap<Identifier, T>),
    Missing { missing: Vec<u16>, refused: Vec<(u16, String)> },
}

impl<C: Ciphersuite> Coordinator<'_, C> {
    fn choose_signers(&self, participants: &[u16], attempt: u32) -> Vec<u16> {
        let t = usize::from(self.config.min_signers);
        let preferred: Vec<u16> = match &self.config.signers {
            Some(s) => s.clone(),
            None => participants.iter().copied().take(t).collect(),
        };
        let mut chosen: Vec<u16> = preferred.into_iter().filter(|i| !self.excluded.contains(i)).collect();
        if attempt > 0 || chosen.len() < t {
            // Top up with the lowest-numbered participants not yet excluded.
            for i in participants {
                if chosen.len() >= t {
                    break;
                }
                if !self.excluded.contains(i) && !chosen.contains(i) {
                    chosen.push(*i);
                }
            }
        }
        chosen.sort_unstable();
        chosen
    }

    fn gather<T>(
        &self,
        session: u32,
        signers: &[u16],
        mut pick: impl FnMut(Message<C>) -> Option<(u32, T)>,
    ) -> Gather<T> {
        let mut got: BTreeMap<u16, T> = BTreeMap::new();
        let mut refused = Vec::new();
        while got.len() + refused.len() < signers.len() {
            match self.ep.recv::<C>(self.config.timeout) {
                Ok((NodeId::Participant(i), msg)) if signers.contains(&i) => match msg {
                    Message::Abort { reason, .. } => refused.push((i, reason)),
                    other => {
                        if let Some((s, v)) = pick(other) {
                            if s == session && !got.contains_key(&i) {
                                got.insert(i, v);
                            }
                        }
                    }
                },
                Ok(_) => {}
                Err(RecvError::Malformed { from: NodeId::Participant(i), .. }) if signers.contains(&i) => {
                    refused.push((i, "sent a malformed message".into()));
                }
                Err(RecvError::Malformed { .. }) => {}
                Err(RecvError::Timeout | RecvError::Disconnected) => break,
            }
        }
        let missing: Vec<u16> = signers
            .iter()
            .copied()
            .filter(|i| !got.contains_key(i) && !refused.iter().any(|(r, _)| r == i))
            .collect();
        if missing.is_empty() && refused.is_empty() {
            Gather::All(
                got.into_iter().filter_map(|(i, v)| Identifier::try_from(i).ok().map(|id| (id, v))).collect(),
            )
        } else {
            Gather::Missing { missing, refused }
        }
    }

    fn session(&mut self, index: u32, message: &[u8], participants: &[u16]) -> SessionReport {
        let mut report = SessionReport {
            message: String::from_utf8_lossy(message).into_owned(),
            attempts: Vec::new(),
            signature: None,
            verified: None,
            reference_verified: None,
        };
        for attempt in 0..MAX_ATTEMPTS {
            let signers = self.choose_signers(participants, attempt);
            if signers.len() < usize::from(self.config.min_signers) {
                report.attempts.push(AttemptReport {
                    signers,
                    outcome: "not enough honest participants left; giving up".into(),
                    culprits: vec![],
                });
                break;
            }
            // Session ids are unique per attempt so stale replies are ignored.
            let session = index * MAX_ATTEMPTS + attempt;
            let (outcome, culprits, done) = self.attempt(session, &signers, message, &mut report);
            log::info!("session {index} attempt {attempt}: {outcome}");
            self.excluded.extend(culprits.iter().copied());
            report.attempts.push(AttemptReport { signers, outcome, culprits });
            if done {
                break;
            }
        }
        report
    }

    /// One attempt; returns `(outcome, culprits, finished)`.
    fn attempt(
        &self,
        session: u32,
        signers: &[u16],
        message: &[u8],
        report: &mut SessionReport,
    ) -> (String, Vec<u16>, bool) {
        for i in signers {
            self.ep.send::<C>(NodeId::Participant(*i), &Message::CommitRequest { session });
        }
        let commitments: BTreeMap<Identifier, SigningCommitments<C>> =
            match self.gather(session, signers, |m| match m {
                Message::Commitments { session, commitments } => Some((session, commitments)),
                _ => None,
            }) {
                Gather::All(c) => c,
                Gather::Missing { missing, refused } => return describe_missing("round 1", missing, refused),
            };

        let package = SigningPackage::new(commitments, message.to_vec());
        for i in signers {
            self.ep
                .send(NodeId::Participant(*i), &Message::SignRequest { session, package: package.clone() });
        }
        let shares: BTreeMap<Identifier, SignatureShare> = match self.gather(session, signers, |m| match m {
            Message::Share { session, share } => Some((session, share)),
            _ => None,
        }) {
            Gather::All(s) => s,
            Gather::Missing { missing, refused } => return describe_missing("round 2", missing, refused),
        };

        match aggregate(&package, &shares, self.public) {
            Ok(signature) => {
                let verified = self.public.verifying_key().verify(message, &signature).is_ok();
                let (sig_hex, reference) =
                    match (signature.to_bytes(), self.public.verifying_key().serialize()) {
                        (Ok(sig), Ok(pk)) => {
                            (Some(hex::encode(sig)), C::reference_verify(&pk, message, &sig))
                        }
                        _ => (None, None),
                    };
                report.signature = sig_hex;
                report.verified = Some(verified);
                report.reference_verified = reference;
                ("signature aggregated".into(), vec![], true)
            }
            Err(Error::InvalidSignatureShares { culprits }) => {
                let ids: Vec<u16> = culprits.iter().filter_map(Identifier::to_u16).collect();
                let names: Vec<String> = ids.iter().map(|i| format!("P{i}")).collect();
                (
                    format!("identifiable abort: invalid signature share from [{}]", names.join(", ")),
                    ids,
                    false,
                )
            }
            Err(e) => (format!("aggregation failed: {e}"), vec![], true),
        }
    }
}

fn describe_missing(round: &str, missing: Vec<u16>, refused: Vec<(u16, String)>) -> (String, Vec<u16>, bool) {
    let mut parts = Vec::new();
    if !missing.is_empty() {
        let m: Vec<String> = missing.iter().map(|i| format!("P{i}")).collect();
        parts.push(format!("no {round} reply from [{}]", m.join(", ")));
    }
    for (i, why) in &refused {
        parts.push(format!("P{i} refused: {why}"));
    }
    let mut culprits = missing;
    culprits.extend(refused.iter().map(|(i, _)| *i));
    culprits.sort_unstable();
    (parts.join("; "), culprits, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_and_refused_are_both_blamed() {
        let (msg, culprits, done) = describe_missing("round 1", vec![4], vec![(2, "no nonces".into())]);
        assert_eq!(msg, "no round 1 reply from [P4]; P2 refused: no nonces");
        assert_eq!(culprits, vec![2, 4]);
        assert!(!done);
    }
}
