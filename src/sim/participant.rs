//! The participant role: key setup (dealer share, DKG or preloaded keys)
//! followed by a signing service driven by the coordinator.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use curve25519_dalek::Scalar;
use rand_chacha::ChaCha20Rng;

use super::transport::{Endpoint, NodeId, RecvError};
use super::Fault;
use crate::ciphersuite::Ciphersuite;
use crate::dkg::{self, Round1Package, Round2Package};
use crate::error::Error;
use crate::identifier::Identifier;
use crate::keys::{KeyPackage, PublicKeyPackage, SigningShare};
use crate::signing::{self, SignatureShare, SigningNonces};
use crate::wire::Message;

/// How a participant obtains its key.
#[derive(Debug)]
pub(crate) enum KeySource<C: Ciphersuite> {
    /// Wait for a share from the dealer.
    Dealer,
    /// Run the DKG with every other participant.
    Dkg,
    /// Keys loaded from disk.
    Preloaded(Box<(KeyPackage<C>, PublicKeyPackage<C>)>),
}

/// Static configuration of one participant thread.
#[derive(Debug)]
pub(crate) struct ParticipantSpec<C: Ciphersuite> {
    pub id: u16,
    pub min_signers: u16,
    pub max_signers: u16,
    pub source: KeySource<C>,
    pub fault: Option<Fault>,
    pub rng: ChaCha20Rng,
    pub timeout: Duration,
}

/// Why key setup failed: who is blamed and why.
struct SetupFailure {
    culprits: Vec<Identifier>,
    reason: String,
    /// The coordinator already said stop; nothing more to report.
    stopped: bool,
}

impl From<Error> for SetupFailure {
    fn from(e: Error) -> Self {
        let culprits = match &e {
            Error::InvalidProofOfKnowledge { culprits } | Error::InvalidDkgShares { culprits } => {
                culprits.clone()
            }
            _ => Vec::new(),
        };
        SetupFailure { culprits, reason: e.to_string(), stopped: false }
    }
}

/// Run one participant to completion; returns its key package if key setup
/// succeeded.
pub(crate) fn run<C: Ciphersuite>(ep: Endpoint, mut spec: ParticipantSpec<C>) -> Option<KeyPackage<C>> {
    let me = NodeId::Participant(spec.id);
    let keys = match setup(&ep, &mut spec) {
        Ok(keys) => keys,
        Err(f) if f.stopped => return None,
        Err(f) => {
            log::warn!("{me}: key setup failed: {}", f.reason);
            ep.send::<C>(NodeId::Coordinator, &Message::Abort { culprits: f.culprits, reason: f.reason });
            wait_for_shutdown::<C>(&ep, spec.timeout);
            return None;
        }
    };
    ep.send::<C>(NodeId::Coordinator, &Message::KeysReady(keys.1.clone()));
    serve(&ep, &mut spec, &keys.0);
    Some(keys.0)
}

fn wait_for_shutdown<C: Ciphersuite>(ep: &Endpoint, timeout: Duration) {
    // Keep draining until the coordinator says stop, so peers' late
    // messages never block on a dead inbox.
    loop {
        match ep.recv::<C>(timeout * 10) {
            Ok((NodeId::Coordinator, Message::Shutdown))
            | Err(RecvError::Timeout | RecvError::Disconnected) => return,
            _ => {}
        }
    }
}

fn setup<C: Ciphersuite>(
    ep: &Endpoint,
    spec: &mut ParticipantSpec<C>,
) -> Result<(KeyPackage<C>, PublicKeyPackage<C>), SetupFailure> {
    match std::mem::replace(&mut spec.source, KeySource::Dealer) {
        KeySource::Preloaded(keys) => Ok(*keys),
        KeySource::Dealer => setup_from_dealer(ep, spec),
        KeySource::Dkg => setup_dkg(ep, spec),
    }
}

fn setup_from_dealer<C: Ciphersuite>(
    ep: &Endpoint,
    spec: &ParticipantSpec<C>,
) -> Result<(KeyPackage<C>, PublicKeyPackage<C>), SetupFailure> {
    loop {
        match ep.recv::<C>(spec.timeout * 10) {
            Ok((NodeId::Dealer, Message::DealerShare(share))) => {
                let key = share.verify()?;
                if key.identifier().to_u16() != Some(spec.id) {
                    return Err(SetupFailure {
                        culprits: vec![],
                        reason: "dealer sent a share for someone else".into(),
                        stopped: false,
                    });
                }
                let public =
                    share.commitment.derive_public_key_package(Identifier::range(spec.max_signers))?;
                return Ok((key, public));
            }
            Ok((_, Message::Shutdown)) => return Err(stopped()),
            Ok(_) => continue,
            Err(e) => return Err(recv_failure("dealer share", e)),
        }
    }
}

fn stopped() -> SetupFailure {
    SetupFailure { culprits: vec![], reason: "stopped by coordinator".into(), stopped: true }
}

fn recv_failure(what: &str, e: RecvError) -> SetupFailure {
    match e {
        RecvError::Malformed { from, error } => {
            let culprits = match from {
                NodeId::Participant(i) => Identifier::try_from(i).into_iter().collect(),
                _ => vec![],
            };
            SetupFailure {
                culprits,
                reason: format!("malformed {what} from {from}: {error}"),
                stopped: false,
            }
        }
        RecvError::Timeout => {
            SetupFailure { culprits: vec![], reason: format!("timed out waiting for {what}"), stopped: false }
        }
        RecvError::Disconnected => {
            SetupFailure { culprits: vec![], reason: "network closed".into(), stopped: false }
        }
    }
}

/// DKG traffic received so far. Peers run at different speeds, so round-two
/// shares and complaints can arrive while we still wait for round one.
struct DkgInbox<C: Ciphersuite> {
    round1: BTreeMap<Identifier, Round1Package<C>>,
    round2: BTreeMap<Identifier, Round2Package>,
    peer_complained: bool,
}

impl<C: Ciphersuite> DkgInbox<C> {
    /// Receive until `done(self)` holds. Complaints are remembered; they end
    /// the wait only when `stop_on_complaint` is set (round two), so every
    /// participant still judges round one for itself.
    fn fill(
        &mut self,
        ep: &Endpoint,
        spec: &ParticipantSpec<C>,
        what: &str,
        stop_on_complaint: bool,
        done: impl Fn(&Self) -> bool,
    ) -> Result<(), SetupFailure> {
        loop {
            if stop_on_complaint && self.peer_complained {
                return Err(SetupFailure {
                    culprits: vec![],
                    reason: "aborted after a peer complaint".into(),
                    stopped: false,
                });
            }
            if done(self) {
                return Ok(());
            }
            match ep.recv::<C>(spec.timeout * 4) {
                Ok((NodeId::Participant(i), msg)) if i != spec.id && i >= 1 && i <= spec.max_signers => {
                    let from = Identifier::try_from(i)?;
                    match msg {
                        Message::DkgRound1(p) => {
                            self.round1.entry(from).or_insert(p);
                        }
                        Message::DkgRound2(p) => {
                            self.round2.entry(from).or_insert(p);
                        }
                        Message::Abort { .. } => {
                            log::debug!("P{}: peer P{i} complained during the DKG", spec.id);
                            self.peer_complained = true;
                        }
                        _ => {}
                    }
                }
                Ok((NodeId::Coordinator, Message::Shutdown)) => return Err(stopped()),
                Ok(_) => {}
                Err(e) => return Err(recv_failure(what, e)),
            }
        }
    }
}

fn setup_dkg<C: Ciphersuite>(
    ep: &Endpoint,
    spec: &mut ParticipantSpec<C>,
) -> Result<(KeyPackage<C>, PublicKeyPackage<C>), SetupFailure> {
    let me = Identifier::try_from(spec.id)?;
    let peers: Vec<u16> = (1..=spec.max_signers).filter(|&i| i != spec.id).collect();
    let (secret1, mut package) = dkg::part1::<C, _>(me, spec.min_signers, spec.max_signers, &mut spec.rng)?;
    if spec.fault == Some(Fault::BadProof) {
        package.proof.mu += Scalar::ONE;
    }
    // An equivocating participant prepares a second, unrelated polynomial
    // for even-numbered peers.
    let mut twin = if spec.fault == Some(Fault::Equivocate) {
        Some(dkg::part1::<C, _>(me, spec.min_signers, spec.max_signers, &mut spec.rng)?)
    } else {
        None
    };
    for p in &peers {
        let pkg = match &twin {
            Some((_, alt)) if p % 2 == 0 => alt.clone(),
            _ => package.clone(),
        };
        ep.send(NodeId::Participant(*p), &Message::DkgRound1(pkg));
    }

    let mut inbox = DkgInbox { round1: BTreeMap::new(), round2: BTreeMap::new(), peer_complained: false };
    inbox.fill(ep, spec, "DKG round 1", false, |b| b.round1.len() == peers.len())?;

    let (secret2, outgoing) = match dkg::part2(secret1, &inbox.round1) {
        Ok(v) => v,
        Err(e) => {
            // Broadcast the complaint so peers stop waiting for our shares.
            for p in &peers {
                ep.send::<C>(
                    NodeId::Participant(*p),
                    &Message::Abort { culprits: vec![], reason: e.to_string() },
                );
            }
            return Err(e.into());
        }
    };
    let twin_shares = match twin.take() {
        Some((secret, _)) => Some(dkg::part2(secret, &inbox.round1)?.1),
        None => None,
    };
    for (to, mut pkg) in outgoing {
        if let Some(alt) = &twin_shares {
            if to.to_u16().is_some_and(|i| i % 2 == 0) {
                pkg = alt[&to].clone();
            }
        }
        if let Some(Fault::BadDkgShare { victim }) = spec.fault {
            if to.to_u16() == Some(victim) {
                pkg.share = SigningShare::new(pkg.share.to_scalar() + Scalar::ONE);
            }
        }
        ep.send::<C>(NodeId::Participant(to.to_u16().unwrap_or(0)), &Message::DkgRound2(pkg));
    }

    inbox.fill(ep, spec, "DKG round 2", true, |b| b.round2.len() == peers.len())?;
    Ok(dkg::part3(&secret2, &inbox.round1, &inbox.round2)?)
}

/// Answer commit and sign requests until shutdown.
fn serve<C: Ciphersuite>(ep: &Endpoint, spec: &mut ParticipantSpec<C>, key: &KeyPackage<C>) {
    let me = NodeId::Participant(spec.id);
    let mut pending: HashMap<u32, SigningNonces<C>> = HashMap::new();
    loop {
        let (from, msg) = match ep.recv::<C>(spec.timeout * 20) {
            Ok(v) => v,
            Err(RecvError::Malformed { from, error }) => {
                log::warn!("{me}: dropping malformed message from {from}: {error}");
                continue;
            }
            Err(_) => return,
        };
        if from != NodeId::Coordinator {
            continue;
        }
        match msg {
            Message::Shutdown => return,
            Message::CommitRequest { session } => {
                if spec.fault == Some(Fault::Silent) {
                    log::debug!("{me}: ignoring commit request (silent fault)");
                    continue;
                }
                let (nonces, commitments) = signing::commit::<C, _>(key.signing_share(), &mut spec.rng);
                pending.insert(session, nonces);
                ep.send(NodeId::Coordinator, &Message::Commitments { session, commitments });
            }
            Message::SignRequest { session, package } => {
                let reply: Message<C> = match pending.remove(&session) {
                    None => Message::Abort {
                        culprits: vec![],
                        reason: format!("no nonces for session {session}"),
                    },
                    Some(nonces) => match signing::sign(&package, nonces, key) {
                        Ok(share) => {
                            let share = if spec.fault == Some(Fault::BadSignatureShare) {
                                SignatureShare::new(share.to_scalar() + Scalar::ONE)
                            } else {
                                share
                            };
                            Message::Share { session, share }
                        }
                        Err(e) => Message::Abort { culprits: vec![], reason: e.to_string() },
                    },
                };
                ep.send(NodeId::Coordinator, &reply);
            }
            _ => {}
        }
    }
}
