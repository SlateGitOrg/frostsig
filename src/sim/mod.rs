//! A multi-party simulation: every participant runs on its own thread and
//! talks to the coordinator (and, during DKG, to its peers) only through
//! encoded messages over local channels.
//!
//! The simulation exists to exercise the protocol the way a deployment would:
//! messages are serialized and re-validated at every hop, signer sets are
//! chosen by a coordinator that holds no secrets, misbehaving participants
//! are identified from authenticated senders, and the coordinator retries a
//! signing session without them (RFC 9591 Section 5.4).
//!
//! Faults can be injected per participant to demonstrate identifiable
//! aborts; see [`Fault`].

mod coordinator;
mod participant;
pub mod transport;

use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::Duration;

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::Serialize;
use sha2::{Digest, Sha512};

use crate::ciphersuite::Ciphersuite;
use crate::dealer::validate_threshold;
use crate::error::{Error, Result};
use crate::keys::{KeyPackage, PublicKeyPackage};

pub use transport::{NodeId, TrafficCount};

/// How the group key is created.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeygenMode {
    /// A dealer samples the secret and distributes Feldman-verified shares.
    TrustedDealer,
    /// Participants run the Pedersen/Feldman DKG among themselves.
    Dkg,
}

impl FromStr for KeygenMode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "dealer" | "trusted-dealer" => Ok(KeygenMode::TrustedDealer),
            "dkg" => Ok(KeygenMode::Dkg),
            other => Err(Error::Config(format!("unknown keygen mode `{other}` (use dealer or dkg)"))),
        }
    }
}

/// Misbehaviour injected into one participant.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Fault {
    /// Adds one to every signature share it sends.
    BadSignatureShare,
    /// Sends an inconsistent DKG share to participant `victim`.
    BadDkgShare {
        /// The participant receiving the bad share.
        victim: u16,
    },
    /// Publishes an invalid DKG proof of knowledge.
    BadProof,
    /// Never answers commit requests.
    Silent,
    /// Equivocates in the DKG: sends one polynomial commitment (and matching
    /// shares) to odd-numbered peers and a different one to even-numbered
    /// peers. Every individual check passes; only comparing views exposes it.
    Equivocate,
}

impl FromStr for Fault {
    type Err = Error;

    /// Parses `bad-share`, `bad-proof`, `silent`, `equivocate`, or
    /// `bad-dkg-share:<victim>`.
    fn from_str(s: &str) -> Result<Self> {
        match s.split_once(':') {
            None => match s {
                "bad-share" => Ok(Fault::BadSignatureShare),
                "bad-proof" => Ok(Fault::BadProof),
                "silent" => Ok(Fault::Silent),
                "equivocate" => Ok(Fault::Equivocate),
                other => Err(Error::Config(format!("unknown fault `{other}`"))),
            },
            Some(("bad-dkg-share", v)) => v
                .parse()
                .map(|victim| Fault::BadDkgShare { victim })
                .map_err(|_| Error::Config(format!("bad victim id `{v}`"))),
            Some(_) => Err(Error::Config(format!("unknown fault `{s}`"))),
        }
    }
}

/// Everything the simulation needs to know.
#[derive(Clone, Debug)]
pub struct SimConfig {
    /// Threshold `t`.
    pub min_signers: u16,
    /// Participants `n`.
    pub max_signers: u16,
    /// Key generation mode (ignored when keys are preloaded).
    pub keygen: KeygenMode,
    /// Preferred signer set; defaults to `1..=t`.
    pub signers: Option<Vec<u16>>,
    /// One signing session per message.
    pub messages: Vec<Vec<u8>>,
    /// Injected faults by participant id.
    pub faults: BTreeMap<u16, Fault>,
    /// Seed for reproducible demo runs. `None` draws from the OS RNG.
    pub seed: Option<u64>,
    /// How long the coordinator waits for any single reply.
    pub timeout: Duration,
}

impl SimConfig {
    /// A `t`-of-`n` configuration with defaults: dealer keygen, no messages,
    /// no faults, OS randomness, 2 s timeout.
    pub fn new(min_signers: u16, max_signers: u16) -> Self {
        Self {
            min_signers,
            max_signers,
            keygen: KeygenMode::TrustedDealer,
            signers: None,
            messages: Vec::new(),
            faults: BTreeMap::new(),
            seed: None,
            timeout: Duration::from_secs(2),
        }
    }

    fn validate(&self) -> Result<()> {
        validate_threshold(self.min_signers, self.max_signers)?;
        let in_range = |i: &u16| (1..=self.max_signers).contains(i);
        if let Some(s) = &self.signers {
            if let Some(bad) = s.iter().find(|i| !in_range(i)) {
                return Err(Error::Config(format!("signer {bad} is not a participant")));
            }
            let mut sorted = s.clone();
            sorted.sort_unstable();
            sorted.dedup();
            if sorted.len() != s.len() {
                return Err(Error::Config("signer list contains duplicates".into()));
            }
            if s.len() < usize::from(self.min_signers) {
                return Err(Error::Config(format!(
                    "{} signers requested but the threshold is {}",
                    s.len(),
                    self.min_signers
                )));
            }
        }
        for (id, fault) in &self.faults {
            if !in_range(id) {
                return Err(Error::Config(format!("fault for unknown participant {id}")));
            }
            if let Fault::BadDkgShare { victim } = fault {
                if !in_range(victim) || victim == id {
                    return Err(Error::Config(format!("invalid DKG victim {victim}")));
                }
            }
        }
        Ok(())
    }

    /// A per-role RNG: seeded deterministically (domain-separated by role)
    /// when a seed is configured, otherwise from OS entropy.
    fn rng_for(&self, role: &str, index: u16) -> ChaCha20Rng {
        match self.seed {
            Some(seed) => {
                let digest = Sha512::new()
                    .chain_update(b"frostsig-sim-seed")
                    .chain_update(seed.to_be_bytes())
                    .chain_update(role.as_bytes())
                    .chain_update(index.to_be_bytes())
                    .finalize();
                let mut key = [0u8; 32];
                key.copy_from_slice(&digest[..32]);
                ChaCha20Rng::from_seed(key)
            }
            None => ChaCha20Rng::from_entropy(),
        }
    }
}

/// Key setup result as seen by the coordinator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum KeygenOutcome {
    /// Every participant reported the same group info.
    Ok,
    /// At least one participant aborted.
    Aborted {
        /// Complaints by accusing participant: `(accused ids, reason)`.
        complaints: BTreeMap<u16, (Vec<u16>, String)>,
        /// Union of all accused participants.
        culprits: Vec<u16>,
    },
    /// Participants finished with different views of the group info
    /// (e.g. after equivocation): group key hex -> participants holding it.
    Inconsistent {
        /// Distinct views.
        views: BTreeMap<String, Vec<u16>>,
    },
}

/// One attempt at a signing session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AttemptReport {
    /// Signer set used.
    pub signers: Vec<u16>,
    /// What happened.
    pub outcome: String,
    /// Participants blamed by this attempt (excluded from later attempts).
    pub culprits: Vec<u16>,
}

/// One message's signing session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SessionReport {
    /// The message (lossy UTF-8 for display).
    pub message: String,
    /// Attempts in order; the last one succeeded if `signature` is set.
    pub attempts: Vec<AttemptReport>,
    /// Hex signature, if produced.
    pub signature: Option<String>,
    /// This crate's verifier.
    pub verified: Option<bool>,
    /// `ed25519-dalek` strict verification (Ed25519 only).
    pub reference_verified: Option<bool>,
}

/// Traffic for one message label.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TrafficRow {
    /// Message label.
    pub label: String,
    /// Count and bytes.
    #[serde(flatten)]
    pub count: TrafficCount,
}

/// Everything a simulation run produced, ready to print or serialize.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SimReport {
    /// Ciphersuite name.
    pub suite: String,
    /// Threshold.
    pub min_signers: u16,
    /// Participants.
    pub max_signers: u16,
    /// `trusted-dealer`, `dkg` or `preloaded`.
    pub keygen: String,
    /// Faults that were injected.
    pub faults: BTreeMap<u16, Fault>,
    /// Hex group public key, if key setup succeeded.
    pub group_public_key: Option<String>,
    /// Key setup outcome.
    pub keygen_outcome: KeygenOutcome,
    /// Signing sessions.
    pub sessions: Vec<SessionReport>,
    /// Message traffic.
    pub traffic: Vec<TrafficRow>,
}

impl SimReport {
    /// True if key setup succeeded and every session produced a signature
    /// that verified.
    pub fn all_verified(&self) -> bool {
        self.keygen_outcome == KeygenOutcome::Ok
            && self.sessions.iter().all(|s| s.verified == Some(true) && s.reference_verified != Some(false))
    }

    /// Human-readable rendering for the CLI.
    pub fn render(&self) -> String {
        let mut out = String::new();
        let line = |out: &mut String, s: String| {
            out.push_str(&s);
            out.push('\n');
        };
        line(&mut out, format!("suite      : {}", self.suite));
        line(&mut out, format!("threshold  : {}-of-{}", self.min_signers, self.max_signers));
        line(&mut out, format!("keygen     : {}", self.keygen));
        if !self.faults.is_empty() {
            let f: Vec<String> = self.faults.iter().map(|(i, f)| format!("P{i}={f:?}")).collect();
            line(&mut out, format!("faults     : {}", f.join(", ")));
        }
        match &self.keygen_outcome {
            KeygenOutcome::Ok => {
                line(&mut out, format!("group key  : {}", self.group_public_key.as_deref().unwrap_or("-")));
            }
            KeygenOutcome::Aborted { complaints, culprits } => {
                line(&mut out, "keygen     : ABORTED".to_string());
                for (who, (accused, reason)) in complaints {
                    let accused: Vec<String> = accused.iter().map(|a| format!("P{a}")).collect();
                    line(&mut out, format!("  P{who} complains [{}]: {reason}", accused.join(", ")));
                }
                let c: Vec<String> = culprits.iter().map(|a| format!("P{a}")).collect();
                line(&mut out, format!("  identified culprits: [{}]", c.join(", ")));
            }
            KeygenOutcome::Inconsistent { views } => {
                line(
                    &mut out,
                    "keygen     : INCONSISTENT group views (broadcast was not consistent)".to_string(),
                );
                for (key, holders) in views {
                    let h: Vec<String> = holders.iter().map(|a| format!("P{a}")).collect();
                    line(&mut out, format!("  {key} held by [{}]", h.join(", ")));
                }
            }
        }
        for (k, s) in self.sessions.iter().enumerate() {
            line(&mut out, format!("session {k}  : message {:?}", s.message));
            for (a, att) in s.attempts.iter().enumerate() {
                let signers: Vec<String> = att.signers.iter().map(|i| format!("P{i}")).collect();
                line(&mut out, format!("  attempt {a}: signers [{}] -> {}", signers.join(", "), att.outcome));
            }
            if let Some(sig) = &s.signature {
                line(&mut out, format!("  signature: {sig}"));
                line(&mut out, format!("  verify (frostsig)          : {}", fmt_check(s.verified)));
                if s.reference_verified.is_some() {
                    line(
                        &mut out,
                        format!("  verify (ed25519-dalek strict): {}", fmt_check(s.reference_verified)),
                    );
                }
            }
        }
        line(&mut out, "traffic    :".to_string());
        for row in &self.traffic {
            line(
                &mut out,
                format!("  {:<26} {:>4} msgs {:>8} bytes", row.label, row.count.messages, row.count.bytes),
            );
        }
        out
    }
}

fn fmt_check(v: Option<bool>) -> &'static str {
    match v {
        Some(true) => "OK",
        Some(false) => "FAILED",
        None => "n/a",
    }
}

/// Keys handed to the simulation instead of running key generation.
#[derive(Clone, Debug)]
pub struct Preloaded<C: Ciphersuite> {
    /// Key packages by participant id (only these participants take part).
    pub keys: BTreeMap<u16, KeyPackage<C>>,
    /// The group info.
    pub public: PublicKeyPackage<C>,
}

/// What a run returns: the report plus the key material participants hold
/// at the end (used by the CLI's `keygen` command).
#[derive(Debug)]
pub struct SimOutput<C: Ciphersuite> {
    /// The report.
    pub report: SimReport,
    /// Key packages of participants whose key setup succeeded.
    pub keys: BTreeMap<u16, KeyPackage<C>>,
    /// Group info, if key setup succeeded.
    pub public: Option<PublicKeyPackage<C>>,
}

/// Run a full simulation: key setup, then one signing session per message.
pub fn run<C: Ciphersuite>(config: &SimConfig, preloaded: Option<Preloaded<C>>) -> Result<SimOutput<C>> {
    config.validate()?;
    if let Some(p) = &preloaded {
        if p.public.max_signers() != config.max_signers || p.public.min_signers() != config.min_signers {
            return Err(Error::Config("preloaded keys do not match the configured threshold".into()));
        }
    }
    coordinator::run(config, preloaded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_faults_and_modes() {
        assert_eq!("bad-share".parse::<Fault>().unwrap(), Fault::BadSignatureShare);
        assert_eq!("bad-proof".parse::<Fault>().unwrap(), Fault::BadProof);
        assert_eq!("silent".parse::<Fault>().unwrap(), Fault::Silent);
        assert_eq!("equivocate".parse::<Fault>().unwrap(), Fault::Equivocate);
        assert_eq!("bad-dkg-share:3".parse::<Fault>().unwrap(), Fault::BadDkgShare { victim: 3 });
        assert!("bad-dkg-share:x".parse::<Fault>().is_err());
        assert!("nope".parse::<Fault>().is_err());
        assert!("nope:1".parse::<Fault>().is_err());
        assert_eq!("dkg".parse::<KeygenMode>().unwrap(), KeygenMode::Dkg);
        assert_eq!("dealer".parse::<KeygenMode>().unwrap(), KeygenMode::TrustedDealer);
        assert!("x".parse::<KeygenMode>().is_err());
    }

    #[test]
    fn config_validation() {
        let mut c = SimConfig::new(2, 3);
        assert!(c.validate().is_ok());
        c.signers = Some(vec![1, 4]);
        assert!(c.validate().is_err());
        c.signers = Some(vec![1, 1]);
        assert!(c.validate().is_err());
        c.signers = Some(vec![1]);
        assert!(c.validate().is_err());
        c.signers = None;
        c.faults.insert(7, Fault::Silent);
        assert!(c.validate().is_err());
        c.faults = BTreeMap::from([(1, Fault::BadDkgShare { victim: 1 })]);
        assert!(c.validate().is_err());
        assert!(SimConfig::new(1, 3).validate().is_err());
    }

    #[test]
    fn seeded_rngs_are_reproducible_and_role_separated() {
        use rand_core::RngCore;
        let mut c = SimConfig::new(2, 3);
        c.seed = Some(5);
        assert_eq!(c.rng_for("p", 1).next_u64(), c.rng_for("p", 1).next_u64());
        assert_ne!(c.rng_for("p", 1).next_u64(), c.rng_for("p", 2).next_u64());
        assert_ne!(c.rng_for("p", 1).next_u64(), c.rng_for("dealer", 1).next_u64());
    }
}
