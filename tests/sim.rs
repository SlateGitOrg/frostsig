//! End-to-end simulations: every participant on its own thread, all traffic
//! encoded, validated and routed over local channels.

use std::collections::BTreeMap;
use std::time::Duration;

use frostsig::sim::{self, Fault, KeygenMode, KeygenOutcome, Preloaded, SimConfig};
use frostsig::{Ciphersuite, Ed25519Sha512, Ristretto255Sha512};

fn config(t: u16, n: u16, keygen: KeygenMode, seed: u64) -> SimConfig {
    let mut c = SimConfig::new(t, n);
    c.keygen = keygen;
    c.seed = Some(seed);
    c.timeout = Duration::from_millis(400);
    c.messages = vec![b"first".to_vec(), b"second".to_vec()];
    c
}

fn honest<C: Ciphersuite>(keygen: KeygenMode) {
    let out = sim::run::<C>(&config(3, 5, keygen, 1), None).unwrap();
    let r = &out.report;
    assert_eq!(r.keygen_outcome, KeygenOutcome::Ok);
    assert!(r.all_verified(), "{}", r.render());
    assert_eq!(r.sessions.len(), 2);
    for s in &r.sessions {
        assert_eq!(s.attempts.len(), 1);
        assert_eq!(s.attempts[0].signers, vec![1, 2, 3]);
    }
    assert_eq!(out.keys.len(), 5);
    let public = out.public.unwrap();
    assert_eq!(
        r.group_public_key.as_deref(),
        Some(hex::encode(public.verifying_key().serialize().unwrap()).as_str())
    );
    // Ed25519 runs are also checked by ed25519-dalek.
    let expect_reference = C::NAME.contains("Ed25519");
    assert!(r.sessions.iter().all(|s| s.reference_verified.is_some() == expect_reference));
}

#[test]
fn honest_runs_all_suites_and_keygens() {
    honest::<Ed25519Sha512>(KeygenMode::TrustedDealer);
    honest::<Ed25519Sha512>(KeygenMode::Dkg);
    honest::<Ristretto255Sha512>(KeygenMode::TrustedDealer);
    honest::<Ristretto255Sha512>(KeygenMode::Dkg);
}

#[test]
fn seeded_runs_are_reproducible() {
    let a = sim::run::<Ed25519Sha512>(&config(2, 4, KeygenMode::Dkg, 9), None).unwrap().report;
    let b = sim::run::<Ed25519Sha512>(&config(2, 4, KeygenMode::Dkg, 9), None).unwrap().report;
    assert_eq!(a, b);
    let c = sim::run::<Ed25519Sha512>(&config(2, 4, KeygenMode::Dkg, 10), None).unwrap().report;
    assert_ne!(a.group_public_key, c.group_public_key);
}

#[test]
fn bad_signature_share_is_identified_and_excluded() {
    let mut c = config(3, 5, KeygenMode::TrustedDealer, 2);
    c.faults.insert(2, Fault::BadSignatureShare);
    let r = sim::run::<Ed25519Sha512>(&c, None).unwrap().report;
    let first = &r.sessions[0];
    assert_eq!(first.attempts.len(), 2);
    assert_eq!(first.attempts[0].culprits, vec![2]);
    assert!(first.attempts[0].outcome.contains("identifiable abort"));
    assert_eq!(first.attempts[1].signers, vec![1, 3, 4]);
    // The exclusion persists into the next session.
    assert_eq!(r.sessions[1].attempts.len(), 1);
    assert_eq!(r.sessions[1].attempts[0].signers, vec![1, 3, 4]);
    assert!(r.all_verified());
}

#[test]
fn silent_signer_is_replaced() {
    let mut c = config(2, 3, KeygenMode::TrustedDealer, 3);
    c.messages.truncate(1);
    c.faults.insert(1, Fault::Silent);
    let r = sim::run::<Ristretto255Sha512>(&c, None).unwrap().report;
    let s = &r.sessions[0];
    assert_eq!(s.attempts[0].culprits, vec![1]);
    assert!(s.attempts[0].outcome.contains("no round 1 reply"));
    assert_eq!(s.attempts[1].signers, vec![2, 3]);
    assert_eq!(s.verified, Some(true));
}

#[test]
fn session_gives_up_when_too_few_honest_participants_remain() {
    let mut c = config(2, 3, KeygenMode::TrustedDealer, 4);
    c.messages.truncate(1);
    c.faults.insert(1, Fault::BadSignatureShare);
    c.faults.insert(2, Fault::BadSignatureShare);
    let r = sim::run::<Ed25519Sha512>(&c, None).unwrap().report;
    let s = &r.sessions[0];
    assert_eq!(s.signature, None);
    assert!(s.attempts.last().unwrap().outcome.contains("giving up"), "{}", r.render());
    assert!(!r.all_verified());
}

#[test]
fn bad_dkg_share_is_attributed_by_its_victim() {
    let mut c = config(2, 4, KeygenMode::Dkg, 5);
    c.faults.insert(3, Fault::BadDkgShare { victim: 1 });
    let out = sim::run::<Ed25519Sha512>(&c, None).unwrap();
    match &out.report.keygen_outcome {
        KeygenOutcome::Aborted { complaints, culprits } => {
            assert_eq!(culprits, &vec![3]);
            assert_eq!(complaints.keys().copied().collect::<Vec<_>>(), vec![1]);
        }
        other => panic!("unexpected {other:?}"),
    }
    assert!(out.report.sessions.is_empty());
    assert!(out.public.is_none());
}

#[test]
fn forged_dkg_proof_is_attributed_by_everyone() {
    let mut c = config(2, 4, KeygenMode::Dkg, 6);
    c.faults.insert(4, Fault::BadProof);
    let r = sim::run::<Ristretto255Sha512>(&c, None).unwrap().report;
    match &r.keygen_outcome {
        KeygenOutcome::Aborted { complaints, culprits } => {
            assert_eq!(culprits, &vec![4]);
            for honest in 1..=3 {
                assert_eq!(complaints[&honest].0, vec![4]);
            }
            assert!(complaints[&4].0.is_empty());
        }
        other => panic!("unexpected {other:?}"),
    }
    assert!(r.render().contains("identified culprits: [P4]"));
}

#[test]
fn equivocation_is_detected_as_inconsistent_views() {
    let mut c = config(2, 4, KeygenMode::Dkg, 7);
    c.faults.insert(1, Fault::Equivocate);
    let r = sim::run::<Ed25519Sha512>(&c, None).unwrap().report;
    match &r.keygen_outcome {
        KeygenOutcome::Inconsistent { views } => {
            assert_eq!(views.len(), 2);
            let holders: Vec<Vec<u16>> = views.values().cloned().collect();
            assert!(holders.contains(&vec![1, 3]) && holders.contains(&vec![2, 4]), "{holders:?}");
        }
        other => panic!("unexpected {other:?}"),
    }
    assert!(r.render().contains("INCONSISTENT"));
}

#[test]
fn preloaded_keys_sign_with_a_subset_of_participants() {
    let first = sim::run::<Ed25519Sha512>(&config(2, 4, KeygenMode::Dkg, 8), None).unwrap();
    let public = first.public.unwrap();
    // Only participants 2 and 4 are present.
    let keys: BTreeMap<u16, _> = first.keys.into_iter().filter(|(i, _)| *i == 2 || *i == 4).collect();
    let mut c = config(2, 4, KeygenMode::TrustedDealer, 9);
    c.messages = vec![b"from disk".to_vec()];
    let r = sim::run::<Ed25519Sha512>(&c, Some(Preloaded { keys, public: public.clone() })).unwrap().report;
    assert_eq!(r.keygen, "preloaded");
    assert_eq!(r.sessions[0].attempts[0].signers, vec![2, 4]);
    assert!(r.all_verified(), "{}", r.render());
    assert_eq!(r.group_public_key, Some(hex::encode(public.verifying_key().serialize().unwrap())));
}

#[test]
fn preloaded_threshold_mismatch_is_rejected() {
    let first = sim::run::<Ed25519Sha512>(&config(2, 3, KeygenMode::TrustedDealer, 10), None).unwrap();
    let pre = Preloaded { keys: first.keys, public: first.public.unwrap() };
    assert!(sim::run::<Ed25519Sha512>(&config(3, 3, KeygenMode::TrustedDealer, 1), Some(pre)).is_err());
}

#[test]
fn reports_serialize_to_json_and_count_traffic() {
    let r = sim::run::<Ed25519Sha512>(&config(2, 3, KeygenMode::Dkg, 11), None).unwrap().report;
    let json = serde_json::to_value(&r).unwrap();
    assert_eq!(json["keygen_outcome"]["status"], "ok");
    assert_eq!(json["keygen"], "dkg");
    let labels: Vec<&str> = r.traffic.iter().map(|t| t.label.as_str()).collect();
    for l in ["keygen/dkg-round1", "keygen/dkg-round2", "sign/round1-commitments", "sign/round2-share"] {
        assert!(labels.contains(&l), "missing {l}");
    }
    // n(n-1) round-one broadcasts for n = 3.
    let r1 = r.traffic.iter().find(|t| t.label == "keygen/dkg-round1").unwrap();
    assert_eq!(r1.count.messages, 6);
}

#[test]
fn invalid_configs_are_rejected() {
    let mut c = config(2, 3, KeygenMode::TrustedDealer, 1);
    c.signers = Some(vec![1, 9]);
    assert!(sim::run::<Ed25519Sha512>(&c, None).is_err());
    assert!(sim::run::<Ed25519Sha512>(&config(4, 3, KeygenMode::Dkg, 1), None).is_err());
}
