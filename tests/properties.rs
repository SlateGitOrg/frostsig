//! Property tests over random thresholds `(t, n)`, random signer subsets and
//! random corruption patterns.

mod common;

use std::collections::BTreeMap;

use curve25519_dalek::Scalar;
use frostsig::compat::{dalek_verify, dalek_verify_strict};
use frostsig::dealer::reconstruct;
use frostsig::signing::{aggregate_with, ShareVerification};
use frostsig::wire::{Decode, Encode, Message};
use frostsig::{Ciphersuite, Ed25519Sha512, Error, Identifier, Ristretto255Sha512, SignatureShare};
use proptest::prelude::*;
use proptest::sample::subsequence;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

/// `(t, n, signer subset of size in [t, n], seed)` with `2 <= t <= n <= max_n`.
fn group(max_n: u16) -> impl Strategy<Value = (u16, u16, Vec<u16>, u64)> {
    (2..=max_n)
        .prop_flat_map(|n| (2..=n, Just(n)))
        .prop_flat_map(|(t, n)| (Just(t), Just(n), usize::from(t)..=usize::from(n)))
        .prop_flat_map(|(t, n, k)| {
            (Just(t), Just(n), subsequence((1..=n).collect::<Vec<u16>>(), k), any::<u64>())
        })
}

fn ids(v: &[u16]) -> Vec<Identifier> {
    v.iter().map(|i| Identifier::try_from(*i).unwrap()).collect()
}

fn dealer_round_trip<C: Ciphersuite>(t: u16, n: u16, signers: &[u16], seed: u64, msg: &[u8]) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let (keys, public) = common::dealer_keys::<C>(t, n, &mut rng);
    let sig = common::threshold_sign(&keys, &public, &ids(signers), msg, &mut rng);
    public.verifying_key().verify(msg, &sig).unwrap();
    let pk = public.verifying_key().serialize().unwrap();
    let bytes = sig.to_bytes().unwrap();
    if let Some(ok) = C::reference_verify(&pk, msg, &bytes) {
        assert!(ok, "reference verifier rejected a FROST signature");
        assert!(dalek_verify(&pk, msg, &bytes));
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

    #[test]
    fn dealer_signatures_verify_ed25519((t, n, signers, seed) in group(10), msg in proptest::collection::vec(any::<u8>(), 0..64)) {
        dealer_round_trip::<Ed25519Sha512>(t, n, &signers, seed, &msg);
    }

    #[test]
    fn dealer_signatures_verify_ristretto255((t, n, signers, seed) in group(10), msg in proptest::collection::vec(any::<u8>(), 0..64)) {
        dealer_round_trip::<Ristretto255Sha512>(t, n, &signers, seed, &msg);
    }

    #[test]
    fn any_t_shares_reconstruct_and_fewer_do_not((t, n, signers, seed) in group(10)) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let (keys, public) = common::dealer_keys::<Ed25519Sha512>(t, n, &mut rng);
        let shares: Vec<_> = ids(&signers).into_iter().map(|id| (id, keys[&id].signing_share().clone())).collect();
        let secret = reconstruct(t, &shares).unwrap();
        prop_assert_eq!(Ed25519Sha512::base_mul(&secret), public.verifying_key().element());
        // t - 1 points on a degree t - 1 polynomial reveal nothing: the
        // interpolated constant is (with overwhelming probability) wrong.
        let short = &shares[..usize::from(t) - 1];
        let too_few = matches!(reconstruct(t, short), Err(Error::NotEnoughShares { .. }));
        prop_assert!(too_few);
        let guess = reconstruct(t - 1, short).unwrap_or(Scalar::ZERO);
        prop_assert_ne!(Ed25519Sha512::base_mul(&guess), public.verifying_key().element());
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 24, ..ProptestConfig::default() })]

    #[test]
    fn dkg_keys_are_consistent_and_sign((t, n, signers, seed) in group(7)) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let (keys, public) = frostsig::dkg::run_in_process::<Ed25519Sha512, _>(t, n, &mut rng).unwrap();
        prop_assert_eq!(keys.len(), usize::from(n));
        for (id, k) in &keys {
            prop_assert_eq!(k.verifying_key(), public.verifying_key());
            prop_assert_eq!(public.verifying_share(id).unwrap(), k.verifying_share());
        }
        let shares: Vec<_> = ids(&signers).into_iter().map(|id| (id, keys[&id].signing_share().clone())).collect();
        let secret = reconstruct(t, &shares).unwrap();
        prop_assert_eq!(Ed25519Sha512::base_mul(&secret), public.verifying_key().element());
        let sig = common::threshold_sign(&keys, &public, &ids(&signers), b"dkg", &mut rng);
        let pk = public.verifying_key().serialize().unwrap();
        prop_assert!(dalek_verify_strict(&pk, b"dkg", &sig.to_bytes().unwrap()));
    }

    #[test]
    fn identifiable_abort_names_exactly_the_cheaters(
        (t, n, signers, seed) in group(8),
        mask in any::<u16>(),
        always in any::<bool>(),
    ) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let (keys, public) = common::dealer_keys::<Ristretto255Sha512>(t, n, &mut rng);
        let signer_ids = ids(&signers);
        let (package, mut shares) = common::sign_rounds(&keys, &signer_ids, b"abort", &mut rng);
        let mut cheaters: Vec<Identifier> =
            signer_ids.iter().enumerate().filter(|(k, _)| mask & (1 << k) != 0).map(|(_, id)| *id).collect();
        cheaters.sort();
        for id in &cheaters {
            let z = shares[id].to_scalar() + Scalar::from(u64::from(mask) + 1);
            shares.insert(*id, SignatureShare::new(z));
        }
        let mode = if always { ShareVerification::Always } else { ShareVerification::OnFailure };
        let result = aggregate_with(&package, &shares, &public, mode);
        if cheaters.is_empty() {
            prop_assert!(result.is_ok());
        } else {
            prop_assert_eq!(result, Err(Error::InvalidSignatureShares { culprits: cheaters }));
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn decoder_never_panics_on_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..400)) {
        let _ = Message::<Ed25519Sha512>::from_bytes(&bytes);
        let _ = Message::<Ristretto255Sha512>::from_bytes(&bytes);
        let _ = frostsig::KeyPackage::<Ed25519Sha512>::from_bytes(&bytes);
        let _ = frostsig::PublicKeyPackage::<Ristretto255Sha512>::from_bytes(&bytes);
    }

    #[test]
    fn decoder_never_panics_on_mutated_valid_messages(seed in any::<u64>(), flips in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..4)) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let (keys, _public) = common::dealer_keys::<Ed25519Sha512>(2, 3, &mut rng);
        let signer_ids: Vec<Identifier> = keys.keys().copied().take(2).collect();
        let (package, _) = common::sign_rounds(&keys, &signer_ids, b"mutate", &mut rng);
        let mut bytes = Message::<Ed25519Sha512>::SignRequest { session: 1, package }.to_bytes();
        for (idx, val) in flips {
            let i = idx.index(bytes.len());
            bytes[i] ^= val | 1;
        }
        if let Ok(m) = Message::<Ed25519Sha512>::from_bytes(&bytes) {
            // Whatever survives decoding re-encodes to the same bytes.
            prop_assert_eq!(m.to_bytes(), bytes);
        }
    }

    #[test]
    fn identifier_order_matches_integer_order(a in 1u16.., b in 1u16..) {
        let (ia, ib) = (Identifier::try_from(a).unwrap(), Identifier::try_from(b).unwrap());
        prop_assert_eq!(ia.cmp(&ib), a.cmp(&b));
        prop_assert_eq!(ia.to_u16(), Some(a));
    }
}

#[test]
fn signer_subsets_of_one_group_all_produce_valid_signatures() {
    // Every 3-subset of a 3-of-5 group signs under the same key.
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (keys, public) = common::dealer_keys::<Ed25519Sha512>(3, 5, &mut rng);
    let all: Vec<u16> = (1..=5).collect();
    let mut count = 0;
    let mut sigs = BTreeMap::new();
    for a in 0..5 {
        for b in a + 1..5 {
            for c in b + 1..5 {
                let s = ids(&[all[a], all[b], all[c]]);
                let sig = common::threshold_sign(&keys, &public, &s, b"subsets", &mut rng);
                public.verifying_key().verify(b"subsets", &sig).unwrap();
                sigs.insert((a, b, c), sig.to_bytes().unwrap());
                count += 1;
            }
        }
    }
    assert_eq!(count, 10);
    // Fresh nonces: no two signatures share an R.
    let rs: std::collections::BTreeSet<_> = sigs.values().map(|s| s[..32].to_vec()).collect();
    assert_eq!(rs.len(), 10);
}
