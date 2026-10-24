//! Criterion benchmarks of each FROST phase as the group grows.
//!
//! Run with `cargo bench` (or `make bench`). For a quick Markdown table use
//! `frostsig bench` instead.

use std::collections::BTreeMap;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use frostsig::bench::threshold_for;
use frostsig::dealer::trusted_dealer_keygen;
use frostsig::dkg::run_in_process;
use frostsig::signing::{aggregate_with, commit, sign, ShareVerification, SigningPackage};
use frostsig::{Ed25519Sha512, Identifier, KeyPackage};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

const SIZES: [u16; 4] = [4, 16, 64, 128];

fn keygen(c: &mut Criterion) {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let mut g = c.benchmark_group("keygen");
    g.sample_size(10);
    for n in SIZES {
        let t = threshold_for(n);
        g.bench_with_input(BenchmarkId::new("trusted_dealer", n), &n, |b, &n| {
            b.iter(|| trusted_dealer_keygen::<Ed25519Sha512, _>(t, n, &mut rng).unwrap())
        });
        if n <= 16 {
            g.bench_with_input(BenchmarkId::new("dkg_all_participants", n), &n, |b, &n| {
                b.iter(|| run_in_process::<Ed25519Sha512, _>(t, n, &mut rng).unwrap())
            });
        }
    }
    g.finish();
}

fn signing(c: &mut Criterion) {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let mut g = c.benchmark_group("signing");
    for n in SIZES {
        let t = threshold_for(n);
        let (shares, public) = trusted_dealer_keygen::<Ed25519Sha512, _>(t, n, &mut rng).unwrap();
        let keys: BTreeMap<Identifier, KeyPackage<Ed25519Sha512>> =
            shares.into_iter().map(|(id, s)| (id, s.verify().unwrap())).collect();
        let signers: Vec<Identifier> = keys.keys().copied().take(usize::from(t)).collect();
        let mut nonces = BTreeMap::new();
        let mut comms = BTreeMap::new();
        for id in &signers {
            let (nn, cc) = commit::<Ed25519Sha512, _>(keys[id].signing_share(), &mut rng);
            nonces.insert(*id, nn);
            comms.insert(*id, cc);
        }
        let package = SigningPackage::new(comms.clone(), b"bench".to_vec());
        let first = signers[0];
        g.bench_with_input(BenchmarkId::new("sign_one_share", n), &n, |b, _| {
            b.iter_batched(
                || {
                    let (nn, cc) = commit::<Ed25519Sha512, _>(keys[&first].signing_share(), &mut rng);
                    let mut cm = comms.clone();
                    cm.insert(first, cc);
                    (SigningPackage::new(cm, b"bench".to_vec()), nn)
                },
                |(pkg, nn)| sign(&pkg, nn, &keys[&first]).unwrap(),
                criterion::BatchSize::SmallInput,
            )
        });
        let shares: BTreeMap<_, _> =
            nonces.into_iter().map(|(id, nn)| (id, sign(&package, nn, &keys[&id]).unwrap())).collect();
        for (name, mode) in
            [("aggregate", ShareVerification::OnFailure), ("aggregate_verify_all", ShareVerification::Always)]
        {
            g.bench_with_input(BenchmarkId::new(name, n), &n, |b, _| {
                b.iter(|| aggregate_with(black_box(&package), &shares, &public, mode).unwrap())
            });
        }
    }
    g.finish();
}

criterion_group!(benches, keygen, signing);
criterion_main!(benches);
