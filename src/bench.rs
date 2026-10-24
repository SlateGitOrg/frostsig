//! A small, dependency-free timing harness behind `frostsig bench`: measures
//! every protocol phase for growing `n` and renders a Markdown table.
//!
//! Each figure is the median of `iterations` wall-clock samples on one core.
//! The Criterion benches in `benches/` cover the same operations with
//! statistical rigour; this harness exists so the README table can be
//! regenerated with one command.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use crate::ciphersuite::Ciphersuite;
use crate::dealer::trusted_dealer_keygen;
use crate::dkg::run_in_process;
use crate::error::Result;
use crate::identifier::Identifier;
use crate::keys::KeyPackage;
use crate::signing::{aggregate_with, commit, sign, ShareVerification, SigningPackage};

/// What to measure.
#[derive(Clone, Debug)]
pub struct BenchConfig {
    /// Group sizes `n` to measure.
    pub sizes: Vec<u16>,
    /// Samples per measurement (median reported).
    pub iterations: u32,
    /// Largest `n` for which the full DKG is timed (it is `O(n^2 t)` overall).
    pub dkg_max_n: u16,
}

/// The threshold used for group size `n`: `max(2, ceil(2n/3))`.
pub fn threshold_for(n: u16) -> u16 {
    let n32 = u32::from(n);
    u16::try_from((2 * n32).div_ceil(3)).unwrap_or(n).clamp(2, n.max(2))
}

/// Medians for one group size.
#[derive(Clone, Debug)]
pub struct BenchRow {
    /// Participants.
    pub n: u16,
    /// Threshold (= number of signers).
    pub t: u16,
    /// `trusted_dealer_keygen` for the whole group.
    pub dealer_keygen: Duration,
    /// DKG compute per participant (total in-process ceremony divided by `n`).
    pub dkg_per_participant: Option<Duration>,
    /// Round one for one signer.
    pub commit: Duration,
    /// Round two for one signer in a `t`-signer session.
    pub sign: Duration,
    /// Aggregate + verify (shares checked only on failure).
    pub aggregate: Duration,
    /// Aggregate after verifying every share.
    pub aggregate_verify_all: Duration,
    /// Verify the final signature.
    pub verify: Duration,
}

fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

fn time<T>(iterations: u32, mut f: impl FnMut() -> T) -> Duration {
    median(
        (0..iterations.max(1))
            .map(|_| {
                let start = Instant::now();
                std::hint::black_box(f());
                start.elapsed()
            })
            .collect(),
    )
}

/// Run the benchmark for suite `C`.
pub fn run<C: Ciphersuite>(config: &BenchConfig) -> Result<Vec<BenchRow>> {
    let mut rng = ChaCha20Rng::seed_from_u64(0x00f2_057a);
    let mut rows = Vec::new();
    for &n in &config.sizes {
        let t = threshold_for(n);
        log::info!("bench {}: n={n} t={t}", C::NAME);
        let dealer_keygen = time(config.iterations, || trusted_dealer_keygen::<C, _>(t, n, &mut rng));
        let dkg_per_participant = (n <= config.dkg_max_n).then(|| {
            let iters = config.iterations.min(5);
            time(iters, || run_in_process::<C, _>(t, n, &mut rng)) / u32::from(n)
        });

        let (shares, public) = trusted_dealer_keygen::<C, _>(t, n, &mut rng)?;
        let keys: BTreeMap<Identifier, KeyPackage<C>> =
            shares.into_iter().map(|(id, s)| Ok((id, s.verify()?))).collect::<Result<_>>()?;
        let signers: Vec<Identifier> = keys.keys().copied().take(usize::from(t)).collect();
        let first = signers[0];

        let commit_time = time(config.iterations, || commit::<C, _>(keys[&first].signing_share(), &mut rng));

        // Round two: fresh nonces per sample (sign consumes them), timed alone.
        let mut fixed = BTreeMap::new();
        let mut nonces = BTreeMap::new();
        for id in &signers {
            let (nn, c) = commit::<C, _>(keys[id].signing_share(), &mut rng);
            fixed.insert(*id, c);
            nonces.insert(*id, nn);
        }
        let mut sign_samples = Vec::new();
        for _ in 0..config.iterations.max(1) {
            let (nn, c) = commit::<C, _>(keys[&first].signing_share(), &mut rng);
            let mut comms = fixed.clone();
            comms.insert(first, c);
            let package = SigningPackage::new(comms, b"benchmark message".to_vec());
            let start = Instant::now();
            std::hint::black_box(sign(&package, nn, &keys[&first])?);
            sign_samples.push(start.elapsed());
        }

        let package = SigningPackage::new(fixed, b"benchmark message".to_vec());
        let sig_shares = nonces
            .into_iter()
            .map(|(id, nn)| Ok((id, sign(&package, nn, &keys[&id])?)))
            .collect::<Result<BTreeMap<_, _>>>()?;
        let aggregate = time(config.iterations, || {
            aggregate_with(&package, &sig_shares, &public, ShareVerification::OnFailure)
        });
        let aggregate_verify_all = time(config.iterations, || {
            aggregate_with(&package, &sig_shares, &public, ShareVerification::Always)
        });
        let signature = aggregate_with(&package, &sig_shares, &public, ShareVerification::OnFailure)?;
        let verify = time(config.iterations, || public.verifying_key().verify(package.message(), &signature));

        rows.push(BenchRow {
            n,
            t,
            dealer_keygen,
            dkg_per_participant,
            commit: commit_time,
            sign: median(sign_samples),
            aggregate,
            aggregate_verify_all,
            verify,
        });
    }
    Ok(rows)
}

fn fmt_duration(d: Duration) -> String {
    let us = d.as_secs_f64() * 1e6;
    if us >= 1000.0 {
        format!("{:.2} ms", us / 1000.0)
    } else {
        format!("{us:.0} µs")
    }
}

/// Render rows as a Markdown table.
pub fn render_markdown(suite: &str, iterations: u32, rows: &[BenchRow]) -> String {
    let mut out = format!(
        "{suite}: median of {iterations} samples (DKG: median of up to 5), single thread\n\n\
         | n | t | dealer keygen | DKG / participant | commit (1 signer) | sign (1 signer) | aggregate | aggregate + verify all shares | verify |\n\
         |---:|---:|---:|---:|---:|---:|---:|---:|---:|\n"
    );
    for r in rows {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            r.n,
            r.t,
            fmt_duration(r.dealer_keygen),
            r.dkg_per_participant.map_or_else(|| "-".to_string(), fmt_duration),
            fmt_duration(r.commit),
            fmt_duration(r.sign),
            fmt_duration(r.aggregate),
            fmt_duration(r.aggregate_verify_all),
            fmt_duration(r.verify),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ciphersuite::Ristretto255Sha512;

    #[test]
    fn thresholds() {
        assert_eq!(threshold_for(2), 2);
        assert_eq!(threshold_for(3), 2);
        assert_eq!(threshold_for(4), 3);
        assert_eq!(threshold_for(9), 6);
        assert_eq!(threshold_for(64), 43);
    }

    #[test]
    fn tiny_run_renders() {
        let cfg = BenchConfig { sizes: vec![3, 4], iterations: 2, dkg_max_n: 3 };
        let rows = run::<Ristretto255Sha512>(&cfg).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows[0].dkg_per_participant.is_some());
        assert!(rows[1].dkg_per_participant.is_none());
        let md = render_markdown("x", 2, &rows);
        assert_eq!(md.lines().filter(|l| l.starts_with("| ")).count(), 3);
        assert!(md.contains("| 4 | 3 |"));
        assert_eq!(fmt_duration(Duration::from_micros(1500)), "1.50 ms");
        assert_eq!(fmt_duration(Duration::from_micros(15)), "15 µs");
    }
}
