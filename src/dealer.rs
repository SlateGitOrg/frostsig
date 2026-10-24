//! Trusted-dealer key generation (RFC 9591 Appendix C) and Shamir
//! reconstruction (`secret_share_combine`).
//!
//! The dealer learns the group secret. Use [`crate::dkg`] when no single
//! party may know it.

use std::collections::BTreeMap;

use curve25519_dalek::Scalar;
use rand_core::{CryptoRng, RngCore};

use crate::ciphersuite::{random_nonzero_scalar, Ciphersuite};
use crate::error::{Error, Result};
use crate::identifier::Identifier;
use crate::keys::{PublicKeyPackage, SecretShare, SigningShare};
use crate::polynomial::{interpolate_constant, SecretPolynomial};

/// Output of trusted-dealer key generation: one [`SecretShare`] per
/// participant plus the public group info.
pub type DealerOutput<C> = (BTreeMap<Identifier, SecretShare<C>>, PublicKeyPackage<C>);

/// Check `2 <= min_signers <= max_signers`.
pub fn validate_threshold(min_signers: u16, max_signers: u16) -> Result<()> {
    if min_signers < 2 || min_signers > max_signers {
        return Err(Error::InvalidThreshold { min_signers, max_signers });
    }
    Ok(())
}

/// `trusted_dealer_keygen` with a freshly sampled group secret.
pub fn trusted_dealer_keygen<C: Ciphersuite, R: RngCore + CryptoRng>(
    min_signers: u16,
    max_signers: u16,
    rng: &mut R,
) -> Result<DealerOutput<C>> {
    validate_threshold(min_signers, max_signers)?;
    let secret = random_nonzero_scalar(rng);
    let polynomial = SecretPolynomial::random(secret, min_signers, rng);
    split(&polynomial, max_signers)
}

/// `secret_share_shard` for a caller-chosen polynomial: evaluates it at
/// `1..=max_signers`, commits to it, and derives the group info.
///
/// Exposed so the RFC test vectors (which fix the polynomial) can be checked.
/// `O(n * t)` field operations and `O(n * t)` point operations.
pub fn split<C: Ciphersuite>(
    polynomial: &SecretPolynomial,
    max_signers: u16,
) -> Result<DealerOutput<C>> {
    let min_signers = u16::try_from(polynomial.len()).map_err(|_| Error::InvalidThreshold {
        min_signers: u16::MAX,
        max_signers,
    })?;
    validate_threshold(min_signers, max_signers)?;
    let commitment = polynomial.commit::<C>();
    let shares = Identifier::range(max_signers)
        .map(|id| {
            let share = SecretShare {
                identifier: id,
                signing_share: SigningShare::new(polynomial.evaluate(&id)),
                commitment: commitment.clone(),
            };
            (id, share)
        })
        .collect();
    let public = commitment.derive_public_key_package(Identifier::range(max_signers))?;
    log::debug!(
        "dealer split a {}-of-{} secret for {}",
        min_signers,
        max_signers,
        C::NAME
    );
    Ok((shares, public))
}

/// `secret_share_combine`: recover the group secret from at least
/// `min_signers` shares. Only meaningful for tests, audits and recovery
/// drills; FROST signing never reconstructs the secret.
pub fn reconstruct(min_signers: u16, shares: &[(Identifier, SigningShare)]) -> Result<Scalar> {
    if shares.len() < usize::from(min_signers) {
        return Err(Error::NotEnoughShares { needed: min_signers, got: shares.len() });
    }
    let points: Vec<(Identifier, Scalar)> =
        shares.iter().map(|(id, s)| (*id, s.to_scalar())).collect();
    interpolate_constant(&points)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ciphersuite::{Ed25519Sha512, Ristretto255Sha512};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn rejects_bad_thresholds() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        for (t, n) in [(0, 3), (1, 3), (4, 3)] {
            assert_eq!(
                trusted_dealer_keygen::<Ed25519Sha512, _>(t, n, &mut rng).unwrap_err(),
                Error::InvalidThreshold { min_signers: t, max_signers: n }
            );
        }
    }

    #[test]
    fn every_share_verifies_and_any_t_reconstruct() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let (shares, public) = trusted_dealer_keygen::<Ristretto255Sha512, _>(3, 5, &mut rng).unwrap();
        assert_eq!(public.max_signers(), 5);
        assert_eq!(public.min_signers(), 3);
        let mut collected = Vec::new();
        for (id, share) in &shares {
            let kp = share.verify().unwrap();
            assert_eq!(kp.verifying_share(), public.verifying_share(id).unwrap());
            assert_eq!(kp.verifying_key(), public.verifying_key());
            collected.push((*id, share.signing_share.clone()));
        }
        let s1 = reconstruct(3, &collected[0..3]).unwrap();
        let s2 = reconstruct(3, &collected[2..5]).unwrap();
        assert_eq!(s1, s2);
        assert_eq!(Ristretto255Sha512::base_mul(&s1), public.verifying_key().element());
        assert_eq!(
            reconstruct(3, &collected[0..2]),
            Err(Error::NotEnoughShares { needed: 3, got: 2 })
        );
    }

    #[test]
    fn split_rejects_degenerate_polynomial() {
        let poly = SecretPolynomial::new(Scalar::ONE, vec![]);
        assert!(split::<Ed25519Sha512>(&poly, 3).is_err());
    }
}
