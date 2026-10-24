//! Distributed key generation: Pedersen's DKG with Feldman VSS and Schnorr
//! proofs of knowledge, i.e. the KeyGen protocol of the FROST paper
//! (Komlo & Goldberg, 2020, Figure 1). No party ever learns the group secret.
//!
//! RFC 9591 deliberately leaves DKG unspecified; the proof-of-knowledge
//! challenge here uses `HDKG = H(contextString || "dkg" || m)`, see
//! `DECISIONS.md`.
//!
//! Flow for participant `i` among `n`, threshold `t`:
//!
//! 1. [`part1`]: sample `f_i` of degree `t-1`, broadcast its VSS commitment
//!    and a proof of knowledge of `f_i(0)` ([`Round1Package`]).
//! 2. [`part2`]: verify everyone's proof, then privately send `f_i(j)` to each
//!    `j` ([`Round2Package`]).
//! 3. [`part3`]: verify each received `f_j(i)` against `j`'s commitment
//!    (Feldman), sum them into the signing share `s_i = sum_j f_j(i)`, and
//!    derive the group key `PK = sum_j C_j0` and every verifying share.
//!
//! Every verification failure reports the culprits (identifiable abort),
//! which presumes authenticated channels and a consistent broadcast.

use std::collections::BTreeMap;

use curve25519_dalek::Scalar;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ciphersuite::{random_nonzero_scalar, Ciphersuite};
use crate::dealer::validate_threshold;
use crate::error::{Error, Result};
use crate::identifier::Identifier;
use crate::keys::{KeyPackage, PublicKeyPackage, SigningShare, VssCommitment};
use crate::polynomial::SecretPolynomial;

/// Schnorr proof of knowledge of the constant term `a_i0` behind `C_i0`,
/// bound to the prover's identifier to stop rogue-key and replay attacks.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ProofOfKnowledge<C: Ciphersuite> {
    /// Commitment `R_i = k * B`.
    pub r: C::Element,
    /// Response `mu_i = k + a_i0 * c_i`.
    pub mu: Scalar,
}

/// `c_i = HDKG(SerializeScalar(i) || SerializeElement(C_i0) || SerializeElement(R_i))`.
fn pok_challenge<C: Ciphersuite>(
    id: &Identifier,
    constant_commitment: &C::Element,
    r: &C::Element,
) -> Result<Scalar> {
    let phi0 = C::serialize_element(constant_commitment)?;
    let r = C::serialize_element(r)?;
    Ok(C::hdkg(&[&id.serialize(), &phi0, &r]))
}

impl<C: Ciphersuite> ProofOfKnowledge<C> {
    fn prove<R: RngCore + CryptoRng>(
        id: &Identifier,
        secret: &Scalar,
        constant_commitment: &C::Element,
        rng: &mut R,
    ) -> Result<Self> {
        let mut k = random_nonzero_scalar(rng);
        let r = C::base_mul(&k);
        let c = pok_challenge::<C>(id, constant_commitment, &r)?;
        let mu = k + secret * c;
        k.zeroize();
        Ok(Self { r, mu })
    }

    /// Check `mu * B == R + c * C_i0`.
    pub fn verify(&self, id: &Identifier, constant_commitment: &C::Element) -> bool {
        match pok_challenge::<C>(id, constant_commitment, &self.r) {
            Ok(c) => C::base_mul(&self.mu) == self.r + *constant_commitment * c,
            Err(_) => false,
        }
    }
}

/// Round-one broadcast: VSS commitment plus proof of knowledge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Round1Package<C: Ciphersuite> {
    /// Commitment to the sender's polynomial `f_i`.
    pub commitment: VssCommitment<C>,
    /// Proof of knowledge of `f_i(0)`.
    pub proof: ProofOfKnowledge<C>,
}

/// Round-two private message: `f_i(j)` for recipient `j`. Must travel over a
/// confidential, authenticated channel.
#[derive(Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Round2Package {
    /// The share `f_sender(recipient)`.
    pub share: SigningShare,
}

/// Secret state kept between [`part1`] and [`part2`].
#[derive(Debug)]
pub struct Round1Secret<C: Ciphersuite> {
    identifier: Identifier,
    polynomial: SecretPolynomial,
    commitment: VssCommitment<C>,
    min_signers: u16,
    max_signers: u16,
}

impl<C: Ciphersuite> Round1Secret<C> {
    /// This participant's identifier.
    pub fn identifier(&self) -> &Identifier {
        &self.identifier
    }
}

/// Secret state kept between [`part2`] and [`part3`].
#[derive(Debug)]
pub struct Round2Secret<C: Ciphersuite> {
    identifier: Identifier,
    own_share: SigningShare,
    commitment: VssCommitment<C>,
    min_signers: u16,
    max_signers: u16,
}

/// Round one for participant `identifier`.
pub fn part1<C: Ciphersuite, R: RngCore + CryptoRng>(
    identifier: Identifier,
    min_signers: u16,
    max_signers: u16,
    rng: &mut R,
) -> Result<(Round1Secret<C>, Round1Package<C>)> {
    validate_threshold(min_signers, max_signers)?;
    let secret = random_nonzero_scalar(rng);
    let polynomial = SecretPolynomial::random(secret, min_signers, rng);
    let commitment = polynomial.commit::<C>();
    let proof =
        ProofOfKnowledge::prove(&identifier, polynomial.secret(), &commitment.constant_term(), rng)?;
    log::debug!("dkg part1: participant {identifier} committed to a degree-{} polynomial", min_signers - 1);
    let package = Round1Package { commitment: commitment.clone(), proof };
    Ok((
        Round1Secret { identifier, polynomial, commitment, min_signers, max_signers },
        package,
    ))
}

fn check_peer_set<T>(
    me: &Identifier,
    max_signers: u16,
    packages: &BTreeMap<Identifier, T>,
) -> Result<()> {
    let expected = usize::from(max_signers) - 1;
    if packages.len() != expected {
        return Err(Error::IncorrectPackageCount { expected, got: packages.len() });
    }
    if packages.contains_key(me) {
        return Err(Error::DuplicateIdentifier(*me));
    }
    Ok(())
}

/// Round two: verify all peers' round-one packages and produce one private
/// share for each peer.
///
/// `round1_packages` holds the packages of the other `n - 1` participants.
/// Errors with [`Error::InvalidProofOfKnowledge`] listing every peer whose
/// proof fails, or [`Error::IncorrectCommitmentLength`] for a malformed one.
pub fn part2<C: Ciphersuite>(
    secret: Round1Secret<C>,
    round1_packages: &BTreeMap<Identifier, Round1Package<C>>,
) -> Result<(Round2Secret<C>, BTreeMap<Identifier, Round2Package>)> {
    check_peer_set(&secret.identifier, secret.max_signers, round1_packages)?;
    let mut culprits = Vec::new();
    for (id, package) in round1_packages {
        if package.commitment.threshold() != usize::from(secret.min_signers) {
            return Err(Error::IncorrectCommitmentLength {
                expected: usize::from(secret.min_signers),
                got: package.commitment.threshold(),
            });
        }
        if !package.proof.verify(id, &package.commitment.constant_term()) {
            culprits.push(*id);
        }
    }
    if !culprits.is_empty() {
        log::warn!("dkg part2: participant {} rejects proofs from {culprits:?}", secret.identifier);
        return Err(Error::InvalidProofOfKnowledge { culprits });
    }
    let outgoing = round1_packages
        .keys()
        .map(|peer| (*peer, Round2Package { share: SigningShare::new(secret.polynomial.evaluate(peer)) }))
        .collect();
    let own_share = SigningShare::new(secret.polynomial.evaluate(&secret.identifier));
    Ok((
        Round2Secret {
            identifier: secret.identifier,
            own_share,
            commitment: secret.commitment.clone(),
            min_signers: secret.min_signers,
            max_signers: secret.max_signers,
        },
        outgoing,
    ))
}

/// Round three (local): verify every received share against its sender's
/// commitment, then derive this participant's [`KeyPackage`] and the shared
/// [`PublicKeyPackage`].
///
/// Errors with [`Error::InvalidDkgShares`] listing every peer whose share
/// fails Feldman verification. `O(n * t)` point operations for the checks
/// plus `O(n * t)` for deriving all verifying shares.
pub fn part3<C: Ciphersuite>(
    secret: &Round2Secret<C>,
    round1_packages: &BTreeMap<Identifier, Round1Package<C>>,
    round2_packages: &BTreeMap<Identifier, Round2Package>,
) -> Result<(KeyPackage<C>, PublicKeyPackage<C>)> {
    let me = secret.identifier;
    check_peer_set(&me, secret.max_signers, round1_packages)?;
    check_peer_set(&me, secret.max_signers, round2_packages)?;
    if let Some(stranger) = round2_packages.keys().find(|id| !round1_packages.contains_key(id)) {
        return Err(Error::UnknownParticipant(*stranger));
    }

    let mut culprits = Vec::new();
    let mut total = secret.own_share.to_scalar();
    for (sender, package) in round2_packages {
        let commitment = &round1_packages[sender].commitment;
        if commitment.verify_share(&me, &package.share) {
            total += package.share.to_scalar();
        } else {
            culprits.push(*sender);
        }
    }
    if !culprits.is_empty() {
        total.zeroize();
        log::warn!("dkg part3: participant {me} rejects shares from {culprits:?}");
        return Err(Error::InvalidDkgShares { culprits });
    }

    let group_commitment = VssCommitment::sum(
        core::iter::once(&secret.commitment).chain(round1_packages.values().map(|p| &p.commitment)),
    )?;
    let mut ids: Vec<Identifier> = round1_packages.keys().copied().collect();
    ids.push(me);
    let public = group_commitment.derive_public_key_package(ids)?;
    let key = KeyPackage::new(me, SigningShare::new(total), *public.verifying_key(), secret.min_signers)?;
    total.zeroize();
    // Self-consistency: our derived public share must match our secret share.
    if public.verifying_share(&me)? != key.verifying_share() {
        return Err(Error::InvalidSecretShare(me));
    }
    log::debug!("dkg part3: participant {me} derived its key package");
    Ok((key, public))
}

/// Run a complete honest DKG in-process for identifiers `1..=n`. Handy for
/// tests, benchmarks and examples; real deployments run the three parts on
/// separate machines (see [`crate::sim`]).
pub fn run_in_process<C: Ciphersuite, R: RngCore + CryptoRng>(
    min_signers: u16,
    max_signers: u16,
    rng: &mut R,
) -> Result<(BTreeMap<Identifier, KeyPackage<C>>, PublicKeyPackage<C>)> {
    let mut secrets1 = BTreeMap::new();
    let mut broadcasts = BTreeMap::new();
    for id in Identifier::range(max_signers) {
        let (s, p) = part1::<C, _>(id, min_signers, max_signers, rng)?;
        secrets1.insert(id, s);
        broadcasts.insert(id, p);
    }
    let peers_of = |me: &Identifier| -> BTreeMap<Identifier, Round1Package<C>> {
        broadcasts.iter().filter(|(id, _)| *id != me).map(|(id, p)| (*id, p.clone())).collect()
    };
    let mut secrets2 = BTreeMap::new();
    let mut inboxes: BTreeMap<Identifier, BTreeMap<Identifier, Round2Package>> = BTreeMap::new();
    for (id, s) in secrets1 {
        let (s2, outgoing) = part2(s, &peers_of(&id))?;
        secrets2.insert(id, s2);
        for (to, pkg) in outgoing {
            inboxes.entry(to).or_default().insert(id, pkg);
        }
    }
    let mut keys = BTreeMap::new();
    let mut public = None;
    for (id, s2) in &secrets2 {
        let (key, pk) = part3(s2, &peers_of(id), &inboxes.remove(id).unwrap_or_default())?;
        keys.insert(*id, key);
        public = Some(pk);
    }
    let public = public.ok_or(Error::IncorrectPackageCount { expected: 1, got: 0 })?;
    Ok((keys, public))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ciphersuite::{Ed25519Sha512, Ristretto255Sha512};
    use crate::dealer::reconstruct;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn id(i: u16) -> Identifier {
        Identifier::try_from(i).unwrap()
    }

    #[test]
    fn honest_dkg_produces_consistent_keys() {
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        let (keys, public) = run_in_process::<Ristretto255Sha512, _>(3, 5, &mut rng).unwrap();
        let shares: Vec<_> = keys.iter().map(|(i, k)| (*i, k.signing_share().clone())).collect();
        let s = reconstruct(3, &shares[1..4]).unwrap();
        assert_eq!(Ristretto255Sha512::base_mul(&s), public.verifying_key().element());
        for (i, k) in &keys {
            assert_eq!(public.verifying_share(i).unwrap(), k.verifying_share());
        }
    }

    type Setup<C> = (
        BTreeMap<Identifier, Round1Secret<C>>,
        BTreeMap<Identifier, Round1Package<C>>,
    );

    fn round1<C: Ciphersuite>(t: u16, n: u16, seed: u64) -> Setup<C> {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let mut secrets = BTreeMap::new();
        let mut pkgs = BTreeMap::new();
        for i in Identifier::range(n) {
            let (s, p) = part1::<C, _>(i, t, n, &mut rng).unwrap();
            secrets.insert(i, s);
            pkgs.insert(i, p);
        }
        (secrets, pkgs)
    }

    fn without<T: Clone>(m: &BTreeMap<Identifier, T>, me: Identifier) -> BTreeMap<Identifier, T> {
        m.iter().filter(|(i, _)| **i != me).map(|(i, v)| (*i, v.clone())).collect()
    }

    #[test]
    fn forged_proof_is_attributed() {
        let (mut secrets, mut pkgs) = round1::<Ed25519Sha512>(2, 3, 12);
        pkgs.get_mut(&id(2)).unwrap().proof.mu += Scalar::ONE;
        let s1 = secrets.remove(&id(1)).unwrap();
        assert_eq!(
            part2(s1, &without(&pkgs, id(1))).unwrap_err(),
            Error::InvalidProofOfKnowledge { culprits: vec![id(2)] }
        );
    }

    #[test]
    fn replayed_proof_under_another_identifier_fails() {
        // Participant 3 copies participant 2's round-one package verbatim.
        let (mut secrets, mut pkgs) = round1::<Ed25519Sha512>(2, 3, 13);
        let copy = pkgs[&id(2)].clone();
        pkgs.insert(id(3), copy);
        let s1 = secrets.remove(&id(1)).unwrap();
        assert_eq!(
            part2(s1, &without(&pkgs, id(1))).unwrap_err(),
            Error::InvalidProofOfKnowledge { culprits: vec![id(3)] }
        );
    }

    #[test]
    fn bad_share_is_attributed() {
        let (secrets, pkgs) = round1::<Ristretto255Sha512>(2, 3, 14);
        let mut seconds = BTreeMap::new();
        let mut inbox: BTreeMap<Identifier, BTreeMap<Identifier, Round2Package>> = BTreeMap::new();
        for (i, s) in secrets {
            let (s2, out) = part2(s, &without(&pkgs, i)).unwrap();
            seconds.insert(i, s2);
            for (to, mut p) in out {
                if i == id(3) && to == id(1) {
                    p.share = SigningShare::new(p.share.to_scalar() + Scalar::ONE);
                }
                inbox.entry(to).or_default().insert(i, p);
            }
        }
        assert_eq!(
            part3(&seconds[&id(1)], &without(&pkgs, id(1)), &inbox[&id(1)]).unwrap_err(),
            Error::InvalidDkgShares { culprits: vec![id(3)] }
        );
        // Participant 2 received honest shares and completes.
        assert!(part3(&seconds[&id(2)], &without(&pkgs, id(2)), &inbox[&id(2)]).is_ok());
    }

    #[test]
    fn package_count_and_shape_are_checked() {
        let (mut secrets, pkgs) = round1::<Ed25519Sha512>(2, 3, 15);
        let s1 = secrets.remove(&id(1)).unwrap();
        // Including our own package.
        assert!(matches!(part2(s1, &pkgs), Err(Error::IncorrectPackageCount { .. })));

        let s2 = secrets.remove(&id(2)).unwrap();
        let mut only_one = without(&pkgs, id(2));
        only_one.remove(&id(1));
        assert_eq!(
            part2(s2, &only_one).unwrap_err(),
            Error::IncorrectPackageCount { expected: 2, got: 1 }
        );

        // A commitment with the wrong threshold.
        let (_, other) = round1::<Ed25519Sha512>(3, 3, 16);
        let s3 = secrets.remove(&id(3)).unwrap();
        let mut mixed = without(&pkgs, id(3));
        mixed.insert(id(1), other[&id(1)].clone());
        assert_eq!(
            part2(s3, &mixed).unwrap_err(),
            Error::IncorrectCommitmentLength { expected: 2, got: 3 }
        );
    }

    #[test]
    fn part3_rejects_shares_from_strangers() {
        let (secrets, pkgs) = round1::<Ed25519Sha512>(2, 3, 17);
        let mut it = secrets.into_iter();
        let (me, s) = it.next().unwrap();
        let (s2, _) = part2(s, &without(&pkgs, me)).unwrap();
        let mut inbox = BTreeMap::new();
        inbox.insert(id(2), Round2Package { share: SigningShare::new(Scalar::ONE) });
        inbox.insert(id(9), Round2Package { share: SigningShare::new(Scalar::ONE) });
        assert_eq!(
            part3(&s2, &without(&pkgs, me), &inbox).unwrap_err(),
            Error::UnknownParticipant(id(9))
        );
        assert_eq!(s2.identifier, me);
    }

    #[test]
    fn invalid_threshold_is_rejected() {
        let mut rng = ChaCha20Rng::seed_from_u64(18);
        assert!(part1::<Ed25519Sha512, _>(id(1), 1, 3, &mut rng).is_err());
        assert!(run_in_process::<Ed25519Sha512, _>(4, 3, &mut rng).is_err());
    }
}
