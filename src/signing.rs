//! The two-round FROST signing protocol (RFC 9591 Section 5): nonce
//! generation and commitments (round one), signature shares (round two),
//! aggregation, and share verification for identifiable aborts.

use std::collections::BTreeMap;

use curve25519_dalek::traits::VartimeMultiscalarMul;
use curve25519_dalek::Scalar;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ciphersuite::{deserialize_scalar, serialize_scalar, Ciphersuite, SCALAR_LEN};
use crate::error::{Error, Result};
use crate::identifier::Identifier;
use crate::keys::{KeyPackage, PublicKeyPackage, SigningShare, VerifyingKey, VerifyingShare};
use crate::polynomial::derive_interpolating_value;
use crate::signature::{compute_challenge, Signature};

/// `nonce_generate(secret)` with caller-supplied randomness:
/// `H3(random_bytes || SerializeScalar(secret))` (Section 4.1).
///
/// Hedging with the secret share means a weak RNG alone does not leak the key.
pub fn nonce_generate_from_randomness<C: Ciphersuite>(
    secret: &SigningShare,
    random_bytes: &[u8; 32],
) -> Scalar {
    let mut secret_enc = serialize_scalar(&secret.to_scalar());
    let nonce = C::h3(&[random_bytes, &secret_enc]);
    secret_enc.zeroize();
    nonce
}

/// `nonce_generate(secret)` drawing 32 fresh bytes from `rng`.
pub fn nonce_generate<C: Ciphersuite, R: RngCore + CryptoRng>(
    secret: &SigningShare,
    rng: &mut R,
) -> Scalar {
    let mut random_bytes = [0u8; 32];
    rng.fill_bytes(&mut random_bytes);
    let nonce = nonce_generate_from_randomness::<C>(secret, &random_bytes);
    random_bytes.zeroize();
    nonce
}

/// A participant's public round-one output: `(D_i, E_i)` = hiding and
/// binding nonce commitments.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SigningCommitments<C: Ciphersuite> {
    hiding: C::Element,
    binding: C::Element,
}

impl<C: Ciphersuite> SigningCommitments<C> {
    /// Wrap two commitments, rejecting identity elements.
    pub fn new(hiding: C::Element, binding: C::Element) -> Result<Self> {
        C::serialize_element(&hiding)?;
        C::serialize_element(&binding)?;
        Ok(Self { hiding, binding })
    }

    /// Hiding nonce commitment `D_i`.
    pub fn hiding(&self) -> C::Element {
        self.hiding
    }

    /// Binding nonce commitment `E_i`.
    pub fn binding(&self) -> C::Element {
        self.binding
    }
}

/// A participant's secret round-one state: the nonce pair plus the
/// commitments it published.
///
/// Deliberately neither `Clone` nor `Copy`: [`sign`] consumes it, so the
/// type system enforces the RFC's "MUST NOT use the nonce more than once".
/// Nonces are wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SigningNonces<C: Ciphersuite> {
    hiding: Scalar,
    binding: Scalar,
    #[zeroize(skip)]
    commitments: SigningCommitments<C>,
}

impl<C: Ciphersuite> core::fmt::Debug for SigningNonces<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SigningNonces")
            .field("commitments", &self.commitments)
            .finish_non_exhaustive()
    }
}

impl<C: Ciphersuite> SigningNonces<C> {
    /// Derive nonces from explicit randomness (deterministic; for test vectors).
    pub fn from_randomness(
        secret: &SigningShare,
        hiding_randomness: &[u8; 32],
        binding_randomness: &[u8; 32],
    ) -> Result<Self> {
        let hiding = nonce_generate_from_randomness::<C>(secret, hiding_randomness);
        let binding = nonce_generate_from_randomness::<C>(secret, binding_randomness);
        Self::from_nonces(hiding, binding)
    }

    fn from_nonces(hiding: Scalar, binding: Scalar) -> Result<Self> {
        let commitments = SigningCommitments::new(C::base_mul(&hiding), C::base_mul(&binding))?;
        Ok(Self { hiding, binding, commitments })
    }

    /// The public commitments matching these nonces.
    pub fn commitments(&self) -> &SigningCommitments<C> {
        &self.commitments
    }
}

/// Round one, `commit(sk_i)`: fresh nonces and their commitments.
///
/// Keep the returned [`SigningNonces`] private until round two; send the
/// [`SigningCommitments`] to the coordinator.
pub fn commit<C: Ciphersuite, R: RngCore + CryptoRng>(
    secret: &SigningShare,
    rng: &mut R,
) -> (SigningNonces<C>, SigningCommitments<C>) {
    loop {
        let hiding = nonce_generate::<C, _>(secret, rng);
        let binding = nonce_generate::<C, _>(secret, rng);
        // A zero nonce (probability ~2^-252) would give an identity commitment.
        if let Ok(nonces) = SigningNonces::from_nonces(hiding, binding) {
            let commitments = nonces.commitments;
            return (nonces, commitments);
        }
    }
}

/// What the coordinator sends in round two: the message and the commitment
/// list, kept sorted by identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningPackage<C: Ciphersuite> {
    commitments: BTreeMap<Identifier, SigningCommitments<C>>,
    message: Vec<u8>,
}

impl<C: Ciphersuite> SigningPackage<C> {
    /// Assemble a package. A `BTreeMap` keeps the list sorted and duplicate
    /// free, as Section 4.3 requires.
    pub fn new(commitments: BTreeMap<Identifier, SigningCommitments<C>>, message: Vec<u8>) -> Self {
        Self { commitments, message }
    }

    /// The commitment list.
    pub fn commitments(&self) -> &BTreeMap<Identifier, SigningCommitments<C>> {
        &self.commitments
    }

    /// The message to sign.
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// `participants_from_commitment_list`.
    pub fn signers(&self) -> Vec<Identifier> {
        self.commitments.keys().copied().collect()
    }

    /// `encode_group_commitment_list` (Section 4.3).
    pub fn encode_commitment_list(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.commitments.len() * 96);
        for (id, c) in &self.commitments {
            out.extend_from_slice(&id.serialize());
            out.extend_from_slice(&C::serialize_element(&c.hiding)?);
            out.extend_from_slice(&C::serialize_element(&c.binding)?);
        }
        Ok(out)
    }

    fn require_threshold(&self, min_signers: u16) -> Result<()> {
        if self.commitments.len() < usize::from(min_signers) {
            return Err(Error::NotEnoughSigners {
                needed: min_signers,
                got: self.commitments.len(),
            });
        }
        Ok(())
    }
}

/// The per-signer binding factor inputs `rho_input` of Section 4.4, in
/// identifier order. Exposed for test-vector checks.
pub fn binding_factor_inputs<C: Ciphersuite>(
    verifying_key: &VerifyingKey<C>,
    package: &SigningPackage<C>,
) -> Result<Vec<(Identifier, Vec<u8>)>> {
    let mut prefix = Vec::with_capacity(32 + 64 + 64 + 32);
    prefix.extend_from_slice(&verifying_key.serialize()?);
    prefix.extend_from_slice(&C::h4(&[package.message()]));
    prefix.extend_from_slice(&C::h5(&[&package.encode_commitment_list()?]));
    Ok(package
        .commitments
        .keys()
        .map(|id| {
            let mut input = prefix.clone();
            input.extend_from_slice(&id.serialize());
            (*id, input)
        })
        .collect())
}

/// `compute_binding_factors` (Section 4.4). `O(n)` hashing.
pub fn compute_binding_factors<C: Ciphersuite>(
    verifying_key: &VerifyingKey<C>,
    package: &SigningPackage<C>,
) -> Result<BTreeMap<Identifier, Scalar>> {
    Ok(binding_factor_inputs(verifying_key, package)?
        .into_iter()
        .map(|(id, input)| (id, C::h1(&[&input])))
        .collect())
}

/// `compute_group_commitment` (Section 4.5):
/// `R = sum_i (D_i + rho_i * E_i)`, computed as one variable-time
/// multi-scalar multiplication over public values (the RFC's suggested
/// optimisation), `O(n)` with Pippenger/Straus speedups.
pub fn compute_group_commitment<C: Ciphersuite>(
    package: &SigningPackage<C>,
    binding_factors: &BTreeMap<Identifier, Scalar>,
) -> Result<C::Element> {
    let mut scalars = Vec::with_capacity(package.commitments.len() * 2);
    let mut points = Vec::with_capacity(package.commitments.len() * 2);
    for (id, c) in &package.commitments {
        let rho = binding_factors.get(id).ok_or(Error::UnknownParticipant(*id))?;
        scalars.push(Scalar::ONE);
        points.push(c.hiding);
        scalars.push(*rho);
        points.push(c.binding);
    }
    Ok(C::Element::vartime_multiscalar_mul(scalars.iter(), points.iter()))
}

/// The values every round-two computation shares: binding factors, the group
/// commitment `R`, the challenge `c` and the signer list. Computing them once
/// lets the coordinator verify all `n` shares in `O(n)` point operations
/// instead of the naive `O(n^2)` of calling `verify_signature_share` per share.
#[derive(Clone, Debug)]
pub struct SigningSession<C: Ciphersuite> {
    binding_factors: BTreeMap<Identifier, Scalar>,
    group_commitment: C::Element,
    challenge: Scalar,
    signers: Vec<Identifier>,
}

impl<C: Ciphersuite> SigningSession<C> {
    /// Derive the session values for `package` under `verifying_key`.
    pub fn new(verifying_key: &VerifyingKey<C>, package: &SigningPackage<C>) -> Result<Self> {
        let binding_factors = compute_binding_factors(verifying_key, package)?;
        let group_commitment = compute_group_commitment(package, &binding_factors)?;
        let challenge = compute_challenge(&group_commitment, verifying_key, package.message())?;
        Ok(Self { binding_factors, group_commitment, challenge, signers: package.signers() })
    }

    /// `rho_i`.
    pub fn binding_factor(&self, id: &Identifier) -> Result<Scalar> {
        self.binding_factors.get(id).copied().ok_or(Error::UnknownParticipant(*id))
    }

    /// The group commitment `R`.
    pub fn group_commitment(&self) -> C::Element {
        self.group_commitment
    }

    /// The challenge `c`.
    pub fn challenge(&self) -> Scalar {
        self.challenge
    }

    /// `lambda_i` for this signer set.
    pub fn lagrange_coefficient(&self, id: &Identifier) -> Result<Scalar> {
        derive_interpolating_value(&self.signers, id)
    }

    /// The core of `verify_signature_share`:
    /// `z_i * B == D_i + rho_i * E_i + (c * lambda_i) * PK_i`.
    pub fn verify_share(
        &self,
        id: &Identifier,
        commitments: &SigningCommitments<C>,
        verifying_share: &VerifyingShare<C>,
        share: &SignatureShare,
    ) -> Result<bool> {
        let rho = self.binding_factor(id)?;
        let lambda = self.lagrange_coefficient(id)?;
        let lhs = C::base_mul(&share.0);
        let rhs = C::Element::vartime_multiscalar_mul(
            [Scalar::ONE, rho, self.challenge * lambda].iter(),
            [commitments.hiding, commitments.binding, verifying_share.0].iter(),
        );
        Ok(lhs == rhs)
    }
}

/// A round-two output `z_i`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SignatureShare(Scalar);

impl SignatureShare {
    /// Wrap a scalar.
    pub fn new(z: Scalar) -> Self {
        Self(z)
    }

    /// The scalar `z_i`.
    pub fn to_scalar(&self) -> Scalar {
        self.0
    }

    /// `SerializeScalar(z_i)`.
    pub fn serialize(&self) -> [u8; SCALAR_LEN] {
        serialize_scalar(&self.0)
    }

    /// `DeserializeScalar`, which the coordinator MUST apply to every share
    /// it receives (Section 5.3).
    pub fn deserialize(bytes: &[u8; SCALAR_LEN]) -> Result<Self> {
        Ok(Self(deserialize_scalar(bytes)?))
    }
}

/// Round two, `sign(...)` (Section 5.2).
///
/// Validates that the package meets the threshold, includes this signer, and
/// carries exactly the commitments this signer issued (guarding against a
/// coordinator substituting commitments). Consumes `nonces`.
pub fn sign<C: Ciphersuite>(
    package: &SigningPackage<C>,
    nonces: SigningNonces<C>,
    key_package: &KeyPackage<C>,
) -> Result<SignatureShare> {
    let id = key_package.identifier();
    package.require_threshold(key_package.min_signers())?;
    let own = package.commitments.get(id).ok_or(Error::MissingSigner(*id))?;
    if *own != nonces.commitments {
        return Err(Error::IncorrectCommitment(*id));
    }
    let session = SigningSession::new(key_package.verifying_key(), package)?;
    let rho = session.binding_factor(id)?;
    let lambda = session.lagrange_coefficient(id)?;
    let sk = key_package.signing_share().to_scalar();
    let z = nonces.hiding + nonces.binding * rho + lambda * sk * session.challenge;
    log::debug!("participant {id} produced a signature share over {} signers", package.commitments.len());
    Ok(SignatureShare(z))
}

/// `verify_signature_share` exactly as specified in Section 5.3: recomputes
/// the session values for a single share. Prefer [`SigningSession`] when
/// checking many shares.
pub fn verify_signature_share<C: Ciphersuite>(
    id: &Identifier,
    verifying_share: &VerifyingShare<C>,
    share: &SignatureShare,
    package: &SigningPackage<C>,
    verifying_key: &VerifyingKey<C>,
) -> Result<()> {
    let commitments = package.commitments.get(id).ok_or(Error::MissingSigner(*id))?;
    let session = SigningSession::new(verifying_key, package)?;
    if session.verify_share(id, commitments, verifying_share, share)? {
        Ok(())
    } else {
        Err(Error::InvalidSignatureShares { culprits: vec![*id] })
    }
}

/// How [`aggregate_with`] treats share verification.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ShareVerification {
    /// Aggregate, verify the final signature, and only check individual
    /// shares if it fails (the cheap path the RFC describes).
    OnFailure,
    /// Check every share before aggregating (always identifies cheaters,
    /// costs `O(n)` extra point operations).
    Always,
}

/// `aggregate(...)` followed by signature verification and, on failure,
/// identifiable abort. Equivalent to [`aggregate_with`] with
/// [`ShareVerification::OnFailure`].
pub fn aggregate<C: Ciphersuite>(
    package: &SigningPackage<C>,
    shares: &BTreeMap<Identifier, SignatureShare>,
    public: &PublicKeyPackage<C>,
) -> Result<Signature<C>> {
    aggregate_with(package, shares, public, ShareVerification::OnFailure)
}

/// Aggregate signature shares into `(R, z)` (Section 5.3) and verify the
/// result under the group key.
///
/// Errors with [`Error::InvalidSignatureShares`] naming every participant
/// whose share fails `verify_signature_share`.
pub fn aggregate_with<C: Ciphersuite>(
    package: &SigningPackage<C>,
    shares: &BTreeMap<Identifier, SignatureShare>,
    public: &PublicKeyPackage<C>,
    mode: ShareVerification,
) -> Result<Signature<C>> {
    package.require_threshold(public.min_signers())?;
    for id in package.commitments.keys() {
        if !shares.contains_key(id) {
            return Err(Error::MissingSignatureShare(*id));
        }
        public.verifying_share(id)?;
    }
    if let Some(extra) = shares.keys().find(|id| !package.commitments.contains_key(id)) {
        return Err(Error::UnknownParticipant(*extra));
    }

    let session = SigningSession::new(public.verifying_key(), package)?;
    if mode == ShareVerification::Always {
        identify_cheaters(&session, package, shares, public)?;
    }
    let z: Scalar = shares.values().map(|s| s.0).sum();
    let signature = Signature::new(session.group_commitment, z);
    match public.verifying_key().verify(package.message(), &signature) {
        Ok(()) => Ok(signature),
        Err(_) => {
            identify_cheaters(&session, package, shares, public)?;
            // Every share verified yet the signature does not: the group info
            // itself is inconsistent with the shares' keys.
            Err(Error::InvalidSignature)
        }
    }
}

fn identify_cheaters<C: Ciphersuite>(
    session: &SigningSession<C>,
    package: &SigningPackage<C>,
    shares: &BTreeMap<Identifier, SignatureShare>,
    public: &PublicKeyPackage<C>,
) -> Result<()> {
    let mut culprits = Vec::new();
    for (id, commitments) in &package.commitments {
        let share = shares.get(id).ok_or(Error::MissingSignatureShare(*id))?;
        if !session.verify_share(id, commitments, public.verifying_share(id)?, share)? {
            culprits.push(*id);
        }
    }
    if culprits.is_empty() {
        Ok(())
    } else {
        log::warn!("identifiable abort: invalid shares from {culprits:?}");
        Err(Error::InvalidSignatureShares { culprits })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ciphersuite::{Ed25519Sha512, Ristretto255Sha512};
    use crate::dealer::trusted_dealer_keygen;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    type Fixture<C> = (BTreeMap<Identifier, KeyPackage<C>>, PublicKeyPackage<C>);

    fn setup<C: Ciphersuite>(t: u16, n: u16, seed: u64) -> Fixture<C> {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let (shares, public) = trusted_dealer_keygen::<C, _>(t, n, &mut rng).unwrap();
        let keys = shares.into_iter().map(|(id, s)| (id, s.verify().unwrap())).collect();
        (keys, public)
    }

    fn run<C: Ciphersuite>(
        keys: &BTreeMap<Identifier, KeyPackage<C>>,
        signers: &[u16],
        msg: &[u8],
        rng: &mut ChaCha20Rng,
    ) -> (SigningPackage<C>, BTreeMap<Identifier, SignatureShare>) {
        let mut nonces = BTreeMap::new();
        let mut comms = BTreeMap::new();
        for &s in signers {
            let id = Identifier::try_from(s).unwrap();
            let (n, c) = commit::<C, _>(keys[&id].signing_share(), rng);
            nonces.insert(id, n);
            comms.insert(id, c);
        }
        let package = SigningPackage::new(comms, msg.to_vec());
        let shares = nonces
            .into_iter()
            .map(|(id, n)| (id, sign(&package, n, &keys[&id]).unwrap()))
            .collect();
        (package, shares)
    }

    fn end_to_end<C: Ciphersuite>() {
        let (keys, public) = setup::<C>(3, 5, 1);
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let (package, shares) = run(&keys, &[1, 3, 5], b"frost", &mut rng);
        let sig = aggregate(&package, &shares, &public).unwrap();
        public.verifying_key().verify(b"frost", &sig).unwrap();
        let sig2 = aggregate_with(&package, &shares, &public, ShareVerification::Always).unwrap();
        assert_eq!(sig, sig2);
        for (id, share) in &shares {
            verify_signature_share(id, public.verifying_share(id).unwrap(), share, &package, public.verifying_key())
                .unwrap();
        }
    }

    #[test]
    fn end_to_end_both_suites() {
        end_to_end::<Ed25519Sha512>();
        end_to_end::<Ristretto255Sha512>();
    }

    #[test]
    fn identifies_every_cheater() {
        let (keys, public) = setup::<Ed25519Sha512>(3, 5, 3);
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let (package, mut shares) = run(&keys, &[1, 2, 4, 5], b"m", &mut rng);
        for bad in [2u16, 5] {
            let id = Identifier::try_from(bad).unwrap();
            let s = shares[&id].to_scalar() + Scalar::ONE;
            shares.insert(id, SignatureShare::new(s));
        }
        let want = vec![Identifier::try_from(2).unwrap(), Identifier::try_from(5).unwrap()];
        for mode in [ShareVerification::OnFailure, ShareVerification::Always] {
            assert_eq!(
                aggregate_with(&package, &shares, &public, mode),
                Err(Error::InvalidSignatureShares { culprits: want.clone() })
            );
        }
    }

    #[test]
    fn sign_validates_package() {
        let (keys, _) = setup::<Ristretto255Sha512>(2, 3, 5);
        let mut rng = ChaCha20Rng::seed_from_u64(6);
        let id1 = Identifier::try_from(1).unwrap();
        let id2 = Identifier::try_from(2).unwrap();
        let id3 = Identifier::try_from(3).unwrap();
        let (n1, c1) = commit::<Ristretto255Sha512, _>(keys[&id1].signing_share(), &mut rng);
        let (_n2, c2) = commit::<Ristretto255Sha512, _>(keys[&id2].signing_share(), &mut rng);

        // Below threshold.
        let alone = SigningPackage::new(BTreeMap::from([(id1, c1)]), b"m".to_vec());
        assert_eq!(sign(&alone, n1, &keys[&id1]), Err(Error::NotEnoughSigners { needed: 2, got: 1 }));

        // Not a member of the package.
        let (n1, c1) = commit::<Ristretto255Sha512, _>(keys[&id1].signing_share(), &mut rng);
        let (_n3, c3) = commit::<Ristretto255Sha512, _>(keys[&id3].signing_share(), &mut rng);
        let others = SigningPackage::new(BTreeMap::from([(id2, c2), (id3, c3)]), b"m".to_vec());
        assert_eq!(sign(&others, n1, &keys[&id1]), Err(Error::MissingSigner(id1)));

        // Coordinator swapped our commitment.
        let (n1, _c1) = commit::<Ristretto255Sha512, _>(keys[&id1].signing_share(), &mut rng);
        let swapped = SigningPackage::new(BTreeMap::from([(id1, c1), (id2, c2)]), b"m".to_vec());
        assert_eq!(sign(&swapped, n1, &keys[&id1]), Err(Error::IncorrectCommitment(id1)));
    }

    #[test]
    fn aggregate_validates_share_set() {
        let (keys, public) = setup::<Ed25519Sha512>(2, 3, 7);
        let mut rng = ChaCha20Rng::seed_from_u64(8);
        let (package, shares) = run(&keys, &[1, 2], b"m", &mut rng);
        let id1 = Identifier::try_from(1).unwrap();
        let id3 = Identifier::try_from(3).unwrap();

        let mut missing = shares.clone();
        missing.remove(&id1);
        assert_eq!(aggregate(&package, &missing, &public), Err(Error::MissingSignatureShare(id1)));

        let mut extra = shares.clone();
        extra.insert(id3, SignatureShare::new(Scalar::ONE));
        assert_eq!(aggregate(&package, &extra, &public), Err(Error::UnknownParticipant(id3)));

        // Shares that verify against a *different* group's info.
        let (_, other_public) = setup::<Ed25519Sha512>(2, 3, 99);
        assert!(matches!(
            aggregate(&package, &shares, &other_public),
            Err(Error::InvalidSignatureShares { .. })
        ));
    }

    #[test]
    fn standalone_share_verification_rejects_tampering() {
        let (keys, public) = setup::<Ristretto255Sha512>(2, 2, 9);
        let mut rng = ChaCha20Rng::seed_from_u64(10);
        let (package, shares) = run(&keys, &[1, 2], b"m", &mut rng);
        let id = Identifier::try_from(2).unwrap();
        let bad = SignatureShare::new(shares[&id].to_scalar() + Scalar::ONE);
        assert_eq!(
            verify_signature_share(&id, public.verifying_share(&id).unwrap(), &bad, &package, public.verifying_key()),
            Err(Error::InvalidSignatureShares { culprits: vec![id] })
        );
        let unknown = Identifier::try_from(9).unwrap();
        assert_eq!(
            verify_signature_share(&unknown, public.verifying_share(&id).unwrap(), &bad, &package, public.verifying_key()),
            Err(Error::MissingSigner(unknown))
        );
    }

    #[test]
    fn nonces_hedge_with_secret_and_debug_is_redacted() {
        let r = [9u8; 32];
        let a = nonce_generate_from_randomness::<Ed25519Sha512>(&SigningShare::new(Scalar::ONE), &r);
        let b = nonce_generate_from_randomness::<Ed25519Sha512>(&SigningShare::new(Scalar::from(2u8)), &r);
        assert_ne!(a, b, "same randomness, different secrets must give different nonces");
        let nonces =
            SigningNonces::<Ed25519Sha512>::from_randomness(&SigningShare::new(Scalar::ONE), &r, &[1; 32]).unwrap();
        let dbg = format!("{nonces:?}");
        assert!(dbg.starts_with("SigningNonces { commitments"));
        assert!(dbg.ends_with(".. }"));
    }

    #[test]
    fn signature_share_encoding() {
        let s = SignatureShare::new(Scalar::from(77u8));
        assert_eq!(SignatureShare::deserialize(&s.serialize()).unwrap(), s);
        assert_eq!(SignatureShare::deserialize(&[0xff; 32]), Err(Error::MalformedScalar));
    }
}
