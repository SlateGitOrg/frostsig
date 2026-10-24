//! Key material: signing shares, verifying shares, the group verifying key,
//! Feldman VSS commitments (RFC 9591 Appendix C.2) and the per-participant /
//! public packages that signing consumes.

use std::collections::BTreeMap;

use curve25519_dalek::traits::VartimeMultiscalarMul;
use curve25519_dalek::Scalar;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ciphersuite::Ciphersuite;
use crate::error::{Error, Result};
use crate::identifier::Identifier;

/// A participant's secret Shamir share `sk_i = f(i)`. Wiped on drop, compared
/// in constant time, and never printed.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SigningShare(Scalar);

impl SigningShare {
    /// Wrap a share value.
    pub fn new(s: Scalar) -> Self {
        Self(s)
    }

    /// The secret scalar. Callers must not log or persist it carelessly.
    pub fn to_scalar(&self) -> Scalar {
        self.0
    }

    /// The matching public verifying share `PK_i = sk_i * B`.
    pub fn verifying_share<C: Ciphersuite>(&self) -> VerifyingShare<C> {
        VerifyingShare(C::base_mul(&self.0))
    }
}

impl PartialEq for SigningShare {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for SigningShare {}

impl core::fmt::Debug for SigningShare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SigningShare(<redacted>)")
    }
}

/// A participant's public key `PK_i`, used to verify its signature shares.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VerifyingShare<C: Ciphersuite>(pub(crate) C::Element);

impl<C: Ciphersuite> VerifyingShare<C> {
    /// Wrap an element, rejecting the identity.
    pub fn new(e: C::Element) -> Result<Self> {
        C::serialize_element(&e)?;
        Ok(Self(e))
    }

    /// The underlying element.
    pub fn element(&self) -> C::Element {
        self.0
    }

    /// `G.SerializeElement(PK_i)`.
    pub fn serialize(&self) -> Result<[u8; 32]> {
        C::serialize_element(&self.0)
    }

    /// Validated decoding.
    pub fn deserialize(bytes: &[u8; 32]) -> Result<Self> {
        Ok(Self(C::deserialize_element(bytes)?))
    }
}

/// The group public key `PK = s * B`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VerifyingKey<C: Ciphersuite>(pub(crate) C::Element);

impl<C: Ciphersuite> VerifyingKey<C> {
    /// Wrap an element, rejecting the identity.
    pub fn new(e: C::Element) -> Result<Self> {
        C::serialize_element(&e)?;
        Ok(Self(e))
    }

    /// The underlying element.
    pub fn element(&self) -> C::Element {
        self.0
    }

    /// `G.SerializeElement(PK)`: for Ed25519 this is the standard 32-byte
    /// public key format.
    pub fn serialize(&self) -> Result<[u8; 32]> {
        C::serialize_element(&self.0)
    }

    /// Validated decoding.
    pub fn deserialize(bytes: &[u8; 32]) -> Result<Self> {
        Ok(Self(C::deserialize_element(bytes)?))
    }
}

/// A Feldman VSS commitment `[a_0 B, ..., a_{t-1} B]` to a secret polynomial.
/// Its length is the threshold `t`; its first entry is the group key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VssCommitment<C: Ciphersuite> {
    elements: Vec<C::Element>,
}

impl<C: Ciphersuite> VssCommitment<C> {
    /// Build from coefficient commitments, rejecting empty lists and identity
    /// entries (which could not be serialized).
    pub fn new(elements: Vec<C::Element>) -> Result<Self> {
        if elements.is_empty() {
            return Err(Error::IncorrectCommitmentLength { expected: 1, got: 0 });
        }
        for e in &elements {
            C::serialize_element(e)?;
        }
        Ok(Self { elements })
    }

    pub(crate) fn from_elements_unchecked(elements: Vec<C::Element>) -> Self {
        Self { elements }
    }

    /// The coefficient commitments.
    pub fn elements(&self) -> &[C::Element] {
        &self.elements
    }

    /// The threshold `t` this commitment encodes.
    pub fn threshold(&self) -> usize {
        self.elements.len()
    }

    /// `vss_commitment[0]`, the commitment to the constant term.
    pub fn constant_term(&self) -> C::Element {
        self.elements[0]
    }

    /// `sum_j C_j * i^j`: the public image `f(i) * B` of participant `i`'s
    /// share. Uses a variable-time multi-scalar multiplication; every input is
    /// public. `O(t)` point operations.
    pub fn evaluate(&self, id: &Identifier) -> C::Element {
        let x = id.to_scalar();
        let mut powers = Vec::with_capacity(self.elements.len());
        let mut acc = Scalar::ONE;
        for _ in 0..self.elements.len() {
            powers.push(acc);
            acc *= x;
        }
        C::Element::vartime_multiscalar_mul(powers.iter(), self.elements.iter())
    }

    /// `vss_verify(share_i, vss_commitment)`.
    pub fn verify_share(&self, id: &Identifier, share: &SigningShare) -> bool {
        C::base_mul(&share.0) == self.evaluate(id)
    }

    /// Coefficient-wise sum of several commitments (the DKG's group polynomial).
    pub fn sum<'a, I>(commitments: I) -> Result<Self>
    where
        I: IntoIterator<Item = &'a VssCommitment<C>>,
    {
        let mut iter = commitments.into_iter();
        let first = iter.next().ok_or(Error::IncorrectCommitmentLength { expected: 1, got: 0 })?;
        let mut acc = first.elements.clone();
        for c in iter {
            if c.elements.len() != acc.len() {
                return Err(Error::IncorrectCommitmentLength { expected: acc.len(), got: c.elements.len() });
            }
            for (a, e) in acc.iter_mut().zip(&c.elements) {
                *a = *a + *e;
            }
        }
        Ok(Self { elements: acc })
    }

    /// `derive_group_info`: the group key and every listed participant's
    /// verifying share. `O(n * t)` point operations.
    pub fn derive_public_key_package(
        &self,
        ids: impl IntoIterator<Item = Identifier>,
    ) -> Result<PublicKeyPackage<C>> {
        let verifying_shares = ids
            .into_iter()
            .map(|id| Ok((id, VerifyingShare::new(self.evaluate(&id))?)))
            .collect::<Result<BTreeMap<_, _>>>()?;
        let min_signers = u16::try_from(self.threshold())
            .map_err(|_| Error::InvalidThreshold { min_signers: u16::MAX, max_signers: u16::MAX })?;
        PublicKeyPackage::new(verifying_shares, VerifyingKey::new(self.constant_term())?, min_signers)
    }
}

/// What a trusted dealer sends to participant `i`: its share plus the public
/// VSS commitment it must check the share against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretShare<C: Ciphersuite> {
    /// Recipient.
    pub identifier: Identifier,
    /// `f(i)`.
    pub signing_share: SigningShare,
    /// The dealer's commitment to `f`.
    pub commitment: VssCommitment<C>,
}

impl<C: Ciphersuite> SecretShare<C> {
    /// Run `vss_verify` and, on success, turn the share into a [`KeyPackage`].
    pub fn verify(&self) -> Result<KeyPackage<C>> {
        if !self.commitment.verify_share(&self.identifier, &self.signing_share) {
            return Err(Error::InvalidSecretShare(self.identifier));
        }
        let min_signers =
            u16::try_from(self.commitment.threshold()).map_err(|_| Error::IncorrectCommitmentLength {
                expected: usize::from(u16::MAX),
                got: self.commitment.threshold(),
            })?;
        KeyPackage::new(
            self.identifier,
            self.signing_share.clone(),
            VerifyingKey::new(self.commitment.constant_term())?,
            min_signers,
        )
    }
}

/// Everything one participant needs to sign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPackage<C: Ciphersuite> {
    identifier: Identifier,
    signing_share: SigningShare,
    verifying_share: VerifyingShare<C>,
    verifying_key: VerifyingKey<C>,
    min_signers: u16,
}

impl<C: Ciphersuite> KeyPackage<C> {
    /// Assemble a key package; the verifying share is derived from the signing share.
    pub fn new(
        identifier: Identifier,
        signing_share: SigningShare,
        verifying_key: VerifyingKey<C>,
        min_signers: u16,
    ) -> Result<Self> {
        if min_signers < 2 {
            return Err(Error::InvalidThreshold { min_signers, max_signers: min_signers });
        }
        let verifying_share = VerifyingShare::new(C::base_mul(&signing_share.0))?;
        Ok(Self { identifier, signing_share, verifying_share, verifying_key, min_signers })
    }

    /// This participant's identifier.
    pub fn identifier(&self) -> &Identifier {
        &self.identifier
    }

    /// The secret share.
    pub fn signing_share(&self) -> &SigningShare {
        &self.signing_share
    }

    /// `PK_i`.
    pub fn verifying_share(&self) -> &VerifyingShare<C> {
        &self.verifying_share
    }

    /// The group key `PK`.
    pub fn verifying_key(&self) -> &VerifyingKey<C> {
        &self.verifying_key
    }

    /// The threshold `t`.
    pub fn min_signers(&self) -> u16 {
        self.min_signers
    }
}

/// Every participant's key package plus the shared group info: the output
/// of an in-process key generation.
pub type KeySet<C> = (BTreeMap<Identifier, KeyPackage<C>>, PublicKeyPackage<C>);

/// The public "group info": the group key plus every participant's `PK_i`.
/// The coordinator needs it to verify signature shares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyPackage<C: Ciphersuite> {
    verifying_shares: BTreeMap<Identifier, VerifyingShare<C>>,
    verifying_key: VerifyingKey<C>,
    min_signers: u16,
}

impl<C: Ciphersuite> PublicKeyPackage<C> {
    /// Assemble and sanity-check group info.
    pub fn new(
        verifying_shares: BTreeMap<Identifier, VerifyingShare<C>>,
        verifying_key: VerifyingKey<C>,
        min_signers: u16,
    ) -> Result<Self> {
        let n = verifying_shares.len();
        if min_signers < 2 || n < usize::from(min_signers) {
            return Err(Error::InvalidThreshold {
                min_signers,
                max_signers: u16::try_from(n).unwrap_or(u16::MAX),
            });
        }
        Ok(Self { verifying_shares, verifying_key, min_signers })
    }

    /// `PK_i` for every participant.
    pub fn verifying_shares(&self) -> &BTreeMap<Identifier, VerifyingShare<C>> {
        &self.verifying_shares
    }

    /// `PK_i` for one participant.
    pub fn verifying_share(&self, id: &Identifier) -> Result<&VerifyingShare<C>> {
        self.verifying_shares.get(id).ok_or(Error::UnknownParticipant(*id))
    }

    /// The group key.
    pub fn verifying_key(&self) -> &VerifyingKey<C> {
        &self.verifying_key
    }

    /// The threshold `t`.
    pub fn min_signers(&self) -> u16 {
        self.min_signers
    }

    /// The number of participants `n`.
    pub fn max_signers(&self) -> u16 {
        u16::try_from(self.verifying_shares.len()).unwrap_or(u16::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ciphersuite::{Ed25519Sha512, Ristretto255Sha512};
    use crate::polynomial::SecretPolynomial;
    use curve25519_dalek::traits::Identity;

    fn id(i: u16) -> Identifier {
        Identifier::try_from(i).unwrap()
    }

    #[test]
    fn vss_accepts_honest_and_rejects_tampered_shares() {
        let poly = SecretPolynomial::new(Scalar::from(11u8), vec![Scalar::from(3u8), Scalar::from(5u8)]);
        let commitment = poly.commit::<Ed25519Sha512>();
        let good = SigningShare::new(poly.evaluate(&id(4)));
        assert!(commitment.verify_share(&id(4), &good));
        assert!(!commitment.verify_share(&id(5), &good));
        let bad = SigningShare::new(poly.evaluate(&id(4)) + Scalar::ONE);
        assert!(!commitment.verify_share(&id(4), &bad));
    }

    #[test]
    fn secret_share_verify_reports_identifier() {
        let poly = SecretPolynomial::new(Scalar::from(11u8), vec![Scalar::from(3u8)]);
        let share = SecretShare::<Ristretto255Sha512> {
            identifier: id(2),
            signing_share: SigningShare::new(Scalar::from(99u8)),
            commitment: poly.commit(),
        };
        assert_eq!(share.verify(), Err(Error::InvalidSecretShare(id(2))));
    }

    #[test]
    fn commitment_sum_requires_equal_lengths() {
        let a = SecretPolynomial::new(Scalar::from(1u8), vec![Scalar::from(2u8)]).commit::<Ed25519Sha512>();
        let b = SecretPolynomial::new(Scalar::from(1u8), vec![]).commit::<Ed25519Sha512>();
        assert_eq!(
            VssCommitment::sum([&a, &b]),
            Err(Error::IncorrectCommitmentLength { expected: 2, got: 1 })
        );
        let s = VssCommitment::sum([&a, &a]).unwrap();
        assert_eq!(s.constant_term(), Ed25519Sha512::base_mul(&Scalar::from(2u8)));
        assert!(VssCommitment::<Ed25519Sha512>::sum([]).is_err());
    }

    #[test]
    fn identity_elements_are_rejected_in_public_types() {
        let identity = curve25519_dalek::EdwardsPoint::identity();
        assert_eq!(VerifyingKey::<Ed25519Sha512>::new(identity), Err(Error::IdentityElement));
        assert_eq!(VerifyingShare::<Ed25519Sha512>::new(identity), Err(Error::IdentityElement));
        assert_eq!(VssCommitment::<Ed25519Sha512>::new(vec![identity]), Err(Error::IdentityElement));
        assert!(VssCommitment::<Ed25519Sha512>::new(vec![]).is_err());
    }

    #[test]
    fn key_and_public_packages_validate_threshold() {
        let vk = VerifyingKey::<Ed25519Sha512>::new(Ed25519Sha512::generator()).unwrap();
        let share = SigningShare::new(Scalar::from(5u8));
        assert!(KeyPackage::new(id(1), share.clone(), vk, 1).is_err());
        let kp = KeyPackage::new(id(1), share, vk, 2).unwrap();
        assert_eq!(kp.min_signers(), 2);
        assert_eq!(kp.verifying_share().element(), Ed25519Sha512::base_mul(&Scalar::from(5u8)));

        let mut shares = BTreeMap::new();
        shares.insert(id(1), *kp.verifying_share());
        assert!(PublicKeyPackage::new(shares.clone(), vk, 2).is_err());
        shares.insert(id(2), *kp.verifying_share());
        let pkp = PublicKeyPackage::new(shares, vk, 2).unwrap();
        assert_eq!(pkp.max_signers(), 2);
        assert!(pkp.verifying_share(&id(3)).is_err());
    }

    #[test]
    fn signing_share_debug_is_redacted() {
        let s = SigningShare::new(Scalar::from(5u8));
        assert_eq!(format!("{s:?}"), "SigningShare(<redacted>)");
        assert_eq!(s, SigningShare::new(Scalar::from(5u8)));
    }

    #[test]
    fn element_wrappers_round_trip() {
        let vk = VerifyingKey::<Ristretto255Sha512>::new(Ristretto255Sha512::generator()).unwrap();
        let bytes = vk.serialize().unwrap();
        assert_eq!(VerifyingKey::<Ristretto255Sha512>::deserialize(&bytes).unwrap(), vk);
        let vs = VerifyingShare::<Ristretto255Sha512>::deserialize(&bytes).unwrap();
        assert_eq!(vs.serialize().unwrap(), bytes);
    }
}
