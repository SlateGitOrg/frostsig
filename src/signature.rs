//! Schnorr signatures `(R, z)`: canonical encoding (RFC 9591 Appendix A),
//! verification (Section 6 / Appendix B) and a single-signer reference
//! signer used to cross-check threshold output.

use curve25519_dalek::traits::Identity;
use curve25519_dalek::Scalar;
use rand_core::{CryptoRng, RngCore};

use crate::ciphersuite::{deserialize_scalar, random_nonzero_scalar, serialize_scalar, Ciphersuite};
use crate::error::{Error, Result};
use crate::keys::VerifyingKey;

/// Length of an encoded signature: `Ne + Ns`.
pub const SIGNATURE_LEN: usize = 64;

/// A Schnorr signature: commitment `R` and response `z`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Signature<C: Ciphersuite> {
    r: C::Element,
    z: Scalar,
}

impl<C: Ciphersuite> Signature<C> {
    /// Assemble from parts.
    pub fn new(r: C::Element, z: Scalar) -> Self {
        Self { r, z }
    }

    /// The commitment `R`.
    pub fn r(&self) -> C::Element {
        self.r
    }

    /// The response `z`.
    pub fn z(&self) -> Scalar {
        self.z
    }

    /// `SerializeElement(R) || SerializeScalar(z)`. For Ed25519 this is the
    /// standard 64-byte RFC 8032 signature format.
    pub fn to_bytes(&self) -> Result<[u8; SIGNATURE_LEN]> {
        let mut out = [0u8; SIGNATURE_LEN];
        out[..32].copy_from_slice(&C::serialize_element(&self.r)?);
        out[32..].copy_from_slice(&serialize_scalar(&self.z));
        Ok(out)
    }

    /// Validated decoding of the canonical encoding.
    pub fn from_bytes(bytes: &[u8; SIGNATURE_LEN]) -> Result<Self> {
        let mut r = [0u8; 32];
        let mut z = [0u8; 32];
        r.copy_from_slice(&bytes[..32]);
        z.copy_from_slice(&bytes[32..]);
        Ok(Self { r: C::deserialize_element(&r)?, z: deserialize_scalar(&z)? })
    }
}

/// `compute_challenge(R, PK, msg) = H2(enc(R) || enc(PK) || msg)` (Section 4.6).
pub fn compute_challenge<C: Ciphersuite>(
    group_commitment: &C::Element,
    verifying_key: &VerifyingKey<C>,
    message: &[u8],
) -> Result<Scalar> {
    let r = C::serialize_element(group_commitment)?;
    let pk = verifying_key.serialize()?;
    Ok(C::h2(&[&r, &pk, message]))
}

impl<C: Ciphersuite> VerifyingKey<C> {
    /// Verify `signature` on `message`.
    ///
    /// Checks the cofactored equation `[h][z]B == [h]R + [h][c]PK`, which
    /// RFC 9591 mandates for Ed25519 (h = 8) and which reduces to
    /// `prime_order_verify` for ristretto255 (h = 1).
    pub fn verify(&self, message: &[u8], signature: &Signature<C>) -> Result<()> {
        let c = compute_challenge::<C>(&signature.r, self, message)?;
        let lhs = C::base_mul(&signature.z);
        let rhs = signature.r + self.0 * c;
        if C::clear_cofactor(&(lhs - rhs)) == C::Element::identity() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

/// `prime_order_sign(msg, sk)` (Appendix B): an ordinary single-party Schnorr
/// signature under the full secret key. Used in tests to show that threshold
/// and single-signer signatures verify identically.
pub fn single_signer_sign<C: Ciphersuite, R: RngCore + CryptoRng>(
    secret_key: &Scalar,
    message: &[u8],
    rng: &mut R,
) -> Result<Signature<C>> {
    let k = random_nonzero_scalar(rng);
    let r = C::base_mul(&k);
    let vk = VerifyingKey::<C>::new(C::base_mul(secret_key))?;
    let c = compute_challenge::<C>(&r, &vk, message)?;
    Ok(Signature { r, z: k + c * secret_key })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ciphersuite::{Ed25519Sha512, Ristretto255Sha512};
    use curve25519_dalek::constants::EIGHT_TORSION;
    use rand_core::OsRng;

    fn round_trip<C: Ciphersuite>() {
        let sk = random_nonzero_scalar(&mut OsRng);
        let vk = VerifyingKey::<C>::new(C::base_mul(&sk)).unwrap();
        let sig = single_signer_sign::<C, _>(&sk, b"hello", &mut OsRng).unwrap();
        vk.verify(b"hello", &sig).unwrap();
        assert_eq!(vk.verify(b"hellO", &sig), Err(Error::InvalidSignature));
        let bytes = sig.to_bytes().unwrap();
        assert_eq!(Signature::<C>::from_bytes(&bytes).unwrap(), sig);
        let tampered = Signature::<C>::new(sig.r(), sig.z() + Scalar::ONE);
        assert_eq!(vk.verify(b"hello", &tampered), Err(Error::InvalidSignature));
    }

    #[test]
    fn single_signer_round_trip_both_suites() {
        round_trip::<Ed25519Sha512>();
        round_trip::<Ristretto255Sha512>();
    }

    #[test]
    fn single_signer_ed25519_passes_dalek() {
        let sk = random_nonzero_scalar(&mut OsRng);
        let vk = VerifyingKey::<Ed25519Sha512>::new(Ed25519Sha512::base_mul(&sk)).unwrap();
        let sig = single_signer_sign::<Ed25519Sha512, _>(&sk, b"m", &mut OsRng).unwrap();
        let ok = Ed25519Sha512::reference_verify(&vk.serialize().unwrap(), b"m", &sig.to_bytes().unwrap());
        assert_eq!(ok, Some(true));
        assert_eq!(Ristretto255Sha512::reference_verify(&[0; 32], b"m", &[0; 64]), None);
    }

    #[test]
    fn cofactored_check_tolerates_torsion_in_r() {
        // A signature whose R carries a small-order component passes the
        // cofactored equation required by RFC 9591 6.1 (it is not canonical
        // FROST output, which never contains torsion).
        let sk = random_nonzero_scalar(&mut OsRng);
        let vk = VerifyingKey::<Ed25519Sha512>::new(Ed25519Sha512::base_mul(&sk)).unwrap();
        let k = random_nonzero_scalar(&mut OsRng);
        let r = Ed25519Sha512::base_mul(&k) + EIGHT_TORSION[1];
        let c = compute_challenge::<Ed25519Sha512>(&r, &vk, b"m").unwrap();
        let sig = Signature::<Ed25519Sha512>::new(r, k + c * sk);
        vk.verify(b"m", &sig).unwrap();
        // ...but such an R is refused at the encoding boundary.
        let bytes = sig.to_bytes().unwrap();
        assert_eq!(Signature::<Ed25519Sha512>::from_bytes(&bytes), Err(Error::MalformedElement));
    }

    #[test]
    fn malformed_signature_bytes_are_rejected() {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&Ed25519Sha512::encode_element(&Ed25519Sha512::generator()));
        bytes[32..].fill(0xff);
        assert_eq!(Signature::<Ed25519Sha512>::from_bytes(&bytes), Err(Error::MalformedScalar));
    }
}
