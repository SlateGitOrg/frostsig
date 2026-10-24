//! Ciphersuite abstraction (RFC 9591, Section 6) and the two suites this crate
//! implements: `FROST(Ed25519, SHA-512)` and `FROST(ristretto255, SHA-512)`.
//!
//! Both suites share the scalar field of curve25519 (order
//! `L = 2^252 + 27742317777372353535851937790883648493`), so scalars are always
//! [`curve25519_dalek::Scalar`]; only the group element type, the element
//! encoding and the `H2` challenge hash differ.

use core::fmt::Debug;
use core::ops::{Add, Mul, Neg, Sub};

use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, RISTRETTO_BASEPOINT_POINT};
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::traits::{Identity, VartimeMultiscalarMul};
use curve25519_dalek::Scalar;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

use crate::error::{Error, Result};

/// Length in bytes of a serialized scalar (`Ns`).
pub const SCALAR_LEN: usize = 32;
/// Length in bytes of a serialized group element (`Ne`).
pub const ELEMENT_LEN: usize = 32;

/// A FROST ciphersuite: a prime-order group plus the hash functions H1..H5.
///
/// Implementors only provide the group-specific primitives; the hash
/// functions that are identical across both curve25519 suites are provided
/// methods.
pub trait Ciphersuite:
    Copy + Clone + Debug + Default + PartialEq + Eq + Send + Sync + 'static
{
    /// Group element type.
    type Element: Copy
        + Clone
        + Debug
        + PartialEq
        + Eq
        + Send
        + Sync
        + 'static
        + Identity
        + Add<Output = Self::Element>
        + Sub<Output = Self::Element>
        + Neg<Output = Self::Element>
        + Mul<Scalar, Output = Self::Element>
        + VartimeMultiscalarMul<Point = Self::Element>;

    /// Human-readable suite name as written in the RFC.
    const NAME: &'static str;
    /// The RFC `contextString` used for domain separation.
    const CONTEXT_STRING: &'static str;
    /// Short name used by the CLI and in key files.
    const SHORT_NAME: &'static str;
    /// One-byte identifier used in the wire format.
    const WIRE_ID: u8;

    /// The fixed generator `B`.
    fn generator() -> Self::Element;

    /// `G.ScalarBaseMult(s)`.
    fn base_mul(s: &Scalar) -> Self::Element;

    /// Raw encoding of an element, without the RFC's identity check.
    fn encode_element(e: &Self::Element) -> [u8; ELEMENT_LEN];

    /// Raw decoding of an element with all suite-specific validation
    /// (canonical encoding, prime-order subgroup) except the identity check.
    fn decode_element(bytes: &[u8; ELEMENT_LEN]) -> Option<Self::Element>;

    /// `H2`: the signature challenge hash.
    fn h2(parts: &[&[u8]]) -> Scalar;

    /// Multiply by the cofactor (identity map for prime-order groups).
    fn clear_cofactor(e: &Self::Element) -> Self::Element;

    /// Verify a serialized signature with an independent, widely used
    /// implementation of the target scheme, when one exists.
    ///
    /// For Ed25519 this calls `ed25519-dalek`'s strict RFC 8032 verifier;
    /// ristretto255 has no external standard verifier and returns `None`.
    fn reference_verify(
        _public_key: &[u8; ELEMENT_LEN],
        _message: &[u8],
        _signature: &[u8; 64],
    ) -> Option<bool> {
        None
    }

    /// `H1`: binding-factor hash, `H(contextString || "rho" || m) mod L`.
    fn h1(parts: &[&[u8]]) -> Scalar {
        hash_to_scalar(&[Self::CONTEXT_STRING.as_bytes(), b"rho"], parts)
    }

    /// `H3`: nonce-derivation hash, `H(contextString || "nonce" || m) mod L`.
    fn h3(parts: &[&[u8]]) -> Scalar {
        hash_to_scalar(&[Self::CONTEXT_STRING.as_bytes(), b"nonce"], parts)
    }

    /// `H4`: message hash, `H(contextString || "msg" || m)`.
    fn h4(parts: &[&[u8]]) -> [u8; 64] {
        hash_wide(&[Self::CONTEXT_STRING.as_bytes(), b"msg"], parts)
    }

    /// `H5`: commitment-list hash, `H(contextString || "com" || m)`.
    fn h5(parts: &[&[u8]]) -> [u8; 64] {
        hash_wide(&[Self::CONTEXT_STRING.as_bytes(), b"com"], parts)
    }

    /// `HDKG`: challenge hash for the DKG proof of knowledge,
    /// `H(contextString || "dkg" || m) mod L`. Not part of RFC 9591, which
    /// leaves DKG unspecified; see `DECISIONS.md`.
    fn hdkg(parts: &[&[u8]]) -> Scalar {
        hash_to_scalar(&[Self::CONTEXT_STRING.as_bytes(), b"dkg"], parts)
    }

    /// `G.SerializeElement`: rejects the identity element.
    fn serialize_element(e: &Self::Element) -> Result<[u8; ELEMENT_LEN]> {
        if *e == Self::Element::identity() {
            return Err(Error::IdentityElement);
        }
        Ok(Self::encode_element(e))
    }

    /// `G.DeserializeElement`: full validation including the identity check.
    fn deserialize_element(bytes: &[u8; ELEMENT_LEN]) -> Result<Self::Element> {
        let e = Self::decode_element(bytes).ok_or(Error::MalformedElement)?;
        if e == Self::Element::identity() {
            return Err(Error::IdentityElement);
        }
        Ok(e)
    }
}

/// `G.SerializeScalar`: 32-byte little-endian encoding.
pub fn serialize_scalar(s: &Scalar) -> [u8; SCALAR_LEN] {
    s.to_bytes()
}

/// `G.DeserializeScalar`: rejects encodings of values `>= L`.
pub fn deserialize_scalar(bytes: &[u8; SCALAR_LEN]) -> Result<Scalar> {
    Option::from(Scalar::from_canonical_bytes(*bytes)).ok_or(Error::MalformedScalar)
}

/// `G.RandomScalar` by wide reduction (RFC 9591 Appendix D.2): 64 random
/// bytes reduced modulo `L`, statistically indistinguishable from uniform.
pub fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
    Scalar::random(rng)
}

/// A uniformly random scalar that is not zero (used for secrets, where a zero
/// value would yield the unserializable identity public key).
pub fn random_nonzero_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
    loop {
        let s = Scalar::random(rng);
        if s != Scalar::ZERO {
            return s;
        }
    }
}

fn hash_wide(prefix: &[&[u8]], parts: &[&[u8]]) -> [u8; 64] {
    let mut h = Sha512::new();
    for p in prefix.iter().chain(parts) {
        h.update(p);
    }
    h.finalize().into()
}

fn hash_to_scalar(prefix: &[&[u8]], parts: &[&[u8]]) -> Scalar {
    Scalar::from_bytes_mod_order_wide(&hash_wide(prefix, parts))
}

/// `FROST(Ed25519, SHA-512)`: produces signatures verifiable by any RFC 8032
/// Ed25519 verifier.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Ed25519Sha512;

impl Ciphersuite for Ed25519Sha512 {
    type Element = EdwardsPoint;

    const NAME: &'static str = "FROST(Ed25519, SHA-512)";
    const CONTEXT_STRING: &'static str = "FROST-ED25519-SHA512-v1";
    const SHORT_NAME: &'static str = "ed25519";
    const WIRE_ID: u8 = 1;

    fn generator() -> EdwardsPoint {
        ED25519_BASEPOINT_POINT
    }

    fn base_mul(s: &Scalar) -> EdwardsPoint {
        EdwardsPoint::mul_base(s)
    }

    fn encode_element(e: &EdwardsPoint) -> [u8; ELEMENT_LEN] {
        e.compress().to_bytes()
    }

    fn decode_element(bytes: &[u8; ELEMENT_LEN]) -> Option<EdwardsPoint> {
        let p = CompressedEdwardsY(*bytes).decompress()?;
        // RFC 8032 5.1.3 rejects y >= p and the (x = 0, sign = 1) encoding;
        // curve25519-dalek accepts both, so insist on a canonical round trip.
        if p.compress().to_bytes() != *bytes {
            return None;
        }
        // RFC 9591 6.1: the element must lie in the prime-order subgroup.
        if !p.is_torsion_free() {
            return None;
        }
        Some(p)
    }

    fn h2(parts: &[&[u8]]) -> Scalar {
        // No domain separation, for RFC 8032 compatibility (RFC 9591 6.1).
        hash_to_scalar(&[], parts)
    }

    fn clear_cofactor(e: &EdwardsPoint) -> EdwardsPoint {
        e.mul_by_cofactor()
    }

    fn reference_verify(
        public_key: &[u8; ELEMENT_LEN],
        message: &[u8],
        signature: &[u8; 64],
    ) -> Option<bool> {
        Some(crate::compat::dalek_verify_strict(public_key, message, signature))
    }
}

/// `FROST(ristretto255, SHA-512)`: the RFC's RECOMMENDED suite.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Ristretto255Sha512;

impl Ciphersuite for Ristretto255Sha512 {
    type Element = RistrettoPoint;

    const NAME: &'static str = "FROST(ristretto255, SHA-512)";
    const CONTEXT_STRING: &'static str = "FROST-RISTRETTO255-SHA512-v1";
    const SHORT_NAME: &'static str = "ristretto255";
    const WIRE_ID: u8 = 2;

    fn generator() -> RistrettoPoint {
        RISTRETTO_BASEPOINT_POINT
    }

    fn base_mul(s: &Scalar) -> RistrettoPoint {
        RistrettoPoint::mul_base(s)
    }

    fn encode_element(e: &RistrettoPoint) -> [u8; ELEMENT_LEN] {
        e.compress().to_bytes()
    }

    fn decode_element(bytes: &[u8; ELEMENT_LEN]) -> Option<RistrettoPoint> {
        // The ristretto255 Decode function is canonical by construction.
        CompressedRistretto(*bytes).decompress()
    }

    fn h2(parts: &[&[u8]]) -> Scalar {
        hash_to_scalar(&[Self::CONTEXT_STRING.as_bytes(), b"chal"], parts)
    }

    fn clear_cofactor(e: &RistrettoPoint) -> RistrettoPoint {
        *e
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::EIGHT_TORSION;

    #[test]
    fn scalar_round_trip_and_rejects_unreduced() {
        let s = Scalar::from(123_456_789u64);
        assert_eq!(deserialize_scalar(&serialize_scalar(&s)).unwrap(), s);
        // L itself (little-endian) is not a canonical scalar.
        let l = hex::decode("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
            .unwrap();
        let l: [u8; 32] = l.try_into().unwrap();
        assert_eq!(deserialize_scalar(&l), Err(Error::MalformedScalar));
        assert_eq!(deserialize_scalar(&[0xff; 32]), Err(Error::MalformedScalar));
    }

    #[test]
    fn identity_is_rejected_both_ways() {
        let id = EdwardsPoint::identity();
        assert_eq!(Ed25519Sha512::serialize_element(&id), Err(Error::IdentityElement));
        let enc = Ed25519Sha512::encode_element(&id);
        assert_eq!(Ed25519Sha512::deserialize_element(&enc), Err(Error::IdentityElement));

        let rid = RistrettoPoint::identity();
        assert_eq!(Ristretto255Sha512::serialize_element(&rid), Err(Error::IdentityElement));
        let renc = Ristretto255Sha512::encode_element(&rid);
        assert_eq!(Ristretto255Sha512::deserialize_element(&renc), Err(Error::IdentityElement));
    }

    #[test]
    fn small_order_and_mixed_order_points_are_rejected() {
        for t in EIGHT_TORSION.iter().skip(1) {
            let enc = t.compress().to_bytes();
            assert_eq!(Ed25519Sha512::deserialize_element(&enc), Err(Error::MalformedElement));
            let mixed = ED25519_BASEPOINT_POINT + t;
            let enc = mixed.compress().to_bytes();
            assert_eq!(Ed25519Sha512::deserialize_element(&enc), Err(Error::MalformedElement));
        }
    }

    #[test]
    fn non_canonical_edwards_encoding_is_rejected() {
        // y = p + 1 (non-canonical encoding of y = 1, the identity's y).
        let mut enc = [0u8; 32];
        enc[0] = 0xee;
        enc[1..31].fill(0xff);
        enc[31] = 0x7f;
        assert_eq!(Ed25519Sha512::deserialize_element(&enc), Err(Error::MalformedElement));
        // x = 0 with the sign bit set: (0, 1) encoded with sign 1.
        let mut enc = [0u8; 32];
        enc[0] = 1;
        enc[31] = 0x80;
        assert_eq!(Ed25519Sha512::deserialize_element(&enc), Err(Error::MalformedElement));
    }

    #[test]
    fn non_canonical_ristretto_encoding_is_rejected() {
        let mut enc = Ristretto255Sha512::encode_element(&RISTRETTO_BASEPOINT_POINT);
        enc[31] |= 0x80;
        assert_eq!(Ristretto255Sha512::deserialize_element(&enc), Err(Error::MalformedElement));
    }

    #[test]
    fn generator_round_trips() {
        let g = Ed25519Sha512::serialize_element(&Ed25519Sha512::generator()).unwrap();
        assert_eq!(Ed25519Sha512::deserialize_element(&g).unwrap(), Ed25519Sha512::generator());
        let g = Ristretto255Sha512::serialize_element(&Ristretto255Sha512::generator()).unwrap();
        assert_eq!(
            Ristretto255Sha512::deserialize_element(&g).unwrap(),
            Ristretto255Sha512::generator()
        );
    }

    #[test]
    fn hashes_are_domain_separated() {
        let m: &[&[u8]] = &[b"abc"];
        assert_ne!(Ed25519Sha512::h1(m), Ristretto255Sha512::h1(m));
        assert_ne!(Ed25519Sha512::h1(m), Ed25519Sha512::h3(m));
        assert_ne!(Ed25519Sha512::h4(m), Ed25519Sha512::h5(m));
        assert_ne!(Ed25519Sha512::hdkg(m), Ed25519Sha512::h1(m));
        // Ed25519's H2 is plain SHA-512 mod L.
        let plain = Scalar::from_bytes_mod_order_wide(&Sha512::digest(b"abc").into());
        assert_eq!(Ed25519Sha512::h2(m), plain);
        assert_ne!(Ristretto255Sha512::h2(m), plain);
        // Splitting the input across parts does not change the hash.
        assert_eq!(Ed25519Sha512::h1(&[b"a", b"bc"]), Ed25519Sha512::h1(m));
    }

    #[test]
    fn random_scalars_are_nonzero_and_distinct() {
        let mut rng = rand_core::OsRng;
        let a = random_nonzero_scalar(&mut rng);
        let b = random_scalar(&mut rng);
        assert_ne!(a, Scalar::ZERO);
        assert_ne!(a, b);
    }
}
