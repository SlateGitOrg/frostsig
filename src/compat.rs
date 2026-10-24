//! Interoperability with the standard Ed25519 ecosystem via `ed25519-dalek`.
//!
//! FROST(Ed25519, SHA-512) output is meant to be indistinguishable from an
//! ordinary RFC 8032 signature. These helpers verify that claim with an
//! independent implementation instead of this crate's own verifier.

use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey as DalekVerifyingKey};

/// Verify with `ed25519-dalek`'s `verify_strict`, which additionally rejects
/// small-order public keys and `R` values (stricter than RFC 8032).
pub fn dalek_verify_strict(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(vk) = DalekVerifyingKey::from_bytes(public_key) else {
        return false;
    };
    vk.verify_strict(message, &DalekSignature::from_bytes(signature)).is_ok()
}

/// Verify with `ed25519-dalek`'s default (RFC 8032 cofactorless) verifier,
/// the check most Ed25519 deployments run.
pub fn dalek_verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(vk) = DalekVerifyingKey::from_bytes(public_key) else {
        return false;
    };
    vk.verify(message, &DalekSignature::from_bytes(signature)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn verifies_native_dalek_signatures() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let sig = sk.sign(b"interop").to_bytes();
        let pk = sk.verifying_key().to_bytes();
        assert!(dalek_verify_strict(&pk, b"interop", &sig));
        assert!(dalek_verify(&pk, b"interop", &sig));
        assert!(!dalek_verify_strict(&pk, b"interop!", &sig));
        assert!(!dalek_verify(&pk, b"interop!", &sig));
    }

    #[test]
    fn rejects_undecodable_public_key() {
        // Find a y-coordinate with no matching x on the curve.
        let pk = (2u8..)
            .map(|y| {
                let mut b = [0u8; 32];
                b[0] = y;
                b
            })
            .find(|b| curve25519_dalek::edwards::CompressedEdwardsY(*b).decompress().is_none())
            .unwrap();
        assert!(!dalek_verify_strict(&pk, b"x", &[0u8; 64]));
        assert!(!dalek_verify(&pk, b"x", &[0u8; 64]));
    }
}
