//! RFC 9591 Appendix E: every published intermediate value must be
//! reproduced exactly, for both implemented ciphersuites.

use frostsig::compat::{dalek_verify, dalek_verify_strict};
use frostsig::vectors::{check_bundled, check_vector, RfcVector, ED25519_VECTOR, RISTRETTO255_VECTOR};
use frostsig::{Ed25519Sha512, Ristretto255Sha512};

#[test]
fn all_bundled_vector_checks_pass() {
    let results = check_bundled().expect("vectors parse");
    assert_eq!(results.len(), 2);
    for (suite, checks) in results {
        let failed: Vec<_> = checks.iter().filter(|c| !c.passed).map(|c| c.step.clone()).collect();
        assert!(failed.is_empty(), "{suite}: failed steps {failed:?}");
        // Dealer (5) + per signer (2 x 9) + aggregate/verify (2) at least.
        assert!(checks.len() >= 23, "{suite}: only {} checks", checks.len());
    }
}

#[test]
fn ed25519_vector_signature_is_a_standard_ed25519_signature() {
    let v = RfcVector::parse(ED25519_VECTOR).unwrap();
    let pk: [u8; 32] = v.group_public_key.clone().try_into().unwrap();
    let sig: [u8; 64] = v.signature.clone().try_into().unwrap();
    assert!(dalek_verify(&pk, &v.message, &sig));
    assert!(dalek_verify_strict(&pk, &v.message, &sig));
    assert!(!dalek_verify_strict(&pk, b"tesT", &sig));
    let checks = check_vector::<Ed25519Sha512>(&v).unwrap();
    assert!(checks.iter().any(|c| c.step == "verify (ed25519-dalek, strict)" && c.passed));
}

#[test]
fn vectors_do_not_cross_verify_between_suites() {
    // The ristretto255 vector run under the Ed25519 suite must fail (or not
    // even decode): suites are domain separated.
    let v = RfcVector::parse(RISTRETTO255_VECTOR).unwrap();
    if let Ok(checks) = check_vector::<Ed25519Sha512>(&v) {
        assert!(checks.iter().any(|c| !c.passed));
    }
    let v = RfcVector::parse(ED25519_VECTOR).unwrap();
    if let Ok(checks) = check_vector::<Ristretto255Sha512>(&v) {
        assert!(checks.iter().any(|c| !c.passed));
    }
}
