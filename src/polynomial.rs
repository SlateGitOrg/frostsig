//! Polynomial arithmetic over the scalar field: Horner evaluation, Lagrange
//! coefficients and Shamir reconstruction (RFC 9591 Sections 4.2 and C.1).

use std::collections::BTreeSet;

use curve25519_dalek::Scalar;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ciphersuite::{random_scalar, Ciphersuite};
use crate::error::{Error, Result};
use crate::identifier::Identifier;
use crate::keys::VssCommitment;

/// `polynomial_evaluate(x, coeffs)` by Horner's method; `coeffs[0]` is the
/// constant term. `O(len(coeffs))` field operations.
pub fn evaluate(coefficients: &[Scalar], x: &Scalar) -> Scalar {
    coefficients.iter().rev().fold(Scalar::ZERO, |acc, c| acc * x + c)
}

/// `derive_interpolating_value(L, x_i)`: the Lagrange coefficient
/// `lambda_i = prod_{j != i} x_j / (x_j - x_i)` evaluated at zero.
///
/// Errors if `x_i` is not in `ids` or if `ids` contains duplicates.
/// `O(n log n)` for the duplicate check plus `O(n)` field multiplications and
/// one inversion.
pub fn derive_interpolating_value(ids: &[Identifier], x_i: &Identifier) -> Result<Scalar> {
    if !ids.contains(x_i) {
        return Err(Error::UnknownParticipant(*x_i));
    }
    let mut seen = BTreeSet::new();
    for id in ids {
        if !seen.insert(*id) {
            return Err(Error::DuplicateIdentifier(*id));
        }
    }
    let xi = x_i.to_scalar();
    let mut numerator = Scalar::ONE;
    let mut denominator = Scalar::ONE;
    for id in ids {
        if id == x_i {
            continue;
        }
        let xj = id.to_scalar();
        numerator *= xj;
        denominator *= xj - xi;
    }
    // Distinct non-zero identifiers make the denominator non-zero.
    Ok(numerator * denominator.invert())
}

/// `polynomial_interpolate_constant(points)`: recover `f(0)` from points on `f`.
pub fn interpolate_constant(points: &[(Identifier, Scalar)]) -> Result<Scalar> {
    let ids: Vec<Identifier> = points.iter().map(|(id, _)| *id).collect();
    let mut acc = Scalar::ZERO;
    for (id, y) in points {
        acc += y * derive_interpolating_value(&ids, id)?;
    }
    Ok(acc)
}

/// A secret polynomial `f` of degree `t - 1` whose constant term is the
/// secret being shared. Coefficients are wiped on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretPolynomial {
    coefficients: Vec<Scalar>,
}

impl core::fmt::Debug for SecretPolynomial {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecretPolynomial(degree={}, <redacted>)", self.coefficients.len() - 1)
    }
}

impl SecretPolynomial {
    /// `[secret] + coefficients`, as built by `secret_share_shard`.
    ///
    /// `coefficients` holds the `min_signers - 1` non-constant terms.
    pub fn new(secret: Scalar, coefficients: Vec<Scalar>) -> Self {
        let mut all = Vec::with_capacity(coefficients.len() + 1);
        all.push(secret);
        all.extend(coefficients);
        Self { coefficients: all }
    }

    /// A polynomial with the given constant term and `min_signers - 1`
    /// uniformly random higher-order coefficients.
    pub fn random<R: RngCore + CryptoRng>(secret: Scalar, min_signers: u16, rng: &mut R) -> Self {
        let rest = (1..min_signers).map(|_| random_scalar(rng)).collect();
        Self::new(secret, rest)
    }

    /// `f(id)`.
    pub fn evaluate(&self, id: &Identifier) -> Scalar {
        evaluate(&self.coefficients, &id.to_scalar())
    }

    /// The constant term `f(0)`.
    pub fn secret(&self) -> &Scalar {
        &self.coefficients[0]
    }

    /// Number of coefficients, i.e. the threshold `t`.
    pub fn len(&self) -> usize {
        self.coefficients.len()
    }

    /// Always false: a polynomial has at least its constant term.
    pub fn is_empty(&self) -> bool {
        self.coefficients.is_empty()
    }

    /// `vss_commit(coeffs)`: `[a_0 B, a_1 B, ..., a_{t-1} B]`.
    pub fn commit<C: Ciphersuite>(&self) -> VssCommitment<C> {
        VssCommitment::from_elements_unchecked(self.coefficients.iter().map(C::base_mul).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(i: u16) -> Identifier {
        Identifier::try_from(i).unwrap()
    }

    #[test]
    fn horner_matches_rfc_example() {
        // x^2 + 2x + 3 at x = 5 is 38.
        let c = [Scalar::from(3u8), Scalar::from(2u8), Scalar::from(1u8)];
        assert_eq!(evaluate(&c, &Scalar::from(5u8)), Scalar::from(38u8));
        assert_eq!(evaluate(&[], &Scalar::from(5u8)), Scalar::ZERO);
    }

    #[test]
    fn interpolation_recovers_constant_term() {
        let poly = SecretPolynomial::new(Scalar::from(42u8), vec![Scalar::from(7u8), Scalar::from(9u8)]);
        let points: Vec<_> = [2u16, 5, 9].iter().map(|&i| (id(i), poly.evaluate(&id(i)))).collect();
        assert_eq!(interpolate_constant(&points).unwrap(), Scalar::from(42u8));
        // Too few points give a different (wrong) value, not an error.
        assert_ne!(interpolate_constant(&points[..2]).unwrap(), Scalar::from(42u8));
    }

    #[test]
    fn interpolating_value_errors() {
        assert_eq!(
            derive_interpolating_value(&[id(1), id(2)], &id(3)),
            Err(Error::UnknownParticipant(id(3)))
        );
        assert_eq!(
            derive_interpolating_value(&[id(1), id(2), id(1)], &id(2)),
            Err(Error::DuplicateIdentifier(id(1)))
        );
    }

    #[test]
    fn lagrange_coefficients_sum_to_one() {
        let ids = [id(1), id(3), id(4), id(10)];
        let sum: Scalar = ids.iter().map(|i| derive_interpolating_value(&ids, i).unwrap()).sum();
        assert_eq!(sum, Scalar::ONE);
    }

    #[test]
    fn debug_does_not_leak_coefficients() {
        let poly = SecretPolynomial::new(Scalar::from(42u8), vec![Scalar::from(7u8)]);
        assert_eq!(format!("{poly:?}"), "SecretPolynomial(degree=1, <redacted>)");
        assert_eq!(poly.len(), 2);
        assert!(!poly.is_empty());
    }
}
