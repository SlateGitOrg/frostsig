//! Participant identifiers: non-zero scalars (`NonZeroScalar` in RFC 9591).

use core::cmp::Ordering;
use core::fmt;

use curve25519_dalek::Scalar;

use crate::ciphersuite::{deserialize_scalar, serialize_scalar, SCALAR_LEN};
use crate::error::{Error, Result};

/// A participant identifier: the x-coordinate at which that participant's
/// Shamir share is evaluated. Never zero, because `f(0)` is the group secret.
///
/// Identifiers are ordered by their numeric value, which is the order the RFC
/// requires for commitment lists.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct Identifier(Scalar);

impl Identifier {
    /// Wrap a scalar, rejecting zero.
    pub fn from_scalar(s: Scalar) -> Result<Self> {
        if s == Scalar::ZERO {
            Err(Error::InvalidZeroIdentifier)
        } else {
            Ok(Self(s))
        }
    }

    /// The identifier as a scalar.
    pub fn to_scalar(&self) -> Scalar {
        self.0
    }

    /// `G.SerializeScalar(identifier)`.
    pub fn serialize(&self) -> [u8; SCALAR_LEN] {
        serialize_scalar(&self.0)
    }

    /// Decode and validate (canonical and non-zero).
    pub fn deserialize(bytes: &[u8; SCALAR_LEN]) -> Result<Self> {
        Self::from_scalar(deserialize_scalar(bytes)?)
    }

    /// The identifier as a small integer, if it fits in 16 bits.
    ///
    /// All identifiers produced by this crate's key generation are `1..=n`.
    pub fn to_u16(&self) -> Option<u16> {
        let b = self.0.as_bytes();
        if b[2..].iter().all(|&x| x == 0) {
            Some(u16::from_le_bytes([b[0], b[1]]))
        } else {
            None
        }
    }

    /// Identifiers `1..=n`, the set used by trusted-dealer and DKG key generation.
    pub fn range(n: u16) -> impl Iterator<Item = Identifier> {
        (1..=n).map(|i| Identifier(Scalar::from(i)))
    }
}

impl TryFrom<u16> for Identifier {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self> {
        Self::from_scalar(Scalar::from(value))
    }
}

impl Ord for Identifier {
    fn cmp(&self, other: &Self) -> Ordering {
        // Scalars are little-endian; compare from the most significant byte.
        self.0
            .as_bytes()
            .iter()
            .rev()
            .cmp(other.0.as_bytes().iter().rev())
    }
}

impl PartialOrd for Identifier {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_u16() {
            Some(v) => write!(f, "{v}"),
            None => {
                let mut be = self.serialize();
                be.reverse();
                write!(f, "0x{}", hex::encode(be))
            }
        }
    }
}

impl fmt::Debug for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Identifier({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_is_rejected() {
        assert_eq!(Identifier::try_from(0), Err(Error::InvalidZeroIdentifier));
        assert_eq!(Identifier::deserialize(&[0; 32]), Err(Error::InvalidZeroIdentifier));
    }

    #[test]
    fn ordering_is_numeric_not_bytewise() {
        let a = Identifier::try_from(255).unwrap();
        let b = Identifier::try_from(256).unwrap();
        assert!(a < b, "256 must sort after 255 even though its low byte is 0");
        let big = Identifier::from_scalar(-Scalar::ONE).unwrap();
        assert!(b < big);
    }

    #[test]
    fn round_trip_and_display() {
        let id = Identifier::try_from(4242).unwrap();
        assert_eq!(Identifier::deserialize(&id.serialize()).unwrap(), id);
        assert_eq!(id.to_string(), "4242");
        assert_eq!(format!("{id:?}"), "Identifier(4242)");
        let big = Identifier::from_scalar(Scalar::from(1u64 << 40)).unwrap();
        assert_eq!(big.to_u16(), None);
        assert_eq!(big.to_string(), format!("0x{}{}", "0".repeat(52), "010000000000"));
    }

    #[test]
    fn range_yields_one_to_n() {
        let ids: Vec<u16> = Identifier::range(4).map(|i| i.to_u16().unwrap()).collect();
        assert_eq!(ids, vec![1, 2, 3, 4]);
    }
}
