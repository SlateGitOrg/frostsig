//! Error type shared by every module of the crate.

use crate::identifier::Identifier;

/// Convenience alias used throughout the crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Everything that can go wrong while generating keys, signing, aggregating
/// or decoding protocol messages.
///
/// Variants that carry `culprits` implement *identifiable abort*: the list
/// names the participants whose contribution failed verification, so the
/// caller can exclude them from future runs (RFC 9591, Section 5.4).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// `min_signers`/`max_signers` do not describe a usable threshold.
    #[error(
        "invalid threshold: min_signers={min_signers}, max_signers={max_signers} (need 2 <= min <= max)"
    )]
    InvalidThreshold {
        /// Requested threshold.
        min_signers: u16,
        /// Requested number of participants.
        max_signers: u16,
    },
    /// An identifier was zero or otherwise unusable.
    #[error("invalid identifier: identifiers must be non-zero scalars")]
    InvalidZeroIdentifier,
    /// The same identifier appeared twice in a list that must be duplicate free.
    #[error("duplicate identifier {0}")]
    DuplicateIdentifier(Identifier),
    /// An identifier was referenced that is not part of the relevant set.
    #[error("unknown participant {0}")]
    UnknownParticipant(Identifier),
    /// Bytes did not decode to a canonical scalar in `[0, L)`.
    #[error("malformed scalar encoding")]
    MalformedScalar,
    /// Bytes did not decode to a valid group element (non-canonical,
    /// off-curve, or outside the prime-order subgroup).
    #[error("malformed group element encoding")]
    MalformedElement,
    /// The identity element was supplied where RFC 9591 forbids it.
    #[error("identity element is not allowed here")]
    IdentityElement,
    /// Fewer signers than the threshold took part.
    #[error("not enough signers: need at least {needed}, got {got}")]
    NotEnoughSigners {
        /// The threshold.
        needed: u16,
        /// How many commitments were supplied.
        got: usize,
    },
    /// A signer was asked to sign a package that does not contain it.
    #[error("signing package does not include participant {0}")]
    MissingSigner(Identifier),
    /// The commitment in the signing package does not match the signer's own nonces.
    #[error("signing package carries a commitment for {0} that differs from the one it issued")]
    IncorrectCommitment(Identifier),
    /// A signature share is missing for a participant in the commitment list.
    #[error("missing signature share from participant {0}")]
    MissingSignatureShare(Identifier),
    /// One or more signature shares failed `verify_signature_share`.
    #[error("invalid signature shares from participants {}", fmt_ids(.culprits))]
    InvalidSignatureShares {
        /// Participants whose shares were rejected.
        culprits: Vec<Identifier>,
    },
    /// The aggregate signature failed verification.
    #[error("signature verification failed")]
    InvalidSignature,
    /// A secret share does not match its Feldman VSS commitment.
    #[error("secret share for participant {0} does not match the VSS commitment")]
    InvalidSecretShare(Identifier),
    /// Too few shares were supplied to reconstruct a secret.
    #[error("need at least {needed} shares to reconstruct, got {got}")]
    NotEnoughShares {
        /// The threshold.
        needed: u16,
        /// Shares supplied.
        got: usize,
    },
    /// DKG round 1: proofs of knowledge that failed to verify.
    #[error("DKG: invalid proof of knowledge from participants {}", fmt_ids(.culprits))]
    InvalidProofOfKnowledge {
        /// Participants whose round-1 proof was rejected.
        culprits: Vec<Identifier>,
    },
    /// DKG round 2: secret shares that do not match the sender's commitment.
    #[error("DKG: invalid secret shares from participants {}", fmt_ids(.culprits))]
    InvalidDkgShares {
        /// Participants that sent an inconsistent share.
        culprits: Vec<Identifier>,
    },
    /// The number of packages received does not match the protocol requirement.
    #[error("expected {expected} packages, received {got}")]
    IncorrectPackageCount {
        /// Packages required.
        expected: usize,
        /// Packages received.
        got: usize,
    },
    /// A VSS commitment has the wrong number of coefficients.
    #[error("VSS commitment has {got} coefficients, expected {expected}")]
    IncorrectCommitmentLength {
        /// Expected coefficient count (the threshold).
        expected: usize,
        /// Actual coefficient count.
        got: usize,
    },
    /// The wire decoder rejected its input.
    #[error("decode error: {0}")]
    Decode(&'static str),
    /// A message for one ciphersuite was fed to another.
    #[error("ciphersuite mismatch: expected wire id {expected}, found {found}")]
    SuiteMismatch {
        /// Wire id of the suite in use.
        expected: u8,
        /// Wire id carried by the message.
        found: u8,
    },
    /// A test-vector file was malformed or a vector check failed.
    #[error("test vector: {0}")]
    Vector(String),
    /// A simulation or CLI configuration was rejected.
    #[error("configuration: {0}")]
    Config(String),
}

fn fmt_ids(ids: &[Identifier]) -> String {
    ids.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn culprit_lists_render_readably() {
        let e = Error::InvalidSignatureShares {
            culprits: vec![Identifier::try_from(2).unwrap(), Identifier::try_from(5).unwrap()],
        };
        assert_eq!(e.to_string(), "invalid signature shares from participants 2, 5");
    }
}
