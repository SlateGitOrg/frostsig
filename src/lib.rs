//! # frostsig
//!
//! FROST threshold Schnorr signatures as specified in
//! [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591), over
//! `FROST(Ed25519, SHA-512)` and `FROST(ristretto255, SHA-512)`, built on
//! `curve25519-dalek`.
//!
//! * key generation by a [trusted dealer](dealer) or by
//!   [distributed key generation](dkg) (Pedersen DKG with Feldman VSS);
//! * the [two-round signing protocol](signing) with nonce commitments,
//!   aggregation and signature-share verification for identifiable aborts;
//! * Ed25519 output that verifies under standard RFC 8032 verifiers
//!   ([`compat`]);
//! * a strict [wire format](wire) and a [participant simulator](sim) that
//!   runs every party on its own thread over local channels.
//!
//! ## Disclaimer
//!
//! This is an **educational implementation that has not been audited**. It
//! follows the RFC closely and is tested against its vectors, but it makes no
//! side-channel guarantees beyond those of `curve25519-dalek`, has no secure
//! transport, and stores keys unencrypted. Do not use it to protect real
//! assets.
//!
//! ## Example
//!
//! ```
//! use std::collections::BTreeMap;
//! use frostsig::{dealer, signing, Ed25519Sha512};
//!
//! let mut rng = rand_core::OsRng;
//! // 2-of-3 group from a trusted dealer.
//! let (shares, public) = dealer::trusted_dealer_keygen::<Ed25519Sha512, _>(2, 3, &mut rng)?;
//! let keys: BTreeMap<_, _> = shares
//!     .into_iter()
//!     .map(|(id, s)| Ok((id, s.verify()?)))
//!     .collect::<frostsig::Result<_>>()?;
//!
//! // Round one: participants 1 and 3 commit.
//! let signers: Vec<_> = keys.keys().copied().filter(|id| id.to_u16() != Some(2)).collect();
//! let mut nonces = BTreeMap::new();
//! let mut commitments = BTreeMap::new();
//! for id in &signers {
//!     let (n, c) = signing::commit(keys[id].signing_share(), &mut rng);
//!     nonces.insert(*id, n);
//!     commitments.insert(*id, c);
//! }
//!
//! // Round two: each signer produces a share; the coordinator aggregates.
//! let package = signing::SigningPackage::new(commitments, b"hello".to_vec());
//! let mut shares = BTreeMap::new();
//! for (id, n) in nonces {
//!     shares.insert(id, signing::sign(&package, n, &keys[&id])?);
//! }
//! let signature = signing::aggregate(&package, &shares, &public)?;
//! public.verifying_key().verify(b"hello", &signature)?;
//!
//! // The result is an ordinary Ed25519 signature.
//! assert!(frostsig::compat::dalek_verify_strict(
//!     &public.verifying_key().serialize()?,
//!     b"hello",
//!     &signature.to_bytes()?,
//! ));
//! # Ok::<(), frostsig::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod bench;
pub mod ciphersuite;
pub mod compat;
pub mod dealer;
pub mod dkg;
pub mod error;
pub mod identifier;
pub mod keys;
pub mod polynomial;
pub mod signature;
pub mod signing;
pub mod sim;
pub mod vectors;
pub mod wire;

pub use ciphersuite::{Ciphersuite, Ed25519Sha512, Ristretto255Sha512};
pub use error::{Error, Result};
pub use identifier::Identifier;
pub use keys::{KeyPackage, PublicKeyPackage, SecretShare, SigningShare, VerifyingKey, VerifyingShare};
pub use signature::Signature;
pub use signing::{SignatureShare, SigningCommitments, SigningNonces, SigningPackage};
