//! RFC 9591 Appendix E test vectors: a parser for the key/value excerpts in
//! `vectors/` and a step-by-step checker that recomputes every published
//! intermediate value.
//!
//! The excerpts are embedded at compile time, so the CLI's `vectors`
//! command and the test-suite both work from any directory.

use std::collections::BTreeMap;

use curve25519_dalek::Scalar;

use crate::ciphersuite::{deserialize_scalar, Ciphersuite, Ed25519Sha512, Ristretto255Sha512};
use crate::dealer::{reconstruct, split};
use crate::error::{Error, Result};
use crate::identifier::Identifier;
use crate::keys::SigningShare;
use crate::polynomial::SecretPolynomial;
use crate::signature::Signature;
use crate::signing::{
    aggregate, binding_factor_inputs, compute_binding_factors, nonce_generate_from_randomness, sign,
    verify_signature_share, SigningNonces, SigningPackage,
};

/// The Appendix E.1 excerpt for FROST(Ed25519, SHA-512).
pub const ED25519_VECTOR: &str = include_str!("../vectors/rfc9591-ed25519-sha512.txt");
/// The Appendix E.3 excerpt for FROST(ristretto255, SHA-512).
pub const RISTRETTO255_VECTOR: &str = include_str!("../vectors/rfc9591-ristretto255-sha512.txt");

/// Per-signer round-one data from a vector.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignerVector {
    /// `hiding_nonce_randomness`.
    pub hiding_nonce_randomness: Vec<u8>,
    /// `binding_nonce_randomness`.
    pub binding_nonce_randomness: Vec<u8>,
    /// `hiding_nonce`.
    pub hiding_nonce: Vec<u8>,
    /// `binding_nonce`.
    pub binding_nonce: Vec<u8>,
    /// `hiding_nonce_commitment`.
    pub hiding_nonce_commitment: Vec<u8>,
    /// `binding_nonce_commitment`.
    pub binding_nonce_commitment: Vec<u8>,
    /// `binding_factor_input`.
    pub binding_factor_input: Vec<u8>,
    /// `binding_factor`.
    pub binding_factor: Vec<u8>,
    /// `sig_share`.
    pub sig_share: Vec<u8>,
}

/// One parsed Appendix E vector.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RfcVector {
    /// `MAX_PARTICIPANTS`.
    pub max_participants: u16,
    /// `MIN_PARTICIPANTS`.
    pub min_participants: u16,
    /// `participant_list`.
    pub participant_list: Vec<u16>,
    /// `group_secret_key`.
    pub group_secret_key: Vec<u8>,
    /// `group_public_key`.
    pub group_public_key: Vec<u8>,
    /// `message`.
    pub message: Vec<u8>,
    /// `share_polynomial_coefficients[1..]`.
    pub coefficients: Vec<Vec<u8>>,
    /// `P<i> participant_share`.
    pub participant_shares: BTreeMap<u16, Vec<u8>>,
    /// Round-one and round-two data per signer.
    pub signers: BTreeMap<u16, SignerVector>,
    /// The final `sig`.
    pub signature: Vec<u8>,
}

fn bad(msg: impl Into<String>) -> Error {
    Error::Vector(msg.into())
}

fn hex_field(key: &str, value: &str) -> Result<Vec<u8>> {
    hex::decode(value).map_err(|e| bad(format!("{key}: invalid hex ({e})")))
}

fn int_field(key: &str, value: &str) -> Result<u16> {
    value.parse().map_err(|_| bad(format!("{key}: not an integer")))
}

impl RfcVector {
    /// Parse the `key: value` excerpt format written by
    /// `scripts/extract-vectors.sh`.
    pub fn parse(text: &str) -> Result<Self> {
        let mut v = RfcVector::default();
        for (lineno, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = line
                .split_once(": ")
                .ok_or_else(|| bad(format!("line {}: expected `key: value`", lineno + 1)))?;
            match key {
                "MAX_PARTICIPANTS" => v.max_participants = int_field(key, value)?,
                "MIN_PARTICIPANTS" => v.min_participants = int_field(key, value)?,
                "NUM_PARTICIPANTS" => {}
                "participant_list" => {
                    v.participant_list =
                        value.split(',').map(|s| int_field(key, s.trim())).collect::<Result<_>>()?;
                }
                "group_secret_key" => v.group_secret_key = hex_field(key, value)?,
                "group_public_key" => v.group_public_key = hex_field(key, value)?,
                "message" => v.message = hex_field(key, value)?,
                "sig" => v.signature = hex_field(key, value)?,
                k if k.starts_with("share_polynomial_coefficients[") => {
                    v.coefficients.push(hex_field(key, value)?);
                }
                k if k.starts_with('P') => v.parse_participant_field(k, value)?,
                other => return Err(bad(format!("unknown key `{other}`"))),
            }
        }
        if v.max_participants == 0 || v.signature.is_empty() || v.participant_list.is_empty() {
            return Err(bad("vector is missing required fields"));
        }
        Ok(v)
    }

    fn parse_participant_field(&mut self, key: &str, value: &str) -> Result<()> {
        let (who, field) = key.split_once(' ').ok_or_else(|| bad(format!("bad key `{key}`")))?;
        let idx = int_field(key, &who[1..])?;
        let bytes = hex_field(key, value)?;
        if field == "participant_share" {
            self.participant_shares.insert(idx, bytes);
            return Ok(());
        }
        let s = self.signers.entry(idx).or_default();
        let slot = match field {
            "hiding_nonce_randomness" => &mut s.hiding_nonce_randomness,
            "binding_nonce_randomness" => &mut s.binding_nonce_randomness,
            "hiding_nonce" => &mut s.hiding_nonce,
            "binding_nonce" => &mut s.binding_nonce,
            "hiding_nonce_commitment" => &mut s.hiding_nonce_commitment,
            "binding_nonce_commitment" => &mut s.binding_nonce_commitment,
            "binding_factor_input" => &mut s.binding_factor_input,
            "binding_factor" => &mut s.binding_factor,
            "sig_share" => &mut s.sig_share,
            other => return Err(bad(format!("unknown participant field `{other}`"))),
        };
        *slot = bytes;
        Ok(())
    }
}

/// The outcome of one recomputed step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VectorCheck {
    /// What was checked, e.g. `P1 binding_factor`.
    pub step: String,
    /// Whether the recomputed value equals the published one.
    pub passed: bool,
}

fn arr32(key: &str, b: &[u8]) -> Result<[u8; 32]> {
    b.try_into().map_err(|_| bad(format!("{key}: expected 32 bytes, got {}", b.len())))
}

fn scalar(key: &str, b: &[u8]) -> Result<Scalar> {
    deserialize_scalar(&arr32(key, b)?)
}

/// Recompute every published value of `vector` under suite `C` and report
/// each comparison. Errors only if the vector itself is malformed.
pub fn check_vector<C: Ciphersuite>(vector: &RfcVector) -> Result<Vec<VectorCheck>> {
    let mut checks = Vec::new();
    let mut record = |step: String, passed: bool| checks.push(VectorCheck { step, passed });

    // Trusted dealer: shares and group key from the fixed polynomial.
    let secret = scalar("group_secret_key", &vector.group_secret_key)?;
    let coefficients = vector
        .coefficients
        .iter()
        .map(|c| scalar("share_polynomial_coefficients", c))
        .collect::<Result<Vec<_>>>()?;
    let polynomial = SecretPolynomial::new(secret, coefficients);
    let (shares, public) = split::<C>(&polynomial, vector.max_participants)?;
    record(
        "group_public_key".into(),
        public.verifying_key().serialize()?.as_slice() == vector.group_public_key.as_slice(),
    );
    for (i, expected) in &vector.participant_shares {
        let id = Identifier::try_from(*i)?;
        let got = shares.get(&id).map(|s| s.signing_share.to_scalar().to_bytes());
        record(
            format!("P{i} participant_share"),
            got.as_ref().map(|g| g.as_slice()) == Some(expected.as_slice()),
        );
    }

    // secret_share_combine over the signing set recovers the group secret.
    let signer_shares = vector
        .participant_list
        .iter()
        .map(|i| {
            let id = Identifier::try_from(*i)?;
            let share = vector.participant_shares.get(i).ok_or_else(|| bad(format!("no share for P{i}")))?;
            Ok((id, SigningShare::new(scalar("participant_share", share)?)))
        })
        .collect::<Result<Vec<_>>>()?;
    record("secret_share_combine".into(), reconstruct(vector.min_participants, &signer_shares)? == secret);

    // Round one: nonces from the published randomness, then commitments.
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for (id, share) in &signer_shares {
        let i = id.to_u16().unwrap_or(0);
        let sv = vector.signers.get(&i).ok_or_else(|| bad(format!("no round data for P{i}")))?;
        let hr = arr32("hiding_nonce_randomness", &sv.hiding_nonce_randomness)?;
        let br = arr32("binding_nonce_randomness", &sv.binding_nonce_randomness)?;
        let hiding = nonce_generate_from_randomness::<C>(share, &hr);
        let binding = nonce_generate_from_randomness::<C>(share, &br);
        record(format!("P{i} hiding_nonce"), hiding.to_bytes().as_slice() == sv.hiding_nonce.as_slice());
        record(format!("P{i} binding_nonce"), binding.to_bytes().as_slice() == sv.binding_nonce.as_slice());
        let n = SigningNonces::<C>::from_randomness(share, &hr, &br)?;
        let c = *n.commitments();
        record(
            format!("P{i} hiding_nonce_commitment"),
            C::serialize_element(&c.hiding())?.as_slice() == sv.hiding_nonce_commitment.as_slice(),
        );
        record(
            format!("P{i} binding_nonce_commitment"),
            C::serialize_element(&c.binding())?.as_slice() == sv.binding_nonce_commitment.as_slice(),
        );
        nonces.insert(*id, n);
        commitments.insert(*id, c);
    }

    // Binding factors.
    let package = SigningPackage::new(commitments, vector.message.clone());
    let inputs = binding_factor_inputs(public.verifying_key(), &package)?;
    let factors = compute_binding_factors(public.verifying_key(), &package)?;
    for (id, input) in &inputs {
        let i = id.to_u16().unwrap_or(0);
        let sv = &vector.signers[&i];
        record(format!("P{i} binding_factor_input"), *input == sv.binding_factor_input);
        record(
            format!("P{i} binding_factor"),
            factors[id].to_bytes().as_slice() == sv.binding_factor.as_slice(),
        );
    }

    // Round two: signature shares, each verified as the coordinator would.
    let mut sig_shares = BTreeMap::new();
    for (id, n) in nonces {
        let i = id.to_u16().unwrap_or(0);
        let key = shares.get(&id).ok_or(Error::UnknownParticipant(id))?.verify()?;
        let z = sign(&package, n, &key)?;
        record(
            format!("P{i} sig_share"),
            z.serialize().as_slice() == vector.signers[&i].sig_share.as_slice(),
        );
        let vs = public.verifying_share(&id)?;
        record(
            format!("P{i} verify_signature_share"),
            verify_signature_share(&id, vs, &z, &package, public.verifying_key()).is_ok(),
        );
        sig_shares.insert(id, z);
    }

    // Aggregation and verification.
    let signature: Signature<C> = aggregate(&package, &sig_shares, &public)?;
    let sig_bytes = signature.to_bytes()?;
    record("aggregate sig".into(), sig_bytes.as_slice() == vector.signature.as_slice());
    record("verify (frostsig)".into(), public.verifying_key().verify(&vector.message, &signature).is_ok());
    let pk = public.verifying_key().serialize()?;
    if let Some(ok) = C::reference_verify(&pk, &vector.message, &sig_bytes) {
        record("verify (ed25519-dalek, strict)".into(), ok);
    }
    Ok(checks)
}

/// Check both bundled vectors; returns `(suite name, checks)` pairs.
pub fn check_bundled() -> Result<Vec<(&'static str, Vec<VectorCheck>)>> {
    Ok(vec![
        (Ed25519Sha512::NAME, check_vector::<Ed25519Sha512>(&RfcVector::parse(ED25519_VECTOR)?)?),
        (
            Ristretto255Sha512::NAME,
            check_vector::<Ristretto255Sha512>(&RfcVector::parse(RISTRETTO255_VECTOR)?)?,
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_reads_bundled_vectors() {
        let v = RfcVector::parse(ED25519_VECTOR).unwrap();
        assert_eq!(v.max_participants, 3);
        assert_eq!(v.min_participants, 2);
        assert_eq!(v.participant_list, vec![1, 3]);
        assert_eq!(v.message, b"test");
        assert_eq!(v.coefficients.len(), 1);
        assert_eq!(v.participant_shares.len(), 3);
        assert_eq!(v.signers.len(), 2);
        assert_eq!(v.signature.len(), 64);
    }

    #[test]
    fn parser_rejects_garbage() {
        assert!(RfcVector::parse("no separator here").is_err());
        assert!(RfcVector::parse("mystery: 00").is_err());
        assert!(RfcVector::parse("message: zz").is_err());
        assert!(RfcVector::parse("MAX_PARTICIPANTS: three").is_err());
        assert!(RfcVector::parse("P1 surprise: 00").is_err());
        assert!(RfcVector::parse("Pfoo: 00").is_err());
        assert!(RfcVector::parse("message: 00").is_err(), "missing required fields");
    }

    #[test]
    fn checker_flags_a_wrong_published_value() {
        let mut v = RfcVector::parse(RISTRETTO255_VECTOR).unwrap();
        v.signers.get_mut(&3).unwrap().binding_factor[0] ^= 1;
        let checks = check_vector::<Ristretto255Sha512>(&v).unwrap();
        let failed: Vec<_> = checks.iter().filter(|c| !c.passed).map(|c| c.step.as_str()).collect();
        assert_eq!(failed, vec!["P3 binding_factor"]);
    }

    #[test]
    fn checker_errors_on_malformed_vector() {
        let mut v = RfcVector::parse(ED25519_VECTOR).unwrap();
        v.group_secret_key.pop();
        assert!(check_vector::<Ed25519Sha512>(&v).is_err());
    }
}
