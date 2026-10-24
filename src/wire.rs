//! A strict, versioned binary encoding for every protocol message and key
//! package.
//!
//! Every scalar and element is decoded with `DeserializeScalar` /
//! `DeserializeElement`, so anything that crosses the wire is validated
//! exactly as RFC 9591 Section 5 requires. Lengths are bounded, trailing
//! bytes are rejected, and decoding never panics on hostile input (checked by
//! a property test).
//!
//! Frame layout: `"FS" | version (1) | suite wire id | tag | body`.

use std::collections::BTreeMap;

use curve25519_dalek::Scalar;

use crate::ciphersuite::{deserialize_scalar, serialize_scalar, Ciphersuite};
use crate::dkg::{ProofOfKnowledge, Round1Package, Round2Package};
use crate::error::{Error, Result};
use crate::identifier::Identifier;
use crate::keys::{
    KeyPackage, PublicKeyPackage, SecretShare, SigningShare, VerifyingKey, VerifyingShare, VssCommitment,
};
use crate::signature::{Signature, SIGNATURE_LEN};
use crate::signing::{SignatureShare, SigningCommitments, SigningPackage};

/// Frame magic.
pub const MAGIC: [u8; 2] = *b"FS";
/// Wire format version.
pub const VERSION: u8 = 1;
/// Upper bound on the message-to-sign length accepted from the wire.
pub const MAX_MESSAGE_LEN: usize = 1 << 20;
/// Upper bound on free-text fields (abort reasons).
pub const MAX_TEXT_LEN: usize = 1024;

/// Append-only encoder.
#[derive(Default, Debug)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// Empty writer.
    pub fn new() -> Self {
        Self::default()
    }

    /// One byte.
    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    /// Big-endian `u16`.
    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Big-endian `u32`.
    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Raw bytes, no length prefix.
    pub fn raw(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    /// `u32` length prefix followed by the bytes.
    pub fn blob(&mut self, b: &[u8]) {
        self.u32(u32::try_from(b.len()).expect("blob length fits in u32"));
        self.raw(b);
    }

    /// A scalar.
    pub fn scalar(&mut self, s: &Scalar) {
        self.raw(&serialize_scalar(s));
    }

    /// A group element (raw encoding; validated on decode).
    pub fn element<C: Ciphersuite>(&mut self, e: &C::Element) {
        self.raw(&C::encode_element(e));
    }

    /// An identifier.
    pub fn identifier(&mut self, id: &Identifier) {
        self.raw(&id.serialize());
    }

    /// `u16` count prefix.
    pub fn count(&mut self, n: usize) {
        self.u16(u16::try_from(n).expect("collection sizes are bounded by u16 participant counts"));
    }

    /// The encoded bytes.
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// Bounds-checked decoder.
#[derive(Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Decode from `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.buf.len() < n {
            return Err(Error::Decode("truncated input"));
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    fn array32(&mut self) -> Result<[u8; 32]> {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.take(32)?);
        Ok(out)
    }

    /// One byte.
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// Big-endian `u16`.
    pub fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    /// Big-endian `u32`.
    pub fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Length-prefixed bytes, at most `max` long.
    pub fn blob(&mut self, max: usize) -> Result<Vec<u8>> {
        let len = usize::try_from(self.u32()?).map_err(|_| Error::Decode("length overflow"))?;
        if len > max {
            return Err(Error::Decode("length exceeds limit"));
        }
        Ok(self.take(len)?.to_vec())
    }

    /// A canonical scalar.
    pub fn scalar(&mut self) -> Result<Scalar> {
        deserialize_scalar(&self.array32()?)
    }

    /// A validated, non-identity element.
    pub fn element<C: Ciphersuite>(&mut self) -> Result<C::Element> {
        C::deserialize_element(&self.array32()?)
    }

    /// A non-zero identifier.
    pub fn identifier(&mut self) -> Result<Identifier> {
        Identifier::deserialize(&self.array32()?)
    }

    /// `u16` count prefix.
    pub fn count(&mut self) -> Result<usize> {
        Ok(usize::from(self.u16()?))
    }

    /// Fail unless every byte was consumed.
    pub fn finish(self) -> Result<()> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(Error::Decode("trailing bytes"))
        }
    }
}

/// Types with a canonical binary encoding.
pub trait Encode {
    /// Append the encoding to `w`.
    fn encode(&self, w: &mut Writer);

    /// Encode into a fresh buffer.
    fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w);
        w.finish()
    }
}

/// Types decodable from their canonical encoding.
pub trait Decode: Sized {
    /// Read one value from `r`.
    fn decode(r: &mut Reader<'_>) -> Result<Self>;

    /// Decode a buffer that must contain exactly one value.
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let v = Self::decode(&mut r)?;
        r.finish()?;
        Ok(v)
    }
}

impl<C: Ciphersuite> Encode for VssCommitment<C> {
    fn encode(&self, w: &mut Writer) {
        w.count(self.elements().len());
        for e in self.elements() {
            w.element::<C>(e);
        }
    }
}

impl<C: Ciphersuite> Decode for VssCommitment<C> {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let n = r.count()?;
        let elements = (0..n).map(|_| r.element::<C>()).collect::<Result<Vec<_>>>()?;
        VssCommitment::new(elements)
    }
}

impl<C: Ciphersuite> Encode for SecretShare<C> {
    fn encode(&self, w: &mut Writer) {
        w.identifier(&self.identifier);
        w.scalar(&self.signing_share.to_scalar());
        self.commitment.encode(w);
    }
}

impl<C: Ciphersuite> Decode for SecretShare<C> {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            identifier: r.identifier()?,
            signing_share: SigningShare::new(r.scalar()?),
            commitment: VssCommitment::decode(r)?,
        })
    }
}

impl<C: Ciphersuite> Encode for KeyPackage<C> {
    fn encode(&self, w: &mut Writer) {
        w.u8(C::WIRE_ID);
        w.identifier(self.identifier());
        w.scalar(&self.signing_share().to_scalar());
        w.element::<C>(&self.verifying_key().element());
        w.u16(self.min_signers());
    }
}

impl<C: Ciphersuite> Decode for KeyPackage<C> {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        expect_suite::<C>(r.u8()?)?;
        let id = r.identifier()?;
        let share = SigningShare::new(r.scalar()?);
        let vk = VerifyingKey::new(r.element::<C>()?)?;
        KeyPackage::new(id, share, vk, r.u16()?)
    }
}

impl<C: Ciphersuite> Encode for PublicKeyPackage<C> {
    fn encode(&self, w: &mut Writer) {
        w.u8(C::WIRE_ID);
        w.element::<C>(&self.verifying_key().element());
        w.u16(self.min_signers());
        w.count(self.verifying_shares().len());
        for (id, vs) in self.verifying_shares() {
            w.identifier(id);
            w.element::<C>(&vs.element());
        }
    }
}

impl<C: Ciphersuite> Decode for PublicKeyPackage<C> {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        expect_suite::<C>(r.u8()?)?;
        let vk = VerifyingKey::new(r.element::<C>()?)?;
        let min = r.u16()?;
        let n = r.count()?;
        let mut shares = BTreeMap::new();
        for _ in 0..n {
            let id = r.identifier()?;
            let vs = VerifyingShare::new(r.element::<C>()?)?;
            if shares.insert(id, vs).is_some() {
                return Err(Error::DuplicateIdentifier(id));
            }
        }
        PublicKeyPackage::new(shares, vk, min)
    }
}

impl<C: Ciphersuite> Encode for Round1Package<C> {
    fn encode(&self, w: &mut Writer) {
        self.commitment.encode(w);
        w.element::<C>(&self.proof.r);
        w.scalar(&self.proof.mu);
    }
}

impl<C: Ciphersuite> Decode for Round1Package<C> {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let commitment = VssCommitment::decode(r)?;
        let proof = ProofOfKnowledge { r: r.element::<C>()?, mu: r.scalar()? };
        Ok(Self { commitment, proof })
    }
}

impl Encode for Round2Package {
    fn encode(&self, w: &mut Writer) {
        w.scalar(&self.share.to_scalar());
    }
}

impl Decode for Round2Package {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self { share: SigningShare::new(r.scalar()?) })
    }
}

impl<C: Ciphersuite> Encode for SigningCommitments<C> {
    fn encode(&self, w: &mut Writer) {
        w.element::<C>(&self.hiding());
        w.element::<C>(&self.binding());
    }
}

impl<C: Ciphersuite> Decode for SigningCommitments<C> {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        SigningCommitments::new(r.element::<C>()?, r.element::<C>()?)
    }
}

impl<C: Ciphersuite> Encode for SigningPackage<C> {
    fn encode(&self, w: &mut Writer) {
        w.count(self.commitments().len());
        for (id, c) in self.commitments() {
            w.identifier(id);
            c.encode(w);
        }
        w.blob(self.message());
    }
}

impl<C: Ciphersuite> Decode for SigningPackage<C> {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let n = r.count()?;
        let mut commitments = BTreeMap::new();
        for _ in 0..n {
            let id = r.identifier()?;
            if commitments.insert(id, SigningCommitments::decode(r)?).is_some() {
                return Err(Error::DuplicateIdentifier(id));
            }
        }
        Ok(SigningPackage::new(commitments, r.blob(MAX_MESSAGE_LEN)?))
    }
}

impl Encode for SignatureShare {
    fn encode(&self, w: &mut Writer) {
        w.raw(&self.serialize());
    }
}

impl Decode for SignatureShare {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(SignatureShare::new(r.scalar()?))
    }
}

impl<C: Ciphersuite> Encode for Signature<C> {
    fn encode(&self, w: &mut Writer) {
        w.element::<C>(&self.r());
        w.scalar(&self.z());
    }
}

impl<C: Ciphersuite> Decode for Signature<C> {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let mut b = [0u8; SIGNATURE_LEN];
        b.copy_from_slice(r.take(SIGNATURE_LEN)?);
        Signature::from_bytes(&b)
    }
}

fn expect_suite<C: Ciphersuite>(found: u8) -> Result<()> {
    if found == C::WIRE_ID {
        Ok(())
    } else {
        Err(Error::SuiteMismatch { expected: C::WIRE_ID, found })
    }
}

/// Every message exchanged by the participant / coordinator simulation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message<C: Ciphersuite> {
    /// Dealer to participant: a secret share and the VSS commitment.
    DealerShare(SecretShare<C>),
    /// DKG round 1 broadcast.
    DkgRound1(Round1Package<C>),
    /// DKG round 2 private share.
    DkgRound2(Round2Package),
    /// Participant to coordinator: key setup finished; carries the group info
    /// as this participant sees it, so views can be compared.
    KeysReady(PublicKeyPackage<C>),
    /// Coordinator to signer: start round one for `session`.
    CommitRequest {
        /// Session number.
        session: u32,
    },
    /// Signer to coordinator: round-one commitments.
    Commitments {
        /// Session number.
        session: u32,
        /// `(D_i, E_i)`.
        commitments: SigningCommitments<C>,
    },
    /// Coordinator to signer: round-two input.
    SignRequest {
        /// Session number.
        session: u32,
        /// Message plus commitment list.
        package: SigningPackage<C>,
    },
    /// Signer to coordinator: round-two output.
    Share {
        /// Session number.
        session: u32,
        /// `z_i`.
        share: SignatureShare,
    },
    /// Any party: the protocol cannot continue; `culprits` names who is blamed.
    Abort {
        /// Blamed participants (may be empty).
        culprits: Vec<Identifier>,
        /// Human-readable reason.
        reason: String,
    },
    /// Coordinator to participant: stop.
    Shutdown,
}

impl<C: Ciphersuite> Message<C> {
    fn tag(&self) -> u8 {
        match self {
            Message::DealerShare(_) => 1,
            Message::DkgRound1(_) => 2,
            Message::DkgRound2(_) => 3,
            Message::KeysReady(_) => 4,
            Message::CommitRequest { .. } => 5,
            Message::Commitments { .. } => 6,
            Message::SignRequest { .. } => 7,
            Message::Share { .. } => 8,
            Message::Abort { .. } => 9,
            Message::Shutdown => 10,
        }
    }

    /// Short label used for traffic statistics.
    pub fn label(&self) -> &'static str {
        match self {
            Message::DealerShare(_) => "keygen/dealer-share",
            Message::DkgRound1(_) => "keygen/dkg-round1",
            Message::DkgRound2(_) => "keygen/dkg-round2",
            Message::KeysReady(_) => "keygen/ready",
            Message::CommitRequest { .. } => "sign/commit-request",
            Message::Commitments { .. } => "sign/round1-commitments",
            Message::SignRequest { .. } => "sign/round2-package",
            Message::Share { .. } => "sign/round2-share",
            Message::Abort { .. } => "control/abort",
            Message::Shutdown => "control/shutdown",
        }
    }
}

impl<C: Ciphersuite> Encode for Message<C> {
    fn encode(&self, w: &mut Writer) {
        w.raw(&MAGIC);
        w.u8(VERSION);
        w.u8(C::WIRE_ID);
        w.u8(self.tag());
        match self {
            Message::DealerShare(s) => s.encode(w),
            Message::DkgRound1(p) => p.encode(w),
            Message::DkgRound2(p) => p.encode(w),
            Message::KeysReady(p) => p.encode(w),
            Message::CommitRequest { session } => w.u32(*session),
            Message::Commitments { session, commitments } => {
                w.u32(*session);
                commitments.encode(w);
            }
            Message::SignRequest { session, package } => {
                w.u32(*session);
                package.encode(w);
            }
            Message::Share { session, share } => {
                w.u32(*session);
                share.encode(w);
            }
            Message::Abort { culprits, reason } => {
                w.count(culprits.len());
                for c in culprits {
                    w.identifier(c);
                }
                let mut end = reason.len().min(MAX_TEXT_LEN);
                while !reason.is_char_boundary(end) {
                    end -= 1;
                }
                w.blob(&reason.as_bytes()[..end]);
            }
            Message::Shutdown => {}
        }
    }
}

impl<C: Ciphersuite> Decode for Message<C> {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        if r.take(2)? != MAGIC {
            return Err(Error::Decode("bad magic"));
        }
        if r.u8()? != VERSION {
            return Err(Error::Decode("unsupported version"));
        }
        expect_suite::<C>(r.u8()?)?;
        Ok(match r.u8()? {
            1 => Message::DealerShare(SecretShare::decode(r)?),
            2 => Message::DkgRound1(Round1Package::decode(r)?),
            3 => Message::DkgRound2(Round2Package::decode(r)?),
            4 => Message::KeysReady(PublicKeyPackage::decode(r)?),
            5 => Message::CommitRequest { session: r.u32()? },
            6 => Message::Commitments { session: r.u32()?, commitments: SigningCommitments::decode(r)? },
            7 => Message::SignRequest { session: r.u32()?, package: SigningPackage::decode(r)? },
            8 => Message::Share { session: r.u32()?, share: SignatureShare::decode(r)? },
            9 => {
                let n = r.count()?;
                let culprits = (0..n).map(|_| r.identifier()).collect::<Result<Vec<_>>>()?;
                let reason = String::from_utf8(r.blob(MAX_TEXT_LEN)?)
                    .map_err(|_| Error::Decode("abort reason is not UTF-8"))?;
                Message::Abort { culprits, reason }
            }
            10 => Message::Shutdown,
            _ => return Err(Error::Decode("unknown message tag")),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ciphersuite::{Ed25519Sha512, Ristretto255Sha512};
    use crate::dealer::trusted_dealer_keygen;
    use crate::signing::commit;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn roundtrip<C: Ciphersuite>(m: Message<C>) {
        let bytes = m.to_bytes();
        assert_eq!(Message::<C>::from_bytes(&bytes).unwrap(), m);
        // Any truncation fails cleanly.
        for cut in 0..bytes.len() {
            assert!(Message::<C>::from_bytes(&bytes[..cut]).is_err());
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(Message::<C>::from_bytes(&longer), Err(Error::Decode("trailing bytes")));
    }

    fn all_messages<C: Ciphersuite>() {
        let mut rng = ChaCha20Rng::seed_from_u64(21);
        let (shares, public) = trusted_dealer_keygen::<C, _>(2, 3, &mut rng).unwrap();
        let id = Identifier::try_from(1).unwrap();
        let share = shares[&id].clone();
        let kp = share.verify().unwrap();
        let (_n, c) = commit::<C, _>(kp.signing_share(), &mut rng);
        let pkg = SigningPackage::new(BTreeMap::from([(id, c)]), b"hello".to_vec());
        let (_, r1) = crate::dkg::part1::<C, _>(id, 2, 3, &mut rng).unwrap();

        roundtrip::<C>(Message::DealerShare(share));
        roundtrip::<C>(Message::DkgRound1(r1));
        roundtrip::<C>(Message::DkgRound2(Round2Package { share: SigningShare::new(Scalar::ONE) }));
        roundtrip::<C>(Message::KeysReady(public.clone()));
        roundtrip::<C>(Message::CommitRequest { session: 7 });
        roundtrip::<C>(Message::Commitments { session: 7, commitments: c });
        roundtrip::<C>(Message::SignRequest { session: 7, package: pkg });
        roundtrip::<C>(Message::Share { session: 7, share: SignatureShare::new(Scalar::from(3u8)) });
        roundtrip::<C>(Message::Abort { culprits: vec![id], reason: "bad share".into() });
        roundtrip::<C>(Message::Shutdown);

        assert_eq!(KeyPackage::<C>::from_bytes(&kp.to_bytes()).unwrap(), kp);
        assert_eq!(PublicKeyPackage::<C>::from_bytes(&public.to_bytes()).unwrap(), public);
    }

    #[test]
    fn every_message_round_trips_both_suites() {
        all_messages::<Ed25519Sha512>();
        all_messages::<Ristretto255Sha512>();
    }

    #[test]
    fn framing_errors() {
        let ok = Message::<Ed25519Sha512>::Shutdown.to_bytes();
        let mut bad = ok.clone();
        bad[0] = b'X';
        assert_eq!(Message::<Ed25519Sha512>::from_bytes(&bad), Err(Error::Decode("bad magic")));
        let mut bad = ok.clone();
        bad[2] = 9;
        assert_eq!(Message::<Ed25519Sha512>::from_bytes(&bad), Err(Error::Decode("unsupported version")));
        assert_eq!(
            Message::<Ristretto255Sha512>::from_bytes(&ok),
            Err(Error::SuiteMismatch { expected: 2, found: 1 })
        );
        let mut bad = ok.clone();
        bad[4] = 200;
        assert_eq!(Message::<Ed25519Sha512>::from_bytes(&bad), Err(Error::Decode("unknown message tag")));
    }

    #[test]
    fn duplicate_entries_and_oversized_blobs_are_rejected() {
        let mut rng = ChaCha20Rng::seed_from_u64(22);
        let (shares, public) = trusted_dealer_keygen::<Ed25519Sha512, _>(2, 2, &mut rng).unwrap();
        let id = Identifier::try_from(1).unwrap();
        let (_n, c) = commit::<Ed25519Sha512, _>(&shares[&id].signing_share, &mut rng);

        let mut w = Writer::new();
        w.count(2);
        for _ in 0..2 {
            w.identifier(&id);
            c.encode(&mut w);
        }
        w.blob(b"m");
        assert_eq!(
            SigningPackage::<Ed25519Sha512>::from_bytes(&w.finish()),
            Err(Error::DuplicateIdentifier(id))
        );

        let mut w = Writer::new();
        w.u8(Ed25519Sha512::WIRE_ID);
        w.element::<Ed25519Sha512>(&public.verifying_key().element());
        w.u16(2);
        w.count(2);
        for _ in 0..2 {
            w.identifier(&id);
            w.element::<Ed25519Sha512>(&public.verifying_key().element());
        }
        assert_eq!(
            PublicKeyPackage::<Ed25519Sha512>::from_bytes(&w.finish()),
            Err(Error::DuplicateIdentifier(id))
        );

        let mut w = Writer::new();
        w.u32(u32::try_from(MAX_TEXT_LEN + 1).unwrap());
        let bytes = w.finish();
        assert_eq!(Reader::new(&bytes).blob(MAX_TEXT_LEN), Err(Error::Decode("length exceeds limit")));
    }

    #[test]
    fn signature_codec_round_trips() {
        let sig = Signature::<Ristretto255Sha512>::new(Ristretto255Sha512::generator(), Scalar::from(5u8));
        assert_eq!(
            <Signature<Ristretto255Sha512> as Decode>::from_bytes(&Encode::to_bytes(&sig)).unwrap(),
            sig
        );
    }

    #[test]
    fn long_abort_reasons_are_truncated() {
        let m = Message::<Ed25519Sha512>::Abort { culprits: vec![], reason: "x".repeat(5000) };
        match Message::<Ed25519Sha512>::from_bytes(&m.to_bytes()).unwrap() {
            Message::Abort { reason, .. } => assert_eq!(reason.len(), MAX_TEXT_LEN),
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(m.label(), "control/abort");
    }
}
