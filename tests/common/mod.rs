//! Helpers shared by the integration tests.
#![allow(dead_code)]

use std::collections::BTreeMap;

use frostsig::signing::{aggregate, commit, sign};
use frostsig::{
    Ciphersuite, Identifier, KeyPackage, PublicKeyPackage, Signature, SignatureShare, SigningPackage,
};
use rand_chacha::ChaCha20Rng;

/// Verify a key set from a trusted dealer.
pub fn dealer_keys<C: Ciphersuite>(
    t: u16,
    n: u16,
    rng: &mut ChaCha20Rng,
) -> (BTreeMap<Identifier, KeyPackage<C>>, PublicKeyPackage<C>) {
    let (shares, public) = frostsig::dealer::trusted_dealer_keygen::<C, _>(t, n, rng).unwrap();
    let keys = shares.into_iter().map(|(id, s)| (id, s.verify().unwrap())).collect();
    (keys, public)
}

/// Run both rounds for `signers`; returns the package and the shares.
pub fn sign_rounds<C: Ciphersuite>(
    keys: &BTreeMap<Identifier, KeyPackage<C>>,
    signers: &[Identifier],
    msg: &[u8],
    rng: &mut ChaCha20Rng,
) -> (SigningPackage<C>, BTreeMap<Identifier, SignatureShare>) {
    let mut nonces = BTreeMap::new();
    let mut comms = BTreeMap::new();
    for id in signers {
        let (n, c) = commit::<C, _>(keys[id].signing_share(), rng);
        nonces.insert(*id, n);
        comms.insert(*id, c);
    }
    let package = SigningPackage::new(comms, msg.to_vec());
    let shares = nonces.into_iter().map(|(id, n)| (id, sign(&package, n, &keys[&id]).unwrap())).collect();
    (package, shares)
}

/// Full threshold signature by `signers`.
pub fn threshold_sign<C: Ciphersuite>(
    keys: &BTreeMap<Identifier, KeyPackage<C>>,
    public: &PublicKeyPackage<C>,
    signers: &[Identifier],
    msg: &[u8],
    rng: &mut ChaCha20Rng,
) -> Signature<C> {
    let (package, shares) = sign_rounds(keys, signers, msg, rng);
    aggregate(&package, &shares, public).unwrap()
}
