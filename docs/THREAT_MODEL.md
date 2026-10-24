# Threat model

frostsig is an **educational, unaudited** implementation of RFC 9591. This document
covers what the code defends against, what it assumes, and what it leaves out. Every
demo runs against local, in-process simulations. Nothing here touches a real network or
any third-party system.

## Assets

| Asset | Where it lives | Compromise means |
|---|---|---|
| Group secret `s` | Never materialised in DKG mode. In trusted-dealer mode it exists briefly inside `dealer::trusted_dealer_keygen`. | Forgery of any signature |
| Signing shares `sk_i` | `KeyPackage` in memory (zeroized on drop), and plaintext key files written by `frostsig keygen` | With `t` shares an attacker can forge signatures |
| Signing nonces `(d_i, e_i)` | `SigningNonces` between rounds one and two (zeroized on drop, consumed by `sign`) | Reusing one nonce pair across two messages reveals `sk_i` |
| DKG polynomials | `SecretPolynomial` inside `dkg::Round1Secret` (zeroized on drop) | Exposes that participant's contribution to the group secret |

## Adversaries and what holds against them

The protocol-level guarantees are the ones RFC 9591 section 7 states. Each row lists the
mechanism in this code that keeps the guarantee from being lost in implementation.

| Adversary | Guarantee | How the code keeps it |
|---|---|---|
| Up to `t-1` corrupted participants plus a malicious coordinator | Unforgeability (EUF-CMA), from FROST's security proof | Binding factors cover the whole commitment list and the message (`compute_binding_factors`). Each signer checks that its own commitment appears in the package unchanged (`Error::IncorrectCommitment`). The threshold is enforced in `sign` and `aggregate`. |
| A participant sending an invalid signature share | Identifiable abort | `aggregate` checks the final signature and on failure runs `verify_signature_share` for every signer, then returns `InvalidSignatureShares { culprits }`. The simulator excludes the culprits and retries. |
| A participant sending a bad DKG share | Identifiable abort | Feldman verification in `dkg::part3` names the senders whose shares fail (`InvalidDkgShares`). |
| Rogue-key attempts in the DKG (a commitment chosen as a function of others' commitments) | Each `C_i0` is backed by knowledge of its discrete log | A Schnorr proof of knowledge is bound to the sender's identifier. A copied or replayed proof fails, as `replayed_proof_under_another_identifier_fails` shows. |
| A network attacker or peer injecting malformed bytes | No panics, and no invalid group elements get in | Every scalar and element goes through `DeserializeScalar` / `DeserializeElement`. The decoder rejects identity, small-order, mixed-order and non-canonical points, bounds every length, rejects trailing bytes, and requires canonical identifier ordering. A property test runs random and mutated input through the decoder. |
| A bug in the caller's code reusing nonces | Nonces are used once | `SigningNonces` is not `Clone`, and `sign` consumes it. Hedged nonce generation (`H3(random || sk_i)`) protects against a weak RNG on its own. |
| A participant equivocating during DKG broadcast | Detected, not attributed | The coordinator compares the group info every participant reports and outputs `KeygenOutcome::Inconsistent`. See the limitations below. |
| Silent or refusing signers | Liveness through retries | Coordinator timeouts and exclusion. FROST is not robust (RFC 7.1). [ROAST](https://eprint.iacr.org/2022/550) is the principled fix. |

## Assumptions

- **Authenticated channels.** Identifiable abort is only meaningful if the coordinator
  knows who sent each message. The simulator stamps the sender at the transport layer.
  A deployment would need mutually authenticated TLS or signed messages.
- **Confidential channels for secrets.** DKG round-two shares and dealer shares are
  secret. In the simulator they travel over in-process channels in plaintext. A deployment
  would encrypt them.
- **Reliable, consistent broadcast in the DKG.** Not implemented. Equivocation is only
  detected after the fact.
- **A trusted dealer, when dealer mode is used.** The dealer learns `s` and must erase it.
  The code drops it at the end of the function, but it makes no guarantee about copies the
  compiler may leave on the stack.
- **Good OS randomness.** Seeded mode (`--seed`) exists only for reproducible demos and
  is **not secure**.

## Out of scope

- **Side channels beyond curve25519-dalek's.** Variable-time multi-scalar multiplication
  is only used on public values: commitments, verifying shares, and VSS commitments.
  Constant-time behaviour of hashing and of scalar arithmetic in this crate's own code
  has not been verified.
- **Key storage.** `keygen` writes shares as plaintext JSON (mode 0600). There is no
  encryption at rest, HSM support, or key rotation and refresh.
- **Message policy.** RFC 9591 section 7.7 recommends that signers validate what they
  sign so they do not act as signing oracles. The simulated participants sign whatever
  the coordinator sends.
- **Repairable or refreshable shares, share recovery, and proactive security.**
- **Ed448, P-256 and secp256k1 suites.**

## Ethics

This is a defensive and educational project. The fault-injection modes (`bad-share`,
`bad-proof`, `bad-dkg-share`, `equivocate`, `silent`) exist to show how the protocol
detects misbehaviour, and they only run inside the local simulator against keys it has
just generated.
