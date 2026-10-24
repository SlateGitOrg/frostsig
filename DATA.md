# Data

frostsig uses no datasets. The only external data is the set of published test vectors.

| File | Source | Size | License / terms |
|---|---|---|---|
| `vectors/rfc9591-ed25519-sha512.txt` | RFC 9591, Appendix E.1, "FROST(Ed25519, SHA-512)" | 30 lines | Excerpt of an IETF RFC: © IETF Trust and the persons identified as the document authors; reproduced to test an implementation of the specification under the [IETF Trust Legal Provisions](https://trustee.ietf.org/license-info) |
| `vectors/rfc9591-ristretto255-sha512.txt` | RFC 9591, Appendix E.3, "FROST(ristretto255, SHA-512)" | 30 lines | as above |

## Provenance

- Upstream text: <https://www.rfc-editor.org/rfc/rfc9591.txt>
- Pinned SHA-256 of that text: `fd8366795c833348d552e6a4141e8bf413310940fd50af484283207716d1a6a7`
- Regenerate: `./scripts/extract-vectors.sh` (downloads the RFC, checks the hash, and rewrites
  `vectors/`). CI runs this and fails if the result differs from the committed files.

The excerpts keep the RFC's `key: value` lines and undo its 72-column hex wrapping. No
values are changed.

## Synthetic data

Everything else the tests, demo and benchmarks use (keys, nonces, messages, faults) is
generated at run time from seeded ChaCha20 RNGs or the OS RNG. None of it is real key
material.
