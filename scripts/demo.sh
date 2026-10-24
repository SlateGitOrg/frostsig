#!/bin/sh
# Offline end-to-end demo: RFC vectors, honest DKG signing, identifiable
# aborts, equivocation detection, and a keygen -> sign -> verify round trip
# through files. Every run is seeded, so the output is reproducible.
set -eu
cd "$(dirname "$0")/.."

cargo build --quiet --release --locked
run() { cargo run --quiet --release --locked -- "$@"; }
section() { printf '\n==== %s ====\n' "$1"; }

section "1. RFC 9591 Appendix E test vectors"
run vectors

section "2. 3-of-5 DKG, then two signing sessions (Ed25519, checked by ed25519-dalek)"
run simulate --suite ed25519 --keygen dkg -t 3 -n 5 --seed 2026 -m "release v1.2.0" -m "rotate staging key"

section "3. Identifiable abort: P2 sends a bad signature share; the coordinator excludes it and retries"
run simulate --suite ristretto255 --keygen dealer -t 3 -n 5 --seed 7 --fault 2=bad-share -m "approve payout #42"

section "4. Silent signer: P1 never commits; the coordinator times out and replaces it"
run simulate --suite ed25519 -t 2 -n 3 --seed 11 --fault 1=silent --timeout-ms 300

section "5. DKG abort: P3 sends P1 a share that fails Feldman verification"
run simulate --suite ed25519 --keygen dkg -t 2 -n 4 --seed 5 --fault 3=bad-dkg-share:1 --timeout-ms 500

section "6. DKG equivocation: P1 shows different commitments to odd and even peers"
run simulate --suite ed25519 --keygen dkg -t 2 -n 4 --seed 9 --fault 1=equivocate --timeout-ms 500

section "7. keygen -> files -> sign with two of three holders -> verify"
KEYS="$(mktemp -d)"
trap 'rm -rf "$KEYS"' EXIT
run keygen --suite ed25519 --keygen dkg -t 2 -n 3 --seed 99 --out "$KEYS/group"
rm "$KEYS/group/participant-1.json"
SIG_JSON="$(run sign --keys "$KEYS/group" -m "deploy to prod" --seed 100 --json)"
PK="$(sed -n 's/.*"verifying_key": "\([0-9a-f]*\)".*/\1/p' "$KEYS/group/group.json")"
SIG="$(printf '%s\n' "$SIG_JSON" | sed -n 's/.*"signature": "\([0-9a-f]*\)".*/\1/p')"
echo "signers: $(printf '%s\n' "$SIG_JSON" | tr -d ' \n' | sed -n 's/.*"signers":\[\([0-9,]*\)\].*/\1/p')"
echo "public key: $PK"
echo "signature : $SIG"
run verify --suite ed25519 --public-key "$PK" -m "deploy to prod" --signature "$SIG"
echo "tampered message:"
run verify --suite ed25519 --public-key "$PK" -m "deploy to prod!" --signature "$SIG" || echo "(rejected, exit $?)"
