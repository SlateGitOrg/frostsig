#!/bin/sh
# Re-derive vectors/*.txt from the published RFC 9591 text.
#
# Usage: scripts/extract-vectors.sh [path-to-rfc9591.txt]
# Without an argument the RFC is downloaded from rfc-editor.org into a
# temporary directory and checked against the pinned SHA-256 below.
set -eu

RFC_URL="https://www.rfc-editor.org/rfc/rfc9591.txt"
RFC_SHA256="fd8366795c833348d552e6a4141e8bf413310940fd50af484283207716d1a6a7"
OUT_DIR="$(cd "$(dirname "$0")/.." && pwd)/vectors"

if [ "$#" -ge 1 ]; then
    RFC="$1"
else
    TMP="$(mktemp -d)"
    trap 'rm -rf "$TMP"' EXIT
    RFC="$TMP/rfc9591.txt"
    curl -sSfL "$RFC_URL" -o "$RFC"
fi

GOT="$(shasum -a 256 "$RFC" | cut -d' ' -f1)"
if [ "$GOT" != "$RFC_SHA256" ]; then
    echo "checksum mismatch for $RFC: got $GOT, want $RFC_SHA256" >&2
    exit 1
fi

# extract <section-title-regex> <output-file>
# Prints the key/value lines of one Appendix E section with the RFC's
# 72-column hex wrapping undone (continuation lines are pure hex).
extract() {
    awk -v start="$1" '
        $0 ~ start { on = 1; next }
        on && /^E\.[0-9]\./ { on = 0 }
        !on { next }
        /^   \/\// || /^[[:space:]]*$/ { next }
        {
            line = $0
            sub(/^   /, "", line)
            if (line ~ /^[0-9a-f]+$/ && have) { cur = cur line; next }
            if (have) print cur
            cur = line; have = 1
        }
        END { if (have) print cur }
    ' "$RFC" > "$2"
    echo "wrote $2 ($(wc -l < "$2" | tr -d ' ') lines)"
}

extract '^E[.]1[.]  FROST[(]Ed25519, SHA-512[)]' "$OUT_DIR/rfc9591-ed25519-sha512.txt"
extract '^E[.]3[.]  FROST[(]ristretto255, SHA-512[)]' "$OUT_DIR/rfc9591-ristretto255-sha512.txt"
