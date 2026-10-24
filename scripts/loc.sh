#!/bin/sh
# Line counts for the README: shipped source (src/ up to each file's
# `#[cfg(test)]` module) versus tests (inline test modules + tests/ + benches/).
set -eu
cd "$(dirname "$0")/.."
src_total=0
src_tests=0
for f in $(find src -name '*.rs' | sort); do
    total=$(wc -l < "$f")
    shipped=$(awk '/^#\[cfg\(test\)\]/ { exit } { n++ } END { print n + 0 }' "$f")
    src_total=$((src_total + shipped))
    src_tests=$((src_tests + total - shipped))
done
ext=$(cat $(find tests benches -name '*.rs') | wc -l)
echo "shipped source lines (src/, excluding inline test modules): $src_total"
echo "test lines (inline test modules + tests/ + benches/):     $((src_tests + ext))"
