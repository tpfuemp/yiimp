#!/bin/sh
# Build the GETH payout signer (OpenSSL and the sph keccak of the stratum tree).
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

cc -O2 -c -I"$ROOT/stratum/third_party/sph" \
	"$ROOT/stratum/third_party/sph/sph_keccak.c" -o "$WORK/sph_keccak.o"

c++ -std=c++17 -O2 -Wall \
	-I"$ROOT/stratum/third_party/sph" \
	"$ROOT/bin/gethethsig.cpp" "$WORK/sph_keccak.o" \
	-o "$ROOT/bin/gethethsig" -lcrypto

echo "built $ROOT/bin/gethethsig"
