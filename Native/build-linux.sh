#!/bin/sh
set -eu
cd "$(dirname "$0")"
mkdir -p build
cc -std=gnu11 -O2 -fPIC -fno-strict-aliasing -fwrapv -shared \
    -I vendor/monero -I compat \
    xtop_monero.c xtop_proofs.c \
    vendor/monero/crypto-ops.c vendor/monero/crypto-ops-data.c \
    vendor/monero/hash.c vendor/monero/keccak.c \
    -o build/libxtop_monero.so
