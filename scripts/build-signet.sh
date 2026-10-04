#!/bin/sh
# Build the Sig-Net desktop library (shared, mbedTLS) from a source tree and
# install it into vendor/signet, which Package.swift links against.
#   scripts/build-signet.sh /path/to/signet-desktop-src-0.1.0
set -eu
SRC=${1:?usage: $0 /path/to/signet-desktop-src}
HERE=$(cd "$(dirname "$0")/.." && pwd)
BUILD="$HERE/.build/signet-build"
cmake -S "$SRC" -B "$BUILD" -DCMAKE_BUILD_TYPE=Release -DSIGNET_SHARED=ON \
  -DSIGNET_FETCH_DEPS=ON -DSIGNET_WITH_MBEDTLS=ON -DSIGNET_BUILD_TESTS=OFF -Wno-dev
cmake --build "$BUILD" --parallel
cmake --install "$BUILD" --prefix "$HERE/vendor/signet"
echo "Installed to $HERE/vendor/signet"
