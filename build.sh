#!/bin/bash
# Build script — cross-compile tunnel for multiple platforms.
# Usage: ./build.sh   (builds the single binary for all platforms)
#         ./build.sh server   (same — unified binary supports both modes)
#         ./build.sh client   (same)
set -euo pipefail

BIN_DIR="bin"
LDFLAGS="-w -s"
CMD_ROOT="./cmd/tunnel"

mkdir -p "$BIN_DIR"

build_for() {
    local os="$1" arch="$2" ext="${3:-}"
    local out="${BIN_DIR}/tunnel-${os}-${arch}${ext}"
    echo "  → tunnel  ${os}/${arch}"
    GOOS="$os" GOARCH="$arch" go build -ldflags="$LDFLAGS" -o "$out" "$CMD_ROOT"
}

# ------------------------------------------------------------------
# Windows
# ------------------------------------------------------------------
echo ""
echo "==> Windows"
export CGO_ENABLED=0
build_for "windows" "amd64" ".exe"
build_for "windows" "386"   ".exe"

# ------------------------------------------------------------------
# Linux
# ------------------------------------------------------------------
echo ""
echo "==> Linux"
build_for "linux" "386"
build_for "linux" "amd64"
build_for "linux" "arm"
build_for "linux" "arm64"

# ------------------------------------------------------------------
# macOS (Darwin)
# ------------------------------------------------------------------
echo ""
echo "==> macOS"
build_for "darwin" "arm64"
build_for "darwin" "amd64"

echo ""
echo "Done — binaries in ${BIN_DIR}/"
ls -lh "${BIN_DIR}/"
