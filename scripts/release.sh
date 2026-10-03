#!/usr/bin/env bash

set -euo pipefail

APP="kelvosd"
VERSION="$(cat VERSION)"
DIST="dist"
BUILD="build"

echo "================================="
echo " Building $APP v$VERSION"
echo "================================="

rm -rf "$DIST"
mkdir -p "$DIST"

echo
echo "[1/5] Go tests"
go test ./...

echo
echo "[2/5] Building Go binary"
mkdir -p "$BUILD"

go build \
    -trimpath \
    -ldflags "-s -w -X main.version=$VERSION" \
    -o "$BUILD/$APP" \
    ./cmd/$APP

echo
echo "[3/5] Building eBPF"
cmake -S . -B "$BUILD/cmake"
cmake --build "$BUILD/cmake"

echo
echo "[4/5] Creating release directory"

RELEASE_DIR="$DIST/${APP}-${VERSION}"
mkdir -p "$RELEASE_DIR"

cp "$BUILD/$APP" "$RELEASE_DIR/"
cp config/kelvos_config.toml "$RELEASE_DIR/"
cp README.md "$RELEASE_DIR/"

if [ -f CHANGELOG.md ]; then
    cp CHANGELOG.md "$RELEASE_DIR/"
fi

if [ -f LICENSE ]; then
    cp LICENSE "$RELEASE_DIR/"
fi

echo
echo "[5/5] Creating archive"

tar -C "$DIST" \
    -czf "$DIST/${APP}-${VERSION}.tar.gz" \
    "${APP}-${VERSION}"

echo
echo "================================="
echo " Release created"
echo "================================="
echo
echo "$DIST/${APP}-${VERSION}.tar.gz"
