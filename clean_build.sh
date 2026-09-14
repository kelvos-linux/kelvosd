#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$ROOT_DIR/build"
BINARY="$ROOT_DIR/kelvosd"
CONFIG_LOG="/var/log/kelvos_traffic_monitor.jsonl"

printf 'Cleaning generated build files...\n'
rm -rf -- "$BUILD_DIR"
rm -f -- "$BINARY"

printf 'Clearing repository log files...\n'
while IFS= read -r -d '' log_file; do
    rm -f -- "$log_file"
done < <(find "$ROOT_DIR" -path "$BUILD_DIR" -prune -o -type f \( -name '*.log' -o -name '*.jsonl' \) -print0)

if [[ -e "$CONFIG_LOG" ]]; then
    if [[ -w "$CONFIG_LOG" ]]; then
        : > "$CONFIG_LOG"
        printf 'Cleared %s\n' "$CONFIG_LOG"
    else
        printf 'Warning: cannot clear %s without write permission\n' "$CONFIG_LOG" >&2
    fi
fi

printf 'Configuring CMake...\n'
cmake -S "$ROOT_DIR" -B "$BUILD_DIR"

printf 'Building BPF program...\n'
cmake --build "$BUILD_DIR" --parallel

printf 'Building Go userspace binary...\n'
go build -o "$BINARY" ./cmd/kelvosd

printf 'Fresh build complete: %s\n' "$BINARY"
