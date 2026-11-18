#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) TerminalMax contributors
#
# Builds libwgbridge.so for Android (arm64-v8a, x86_64) with the NDK clang,
# API 26, 16 KB page-size aligned, then verifies the LOAD segment alignment.
set -euo pipefail

cd "$(dirname "$0")"
: "${ANDROID_NDK_HOME:?ANDROID_NDK_HOME must point to an Android NDK}"
API="${ANDROID_API:-26}"

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)  HOST_TAG=linux-x86_64 ;;
  Darwin-*)      HOST_TAG=darwin-x86_64 ;;
  *) echo "unsupported build host" >&2; exit 1 ;;
esac
BIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$HOST_TAG/bin"
OBJDUMP="$BIN/llvm-objdump"
[ -x "$OBJDUMP" ] || { echo "llvm-objdump not found in $BIN" >&2; exit 1; }

build() {
  local abi="$1" goarch="$2" triple="$3"
  local out="out/android/$abi/libwgbridge.so"
  mkdir -p "$(dirname "$out")"
  echo "== building $abi ($triple$API)"
  CGO_ENABLED=1 GOOS=android GOARCH="$goarch" \
  CC="$BIN/${triple}${API}-clang" \
  CGO_LDFLAGS="-Wl,-z,max-page-size=16384 -Wl,--build-id=none -Wl,-soname,libwgbridge.so" \
  go build -buildmode=c-shared -trimpath -buildvcs=false \
    -ldflags="-s -w -buildid=" \
    -o "$out" ./cmd/libwgbridge
  rm -f "${out%.so}.h"   # generated header is not needed in the APK tree

  # Fail if any LOAD segment is aligned below 2**14 (16 KB).
  local bad=0 n=0 line a
  while IFS= read -r line; do
    n=$((n + 1))
    a="${line##*2\*\*}"
    case "$a" in
      ''|*[!0-9]*) echo "cannot parse: $line" >&2; bad=1;;
      *) if [ "$a" -lt 14 ]; then echo "bad alignment: $line" >&2; bad=1; fi;;
    esac
  done < <("$OBJDUMP" -p "$out" | grep -E '^[[:space:]]*LOAD')
  if [ "$n" -eq 0 ] || [ "$bad" -ne 0 ]; then
    echo "16 KB alignment check FAILED for $out" >&2
    exit 1
  fi
  echo "   $n LOAD segments, all aligned >= 2**14"
}

build arm64-v8a arm64 aarch64-linux-android
build x86_64    amd64 x86_64-linux-android
echo "done: out/android/*/libwgbridge.so"
