#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) TerminalMax contributors
#
# Builds the desktop shared library for the current host:
#   macOS   -> out/macos-arm64/libwgbridge.dylib (ad-hoc codesigned)
#   Windows -> out/windows-x64/wgbridge.dll      (mingw gcc, Git Bash/MSYS2)
set -euo pipefail

cd "$(dirname "$0")"
LDFLAGS="-s -w -buildid="

case "$(uname -s)" in
  Darwin)
    out=out/macos-arm64/libwgbridge.dylib
    mkdir -p "$(dirname "$out")"
    CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 \
    CGO_CFLAGS="-arch arm64 -mmacosx-version-min=12.0" \
    CGO_LDFLAGS="-arch arm64 -mmacosx-version-min=12.0" \
    go build -buildmode=c-shared -trimpath -buildvcs=false \
      -ldflags="$LDFLAGS -extldflags=-Wl,-install_name,@rpath/libwgbridge.dylib" \
      -o "$out" ./cmd/libwgbridge
    codesign --force -s - "$out"
    codesign -v "$out"
    echo "built $out"
    ;;
  MINGW*|MSYS*|CYGWIN*)
    out=out/windows-x64/wgbridge.dll
    mkdir -p "$(dirname "$out")"
    CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC="${CC:-gcc}" \
    go build -buildmode=c-shared -trimpath -buildvcs=false \
      -ldflags="$LDFLAGS" \
      -o "$out" ./cmd/libwgbridge
    echo "built $out"
    ;;
  *)
    echo "build-desktop.sh supports macOS and Windows (Git Bash/MSYS2) hosts only" >&2
    exit 1
    ;;
esac
