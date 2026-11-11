#!/bin/sh
# Copyright (C) 2026 Daniel Aguayo
# SPDX-License-Identifier: GPL-3.0-or-later
# Cross-compiles credenza for every release target into dist/ and writes
# dist/SHA256SUMS. Run from the repo root: sh scripts/build.sh
set -eu

# go1.27.3 includes security fixes to crypto/x509; raise together with the
# go line of go.mod.
MIN=1.27.3

# split V sets MAJOR, MINOR and PATCH from V (N.N or N.N.N, a missing patch
# counts as 0), or returns 1 when V does not parse, as for a pre-release
# (1.28rc1) or devel build.
split() {
	case $1 in
	'' | *[!0-9.]* | .* | *. | *..*) return 1 ;;
	esac
	old_ifs=$IFS
	IFS=.
	# shellcheck disable=SC2086 # split on dots; the case above admits digits and dots only
	set -- $1
	IFS=$old_ifs
	[ $# -eq 2 ] || [ $# -eq 3 ] || return 1
	MAJOR=$1 MINOR=$2 PATCH=${3:-0}
}

GV=$(go env GOVERSION)
split "$MIN"
set -- "$MAJOR" "$MINOR" "$PATCH"
case $GV in
go[0-9]*) split "${GV#go}" || { echo "build.sh: cannot parse go version $GV; want go$MIN or newer" >&2; exit 1; } ;;
*) echo "build.sh: cannot parse go version $GV; want go$MIN or newer" >&2; exit 1 ;;
esac
# Major, then minor, then patch, compared as numbers.
if [ "$MAJOR" -lt "$1" ] ||
	{ [ "$MAJOR" -eq "$1" ] && [ "$MINOR" -lt "$2" ]; } ||
	{ [ "$MAJOR" -eq "$1" ] && [ "$MINOR" -eq "$2" ] && [ "$PATCH" -lt "$3" ]; }; then
	echo "build.sh: go $GV is older than go$MIN (crypto/x509 security fixes); upgrade Go" >&2
	exit 1
fi

VERSION=$(git describe --tags --always --dirty)

mkdir -p dist
rm -f dist/credenza-* dist/SHA256SUMS

# build NAME GOOS GOARCH [GOARM]
build() {
	CGO_ENABLED=0 GOOS=$2 GOARCH=$3 GOARM=${4:-} \
		go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "dist/$1" ./cmd/credenza
}

build credenza-linux-armv7 linux arm 7
build credenza-linux-arm64 linux arm64
build credenza-linux-amd64 linux amd64
build credenza-darwin-arm64 darwin arm64
build credenza-darwin-amd64 darwin amd64
build credenza-freebsd-amd64 freebsd amd64

# shasum defaults to SHA-1 on macOS.
(cd dist && shasum -a 256 credenza-* > SHA256SUMS)
echo "build.sh: $VERSION: dist/credenza-* and dist/SHA256SUMS"
