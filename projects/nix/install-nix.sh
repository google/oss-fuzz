#!/usr/bin/env bash
# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

oops() {
    echo "$0:" "$@" >&2
    exit 1
}

adduser \
  --home /var/empty \
  --shell /usr/sbin/nologin \
  --system \
  --gecos "" \
  --disabled-password \
  nixbld
addgroup nixbld
adduser nixbld nixbld

mkdir -m 0755 /nix

tmpDir="$(mktemp -d -t nix-binary-tarball-unpack.XXXXXXXXXX)"
tarball="$tmpDir/nix.tar.xz"
url="https://hydra.nixos.org/build/149592200/download/1/nix-2.4pre20210805_d64f967-x86_64-linux.tar.xz"
expected_hash=831e2f7657007c37fff006ed1653c033c703131a9ea733b507c200d983fa78e4

curl -L "$url" -o "$tarball" || oops "failed to download '$url'"

hash="$(shasum -a 256 -b "$tarball" | cut -c1-64)"
if [ "$hash" != "$expected_hash" ]; then
  oops "expected $expected_hash, got $hash"
fi

unpack="$tmpDir/unpack"
mkdir -p "$unpack"
tar -xJf "$tarball" -C "$unpack" || oops "failed to unpack '$url'"

script=$(echo "$unpack"/*/install)
[ -e "$script" ] || oops "installation script is missing from the binary tarball!"
USER="root" HOME="/root" "$script" --no-daemon
