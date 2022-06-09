#!/bin/bash

# Copyright 2020 Google Inc.
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

# If you ran this script as root against a local checkout, you may need to do
# the following to restore the Pigweed build environment before continuing
# development:
#   $ cd $PW_ROOT
#   $ sudo rm -rf .cipd/ .python3-env/ out/
#   $ git reset --hard
#   $ source ./bootstrap.sh

PW_ROOT="$SRC/pigweed"
BUILDROOT="$PW_ROOT/out/oss-fuzz"
mkdir -p $BUILDROOT

# Tweak the ensure file to skip downloading a bunch of build environment pieces
# that we won't use and/or that OSS-Fuzz wants to provide itself.
python $SRC/filter_cipd.py \
  --root "$PW_ROOT" \
  --json "$PW_ROOT/pw_env_setup/py/pw_env_setup/cipd_setup/pigweed.json" \
  --excludes \
      infra/cmake \
      fuchsia/third_party/bazel \
      fuchsia/third_party/clang \
      infra/go \
      pigweed/third_party/protoc-gen-go \
      pigweed/third_party/openocd \
      fuchsia/rust \
      pigweed/third_party/mingw64-x86_64-win32-seh \
      pigweed/host_tools \
      infra/goma/client \
      fuchsia/third_party/qemu \
      pigweed/third_party/kythe

# Pigweed checks that it can find these as part of a "sanity check".
mkdir -p "$PW_ROOT/.environment/cipd/pigweed/bin"
for b in arm-none-eabi-gcc bazel bloaty ; do
  x="$PW_ROOT/.environment/cipd/pigweed/bin/$b"
  if [[ ! -x $x ]] ; then
    ln -s "$(which false)" "$x"
  fi
done

# Setup the Pigweed build environemnt
set +u
PW_ENVSETUP_QUIET=1 source "$PW_ROOT/bootstrap.sh"
set -u

# -stdlib=libc++ conflicts with the -nostdinc++ used on pw_minimal_cpp_stdlib.
EXTRA_CXXFLAGS="-Wno-unused-command-line-argument"

# Disable UBSan vptr since target built with -fno-rtti.
EXTRA_CXXFLAGS+=" -fno-sanitize=vptr"
EXTRA_CXXFLAGS+=" -fcoverage-compilation-dir=$PW_ROOT"

# Build!
CXXFLAGS="$CXXFLAGS $EXTRA_CXXFLAGS" LDFLAGS="$CXXFLAGS" \
  gn gen "$BUILDROOT" \
    --root="$PW_ROOT" \
    --args="pw_toolchain_OSS_FUZZ_ENABLED=true
            pw_toolchain_SANITIZERS=[\"$SANITIZER\"]"
ninja -C "$BUILDROOT" fuzzers

# Use build-generated metadata to identify available fuzzers
python "$SRC/extract_pw_fuzzers.py" --buildroot "$BUILDROOT" --out "$OUT/"


