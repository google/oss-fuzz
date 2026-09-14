#!/bin/bash -eu
# Copyright 2022 Google LLC
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
set -euxo pipefail

export CXXFLAGS="$CXXFLAGS -Wno-error=missing-field-initializers"

# Patch target Makefiles to use absolute include paths for the per-target
# src/ directory (contains tusb_config.h). The upstream Makefiles use a
# relative "src" include which resolves differently per build directory,
# causing the indexer to pick up conflicting compile commands.
for f in test/fuzz/device/*/Makefile; do
  sed -i '/^[[:space:]]\+src[[:space:]]/s|src|$(abspath src)|' "$f"
done

# test/fuzz/make.mk bakes a fixed instrumentation choice into CFLAGS:
#   COVERAGE_FLAGS  ?= -fsanitize-coverage=trace-pc-guard
#   SANITIZER_FLAGS ?= -fsanitize=fuzzer -fsanitize=address
# Those are the right defaults for a developer running the harnesses by hand,
# but under OSS-Fuzz the engine and the sanitizer are chosen for us and are
# already present in $CFLAGS/$LIB_FUZZING_ENGINE. Both are "?=", so clearing
# them in the environment hands that choice back to OSS-Fuzz and stops, for
# example, an msan build from also being asked for -fsanitize=address.
export COVERAGE_FLAGS=""
export SANITIZER_FLAGS=""

fuzz_harness=$(ls -d test/fuzz/device/*/)
for h in $fuzz_harness
do
  name=$(basename $h)
  make -C $h get-deps

  if [ "$name" = "net_ncm" ]; then
    # net_ncm is the one harness that does not include the shared
    # make.mk/rules.mk. It is a standalone single-file harness whose Makefile
    # sets its own flags outright:
    #   CFLAGS += $(addprefix -I,$(INC)) -g -O1 -fsanitize=address
    #   FUZZ_FLAGS := -fsanitize=fuzzer
    # so it never consults $LIB_FUZZING_ENGINE and linked libFuzzer's main() no
    # matter which engine was requested. Under centipede the resulting binary
    # cannot dump a PC table, so check_build reported net_ncm as a broken target
    # ("Could not get PCTable") and failed the whole project; the hardcoded
    # -fsanitize=address would likewise collide with an msan build.
    #
    # Override both on the command line, which takes precedence over the "+="
    # and ":=" in the Makefile, and re-supply the two include paths that the
    # overridden CFLAGS line would otherwise have contributed ($(TOP)/src and
    # the harness directory, which holds tusb_config.h). -lc++ is needed because
    # this harness links with $CC rather than $CXX while the engine archive is
    # C++.
    make -C $h all \
      CFLAGS="$CFLAGS -I$SRC/tinyusb/src -I." \
      FUZZ_FLAGS="$LIB_FUZZING_ENGINE -lc++"
  else
    make -C $h all
  fi

  cp $h/_build/$name $OUT/
  corpus=$h/$(basename $h)_seed_corpus.zip
  if test -f $corpus; then
    cp $corpus $OUT/
  fi
done
