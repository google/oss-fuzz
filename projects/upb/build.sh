#!/bin/bash -eu
# Copyright 2019 Google Inc.
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
FUZZER_DICTIONARIES="\
"

NO_VPTR="--copt=-fno-sanitize=vptr --linkopt=-fno-sanitize=vptr"
EXTRA_BAZEL_FLAGS="--strip=never  $(for f in $CXXFLAGS; do if [ $f != "-stdlib=libc++" ] ; then echo --copt=$f --linkopt=$f; fi; done)"
bazel build --dynamic_mode=off --spawn_strategy=standalone --genrule_strategy=standalone \
  --verbose_failures \
  $EXTRA_BAZEL_FLAGS \
  $NO_VPTR \
  -k \
  :file_descriptor_parsenew_fuzzer

# Copied from projects/envoy/build.sh which also uses Bazel.
# Profiling with coverage requires that we resolve+copy all Bazel symlinks and
# also remap everything under proc/self/cwd to correspond to Bazel build paths.
if [ "$SANITIZER" = "coverage" ]
then
  # The build invoker looks for sources in $SRC, but it turns out that we need
  # to not be buried under src/, paths are expected at out/proc/self/cwd by
  # the profiler.
  declare -r REMAP_PATH="${OUT}/proc/self/cwd"
  mkdir -p "${REMAP_PATH}"
  rsync -av "${SRC}"/upb "${REMAP_PATH}"
fi

file=file_descriptor_parsenew_fuzzer
echo "${file}"
TARGET_DRIVERLESS=bazel-bin/"${file}"
echo "copying fuzzer"
cp "${TARGET_DRIVERLESS}" "${OUT}"/"${file}"_fuzz_test

# Copy dictionaries and options files to $OUT/
for dict in $FUZZER_DICTIONARIES; do
  cp $dict $OUT/
done

# Don't have a consistent naming convention between fuzzer files and corpus
# directories so we resort to hard coding zipping corpses
zip $OUT/file_descriptor_parsenew_fuzzer_seed_corpus.zip tests/*
