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

FUZZER_FILES="\
tests/file_descriptor_parsenew_fuzzer.cc \
"

FUZZER_DICTIONARIES="\
"

FUZZER_LIBRARIES="\
bazel-bin/*.a \
bazel-bin/bazel/*.a \
bazel-bin/*.a \
"

# build upb
NO_VPTR="--copt=-fno-sanitize=vptr --linkopt=-fno-sanitize=vptr"
EXTRA_BAZEL_FLAGS="--strip=never  $(for f in $CXXFLAGS; do if [ $f != "-stdlib=libc++" ] ; then echo --copt=$f --linkopt=$f; fi; done)"
bazel build --dynamic_mode=off --spawn_strategy=standalone --genrule_strategy=standalone \
  $EXTRA_BAZEL_FLAGS \
  $NO_VPTR \
  :all bazel/... @lua//:all

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

CFLAGS="${CFLAGS} -Iinclude -Ithird_party/nanopb -I."
CXXFLAGS="${CXXFLAGS} -Iinclude -Ithird_party/nanopb -I. -stdlib=libc++"

for file in $FUZZER_FILES; do
  fuzzer_name=$(basename $file .cc)
  echo "Building fuzzer $fuzzer_name"
  $CXX $CXXFLAGS \
    $file -o $OUT/$fuzzer_name \
    $LIB_FUZZING_ENGINE ${FUZZER_LIBRARIES}
done

# Copy dictionaries and options files to $OUT/
for dict in $FUZZER_DICTIONARIES; do
  cp $dict $OUT/
done

cp $SRC/upb/tests/options/*.options $OUT/

zip $OUT/file_descriptor_parsenew_fuzzer.zip tests/corpus/*
