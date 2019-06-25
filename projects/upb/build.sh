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

# build fuzz target
NO_VPTR="--copt=-fno-sanitize=vptr --linkopt=-fno-sanitize=vptr"
EXTRA_BAZEL_FLAGS="--strip=never  $(for f in $CXXFLAGS; do if [ $f != "-stdlib=libc++" ] ; then echo --copt=$f --linkopt=$f; fi; done)"
bazel build --dynamic_mode=off --spawn_strategy=standalone --genrule_strategy=standalone \
  $EXTRA_BAZEL_FLAGS \
  $NO_VPTR -k \
  :file_descriptor_parsenew_fuzzer || true

# Copied from projects/envoy/build.sh which also uses Bazel.
if [ "$SANITIZER" = "coverage" ]
then
  declare -r REMAP_PATH=${OUT}/proc/self/cwd
  mkdir -p ${REMAP_PATH}
  rsync -ak ${SRC}/upb ${REMAP_PATH}
fi

# Now that all is done, we just have to copy the existing corpora and
# dictionaries to have them available in the runtime environment.
# The tweaks to the filenames below are to make sure corpora/dictionary have
# similar names as the fuzzer binary.
for dict in $FUZZER_DICTIONARIES; do
  cp $dict $OUT/
done

# Zip corpus
zip $OUT/file_descriptor_parsenew_fuzzer_seed_corpus.zip tests/*

# Finally, make sure we don't accidentally run with stuff from the bazel cache.
rm -f bazel-*
