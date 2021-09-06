#!/bin/bash -eu
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

cp standalone.gclient .gclient
gclient sync

mkdir -p out/Debug
pushd out/Debug

# ubsan's vptr sanitization is desabled as it requires RTTI, which is disabled
# when building tint.
CFLAGS="$CFLAGS -fno-sanitize=vptr" \
CXXFLAGS="$CXXFLAGS -fno-sanitize=vptr" \
cmake -GNinja ../.. -DTINT_BUILD_FUZZERS=ON -DTINT_BUILD_SPIRV_TOOLS_FUZZER=ON -DTINT_BUILD_TESTS=OFF -DTINT_LIB_FUZZING_ENGINE_LINK_OPTIONS=$LIB_FUZZING_ENGINE

SPIRV_FUZZERS="tint_spv_reader_fuzzer\
 tint_spv_reader_msl_writer_fuzzer\
 tint_spv_reader_wgsl_writer_fuzzer\
 tint_spv_reader_hlsl_writer_fuzzer\
 tint_spv_reader_spv_writer_fuzzer"

# TODO(afd): add tint_spirv_tools_fuzzer

# The spirv-as tool is used to build seed corpora
ninja ${SPIRV_FUZZERS} spirv-as

cp ${SPIRV_FUZZERS} $OUT

popd

# Generate a corpus of SPIR-V binaries from the SPIR-V assembly files in the
# tint repository.
mkdir $WORK/spirv-corpus
python3 fuzzers/generate_spirv_corpus.py test $WORK/spirv-corpus out/Debug/spirv-as

mkdir $WORK/spirv-corpus-hashed-names
for f in `ls $WORK/spirv-corpus/*.spv`
do
  hashed_name=$(sha1sum "$f" | awk '{print $1}')
  cp $f $WORK/spirv-corpus-hashed-names/$hashed_name
done

zip -j "$WORK/seed_corpus.zip" "$WORK"/spirv-corpus-hashed-names/*

for fuzzer in $SPIRV_FUZZERS
do
  cp "$WORK/seed_corpus.zip" "$OUT/${fuzzer}_seed_corpus.zip"
done
