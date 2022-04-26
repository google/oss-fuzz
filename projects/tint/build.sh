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

if [ -n "${OSS_FUZZ_CI-}" ]
then
  # When running in the CI, restrict to a small number of fuzz targets to save
  # time and disk space.  A SPIR-V Tools-based fuzzer that uses the HLSL
  # back-end, and a regular fuzzer that uses the MSL back-end, are selected.
  SPIRV_TOOLS_FUZZERS="tint_spirv_tools_hlsl_writer_fuzzer"
  SPIRV_FUZZERS="tint_spv_reader_msl_writer_fuzzer\
   ${SPIRV_TOOLS_FUZZERS}"
else
  SPIRV_TOOLS_FUZZERS="tint_spirv_tools_hlsl_writer_fuzzer\
   tint_spirv_tools_msl_writer_fuzzer\
   tint_spirv_tools_spv_writer_fuzzer\
   tint_spirv_tools_wgsl_writer_fuzzer"
  SPIRV_FUZZERS="tint_spv_reader_hlsl_writer_fuzzer\
   tint_spv_reader_msl_writer_fuzzer\
   tint_spv_reader_spv_writer_fuzzer\
   tint_spv_reader_wgsl_writer_fuzzer\
   ${SPIRV_TOOLS_FUZZERS}"
fi

# An un-instrumented build of spirv-as is used to generate a corpus of SPIR-V binaries.
git clone --depth 1 https://github.com/KhronosGroup/SPIRV-Tools.git spirv-tools
git clone https://github.com/KhronosGroup/SPIRV-Headers spirv-tools/external/spirv-headers --depth=1
mkdir -p out/spirv-tools-build
pushd out/spirv-tools-build

# Back-up instrumentation options
CFLAGS_SAVE="$CFLAGS"
CXXFLAGS_SAVE="$CXXFLAGS"
unset CFLAGS
unset CXXFLAGS
export AFL_NOOPT=1

cmake -GNinja ../../spirv-tools -DCMAKE_BUILD_TYPE=Release
ninja spirv-as

# Restore instrumentation options
export CFLAGS="${CFLAGS_SAVE}"
export CXXFLAGS="${CXXFLAGS_SAVE}"
unset AFL_NOOPT

popd

# Generate a corpus of SPIR-V binaries from the SPIR-V assembly files in the
# tint repository.
mkdir $WORK/spirv-corpus
python3 src/tint/fuzzers/generate_spirv_corpus.py test/tint $WORK/spirv-corpus out/spirv-tools-build/tools/spirv-as

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

for fuzzer in $SPIRV_TOOLS_FUZZERS
do
  echo "[libfuzzer]
max_len = 10000
cross_over = 0
mutate_depth = 1
tint_enable_all_mutations = false
tint_mutation_batch_size = 5
" > "$OUT/${fuzzer}.options"
done

# Now actually build tint

cp scripts/standalone.gclient .gclient
gclient sync

mkdir -p out/Debug
pushd out/Debug

# ubsan's vptr sanitization is desabled as it requires RTTI, which is disabled
# when building tint.
CFLAGS="$CFLAGS -fno-sanitize=vptr" \
CXXFLAGS="$CXXFLAGS -fno-sanitize=vptr" \
cmake -GNinja ../.. -DCMAKE_BUILD_TYPE=Release -DTINT_BUILD_FUZZERS=ON -DTINT_BUILD_SPIRV_TOOLS_FUZZER=ON -DTINT_BUILD_TESTS=OFF -DTINT_LIB_FUZZING_ENGINE_LINK_OPTIONS=$LIB_FUZZING_ENGINE

ninja ${SPIRV_FUZZERS}

cp ${SPIRV_FUZZERS} $OUT

popd
