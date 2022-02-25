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

git clone https://github.com/KhronosGroup/SPIRV-Headers external/spirv-headers --depth=1
git clone https://github.com/protocolbuffers/protobuf   external/protobuf      --branch v3.13.0.1
git clone https://dawn.googlesource.com/tint --depth=1

mkdir build
pushd build

CMAKE_ARGS="-DSPIRV_BUILD_LIBFUZZER_TARGETS=ON -DSPIRV_LIB_FUZZING_ENGINE_LINK_OPTIONS=$LIB_FUZZING_ENGINE"

# With ubsan, RTTI must be enabled due to certain checks (vptr) requiring it.
if [ $SANITIZER == "undefined" ];
then
  CMAKE_ARGS="${CMAKE_ARGS} -DENABLE_RTTI=ON"
fi
cmake -G Ninja .. ${CMAKE_ARGS}
ninja

SPIRV_BINARY_FUZZERS="spvtools_binary_parser_fuzzer\
 spvtools_dis_fuzzer\
 spvtools_opt_legalization_fuzzer\
 spvtools_opt_performance_fuzzer\
 spvtools_opt_size_fuzzer\
 spvtools_val_fuzzer"

SPIRV_ASSEMBLY_FUZZERS="spvtools_as_fuzzer"

for fuzzer in $SPIRV_BINARY_FUZZERS $SPIRV_ASSEMBLY_FUZZERS
do
  cp test/fuzzers/$fuzzer $OUT
done

popd

# An un-instrumented build of spirv-as is used to generate a corpus of SPIR-V binaries.
mkdir standard-build
pushd standard-build

# Back-up instrumentation options
CFLAGS_SAVE="$CFLAGS"
CXXFLAGS_SAVE="$CXXFLAGS"
unset CFLAGS
unset CXXFLAGS
export AFL_NOOPT=1

cmake -G Ninja .. ${CMAKE_ARGS}
ninja spirv-as

# Restore instrumentation options
export CFLAGS="${CFLAGS_SAVE}"
export CXXFLAGS="${CXXFLAGS_SAVE}"
unset AFL_NOOPT

popd


# Generate a corpus of SPIR-V binaries from the SPIR-V assembly files in the
# SPIRV-Tools and tint repositories.
mkdir $WORK/tint-binary-corpus
python3 tint/src/tint/fuzzers/generate_spirv_corpus.py tint/test $WORK/tint-binary-corpus standard-build/tools/spirv-as
mkdir $WORK/spirv-binary-corpus-hashed-names
tint_test_cases=`ls $WORK/tint-binary-corpus/*.spv`
spirv_tools_test_cases=`find test/fuzzers/corpora -name "*.spv"`
for f in $tint_test_cases $spirv_tools_test_cases
do
  hashed_name=$(sha1sum "$f" | awk '{print $1}')
  cp $f $WORK/spirv-binary-corpus-hashed-names/$hashed_name
done
zip -j "$WORK/spirv_binary_seed_corpus.zip" "$WORK/spirv-binary-corpus-hashed-names"/*

# Supply each of the binary fuzzers with this seed corpus.
for fuzzer in $SPIRV_BINARY_FUZZERS
do
  cp "$WORK/spirv_binary_seed_corpus.zip" "$OUT/${fuzzer}_seed_corpus.zip"
done

# Generate a corpus of SPIR-V assembly files from the tint repository.
mkdir $WORK/spirv-assembly-corpus-hashed-names
for f in `find tint/test -name "*.spvasm"`
do
  hashed_name=$(sha1sum "$f" | awk '{print $1}')
  cp $f $WORK/spirv-assembly-corpus-hashed-names/$hashed_name
done

zip -j "$WORK/spirv_assembly_seed_corpus.zip" "$WORK/spirv-assembly-corpus-hashed-names"/*

# Supply each of the assembly fuzzers with this seed corpus.
for fuzzer in $SPIRV_ASSEMBLY_FUZZERS
do
  cp "$WORK/spirv_assembly_seed_corpus.zip" "$OUT/${fuzzer}_seed_corpus.zip"
done
