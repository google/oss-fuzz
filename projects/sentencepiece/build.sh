#!/bin/bash -eu
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

set -x

# build project
mkdir build
cd build
cmake ../ -B ./ -DSPM_ENABLE_SHARED=ON -DCMAKE_INSTALL_PREFIX=./root -DSPM_BUILD_TEST=ON
cmake --build ./ --config Release --target install --parallel $(nproc)

# Generate a minimal sentencepiece model for the processor_text_fuzzer.
# Use the sanitized compiler but link without the fuzzer engine since
# this is a regular executable, not a fuzzer.
$CXX $CXXFLAGS -std=c++17 \
    -I../src -I../src/builtin_pb -I../third_party/protobuf-lite \
    -I. -I./root/include \
    $SRC/generate_model.cc \
    ./root/lib/*.a \
    -lpthread \
    -o generate_model

# Generate the unigram model and convert it to a C header for embedding
./generate_model /tmp/embedded_model.bin unigram

# Create embedded_model.h with the model as a byte array
python3 -c "
import sys
data = open('/tmp/embedded_model.bin', 'rb').read()
with open('embedded_model.h', 'w') as f:
    f.write('// Auto-generated embedded model data\\n')
    f.write('#pragma once\\n')
    f.write('static const unsigned char kEmbeddedModelData[] = {\\n')
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        f.write('  ' + ', '.join(f'0x{b:02x}' for b in chunk) + ',\\n')
    f.write('};\\n')
    f.write(f'static const size_t kEmbeddedModelSize = {len(data)};\\n')
print(f'Generated embedded_model.h ({len(data)} bytes)')
"

# Create seed corpus for model_load_fuzzer with models of all types
mkdir -p /tmp/model_seeds
./generate_model /tmp/model_seeds/unigram.model unigram
./generate_model /tmp/model_seeds/bpe.model bpe
./generate_model /tmp/model_seeds/word.model word
./generate_model /tmp/model_seeds/char.model char
cd /tmp/model_seeds && zip -j $OUT/model_load_fuzzer_seed_corpus.zip *.model && cd -

# build fuzzers
for fuzzer in $(find $SRC -name '*_fuzzer.cc' | grep -v 'third_party'); do
  fuzz_basename=$(basename -s .cc $fuzzer)
  echo "Building fuzzer: $fuzz_basename"
  $CXX $CXXFLAGS -std=c++17 \
      -I. -I./root/include \
      $fuzzer $LIB_FUZZING_ENGINE \
      ./root/lib/*.a \
      -o $OUT/$fuzz_basename
done
