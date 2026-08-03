# Copyright 2023 Google LLC
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

mkdir -p build
cd build
cmake -DOGRE_STATIC=TRUE -DOGRE_BUILD_FUZZERS=TRUE -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
  -DOGRE_BUILD_DEPENDENCIES=FALSE -DOGRE_BUILD_SAMPLES=FALSE  ..
make -j$(nproc)

# copy the fuzzers
for fuzzer in image_fuzz stream_fuzz zip_fuzz ogre_deep_fuzz; do 
  cp bin/${fuzzer} $OUT/${fuzzer}
done

# Create seed corpus for the deep fuzzer from Ogre's test/sample media files
mkdir -p /tmp/ogre_deep_seeds
# Mesh samples (selector byte 0x00 = FUZZ_MESH)
for f in $(find .. -name '*.mesh' -not -name '*.skeleton' | head -5); do
  base=$(basename "$f")
  printf '\x00' | cat - "$f" > "/tmp/ogre_deep_seeds/mesh_${base}"
done
# Skeleton samples (selector byte 0x01 = FUZZ_SKELETON)
for f in $(find .. -name '*.skeleton' | head -5); do
  base=$(basename "$f")
  printf '\x01' | cat - "$f" > "/tmp/ogre_deep_seeds/skel_${base}"
done
# ConfigFile samples (selector byte 0x02 = FUZZ_CONFIG)
for f in $(find .. -name '*.cfg' | head -3); do
  base=$(basename "$f")
  printf '\x03' | cat - "$f" > "/tmp/ogre_deep_seeds/cfg_${base}"
done

cd /tmp/ogre_deep_seeds && zip -q $OUT/ogre_deep_fuzz_seed_corpus.zip * 2>/dev/null || true

# Copy dictionary
cp ../Tests/fuzz/ogre_deep_fuzz.dict $OUT/ogre_deep_fuzz.dict 2>/dev/null || true
