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
cmake -DOGRE_STATIC=TRUE ..
make -j$(nproc)

# Build the fuzzers
for fuzzer in image_fuzz stream_fuzz; do
  $CXX $CXXFLAGS $LIB_FUZZING_ENGINE $SRC/${fuzzer}.cpp -o $OUT/${fuzzer} \
    -I../OgreMain/include/ -I./include/ \
    -pthread -I../PlugIns/STBICodec/include/ -I../Components/Bites/include/ \
     -Wl,--start-group \
	./lib/libOgreOverlayStatic.a            \
	./lib/libOgreRTShaderSystemStatic.a     \
	./lib/libOgreBulletStatic.a             \
	./lib/libPlugin_PCZSceneManagerStatic.a \
	./lib/libOgreMainStatic.a               \
	./lib/libOgreTerrainStatic.a            \
	./lib/libPlugin_OctreeZoneStatic.a      \
	./lib/libOgrePropertyStatic.a           \
	./lib/libCodec_STBIStatic.a             \
	./lib/libOgreMeshLodGeneratorStatic.a \
	./lib/libOgreVolumeStatic.a \
	./lib/libOgrePagingStatic.a \
	./lib/libPlugin_BSPSceneManagerStatic.a \
	./lib/libPlugin_OctreeSceneManagerStatic.a \
	./lib/libDefaultSamples.a \
	./lib/libOgreBitesStatic.a \
	./lib/libPlugin_DotSceneStatic.a \
	./lib/libPlugin_ParticleFXStatic.a \
	./pugixml-1.14/libpugixml.a \
      -Wl,--end-group
done
