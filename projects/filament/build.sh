#!/bin/bash -eu
# Copyright 2024 Google LLC
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
# OSS-Fuzz build script for google/filament.
# Builds three libFuzzer targets over filament's untrusted-asset loaders:
#   filameshio_fuzzer      -> MeshReader::loadMeshFromBuffer        (.filamesh)
#   gltfio_meshopt_fuzzer  -> gltfio EXT_meshopt_compression decode (glTF/GLB)
#   gltfio_accessor_fuzzer -> gltfio cgltf accessor unpack          (glTF/GLB, sparse)
#
# OSS-Fuzz provides $CC/$CXX/$CFLAGS/$CXXFLAGS (sanitizer + fuzzer-no-link
# instrumentation), $LIB_FUZZING_ENGINE (the libFuzzer main), $OUT and $WORK.

cd $SRC/filament

# ---------------------------------------------------------------------------
# 1. Drop the fuzz targets into a dedicated library subdirectory.
# ---------------------------------------------------------------------------
FUZZ_DIR=libs/filament_ossfuzz
mkdir -p $FUZZ_DIR
cp $SRC/filameshio_fuzzer.cpp $SRC/gltfio_meshopt_fuzzer.cpp $SRC/gltfio_accessor_fuzzer.cpp $FUZZ_DIR/

cat > $FUZZ_DIR/CMakeLists.txt <<'EOF'
# OSS-Fuzz fuzz targets. Instrumentation comes from CMAKE_*_FLAGS (= $CFLAGS/
# $CXXFLAGS); the libFuzzer main comes from $LIB_FUZZING_ENGINE.
set(FUZZ_LINK "$ENV{LIB_FUZZING_ENGINE}")

add_executable(filameshio_fuzzer filameshio_fuzzer.cpp)
target_link_libraries(filameshio_fuzzer PRIVATE filameshio filament utils math)
target_compile_options(filameshio_fuzzer PRIVATE -Wno-everything)
target_link_options(filameshio_fuzzer PRIVATE ${FUZZ_LINK})

foreach(t gltfio_meshopt_fuzzer gltfio_accessor_fuzzer)
  add_executable(${t} ${t}.cpp)
  target_link_libraries(${t} PRIVATE gltfio_core)
  target_include_directories(${t} PRIVATE
      ${CMAKE_CURRENT_SOURCE_DIR}/../gltfio/src
      ${CMAKE_CURRENT_SOURCE_DIR}/../../third_party/cgltf)
  target_compile_options(${t} PRIVATE -Wno-everything)
  target_link_options(${t} PRIVATE ${FUZZ_LINK})
endforeach()
EOF

# Wire the subdirectory into the top-level build (after the last libs/ entry).
if ! grep -q "add_subdirectory(\${LIBRARIES}/filament_ossfuzz)" CMakeLists.txt; then
  # Insert right after the gltfio library is added so its targets exist.
  sed -i 's#\(add_subdirectory(${LIBRARIES}/gltfio)\)#\1\nadd_subdirectory(${LIBRARIES}/filament_ossfuzz)#' CMakeLists.txt
fi

# ---------------------------------------------------------------------------
# 2. Toolchain compatibility fixes for building under clang + OSS-Fuzz flags.
#    filament builds with -Werror and clang thread-safety attributes that the
#    OSS-Fuzz clang rejects; relax those so instrumentation flags don't trip them.
# ---------------------------------------------------------------------------
for f in filament/CMakeLists.txt filament/backend/CMakeLists.txt libs/utils/CMakeLists.txt; do
  sed -i 's/PRIVATE -Wthread-safety)/PRIVATE -Wno-thread-safety)/g' $f || true
  sed -i '/^[[:space:]]*-Werror$/d' $f || true
done

# ---------------------------------------------------------------------------
# 3. Configure. NDEBUG is essential: filament gates cgltf_validate behind
#    #ifndef NDEBUG and meshoptimizer enforces decoder preconditions with
#    assert() only -- i.e. the release config is the vulnerable one we fuzz.
# ---------------------------------------------------------------------------
BUILD=$WORK/build
mkdir -p $BUILD
cmake -GNinja -S $SRC/filament -B $BUILD \
  -DCMAKE_C_COMPILER="$CC" \
  -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_C_FLAGS="$CFLAGS -DNDEBUG" \
  -DCMAKE_CXX_FLAGS="$CXXFLAGS -DNDEBUG" \
  -DCMAKE_BUILD_TYPE=Release \
  -DUSE_STATIC_LIBCXX=OFF \
  -DFILAMENT_SKIP_SAMPLES=ON \
  -DFILAMENT_SKIP_SDL2=ON \
  -DFILAMENT_SUPPORTS_VULKAN=OFF \
  -DFILAMENT_SUPPORTS_OPENGL=OFF \
  -DFILAMENT_ENABLE_MATDBG=OFF \
  -DFILAMENT_USE_EXTERNAL_GLES3=OFF

# ---------------------------------------------------------------------------
# 4. Build only the three fuzz targets (pulls in their deps transitively).
# ---------------------------------------------------------------------------
cmake --build $BUILD --target filameshio_fuzzer gltfio_meshopt_fuzzer gltfio_accessor_fuzzer

# ---------------------------------------------------------------------------
# 5. Stage binaries and seed corpora.
# ---------------------------------------------------------------------------
for t in filameshio_fuzzer gltfio_meshopt_fuzzer gltfio_accessor_fuzzer; do
  cp "$(find $BUILD -name $t -type f -perm -u+x | head -1)" $OUT/
done

# Seed corpora (optional but recommended): any sample assets shipped in-tree.
if compgen -G "$SRC/filament/assets/models/**/*.glb" > /dev/null 2>&1; then
  mkdir -p $WORK/gltf_seeds
  find $SRC/filament/assets -name '*.glb' -exec cp {} $WORK/gltf_seeds/ \; 2>/dev/null || true
  (cd $WORK/gltf_seeds && zip -q $OUT/gltfio_meshopt_fuzzer_seed_corpus.zip ./* 2>/dev/null) || true
  cp -f $OUT/gltfio_meshopt_fuzzer_seed_corpus.zip $OUT/gltfio_accessor_fuzzer_seed_corpus.zip 2>/dev/null || true
fi
