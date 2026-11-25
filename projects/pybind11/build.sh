#!/bin/bash -eu
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

# Prepare the necessary requirements for the build
python3 -m pip install -r tests/requirements.txt

# Build every upstream harness under tests/fuzz via CMake
cmake -S . -B build \
  -DDOWNLOAD_CATCH=ON \
  -DDOWNLOAD_EIGEN=ON \
  -DPYBIND11_BUILD_FUZZERS=ON \
  -DCMAKE_CXX_COMPILER="${CXX}" \
  -DCMAKE_CXX_FLAGS="${CXXFLAGS}" \
  -DCMAKE_EXE_LINKER_FLAGS="${CXXFLAGS}"

# Prepare corpus and fuzzer binary in $OUT
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
cp /usr/local/lib/libpython${PYTHON_VERSION}.so.1.0 "$OUT/"

for src in tests/fuzz/*_fuzzer.cpp; do
  name=$(basename "$src" .cpp)
  cmake --build build -j$(nproc) --target "$name"
  cp "build/tests/fuzz/$name" "$OUT/$name"
  patchelf --set-rpath '$ORIGIN/' "$OUT/$name"

  if [[ -d tests/fuzz/corpus ]]; then
    zip -j -q "$OUT/${name}_seed_corpus.zip" tests/fuzz/corpus/*
  fi
done
