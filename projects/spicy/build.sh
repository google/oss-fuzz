#!/bin/bash -eu
# Copyright 2022 Google LLC
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

echo 'add_subdirectory(ci/fuzz)' >> CMakeLists.txt

export LIBFUZZER_LIB=$( echo /usr/local/lib/clang/*/lib/$ARCHITECTURE-unknown-linux-gnu/libclang_rt.fuzzer_no_main.a )

CXXFLAGS="${CXXFLAGS} -DHILTI_HAVE_SANITIZER" ./configure --generator=Ninja --build-type=Release || (cat build/config.log && exit)
mapfile -t FUZZ_TARGETS < <(ninja -C build -t targets | grep fuzz- | cut -d: -f1)
ninja -j"$(nproc)" -C build "${FUZZ_TARGETS[@]}"

cp build/bin/fuzz-* "${OUT}"
cp -r build "${OUT}"

## Replace soflinks in copied out build directory with actual contents.
FROM=${SRC}/spicy
TO=${OUT}/$(basename "${SRC}")/spicy

# Replace softlinks to runtime headers with actual contents.
mkdir -p "${TO}/hilti/runtime/include/hilti/rt"
rm -rf "${TO}/hilti/runtime/include/hilti/rt"/*
cp -rP "${FROM}/hilti/runtime/include/"* "${TO}/hilti/runtime/include/hilti/rt"

mkdir -p "${TO}/spicy/runtime/include/spicy/rt"
rm -rf "${TO}/spicy/runtime/include/spicy/rt"/*
cp -rP "${FROM}/spicy/runtime/include/"* "${TO}/spicy/runtime/include/spicy/rt"

# Replace softlinks to 3rdparty dependencies with actual contents.
for DEP in any ArticleEnumClass-v2 ghc SafeInt tinyformat nlohmann; do
	D=${TO}/hilti/runtime/include/hilti/rt/3rdparty
	rm -r "${D}/${DEP}"
	mkdir -p "${D}/${DEP}"
	cp -rL "${FROM}/hilti/runtime/include/hilti/rt/3rdparty/${DEP}"/* "${D}/${DEP}/"
done
