#!/bin/bash
# Copyright 2026 Google LLC
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
# Builds dav2d fuzz targets and prepares the IVF seed corpus.

set -eu

readonly BUILD_DIR="${WORK}/build"

rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

# Prepare cross file for i386 compilation.
cross_args=()
if [[ "${ARCHITECTURE}" == "i386" ]]; then
  read -r -a cflags_array <<< "${CFLAGS}"
  printf -v meson_cflags "'%s', " "${cflags_array[@]}"
  read -r -a cxxflags_array <<< "${CXXFLAGS}"
  printf -v meson_cxxflags "'%s', " "${cxxflags_array[@]}"
  sed -e "s|CC$|'${CC}'|" \
      -e "s|CXX$|'${CXX}'|" \
      -e "s|CFLAGS$|[${meson_cflags%, }]|" \
      -e "s|CXXFLAGS$|[${meson_cxxflags%, }]|" \
      "${SRC}/linux32.meson" > "${WORK}/linux32.meson"
  cross_args=(--cross-file "${WORK}/linux32.meson")
fi

# Build library and fuzzers.
meson setup \
    -Denable_tools=false \
    -Dfuzzing_engine=oss-fuzz \
    -Db_lundef=false \
    -Ddefault_library=static \
    -Dbuildtype=debugoptimized \
    -Dlogging=false \
    "-Dfuzzer_ldflags=${LIB_FUZZING_ENGINE}" \
    -Dtestdata_tests=true \
    --wrap-mode=nodownload \
    "${cross_args[@]}" \
    "${BUILD_DIR}"
ninja -j "$(nproc)" -C "${BUILD_DIR}"

# Prepare seed corpus: copy .ivf files as-is and wrap Section-5 .obu streams
# (split into frames on DAV2D_OBU_TD temporal delimiters) in AV02 IVF
# containers for dav2d_fuzzer.
rm -rf "${WORK}/tmp"
mkdir -p "${WORK}/tmp/testdata"
python3 "${SRC}/prepare_seed_corpus.py" \
    --output-dir "${WORK}/tmp/testdata" \
    "${SRC}/dav2d/tests/dav2d-test-data"
(
  cd "${WORK}/tmp/testdata"
  zip -q -m -r -0 "${WORK}/tmp/seed_corpus.zip" .
)

# Copy fuzzers and seed corpora.
for fuzzer in "${BUILD_DIR}"/tests/libfuzzer/dav2d_fuzzer*; do
  if [[ -f "${fuzzer}" && -x "${fuzzer}" ]]; then
    cp "${fuzzer}" "${OUT}/"
    cp "${WORK}/tmp/seed_corpus.zip" "${OUT}/${fuzzer##*/}_seed_corpus.zip"
  fi
done
