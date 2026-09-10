#!/bin/bash -eu
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

# Regenerate the seed corpora from the project's known-good/known-bad unit
# test vectors (tests/fuzz/{ofh,ngap}/gen_corpus.py). No build dependencies.
python3 tests/fuzz/ofh/gen_corpus.py
python3 tests/fuzz/ngap/gen_corpus.py

# Configure the fuzz harnesses via OCUDU's own ENABLE_FUZZTESTS CMake option
# (see tests/fuzz/CMakeLists.txt). Sanitizer and coverage instrumentation is
# left entirely to $CFLAGS/$CXXFLAGS, which OSS-Fuzz already sets for the
# selected $SANITIZER; every optional vendor/hardware backend not needed by
# the fuzz targets is disabled to keep the build minimal, matching the
# configuration OCUDU's own tests/fuzz/Dockerfile uses.
cmake -S "$SRC/ocudu" -B "$WORK/build" \
    -GNinja \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DENABLE_FUZZTESTS=ON \
    -DBUILD_TESTING=OFF \
    -DENABLE_WERROR=OFF \
    -DENABLE_UHD=OFF \
    -DENABLE_ZEROMQ=OFF \
    -DENABLE_FFTW=OFF \
    -DENABLE_MKL=OFF \
    -DENABLE_FFTZ=OFF \
    -DENABLE_ARMPL=OFF \
    -DENABLE_DPDK=OFF \
    -DENABLE_LIBNUMA=OFF \
    -DENABLE_BACKWARD=OFF

# fuzz_targets is an aggregate target that depends on every fuzz binary (see
# tests/fuzz/CMakeLists.txt), so this needs no update when a new harness is
# added upstream.
ninja -C "$WORK/build" fuzz_targets

find "$WORK/build/tests/fuzz" -maxdepth 2 -type f -name '*_fuzzer' \
    -exec cp -v '{}' "$OUT" ';'

# ngap_cu_cp_fuzzer links ocudu_cu_cp, which pulls in lib/security (MbedTLS)
# and lib/gateways (SCTP) transitively (yaml-cpp is a build dep of other
# subsystems and may end up linked too, depending on what else a harness
# pulls in). Those come from apt packages installed only in this builder
# image and are dynamically linked by default, so they won't exist wherever
# OSS-Fuzz later copies the binary to run it. Ship the .so files alongside
# each fuzzer that actually needs them and point RPATH at $ORIGIN so the
# loader finds them regardless of cwd.
for fuzzer in "$OUT"/*_fuzzer; do
    needs_rpath=0
    while IFS= read -r lib; do
        [[ -z "$lib" ]] && continue
        cp -vn "$lib" "$OUT/"
        needs_rpath=1
    done < <(ldd "$fuzzer" | awk '/=>/ { print $3 }' | grep -E '/lib(mbedcrypto|mbedtls|mbedx509|sctp|yaml-cpp)[.-]' || true)
    if [[ "$needs_rpath" -eq 1 ]]; then
        patchelf --set-rpath '$ORIGIN' "$fuzzer"
    fi
done

# Package the seed corpora. ngap_cu_cp_fuzzer exercises the same NGAP PDU
# dispatch path as ngap_pdu_decoder_fuzzer, so it reuses the same corpus
# (see tests/fuzz/README.md).
zip -j "$OUT/ofh_uplane_decoder_fuzzer_seed_corpus.zip" tests/fuzz/ofh/corpus/uplane/*
zip -j "$OUT/ofh_ecpri_decoder_fuzzer_seed_corpus.zip" tests/fuzz/ofh/corpus/ecpri/*
zip -j "$OUT/ofh_vlan_frame_decoder_fuzzer_seed_corpus.zip" tests/fuzz/ofh/corpus/vlan/*
zip -j "$OUT/ngap_pdu_decoder_fuzzer_seed_corpus.zip" tests/fuzz/ngap/corpus/ngap/*
zip -j "$OUT/ngap_cu_cp_fuzzer_seed_corpus.zip" tests/fuzz/ngap/corpus/ngap/*
