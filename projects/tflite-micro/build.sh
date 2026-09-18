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

###############################################################################
# OSS-Fuzz build script for tflite-micro
#
# Builds the TFLM static library with OSS-Fuzz sanitizer-instrumented
# compilers, then compiles and links the fuzz harness against it.
#
# The fuzz target exercises:
#   GetModel() -> MicroInterpreter -> AllocateTensors() -> Invoke()
#
###############################################################################

cd $SRC/tflite-micro

# -------------------------------------------------------------------
# Step 1: Download third-party dependencies
# TFLM needs FlatBuffers, gemmlowp, ruy, etc.
# The Makefile has a target that fetches them automatically.
# -------------------------------------------------------------------
echo "[*] Downloading third-party dependencies..."
make -f tensorflow/lite/micro/tools/make/Makefile \
    TARGET=linux \
    third_party_downloads

# -------------------------------------------------------------------
# Step 2: Build the TFLM static library
#
# We pass OSS-Fuzz compilers ($CC, $CXX) and flags ($CFLAGS, $CXXFLAGS)
# through the Makefile's EXTRA_ variables. The Makefile builds
# libtensorflow-microlite.a in gen/linux_x86_64_default/lib/
# -------------------------------------------------------------------
echo "[*] Building libtensorflow-microlite.a..."

# Clean any previous build artifacts
make -f tensorflow/lite/micro/tools/make/Makefile \
    TARGET=linux \
    clean 2>/dev/null || true

make -j$(nproc) -f tensorflow/lite/micro/tools/make/Makefile \
    TARGET=linux \
    CC="${CC}" \
    CXX="${CXX}" \
    AR="${AR:-ar}" \
    EXTRA_CXXFLAGS="${CXXFLAGS}" \
    EXTRA_CFLAGS="${CFLAGS}" \
    microlite

# -------------------------------------------------------------------
# Step 3: Find the built library and set up include paths
# -------------------------------------------------------------------
TFLM_LIB=$(find gen/ -name "libtensorflow-microlite.a" -print -quit)

if [ -z "${TFLM_LIB}" ]; then
    echo "ERROR: libtensorflow-microlite.a not found after build"
    echo "Listing gen/ directory:"
    find gen/ -type f -name "*.a" 2>/dev/null || echo "(no .a files found)"
    exit 1
fi

echo "[+] Found TFLM library: ${TFLM_LIB}"
TFLM_LIB_DIR=$(dirname "${TFLM_LIB}")

# Gather all include paths needed by TFLM headers
TFLM_INCLUDES="-I. \
    -Itensorflow/lite/micro/tools/make/downloads/flatbuffers/include \
    -Itensorflow/lite/micro/tools/make/downloads/gemmlowp \
    -Itensorflow/lite/micro/tools/make/downloads/ruy"

# Check for additional include paths that may exist
for extra_inc in \
    "third_party/flatbuffers/include" \
    "third_party/gemmlowp" \
    "third_party/ruy"; do
    if [ -d "${extra_inc}" ]; then
        TFLM_INCLUDES="${TFLM_INCLUDES} -I${extra_inc}"
    fi
done

# -------------------------------------------------------------------
# Step 4: Compile the fuzz target
#
# Same compilation approach as run_malicious.cc from the PoC:
#   g++ -std=c++17 -o fuzz_target fuzz_model_load.cc \
#       -I. -I<flatbuffers> -I<gemmlowp> -I<ruy> \
#       -L<lib_dir> -ltensorflow-microlite -lpthread -ldl
#
# But using $CXX, $CXXFLAGS, $LIB_FUZZING_ENGINE from OSS-Fuzz.
# -------------------------------------------------------------------
echo "[*] Compiling fuzz_model_load..."

$CXX $CXXFLAGS ${TFLM_INCLUDES} \
    -std=c++17 \
    -c $SRC/fuzz_model_load.cc \
    -o $WORK/fuzz_model_load.o

echo "[*] Linking fuzz_model_load..."

$CXX $CXXFLAGS \
    $WORK/fuzz_model_load.o \
    ${TFLM_LIB} \
    $LIB_FUZZING_ENGINE \
    -lpthread -ldl \
    -o $OUT/fuzz_model_load

echo "[+] Built: $OUT/fuzz_model_load"

# -------------------------------------------------------------------
# Step 5: Package seed corpus
#
# Include PoC seeds for both vulnerabilities and any .tflite test
# models from the TFLM repo as mutation seeds.
# -------------------------------------------------------------------
echo "[*] Packaging seed corpus..."

# Generate the Gather OOB PoC seed if the generator is available
if [ -f "$SRC/build_malicious_gather.py" ]; then
    echo "[*] Generating malicious_gather.tflite seed..."
    python3 $SRC/build_malicious_gather.py || true
    if [ -f "malicious_gather.tflite" ]; then
        cp malicious_gather.tflite $SRC/seed_corpus/ 2>/dev/null || true
        echo "[+] Added malicious_gather.tflite to seed corpus"
    fi
fi

# Start with our hand-crafted seeds (integer overflow + gather OOB)
if [ -d "$SRC/seed_corpus" ] && [ "$(ls -A $SRC/seed_corpus/*.tflite 2>/dev/null)" ]; then
    zip -j $OUT/fuzz_model_load_seed_corpus.zip $SRC/seed_corpus/*.tflite
    echo "[+] Added $(ls $SRC/seed_corpus/*.tflite | wc -l) seed files from seed_corpus/"
fi

# Also grab any .tflite test models from the TFLM repo (good mutation base)
REPO_MODELS=$(find $SRC/tflite-micro -name "*.tflite" -size +0 -size -1M 2>/dev/null | head -50)
if [ -n "${REPO_MODELS}" ]; then
    echo "${REPO_MODELS}" | while read f; do
        # Add to existing zip, skip duplicates
        zip -uj $OUT/fuzz_model_load_seed_corpus.zip "$f" 2>/dev/null || true
    done
    echo "[+] Added repo .tflite files to seed corpus"
fi

# -------------------------------------------------------------------
# Step 6: Create a FlatBuffer dictionary for guided mutation
#
# These tokens help the fuzzer find valid FlatBuffer structures faster.
# Includes TFLite magic bytes, common tensor types, and dimension
# values known to trigger integer overflow.
# -------------------------------------------------------------------
echo "[*] Creating fuzzing dictionary..."

cat > $OUT/fuzz_model_load.dict << 'DICT_EOF'
# TFLite FlatBuffer file identifier
"TFL3"
"\x54\x46\x4C\x33"

# Schema version 3
"\x03\x00\x00\x00"

# Tensor types: FLOAT32=0, INT32=2, INT8=9
"\x00"
"\x02"
"\x09"

# FullyConnected opcode = 9
"\x09"

# GATHER opcode = 36 (0x24)
"\x24"

# BuiltinOptions_GatherOptions = 23 (0x17)
"\x17"

# Common dimension values
"\x01\x00\x00\x00"
"\x03\x00\x00\x00"
"\x04\x00\x00\x00"
"\x08\x00\x00\x00"
"\x10\x00\x00\x00"

# INTEGER OVERFLOW TRIGGER VALUES
# 1073741825 = 0x40000001 -> 4 * this = 4294967300 wraps to 4
"\x01\x00\x00\x40"
# 1610612737 = 0x60000001 -> 4 * this wraps to negative
"\x01\x00\x00\x60"
# INT32_MAX = 0x7FFFFFFF
"\xFF\xFF\xFF\x7F"
# Powers of 2 near overflow boundary
"\x00\x00\x00\x20"
"\x00\x00\x00\x10"

# GATHER OOB INDEX TRIGGER VALUES (as int32 little-endian)
# 999 (0x3E7) -- small OOB, stays within arena (silent info-leak)
"\xE7\x03\x00\x00"
# 100000 (0x186A0) -- large OOB, goes past arena -> ASAN SEGV
"\xA0\x86\x01\x00"
# -1 (0xFFFFFFFF) -- negative index for backward OOB read
"\xFF\xFF\xFF\xFF"
# INT32_MIN (0x80000000) -- extreme negative
"\x00\x00\x00\x80"

# FlatBuffer structural tokens
"\x00\x00\x00\x00"
"\x04\x00"
"\x06\x00"
"\x08\x00"
"\x0C\x00"

# Quantization: scale=1.0f
"\x00\x00\x80\x3F"
# Quantization: zero_point=0
"\x00\x00\x00\x00\x00\x00\x00\x00"
DICT_EOF

echo "[+] Dictionary: $OUT/fuzz_model_load.dict"
echo "[*] Build complete!"
ls -la $OUT/fuzz_model_load*
