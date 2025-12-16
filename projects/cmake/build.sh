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

# Build CMake with all bundled dependencies for proper sanitizer support.
# MSan requires all code to be instrumented, so we use bundled libraries
# and disable OpenSSL (which would require building from source).

mkdir build-dir && cd build-dir

# Configure CMake
# - Use bundled libraries (required for MSan - all code must be instrumented)
# - Disable OpenSSL (not needed for fuzzing, avoids uninstrumented code)
# - Disable server mode (deprecated)
# - Disable tests (not needed for fuzzing)
cmake .. \
  -DCMAKE_C_COMPILER="${CC}" \
  -DCMAKE_CXX_COMPILER="${CXX}" \
  -DCMAKE_C_FLAGS="${CFLAGS}" \
  -DCMAKE_CXX_FLAGS="${CXXFLAGS}" \
  -DCMAKE_USE_SYSTEM_LIBRARIES=OFF \
  -DCMAKE_USE_OPENSSL=OFF \
  -DBUILD_TESTING=OFF \
  -DCMAKE_BUILD_TYPE=Release

# Build CMakeLib (contains all the code we want to fuzz)
make -j$(nproc) CMakeLib

# Store paths for fuzzer linking
CMAKE_SOURCE="${SRC}/CMake"
CMAKE_BUILD="${CMAKE_SOURCE}/build-dir"
CMAKE_LIB_DIR="${CMAKE_BUILD}/Source"
UTILITIES_DIR="${CMAKE_BUILD}/Utilities"

# Common include paths
INCLUDE_FLAGS="-I${CMAKE_SOURCE}/Source"
INCLUDE_FLAGS="${INCLUDE_FLAGS} -I${CMAKE_BUILD}/Source"
INCLUDE_FLAGS="${INCLUDE_FLAGS} -I${CMAKE_SOURCE}/Utilities/std"
INCLUDE_FLAGS="${INCLUDE_FLAGS} -I${CMAKE_SOURCE}/Utilities/cmlibuv/include"
INCLUDE_FLAGS="${INCLUDE_FLAGS} -I${CMAKE_SOURCE}/Utilities/cmlibrhash"
INCLUDE_FLAGS="${INCLUDE_FLAGS} -I${CMAKE_SOURCE}/Utilities/cm3p"
INCLUDE_FLAGS="${INCLUDE_FLAGS} -I${CMAKE_SOURCE}/Utilities"

# Common libraries to link (order matters for static linking!)
COMMON_LIBS="${CMAKE_LIB_DIR}/libCMakeLib.a"
COMMON_LIBS="${COMMON_LIBS} ${UTILITIES_DIR}/cmexpat/libcmexpat.a"
COMMON_LIBS="${COMMON_LIBS} ${UTILITIES_DIR}/cmlibarchive/libarchive/libcmlibarchive.a"
COMMON_LIBS="${COMMON_LIBS} ${UTILITIES_DIR}/cmliblzma/libcmliblzma.a"
COMMON_LIBS="${COMMON_LIBS} ${UTILITIES_DIR}/cmzstd/libcmzstd.a"
COMMON_LIBS="${COMMON_LIBS} ${UTILITIES_DIR}/cmzlib/libcmzlib.a"
COMMON_LIBS="${COMMON_LIBS} ${UTILITIES_DIR}/cmbzip2/libcmbzip2.a"
COMMON_LIBS="${COMMON_LIBS} ${UTILITIES_DIR}/cmcurl/lib/libcmcurl.a"
COMMON_LIBS="${COMMON_LIBS} ${UTILITIES_DIR}/cmnghttp2/libcmnghttp2.a"
COMMON_LIBS="${COMMON_LIBS} ${UTILITIES_DIR}/cmjsoncpp/libcmjsoncpp.a"
COMMON_LIBS="${COMMON_LIBS} ${UTILITIES_DIR}/cmlibrhash/libcmlibrhash.a"
COMMON_LIBS="${COMMON_LIBS} ${UTILITIES_DIR}/cmlibuv/libcmlibuv.a"
COMMON_LIBS="${COMMON_LIBS} ${UTILITIES_DIR}/cmllpkgc/libcmllpkgc.a"

# System libs needed
SYS_LIBS="-lpthread -ldl -lrt"

# Function to build a fuzzer
build_fuzzer() {
    local name=$1
    local source=$2
    echo "Building ${name}..."
    $CXX $CXXFLAGS ${INCLUDE_FLAGS} -c "${source}" -o "${name}.o"
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE "${name}.o" ${COMMON_LIBS} ${SYS_LIBS} -o "$OUT/${name}"
}

# Build fuzzers
cd ../Tests/Fuzzing

# 1. XML Parser Fuzzer (existing)
build_fuzzer "xml_parser_fuzzer" "xml_parser_fuzzer.cc"

# 2. ListFile Lexer Fuzzer
build_fuzzer "cmListFileLexerFuzzer" "cmListFileLexerFuzzer.cxx"

# 3. Generator Expression Fuzzer
build_fuzzer "cmGeneratorExpressionFuzzer" "cmGeneratorExpressionFuzzer.cxx"

# 4. ELF Fuzzer
build_fuzzer "cmELFFuzzer" "cmELFFuzzer.cxx"

# 5. Archive Extract Fuzzer
build_fuzzer "cmArchiveExtractFuzzer" "cmArchiveExtractFuzzer.cxx"

# 6. File Lock Fuzzer
build_fuzzer "cmFileLockFuzzer" "cmFileLockFuzzer.cxx"

# 7. Expression Parser Fuzzer
build_fuzzer "cmExprParserFuzzer" "cmExprParserFuzzer.cxx"

# 8. PkgConfig Parser Fuzzer
build_fuzzer "cmPkgConfigParserFuzzer" "cmPkgConfigParserFuzzer.cxx"

# 9. JSON Parser Fuzzer
build_fuzzer "cmJSONParserFuzzer" "cmJSONParserFuzzer.cxx"

# 10. Script Fuzzer (highest coverage - executes CMake scripts)
build_fuzzer "cmScriptFuzzer" "cmScriptFuzzer.cxx"

# 11. String Algorithms Fuzzer
build_fuzzer "cmStringAlgorithmsFuzzer" "cmStringAlgorithmsFuzzer.cxx"

# 12. Version Fuzzer
build_fuzzer "cmVersionFuzzer" "cmVersionFuzzer.cxx"

# 13. CMake Path Fuzzer
build_fuzzer "cmCMakePathFuzzer" "cmCMakePathFuzzer.cxx"

# 14. GCC Depfile Fuzzer
build_fuzzer "cmGccDepfileFuzzer" "cmGccDepfileFuzzer.cxx"

# 15. Glob Fuzzer
build_fuzzer "cmGlobFuzzer" "cmGlobFuzzer.cxx"

# Build seed corpora
echo "Building seed corpora..."

# Helper function for corpus
build_corpus() {
    local name=$1
    local dir=$2
    if [ -d "${dir}" ]; then
        zip -j "$OUT/${name}_seed_corpus.zip" "${dir}"/* 2>/dev/null || true
    fi
}

# XML corpus (existing)
zip -j $OUT/xml_parser_fuzzer_seed_corpus.zip \
    $SRC/fuzzing-corpus/xml/*.xml 2>/dev/null || true

# New corpora
build_corpus "cmListFileLexerFuzzer" "corpus/listfile"
build_corpus "cmGeneratorExpressionFuzzer" "corpus/genex"
build_corpus "cmELFFuzzer" "corpus/elf"
build_corpus "cmArchiveExtractFuzzer" "corpus/archive"
build_corpus "cmFileLockFuzzer" "corpus/filelock"
build_corpus "cmExprParserFuzzer" "corpus/expr"
build_corpus "cmPkgConfigParserFuzzer" "corpus/pkgconfig"
build_corpus "cmJSONParserFuzzer" "corpus/json"
build_corpus "cmScriptFuzzer" "corpus/script"
build_corpus "cmStringAlgorithmsFuzzer" "corpus/string"
build_corpus "cmVersionFuzzer" "corpus/version"
build_corpus "cmCMakePathFuzzer" "corpus/path"
build_corpus "cmGccDepfileFuzzer" "corpus/depfile"

# Copy dictionaries
echo "Copying dictionaries..."
for dict in *.dict; do
    if [ -f "$dict" ]; then
        # Map dict to fuzzer name
        fuzzer_name="${dict%.dict}"
        case "$fuzzer_name" in
            cmListFileLexer) cp "$dict" "$OUT/cmListFileLexerFuzzer.dict" ;;
            cmGeneratorExpression) cp "$dict" "$OUT/cmGeneratorExpressionFuzzer.dict" ;;
            cmELF) cp "$dict" "$OUT/cmELFFuzzer.dict" ;;
            cmArchiveExtract) cp "$dict" "$OUT/cmArchiveExtractFuzzer.dict" ;;
            cmExprParser) cp "$dict" "$OUT/cmExprParserFuzzer.dict" ;;
            cmPkgConfigParser) cp "$dict" "$OUT/cmPkgConfigParserFuzzer.dict" ;;
            cmJSONParser) cp "$dict" "$OUT/cmJSONParserFuzzer.dict" ;;
            cmScript) cp "$dict" "$OUT/cmScriptFuzzer.dict" ;;
            cmStringAlgorithms) cp "$dict" "$OUT/cmStringAlgorithmsFuzzer.dict" ;;
            cmVersion) cp "$dict" "$OUT/cmVersionFuzzer.dict" ;;
            cmCMakePath) cp "$dict" "$OUT/cmCMakePathFuzzer.dict" ;;
            cmGccDepfile) cp "$dict" "$OUT/cmGccDepfileFuzzer.dict" ;;
            *) cp "$dict" "$OUT/" ;;
        esac
    fi
done

echo "Build complete! Built 15 fuzzers with corpora and dictionaries."
