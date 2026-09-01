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

cd "$SRC"

wget -qO- https://botan.randombit.net/releases/Botan-3.12.0.tar.xz | tar xJ
BOTAN_VERSION=$(ls -d Botan-* | head -n1 | sed 's/Botan-//')
cd "Botan-${BOTAN_VERSION}"

# Filter rnp's module list down to what this Botan version actually provides:
# configure.py rejects unknown module names, and the list contains names
# introduced in newer Botan releases (x25519 in 3.5.0, ml_kem/ml_dsa/slh_dsa_*
# in 3.6.0, legacy_ec_point and pcurves_* in 3.7.0), so an unfiltered list
# would break older pins. Skipped modules simply disable the corresponding
# rnp feature at configure time.
MODULES_AVAILABLE=$(./configure.py --list-modules | grep -v '^$')
BOTAN_MODULES=""
while IFS= read -r module; do
    [ -z "$module" ] && continue
    if [ "$module" = "x25519" ] && ! printf '%s\n' "$MODULES_AVAILABLE" | grep -qx x25519; then
        module=curve25519  # renamed to x25519 in Botan 3.5.0
    fi
    if printf '%s\n' "$MODULES_AVAILABLE" | grep -qx "$module"; then
        BOTAN_MODULES+="${module},"
    else
        echo "note: Botan ${BOTAN_VERSION} has no module '${module}', skipping it"
    fi
done < "$SRC/rnp/ci/botan3-pqc-modules"
./configure.py --prefix=/usr --cc-bin="$CXX" --cc-abi-flags="$CXXFLAGS" \
               --unsafe-fuzzer-mode \
               --with-fuzzer-lib='FuzzingEngine' \
               --minimized-build \
               --disable-modules=locking_allocator \
               --enable-modules="$BOTAN_MODULES"
make "-j$(nproc)"
make install

cd "$SRC"
mkdir fuzzing_corpus

cd "$SRC/rnp/src/tests/data"
find . -type f -print0 | xargs -0 -I bob -- cp bob "$SRC/fuzzing_corpus/"

# -DENABLE_SANITIZERS=0 because oss-fuzz will add the sanitizer flags in CFLAGS
# See https://github.com/google/oss-fuzz/pull/4189 to explain CMAKE_C_LINK_EXECUTABLE

# rnp's crypto-refresh and PQC code paths need Botan >= 3.6.0 and rnp
# aborts configure when they are forced on against an older version.
if [ "$(printf '%s\n' "${BOTAN_VERSION}" "3.6.0" | sort -V | head -n1)" != "3.6.0" ]; then
    RNP_FEATURE_FLAGS="-DENABLE_CRYPTO_REFRESH=off -DENABLE_PQC=off"
else
    RNP_FEATURE_FLAGS="-DENABLE_CRYPTO_REFRESH=on -DENABLE_PQC=on"
fi

cd "$SRC"
mkdir rnp-build
cd rnp-build
cmake \
    -DENABLE_SANITIZERS=0 \
    -DENABLE_FUZZERS=1 \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_LINK_EXECUTABLE="$CXX <FLAGS> <CMAKE_C_LINK_FLAGS> <LINK_FLAGS> <OBJECTS>  -o <TARGET> <LINK_LIBRARIES>" \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DBUILD_SHARED_LIBS=on \
    -DBUILD_TESTING=off \
    $RNP_FEATURE_FLAGS \
    -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON \
    "$SRC/rnp"
make "-j$(nproc)"

FUZZERS=$(find src/fuzzing -maxdepth 1 -type f -name "fuzz_*" -exec basename {} \;)
printf "Detected fuzzers: \n%s\n" "$FUZZERS"
for f in $FUZZERS; do
    cp "src/fuzzing/$f" "${OUT}/"
    patchelf --set-rpath "\$ORIGIN/lib" "${OUT}/$f" || echo "patchelf failed with $?, ignoring."
    zip -j -r "${OUT}/${f}_seed_corpus.zip" "$SRC/fuzzing_corpus/"
done

mkdir -p "${OUT}/lib"
cp src/lib/librnp.so.0 "${OUT}/lib/"
cp /usr/lib/libbotan-3.so.* "${OUT}/lib/"
cp /lib/x86_64-linux-gnu/libjson-c.so.* "${OUT}/lib/"
