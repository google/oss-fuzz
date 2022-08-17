#!/bin/bash -eu
# Copyright (C) 2018 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

set -ex
export GIT_DISCOVERY_ACROSS_FILESYSTEM=1

#
# Build the library.
#
rm -rf ${WORK}/build
mkdir -p ${WORK}/build
cd ${WORK}/build

#
# Run ./configure
#
export CLAMAV_DEPENDENCIES=/mussels/install
cmake ${SRC}/clamav \
    -DENABLE_FUZZ=ON                                                   \
    -DHAVE_MMAP=OFF                                                    \
    -DJSONC_INCLUDE_DIR="$CLAMAV_DEPENDENCIES/include/json-c"          \
    -DJSONC_LIBRARY="$CLAMAV_DEPENDENCIES/lib/libjson-c.a"             \
    -DENABLE_JSON_SHARED=OFF                                           \
    -DBZIP2_INCLUDE_DIR="$CLAMAV_DEPENDENCIES/include"                 \
    -DBZIP2_LIBRARY_RELEASE="$CLAMAV_DEPENDENCIES/lib/libbz2_static.a" \
    -DOPENSSL_ROOT_DIR="$CLAMAV_DEPENDENCIES"                          \
    -DOPENSSL_INCLUDE_DIR="$CLAMAV_DEPENDENCIES/include"               \
    -DOPENSSL_CRYPTO_LIBRARY="$CLAMAV_DEPENDENCIES/lib/libcrypto.a"    \
    -DOPENSSL_SSL_LIBRARY="$CLAMAV_DEPENDENCIES/lib/libssl.a"          \
    -DZLIB_LIBRARY="$CLAMAV_DEPENDENCIES/lib/libssl.a"                 \
    -DLIBXML2_INCLUDE_DIR="$CLAMAV_DEPENDENCIES/include/libxml2"       \
    -DLIBXML2_LIBRARY="$CLAMAV_DEPENDENCIES/lib/libxml2.a"             \
    -DPCRE2_INCLUDE_DIR="$CLAMAV_DEPENDENCIES/include"                 \
    -DPCRE2_LIBRARY="$CLAMAV_DEPENDENCIES/lib/libpcre2-8.a"            \
    -DZLIB_INCLUDE_DIR="$CLAMAV_DEPENDENCIES/include"                  \
    -DZLIB_LIBRARY="$CLAMAV_DEPENDENCIES/lib/libz.a"                   \
    -DCMAKE_INSTALL_PREFIX="install"

# Build libclamav and the fuzz targets
make -j4
cp ./fuzz/clamav_* ${OUT}/.

#
# Collect the fuzz corpora.
#

# `scanfile` & `scanmap`
# ----------
mkdir ${WORK}/all-scantype-seeds
git clone --depth 1 https://github.com/Cisco-Talos/clamav-fuzz-corpus.git $SRC/clamav-fuzz-corpus

for type in ARCHIVE MAIL OLE2 PDF HTML PE ELF SWF XMLDOCS HWP3; do
    # Prepare seed corpus for the type-specific fuzz targets.
    zip ${OUT}/clamav_scanfile_${type}_fuzzer_seed_corpus.zip ${SRC}/clamav-fuzz-corpus/scantype/${type}/*
    zip ${OUT}/clamav_scanmap_${type}_fuzzer_seed_corpus.zip ${SRC}/clamav-fuzz-corpus/scantype/${type}/*

    # Prepare dictionary for the type-specific fuzz targets (may not exist for all types).
    cp ${SRC}/clamav-fuzz-corpus/scantype/${type}.dict ${OUT}/clamav_scanfile_${type}_fuzzer.dict 2>/dev/null || :
    cp ${SRC}/clamav-fuzz-corpus/scantype/${type}.dict ${OUT}/clamav_scanmap_${type}_fuzzer.dict 2>/dev/null || :

    # Copy seeds for the generic fuzz target.
    cp ${SRC}/clamav-fuzz-corpus/scantype/${type}/* ${WORK}/all-scantype-seeds/
done

# Prepare seed corpus for the generic fuzz target.
cp ${SRC}/clamav-fuzz-corpus/scantype/other/* ${WORK}/all-scantype-seeds/
zip ${OUT}/clamav_scanfile_fuzzer_seed_corpus.zip ${WORK}/all-scantype-seeds/*
zip ${OUT}/clamav_scanmap_fuzzer_seed_corpus.zip ${WORK}/all-scantype-seeds/*
rm -r ${WORK}/all-scantype-seeds

# `dbload`
# --------
for type in CDB CFG CRB FP FTM HDB HSB IDB IGN IGN2 LDB MDB MSB NDB PDB WDB YARA; do
    # Prepare seed corpus for the type-specific fuzz targets.
    zip ${OUT}/clamav_dbload_${type}_fuzzer_seed_corpus.zip ${SRC}/clamav-fuzz-corpus/database/${type}/*

    # Prepare dictionary for the type-specific fuzz targets (may not exist for all types).
    cp ${SRC}/clamav-fuzz-corpus/database/${type}.dict ${OUT}/clamav_dbload_${type}_fuzzer.dict 2>/dev/null || :
done
