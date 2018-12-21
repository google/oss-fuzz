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

export CXXFLAGS="-std=c++11 -stdlib=libc++ $CXXFLAGS"

#
# Build the library.
#
./configure --with-libjson=no --with-pcre=no --enable-static=yes --enable-shared=no --disable-llvm --host=x86_64-unknown-linux-gnu
make clean
make -j"$(nproc)"

#
# Build the fuzz targets.
#

# `scanmap`
# ----------
$CXX $CXXFLAGS -Ilibclamav/ ./fuzz/clamav_scanmap_fuzzer.cpp \
	-o $OUT/clamav_scanmap_fuzzer \
    ${LIB_FUZZING_ENGINE} libclamav/.libs/libclamav.a libclamav/.libs/libclammspack.a \
    -Wl,-Bstatic -lssl -lcrypto -lz -Wl,-Bdynamic -lc -lpthread -ldl

for type in ARCHIVE MAIL OLE2 PDF HTML PE ELF SWF XMLDOCS HWP3; do
    $CXX $CXXFLAGS -Ilibclamav/ ./fuzz/clamav_scanmap_fuzzer.cpp \
        -o "${OUT}/clamav_scanmap_${type}_fuzzer" "-DCLAMAV_FUZZ_${type}" \
        ${LIB_FUZZING_ENGINE} libclamav/.libs/libclamav.a libclamav/.libs/libclammspack.a \
        -Wl,-Bstatic -lssl -lcrypto -lz -Wl,-Bdynamic -lc -lpthread -ldl
done

# `scanfile`
# ----------
$CXX $CXXFLAGS -Ilibclamav/ ./fuzz/clamav_scanfile_fuzzer.cpp \
	-o $OUT/clamav_scanfile_fuzzer \
    ${LIB_FUZZING_ENGINE} libclamav/.libs/libclamav.a libclamav/.libs/libclammspack.a \
    -Wl,-Bstatic -lssl -lcrypto -lz -Wl,-Bdynamic -lc -lpthread -ldl

for type in ARCHIVE MAIL OLE2 PDF HTML PE ELF SWF XMLDOCS HWP3; do
    $CXX $CXXFLAGS -Ilibclamav/ ./fuzz/clamav_scanfile_fuzzer.cpp \
        -o "${OUT}/clamav_scanfile_${type}_fuzzer" "-DCLAMAV_FUZZ_${type}" \
        ${LIB_FUZZING_ENGINE} libclamav/.libs/libclamav.a libclamav/.libs/libclammspack.a \
        -Wl,-Bstatic -lssl -lcrypto -lz -Wl,-Bdynamic -lc -lpthread -ldl
done

# `dbload`
# --------
for type in CDB CFG CRB FP FTM HDB HSB IDB IGN IGN2 LDB MDB MSB NDB PDB WDB YARA; do
    $CXX $CXXFLAGS -Ilibclamav/ ./fuzz/clamav_dbload_fuzzer.cpp \
        -o "${OUT}/clamav_dbload_${type}_fuzzer" "-DCLAMAV_FUZZ_${type}" \
        ${LIB_FUZZING_ENGINE} libclamav/.libs/libclamav.a libclamav/.libs/libclammspack.a \
        -Wl,-Bstatic -lssl -lcrypto -lz -Wl,-Bdynamic -lc -lpthread -ldl
done

#
# Collect the fuzz corpora.
#

# `scanfile` & `scanmap`
# ----------
mkdir all-scantype-seeds

for type in ARCHIVE MAIL OLE2 PDF HTML PE ELF SWF XMLDOCS HWP3; do
	# Prepare seed corpus for the type-specific fuzz targets.
	zip $OUT/clamav_scanfile_${type}_fuzzer_seed_corpus.zip $SRC/clamav-fuzz-corpus/scantype/${type}/*
	zip $OUT/clamav_scanmap_${type}_fuzzer_seed_corpus.zip $SRC/clamav-fuzz-corpus/scantype/${type}/*

	# Prepare dictionary for the type-specific fuzz targets (may not exist for all types).
	cp $SRC/clamav-fuzz-corpus/scantype/${type}.dict $OUT/clamav_scanfile_${type}_fuzzer.dict 2>/dev/null || :
	cp $SRC/clamav-fuzz-corpus/scantype/${type}.dict $OUT/clamav_scanmap_${type}_fuzzer.dict 2>/dev/null || :

	# Copy seeds for the generic fuzz target.
	cp $SRC/clamav-fuzz-corpus/scantype/${type}/* all-scantype-seeds/
done

# Prepare seed corpus for the generic fuzz target.
cp $SRC/clamav-fuzz-corpus/scantype/other/* all-scantype-seeds/
zip $OUT/clamav_scanfile_fuzzer_seed_corpus.zip all-scantype-seeds/*
zip $OUT/clamav_scanmap_fuzzer_seed_corpus.zip all-scantype-seeds/*

# `dbload`
# --------
for type in CDB CFG CRB FP FTM HDB HSB IDB IGN IGN2 LDB MDB MSB NDB PDB WDB YARA; do
	# Prepare seed corpus for the type-specific fuzz targets.
	zip $OUT/clamav_dbload_${type}_fuzzer_seed_corpus.zip $SRC/clamav-fuzz-corpus/database/${type}/*

	# Prepare dictionary for the type-specific fuzz targets (may not exist for all types).
	cp $SRC/clamav-fuzz-corpus/database/${type}.dict $OUT/clamav_dbload_${type}_fuzzer.dict 2>/dev/null || :
done
