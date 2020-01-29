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

#
# Build the library.
#
rm -rf ${WORK}/build
mkdir -p ${WORK}/build
cd ${WORK}/build
ac_cv_c_mmap_anonymous=no ${SRC}/clamav-devel/configure --disable-mempool --enable-fuzz=yes --with-libjson=no --with-pcre=no --enable-static=yes --enable-shared=no --disable-llvm --host=x86_64-unknown-linux-gnu
make clean
make -j"$(nproc)"

#
# Build the fuzz targets.
#
make -j"$(nproc)" fuzz-all
cp ./fuzz/clamav_* ${OUT}/.

#
# Collect the fuzz corpora.
#

# `scanfile` & `scanmap`
# ----------
mkdir ${WORK}/all-scantype-seeds

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
