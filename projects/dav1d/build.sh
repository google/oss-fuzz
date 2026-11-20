#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

# setup
build=${WORK}/build

# cleanup
rm -rf ${build}
mkdir -p ${build}

# prepare cross file for i386 compiliation
if [ "$ARCHITECTURE" = "i386" ]; then
	MESON_CFLAGS="'$(echo $CFLAGS | sed -e 's/ /;, ;/g' | tr \; \')'"
	MESON_CXXFLAGS="'$(echo $CXXFLAGS | sed -e 's/ /;, ;/g' | tr \; \')'"
	sed -e "s/CC$/'$CC'/; s/CXX$/'$CXX'/; s/CFLAGS$/[$MESON_CFLAGS]/; s/CXXFLAGS$/[$MESON_CXXFLAGS]/" < ${SRC}/linux32.meson > ${WORK}/linux32.meson
	CROSS="--cross-file ${WORK}/linux32.meson"
fi

# build library
meson -Denable_tools=false -Dfuzzing_engine=oss-fuzz \
      -Db_lundef=false -Ddefault_library=static -Dbuildtype=debugoptimized \
      -Dlogging=false -Dfuzzer_ldflags=$LIB_FUZZING_ENGINE \
      -Dtestdata_tests=true \
      ${CROSS:-} \
      ${build}
ninja -j $(nproc) -C ${build}

# prepare seed corpus
rm -rf ${WORK}/tmp
mkdir -p ${WORK}/tmp/testdata
unzip -q $SRC/dav1d_fuzzer_seed_corpus.zip -d ${WORK}/tmp/testdata

# Add dav1d's conformance IVF vectors (already cloned for the meson tests) and
# the oss-fuzz/ regression testcases to the corpus. They cover AV1 features the
# base corpus lacks (film grain, s-frames, SVC, resize, 10/12-bit). Vectors are
# capped at 2 MB (drops one 8.7 MB clip) and flattened to unique names; nothing
# in the existing corpus is removed.
testdata_src="${SRC}/dav1d/tests/dav1d-test-data"
if [ -d "${testdata_src}" ]; then
	while IFS= read -r f; do
		cp "$f" "${WORK}/tmp/testdata/$(echo "${f#${testdata_src}/}" | tr '/ ' '__')"
	done < <(find "${testdata_src}" \( \( -name '*.ivf' -size -2000000c \) \
		-o \( -path '*/oss-fuzz/*' -type f \) \))
fi

cp $SRC/dec_fuzzer_seed_corpus.zip ${WORK}/tmp/seed_corpus.zip
(cd ${WORK}/tmp && zip -q -m -r -0 ${WORK}/tmp/seed_corpus.zip testdata)

# copy fuzzers and link testdata
for fuzzer in $(find ${build}/tests/libfuzzer -maxdepth 1 -type f -executable -name 'dav1d_fuzzer*'); do
	cp "${fuzzer}" $OUT/
	cp ${WORK}/tmp/seed_corpus.zip $OUT/$(basename "$fuzzer")_seed_corpus.zip
done

# Build a no-SIMD fuzzer variant. By default dav1d runs hand-written assembly for
# all DSP on x86, leaving the portable C reference code (src/*_tmpl.c, itx_1d.c,
# pal.c) unfuzzed. Forcing the CPU-flags mask to 0 routes decoding through that C
# instead. We recompile the harness with mask 0 baked in (so no runtime args are
# needed) against the already-built static libdav1d.a.
nosimd_src=${WORK}/dav1d_fuzzer_nosimd.c
sed 's/^\( *\)int i = 1;/\1dav1d_set_cpu_flags_mask(0);\n\1int i = 1;/' \
	tests/libfuzzer/dav1d_fuzzer.c > "${nosimd_src}"
# Compile as C (so the LLVMFuzzer* symbols stay unmangled); link with CXX.
$CC $CFLAGS \
	-I$SRC/dav1d -I$SRC/dav1d/include -I$SRC/dav1d/include/dav1d \
	-I$SRC/dav1d/tests/libfuzzer -I${build} -I${build}/include \
	-c "${nosimd_src}" -o ${WORK}/dav1d_fuzzer_nosimd.o
$CXX $CXXFLAGS ${WORK}/dav1d_fuzzer_nosimd.o -o $OUT/dav1d_fuzzer_nosimd \
	$LIB_FUZZING_ENGINE ${build}/src/libdav1d.a
cp ${WORK}/tmp/seed_corpus.zip $OUT/dav1d_fuzzer_nosimd_seed_corpus.zip
