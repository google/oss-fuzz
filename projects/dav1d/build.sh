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
      ${CROSS:-} \
      ${build}
ninja -j $(nproc) -C ${build}

# prepare seed corpus
rm -rf ${WORK}/tmp
mkdir -p ${WORK}/tmp/testdata
unzip -q $SRC/dav1d_fuzzer_seed_corpus.zip -d ${WORK}/tmp/testdata
cp $SRC/dec_fuzzer_seed_corpus.zip ${WORK}/tmp/seed_corpus.zip
(cd ${WORK}/tmp && zip -q -m -r -0 ${WORK}/tmp/seed_corpus.zip testdata)

# copy fuzzers and link testdata
for fuzzer in $(find ${build}/tests/libfuzzer -maxdepth 1 -type f -executable -name 'dav1d_fuzzer*'); do
	cp "${fuzzer}" $OUT/
	cp ${WORK}/tmp/seed_corpus.zip $OUT/$(basename "$fuzzer")_seed_corpus.zip
done
