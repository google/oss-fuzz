#!/bin/bash -eu
# Copyright 2016 Google Inc.
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

# For fuzz-introspector. This is to exclude all libxml2 code from the
# fuzz-introspector reports.
export FUZZ_INTROSPECTOR_CONFIG=$SRC/fuzz_introspector_exclusion.config
cat > $FUZZ_INTROSPECTOR_CONFIG <<EOF
FILES_TO_AVOID
libxml2
EOF

DEPS=/deps

cd $SRC/libarchive

sed -i 's/-Wall//g' ./CMakeLists.txt
sed -i 's/-Werror//g' ./CMakeLists.txt

mkdir build2
cd build2
cmake -DCHECK_CRC_ON_SOLID_SKIP=1 -DDONT_FAIL_ON_CRC_ERROR=1 ../
make -j$(nproc)

# build seed
cp $SRC/libarchive/contrib/oss-fuzz/corpus.zip\
        $OUT/libarchive_fuzzer_seed_corpus.zip

# build fuzzer(s)
$CXX $CXXFLAGS -I../libarchive \
    $SRC/libarchive_fuzzer.cc -o $OUT/libarchive_fuzzer \
    $LIB_FUZZING_ENGINE ./libarchive/libarchive.a \
    -Wl,-Bstatic -llzo2 -Wl,-Bdynamic -lcrypto -lacl -llzma -llz4 -lbz2 -lz ${DEPS}/libxml2.a

# add the uuencoded test files
cd $SRC
mkdir ./uudecoded
find $SRC/libarchive/ -type f -name "test_extract.*.uu" -print0 | xargs -0 -I % cp -f % ./uudecoded/
cd ./uudecoded
find ./ -name "*.uu" -exec uudecode {} \;
cd ../
rm -f ./uudecoded/*.uu
zip -jr $OUT/libarchive_fuzzer_seed_corpus.zip ./uudecoded/*

# add weird archives
git clone --depth=1 https://github.com/corkami/pocs
find ./pocs/ -type f -print0 | xargs -0 -I % zip -jr $OUT/libarchive_fuzzer_seed_corpus.zip %
