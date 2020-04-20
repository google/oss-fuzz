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

# build the project
./build/autogen.sh
./configure
make -j$(nproc) all

# build seed
SD=seed
echo "Mary had a little lamb,
Its fleece was white as snow;
And everywhere that Mary went
The lamb was sure to go." >> $SD
bzip2 -k $SD && gzip -k $SD && lrzip $SD && lz4 -k $SD \
	&& lzop $SD && xz -k $SD && zstd -k $SD \
	&& genisoimage -o $SD.iso $SD && lcab $SD $SD.cab \
	&& lha c $SD.lzh $SD && rar a $SD.rar $SD \
	&& tar -czvf $SD.tar.gz $SD && jar -cvf $SD $SD \
	&& zip $SD $SD

zip corpus.zip $SD.* && mv corpus.zip /out/libarchive_fuzzer_seed_corpus.zip
rm $SD.*

# build fuzzer(s)
$CXX $CXXFLAGS -Ilibarchive \
    $SRC/libarchive_fuzzer.cc -o $OUT/libarchive_fuzzer \
    $LIB_FUZZING_ENGINE .libs/libarchive.a \
    -Wl,-Bstatic -lbz2 -llzo2  -lxml2 -llzma -lz -lcrypto -llz4 -licuuc \
    -licudata -Wl,-Bdynamic
