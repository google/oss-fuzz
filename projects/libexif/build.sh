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

autoreconf -fiv
./configure --disable-docs --enable-shared=no --prefix="$WORK"
make -j$(nproc)
make install

pushd $SRC
mkdir -p exif_corpus
find exif-samples -type f -name '*.jpg' -exec mv -n {} exif_corpus/ \; -o -name '*.tiff' -exec mv -n {} exif_corpus/ \;
cp libexif/test/testdata/*.jpg exif_corpus
zip -r "$WORK/exif_seed_corpus.zip" exif_corpus/
popd

for fuzzer in $(find $SRC/ -name '*_fuzzer.cc'); do
  fuzzer_basename=$(basename -s .cc $fuzzer)
  $CXX $CXXFLAGS \
      -std=c++11 \
      -I"$WORK/include" \
      $fuzzer \
      -o $OUT/$fuzzer_basename \
      $LIB_FUZZING_ENGINE \
      "$WORK/lib/libexif.a"
  cp $WORK/exif_seed_corpus.zip "${OUT}/${fuzzer_basename}_seed_corpus.zip"
done
