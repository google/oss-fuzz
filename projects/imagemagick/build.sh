#!/bin/bash -eu
# Copyright 2017 Google Inc.  #
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

# move the corpus
mkdir afl_testcases
(cd afl_testcases; tar xvf "$SRC/afl_testcases.tgz")
mkdir corpus
find afl_testcases -type f -exec mv -n {} corpus/ \;
zip -rj afl_testcases.zip corpus/

./configure --prefix="$WORK" --disable-shared --disable-docs
make "-j$(nproc)"
make install

for f in $SRC/*_fuzzer.cc; do
    fuzzer=$(basename "$f" _fuzzer.cc)
    $CXX $CXXFLAGS -std=c++11 -I"$WORK/include/ImageMagick-7" \
        "$f" -o "$OUT/${fuzzer}_fuzzer" \
        -DMAGICKCORE_HDRI_ENABLE=1 -DMAGICKCORE_QUANTUM_DEPTH=16 \
        -lFuzzingEngine "$WORK/lib/libMagick++-7.Q16HDRI.a" \
        "$WORK/lib/libMagickWand-7.Q16HDRI.a" "$WORK/lib/libMagickCore-7.Q16HDRI.a"
    cp afl_testcases.zip "$OUT/${fuzzer}_seed_corpus.zip"
done
