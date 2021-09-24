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

# supp_size is unused in harfbuzz so we will avoid it being unused.
sed -i 's/supp_size;/supp_size;(void)(supp_size);/g' ./thirdparty/harfbuzz/src/hb-subset-cff1.cc

LDFLAGS="$CXXFLAGS" make -j$(nproc) HAVE_GLUT=no build=debug OUT=$WORK
fuzz_target=pdf_fuzzer

$CXX $CXXFLAGS -std=c++11 -Iinclude \
    $SRC/pdf_fuzzer.cc -o $OUT/$fuzz_target \
    $LIB_FUZZING_ENGINE $WORK/libmupdf.a $WORK/libmupdf-third.a

mv $SRC/{*.zip,*.dict,*.options} $OUT

if [ ! -f "${OUT}/${fuzz_target}_seed_corpus.zip" ]; then
  echo "missing seed corpus"
  exit 1
fi

if [ ! -f "${OUT}/${fuzz_target}.dict" ]; then
  echo "missing dictionary"
  exit 1
fi

if [ ! -f "${OUT}/${fuzz_target}.options" ]; then
  echo "missing options"
  exit 1
fi
