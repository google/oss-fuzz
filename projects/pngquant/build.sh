#!/bin/bash -eu
# Copyright 2021 Google LLC.
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

# Build libpng
pushd $SRC/pngquant/libpng
cat scripts/pnglibconf.dfa | \
  sed -e "s/option WARNING /option WARNING disabled/" \
> scripts/pnglibconf.dfa.temp
mv scripts/pnglibconf.dfa.temp scripts/pnglibconf.dfa
autoreconf -f -i
./configure \
  --prefix="$WORK" \
  --disable-shared \
  --enable-static \
  LDFLAGS="-L$WORK/lib" \
  CPPFLAGS="-I$WORK/include"
make -j$(nproc)
make install
popd

cd $SRC/pngquant

# Remove "static" from read_image
sed 's/static pngquant_error read_image/pngquant_error read_image/g' -i pngquant.c

# Build pngquant
make -j$(nproc) V=1

# Rename "main()" to "main2" and compile
# pngquant.c again. Otherwise libfuzzer will complain
sed 's/int main(/int main2(/g' -i pngquant.c
$CC $CFLAGS  -c pngquant.c -o pngquant.o  -I. -O3 \
	-DNDEBUG -DUSE_SSE=1 -msse -mfpmath=sse \
	-Wno-unknown-pragmas -I./lib -I./libpng \
	-I/usr/include

# Collect all .o files into fuzz_lib.a
find . -name "*.o" -exec ar rcs fuzz_lib.a {} \;

# Build the fuzzer(s)
$CC $CFLAGS -c $SRC/fuzzer.c -o fuzzer.o -I. \
	-O3 -DNDEBUG -DUSE_SSE=1 -msse -mfpmath=sse \
	-Wno-unknown-pragmas -I./lib -I./libpng \
	-I/usr/include

$CC $CFLAGS fuzzer.o -I. -O3 -DNDEBUG -DUSE_SSE=1 \
	-msse -mfpmath=sse -Wno-unknown-pragmas \
	-I./lib -I./libpng -I/usr/include \
	./lib/libimagequant.a ./libpng/.libs/libpng16.a \
	-L/usr/lib/x86_64-linux-gnu -lz -lm $LIB_FUZZING_ENGINE \
	fuzz_lib.a -o $OUT/fuzzer

# Create seed corpus
zip $OUT/fuzzer_seed_corpus.zip $SRC/pngquant/test/img/test.png
