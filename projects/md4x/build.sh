#!/bin/bash -eu
# Copyright 2026 Google LLC
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

# Build libyaml as a static library
cd $SRC/libyaml
./bootstrap
./configure --disable-shared --prefix=$SRC/libyaml-install
make -j$(nproc)
make install
cd $SRC/md4x

LIBYAML_DIR=$SRC/libyaml-install
SRC_DIR=$SRC/md4x/src
RENDERERS=$SRC_DIR/renderers
FUZZERS=$SRC/md4x/test/fuzzers
INCLUDES="-I$SRC_DIR -I$RENDERERS -I$LIBYAML_DIR/include -DMD4X_USE_UTF8"

# Compile shared source files
$CC $CFLAGS $INCLUDES -c $SRC_DIR/md4x.c -o md4x.o
$CC $CFLAGS $INCLUDES -c $SRC_DIR/entity.c -o entity.o
$CC $CFLAGS $INCLUDES -c $RENDERERS/md4x-heal.c -o md4x-heal.o

# Compile renderer source files
$CC $CFLAGS $INCLUDES -c $RENDERERS/md4x-html.c -o md4x-html.o
$CC $CFLAGS $INCLUDES -c $RENDERERS/md4x-ast.c -o md4x-ast.o
$CC $CFLAGS $INCLUDES -c $RENDERERS/md4x-ansi.c -o md4x-ansi.o
$CC $CFLAGS $INCLUDES -c $RENDERERS/md4x-text.c -o md4x-text.o
$CC $CFLAGS $INCLUDES -c $RENDERERS/md4x-meta.c -o md4x-meta.o

# Compile fuzzer harnesses
$CC $CFLAGS $INCLUDES -c $FUZZERS/fuzz-mdhtml.c -o fuzz-mdhtml.o
$CC $CFLAGS $INCLUDES -c $FUZZERS/fuzz-mdast.c -o fuzz-mdast.o
$CC $CFLAGS $INCLUDES -c $FUZZERS/fuzz-mdansi.c -o fuzz-mdansi.o
$CC $CFLAGS $INCLUDES -c $FUZZERS/fuzz-mdtext.c -o fuzz-mdtext.o
$CC $CFLAGS $INCLUDES -c $FUZZERS/fuzz-mdmeta.c -o fuzz-mdmeta.o
$CC $CFLAGS $INCLUDES -c $FUZZERS/fuzz-mdheal.c -o fuzz-mdheal.o

COMMON="md4x.o entity.o md4x-heal.o"

# Link fuzzers
LIBYAML_A=$LIBYAML_DIR/lib/libyaml.a

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz-mdhtml.o md4x-html.o $COMMON $LIBYAML_A -o $OUT/fuzz-mdhtml
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz-mdast.o md4x-ast.o $COMMON $LIBYAML_A -o $OUT/fuzz-mdast
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz-mdansi.o md4x-ansi.o $COMMON -o $OUT/fuzz-mdansi
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz-mdtext.o md4x-text.o $COMMON -o $OUT/fuzz-mdtext
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz-mdmeta.o md4x-meta.o $COMMON $LIBYAML_A -o $OUT/fuzz-mdmeta
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz-mdheal.o md4x-heal.o -o $OUT/fuzz-mdheal

# Copy seed corpus and dictionaries
for fuzzer in fuzz-mdhtml fuzz-mdast fuzz-mdansi fuzz-mdtext fuzz-mdmeta fuzz-mdheal; do
    cp $SRC/seed_corpus.zip $OUT/${fuzzer}_seed_corpus.zip
    mv $SRC/${fuzzer}.dict $OUT/ 2>/dev/null || true
done
