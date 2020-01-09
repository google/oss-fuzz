#!/bin/bash -eu
# Copyright 2019 Google Inc.
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

# Because Pillow's "./setup.py build_ext --inplace" does not work with custom CC and CFLAGS,
# it is necessary to build in the following manner:
#
# Build CPython without instrumentation/sanitization
# Build Pillow in a virtualenv based on uninstrumented and unsanitized CPython. Log the build steps to build.sh
# Build CPython with instrumentation/sanitization
# Rewrite build.sh to compile Pillow based on CPython with instrumentation/sanitization
#
# Why not build Pillow directly with a virtualenv based on instrumented CPython?
# Because the virtualenv will inherit CC and CFLAGS of the instrumented CPython, and that will fail.

cd $SRC/
tar zxf v3.8.1.tar.gz
cd cpython-3.8.1/

# Ignore memory leaks from python scripts invoked in the build
export ASAN_OPTIONS="detect_leaks=0"
export MSAN_OPTIONS="halt_on_error=0:exitcode=0:report_umrs=0"

# Remove -pthread from CFLAGS, this trips up ./configure
# which thinks pthreads are available without any CLI flags
CFLAGS=${CFLAGS//"-pthread"/}

FLAGS=()
case $SANITIZER in
  address)
    FLAGS+=("--with-address-sanitizer")
    ;;
  memory)
    FLAGS+=("--with-memory-sanitizer")
    # installing ensurepip takes a while with MSAN instrumentation, so
    # we disable it here
    FLAGS+=("--without-ensurepip")
    # -msan-keep-going is needed to allow MSAN's halt_on_error to function
    FLAGS+=("CFLAGS=-mllvm -msan-keep-going=1")
    ;;
  undefined)
    FLAGS+=("--with-undefined-behavior-sanitizer")
    ;;
esac

export CPYTHON_INSTALL_PATH=$OUT/cpython-install
rm -rf $CPYTHON_INSTALL_PATH
mkdir $CPYTHON_INSTALL_PATH

export CPYTHON_UNINSTRUMENTED_INSTALL_PATH=$OUT/cpython-install
rm -rf $CPYTHON_UNINSTRUMENTED_INSTALL_PATH
mkdir $CPYTHON_UNINSTRUMENTED_INSTALL_PATH

cd $SRC/
tar zxf v3.8.1.tar.gz

# Compile uninstrumented CPython
cp -R $SRC/cpython-3.8.1/ $SRC/cpython-3.8.1-uninstrumented
cd $SRC/cpython-3.8.1-uninstrumented
CFLAGS="" CXXFLAGS="" ./configure --prefix=$CPYTHON_UNINSTRUMENTED_INSTALL_PATH
CFLAGS="" CXXFLAGS="" make -j$(nproc)
CFLAGS="" CXXFLAGS="" make install

# Compile instrumented CPython
cd $SRC/cpython-3.8.1/
cp $SRC/oss-fuzz-fuzzers/pillow/python_coverage.h Python/

# Patch the interpreter to record code coverage
sed -i '1 s/^.*$/#include "python_coverage.h"/g' Python/ceval.c
sed -i 's/case TARGET\(.*\): {/\0\nfuzzer_record_code_coverage(f->f_code, f->f_lasti);/g' Python/ceval.c

./configure "${FLAGS[@]}" --prefix=$CPYTHON_INSTALL_PATH
make -j$(nproc)
make install

# Compile Pillow fuzzers
cd $SRC/oss-fuzz-fuzzers/pillow
rm $CPYTHON_INSTALL_PATH/lib/python3.8/lib-dynload/_tkinter*.so
make
cp $SRC/oss-fuzz-fuzzers/pillow/fuzzer-loadimg $OUT/
cp $SRC/oss-fuzz-fuzzers/pillow/loadimg.py $OUT/

# Create venv for Pillow compilation
$CPYTHON_UNINSTRUMENTED_INSTALL_PATH/bin/python3 -m venv $SRC/venv
source $SRC/venv/bin/activate

# Compile Pillow
cd $SRC/pillow
CFLAGS="" CXXFLAGS="" ./setup.py build_ext --inplace >build.sh
grep "^\(gcc\|x86_64-linux-gnu-gcc\|clang\) " build.sh | sed 's/^\(gcc\|x86_64-linux-gnu-gcc\|clang\) /$CC $CFLAGS /g' | sed 's/-DPILLOW_VERSION="\([^"]\+\)"/-DPILLOW_VERSION="\\"\1\\""/g' >build2.sh
bash build2.sh
cp -R $SRC/pillow $OUT/
cp /usr/lib/x86_64-linux-gnu/libjpeg.so.8 $OUT/
cp /usr/lib/x86_64-linux-gnu/libtiff.so.5 $OUT/
cp /usr/lib/x86_64-linux-gnu/libjbig.so.0 $OUT/
cp /usr/lib/x86_64-linux-gnu/libwebp.so.5 $OUT/
cp /usr/lib/x86_64-linux-gnu/libwebpmux.so.1 $OUT/
cp /usr/lib/x86_64-linux-gnu/libwebpdemux.so.1 $OUT/
cp $SRC/oss-fuzz-fuzzers/pillow/corpus.zip $OUT/fuzzer-loadimg_seed_corpus.zip
