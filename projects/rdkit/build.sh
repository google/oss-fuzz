#!/bin/bash -eu
# Copyright 2020 Google Inc.
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

# Build zlib
git clone --depth 1 -b master https://github.com/madler/zlib.git $SRC/zlib
cd $SRC/zlib
OLD_CFLAGS="$CFLAGS"
export LDFLAGS="-fPIC $CFLAGS"
export CFLAGS="-fPIC $CFLAGS"
# Only build static libraries, so we don't accidentally link to zlib dynamically.
./configure --static
make -j$(nproc) clean
make -j$(nproc) all install
unset LDFLAGS
export CFLAGS="$OLD_CFLAGS"

# We're building `rdkit` using clang, but the boost package is built using gcc.
# For whatever reason, linking would fail.
# (Mismatch between libstdc++ and libc++ maybe?)
# It works if we build `rdkit` using gcc or build boost using clang instead.
# We've opted for building boost using clang.
cd $SRC && \
wget --quiet https://archives.boost.io/release/1.84.0/source/boost_1_84_0.tar.bz2 && \
tar xjf boost_1_84_0.tar.bz2 && \
cd $SRC/boost_1_84_0 && \
./bootstrap.sh --with-toolset=clang --with-libraries=serialization,system,iostreams,regex,program_options && \
# b2's clang toolset adds --target=x86_64-pc-linux (missing -gnu suffix),
# which breaks libc++ header search. Use a wrapper to fix the target triple.
cat > /tmp/clang_wrapper.sh << 'WRAPPER'
#!/bin/bash
args=()
for arg in "$@"; do
    if [[ "$arg" == "--target="* ]]; then
        args+=("--target=x86_64-unknown-linux-gnu")
    else
        args+=("$arg")
    fi
done
exec /usr/local/bin/clang++ "${args[@]}"
WRAPPER
chmod +x /tmp/clang_wrapper.sh && \
echo "using clang : : /tmp/clang_wrapper.sh ;" > ~/user-config.jam && \
./b2 -q -j$(nproc) toolset=clang linkflags="-fPIC $CXXFLAGS $CXXFLAGS_EXTRA" cxxflags="-fPIC $CXXFLAGS $CXXFLAGS_EXTRA" link=static install

cd $SRC/rdkit

mkdir -p build && cd build
cmake -DRDK_BUILD_PYTHON_WRAPPERS=OFF -DRDK_BUILD_FREETYPE_SUPPORT=OFF -DLIB_FUZZING_ENGINE=${LIB_FUZZING_ENGINE} -DRDK_BUILD_FUZZ_TARGETS=ON -DRDK_INSTALL_STATIC_LIBS=ON -DBoost_USE_STATIC_LIBS=ON ..
# Use -k to keep going past shared library link failures (coverage sanitizer
# causes __llvm_prf section errors in .so files). Fuzzers only need static libs.
make -j$(nproc) -k || true
make install -k || true

# Leave build directory
cd ..

# Copy the fuzzer executables, zip-ed corpora, options and dictionary files to $OUT
find . -type f -name '*_fuzzer' -exec cp -v '{}' $OUT ';'
find . -type f -name '*_fuzzer.dict' -exec cp -v '{}' $OUT ';'
#find . -type f -name '*_fuzzer.options' -exec cp -v '{}' $OUT ';'
corpora=$(find . -type d -name "*_fuzzer")
for corpus in $corpora; do
	corpus_basename=$(basename $corpus)
	zip -j $OUT/${corpus_basename}_seed_corpus.zip ${corpus}/*
done
