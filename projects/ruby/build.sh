#!/bin/bash -eu
# Copyright 2022 Google LLC
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

export ASAN_OPTIONS="detect_leaks=0:use_sigaltstack=0:detect_stack_use_after_return=0"
export UBSAN_OPTIONS="silence_unsigned_overflow=1"

./autogen.sh
./configure --enable-shared --disable-install-doc

make -j $(nproc)

# The `ln` command below is a workaround for an issue with ruby's
# build system, which seems to be a known problem. See this commit:
#
# https://github.com/ruby/ruby/commit/9ee48c0a7ce6e7c497bba87c5702ac88d1373bfb
#
# Our problem is that `make install` runs some ruby code, using the
# newly built ruby interpreter, but with the `LD_PRELOAD` environment
# variable set so that it can find `libruby.so`. Some of the those
# ruby scripts exec other binaries, such as `make`. Those binaries
# then crash because they can't find the ASAN lib, which is
# recursively pulled in by `libruby.so`.
#
# Apparently the same problem happened before on multiarch platforms,
# so a workaround was added in commit 9ee48c0 (link above): if the
# file `exe/ruby` exists then the `LD_PRELOAD` environment variable is
# not set. We trigger the workaround here by creating a symlink to the
# ruby binary.
mkdir -p exe
ln -s ../ruby exe/ruby

make install -j $(nproc)

ruby_version=$(basename `find . -name 'ruby-*.pc'` .pc)
export RUBY_LIB_DIR=$(pkg-config --variable=libdir $ruby_version)
export RUBY_LIBRARIES=$(pkg-config --variable=LIBRUBYARG_SHARED $ruby_version)
export RUBY_INCLUDES=$(pkg-config --cflags $ruby_version)
export RUBY_RUBYLIBDIR=$(pkg-config --variable=rubylibdir $ruby_version)

cd $SRC/fuzz
ruby gen_init_ruby_load_paths.rb > init_ruby_load_paths.h

# The -rpath flag helps the dynamic linker to find .so files in /out/lib
${CC} ${CFLAGS} fuzz_ruby_gems.c -o $OUT/fuzz_ruby_gems \
    -Wall \
    -Wl,-rpath,./lib \
    -L${RUBY_LIB_DIR} \
    ${RUBY_INCLUDES} \
    ${RUBY_LIBRARIES} \
    ${LIB_FUZZING_ENGINE}

# Copy options to out
cp $SRC/fuzz/*.options $OUT/
rm -fr $OUT/lib
cp -r $RUBY_LIB_DIR $OUT/lib
