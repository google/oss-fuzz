#!/bin/bash -eu
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


export MODDABLE=$PWD
export ASAN_OPTIONS="detect_leaks=0"

FUZZ_TARGETS=(
  xst
  xst_jsonparse
)

# Build a wrapper binary for each target to set environment variables.
for FUZZ_TARGET in ${FUZZ_TARGETS[@]}
do
  $CC $CFLAGS -O0 \
    -DFUZZ_TARGET=$FUZZ_TARGET \
    $SRC/target.c -o $OUT/$FUZZ_TARGET
done

# Stash actual binaries in subdirectory so they aren't picked up by target discovery
mkdir -p $OUT/real

# build main target
cd "$MODDABLE/xs/makefiles/lin"
FUZZING=1 OSSFUZZ=1 make debug

cd "$MODDABLE"
cp ./build/bin/lin/debug/xst $OUT/real/xst
cp $SRC/xst.options $OUT/

# build jsonparse target
cd "$MODDABLE/xs/makefiles/lin"
make -f xst.mk clean
FUZZING=1 OSSFUZZ=1 OSSFUZZ_JSONPARSE=1 make debug

cd "$MODDABLE"
cp ./build/bin/lin/debug/xst $OUT/real/xst_jsonparse

cp $SRC/xst.options $OUT/xst_jsonparse.options
