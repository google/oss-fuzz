#!/bin/bash -eu
# Copyright 2020 Google LLC
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
cd Pillow

make || true

BUILD_DIR=build/temp.linux-x86_64-3.8/src
rm ${BUILD_DIR}/_imagingmath.o
rm ${BUILD_DIR}/_imagingtk.o
rm ${BUILD_DIR}/_imagingmorph.o

$CXX -pthread -shared $CXXFLAGS $LIB_FUZZING_ENGINE ${BUILD_DIR}/*.o ${BUILD_DIR}/libImaging/*.o \
    -L/usr/local/lib -L/lib/x86_64-linux-gnu -L/usr/lib/x86_64-linux-gnu \
    -L/usr/lib/x86_64-linux-gnu/libfakeroot -L/usr/lib -L/lib \
    -L/usr/local/lib -ljpeg -lz \
    -o /src/Pillow/src/PIL/_imaging.cpython-38-x86_64-linux-gnu.so -stdlib=libc++

# Build fuzzers in $OUT.
for fuzzer in $(find $SRC -name 'fuzz_*.py'); do
  fuzzer_basename=$(basename -s .py $fuzzer)
  fuzzer_package=${fuzzer_basename}.pkg
  pyinstaller --distpath $OUT --onefile --name $fuzzer_package $fuzzer

  # Create execution wrapper.
  echo "#/bin/sh
# LLVMFuzzerTestOneInput for fuzzer detection.
LD_PRELOAD=\$(dirname "\$0")/libclang_rt.asan-x86_64.so \$(dirname "\$0")/$fuzzer_package \$@" > $OUT/$fuzzer_basename
  chmod u+x $OUT/$fuzzer_basename
done
