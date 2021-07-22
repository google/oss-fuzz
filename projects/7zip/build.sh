#!/bin/bash -eu
# Copyright 2021 Google LLC
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

cd CPP/7zip/Bundles/Alone/

chmod +w ./makefile.gcc
sed -i 's/LOCAL_FLAGS_ST =/LOCAL_FLAGS_ST =${OSSF}/g' ./makefile.gcc
export OSSF="${CFLAGS}"
make -f makefile.gcc || true

rm ./_o/Main.o
ar -rc libzmla.a ./_o/*.o

mv $SRC/fuzz_lzma_dec.cpp .
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -I../../../ ./fuzz_lzma_dec.cpp ./libzmla.a -o $OUT/fuzz_lzma_dec
