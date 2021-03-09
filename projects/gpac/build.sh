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

cd gpac
./configure --static-build --extra-cflags="${CFLAGS}" --extra-ldflags="${CFLAGS}"
make
cp $SRC/fuzz_parse.c . 

$CC $CFLAGS $LIB_FUZZING_ENGINE fuzz_parse.c -o $OUT/fuzz_parse \
    -I./include -I./ ./bin/gcc/libgpac_static.a \
    -lm -lz -lpthread -DGPAC_HAVE_CONFIG_H 
