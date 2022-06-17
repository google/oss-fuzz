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

git apply  --ignore-space-change --ignore-whitespace $SRC/patch.diff

cp $SRC/fuzz_*.c ./parser/

make static

rm main.o
mkdir objects && find . -name "*.o" -exec cp {} ./objects/ \;
ar -r libopensips.a ./objects/*.o

$CC $CFLAGS $LIB_FUZZING_ENGINE ./parser/fuzz_msg_parser.o ./libopensips.a  -ldl -lresolv -o $OUT/fuzz_msg_parser
$CC $CFLAGS $LIB_FUZZING_ENGINE ./parser/fuzz_uri_parser.o ./libopensips.a  -ldl -lresolv -o $OUT/fuzz_uri_parser
$CC $CFLAGS $LIB_FUZZING_ENGINE ./parser/fuzz_csv_parser.o ./libopensips.a  -ldl -lresolv -o $OUT/fuzz_csv_parser
