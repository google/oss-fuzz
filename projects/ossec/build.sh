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

cd $SRC/ossec-hids/src
make TARGET=local
$CC $CFLAGS $LIB_FUZZING_ENGINE $SRC/fuzz_xml.c -o $OUT/fuzz_xml \
    -I./ ./os_xml.a

$CC $CFLAGS $LIB_FUZZING_ENGINE $SRC/fuzz_regex.c -o $OUT/fuzz_regex \
    -I./ -I./os_regex/ ./os_regex.a -lpcre2-8
