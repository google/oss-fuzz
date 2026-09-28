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

# Compile the source file with instrumentation
$CC $CFLAGS -c $SRC/pam-ipmi/src/pam_ipmisave/pam_ipmisave.c -o pam_ipmisave.o

# Compile and link the fuzzer
$CC $CFLAGS $LIB_FUZZING_ENGINE $SRC/pam_ipmi_fuzzer.c pam_ipmisave.o -o $OUT/pam_ipmi_fuzzer -lcrypto -lpam

# Package the corpus
zip -j $OUT/pam_ipmi_fuzzer_seed_corpus.zip $SRC/corpus/*
