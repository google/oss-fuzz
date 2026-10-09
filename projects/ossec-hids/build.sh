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

cd "$SRC/ossec-hids/src"

# Build os_xml.a + fuzz_os_xml with OSS-Fuzz CC/CFLAGS/LIB_FUZZING_ENGINE.
# USE_HARDENING=no avoids -pie which conflicts with libFuzzer.
make clean-internals || true
make -j$(nproc) fuzz_os_xml \
  CC="$CC" \
  CFLAGS="$CFLAGS -fPIC" \
  USE_HARDENING=no \
  LIB_FUZZING_ENGINE="$LIB_FUZZING_ENGINE"

cp fuzz_os_xml "$OUT/fuzz_os_xml"
zip -j "$OUT/fuzz_os_xml_seed_corpus.zip" tests/fuzz/corpus_os_xml/*
cp tests/fuzz/fuzz_os_xml.options "$OUT/fuzz_os_xml.options"
