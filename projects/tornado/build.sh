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

# The fuzzers live in the tornado repo (maint/fuzz/README.md). Build with the
# C extension, which the websocket fuzzing exercises.
TORNADO_EXTENSION=1 pip3 install .

for fuzzer in maint/fuzz/fuzz_*.py; do
  name=$(basename "$fuzzer" .py)
  compile_python_fuzzer "$fuzzer"
  # Each fuzzer can write its seed inputs (from tornado's regression corpus
  # of past security fixes).
  python3 "$fuzzer" --write-seeds="$WORK/seeds/$name"
  zip -j -q "$OUT/${name}_seed_corpus.zip" "$WORK/seeds/$name"/*
done
