#!/bin/bash -eu
# Copyright 2024 Google LLC
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

python3 -m pip cache purge

unset RUSTFLAGS
unset CXXFLAGS
unset CFLAGS
python3 -m pip install .

# Build fuzzers in $OUT.
for fuzzer in $(find $SRC -name '*_fuzzer.py'); do
  fuzz_target=$(basename $fuzzer .py)
  find ${SRC}/unblob/tests/integration -path '*/__input__/*' -type f -print | zip $OUT/${fuzz_target}_seed_corpus.zip -@
  compile_python_fuzzer $fuzzer --hidden-import=_cffi_backend
done
