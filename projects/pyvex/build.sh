#!/bin/bash -eu
# Copyright 2023 Google LLC
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

# Since pyvex requires a specific developer build of archinfo, install it from source
cd "$SRC"/archinfo
pip3 install .

cd "$SRC"/pyvex
pip3 install .

if [ "$SANITIZER" = "address" ]
then
    # Enable pysecsan
    export ENABLE_PYSECSAN="1"
fi

# Generate a simple binary for the corpus
echo -ne "start:\n\txor %edi, %edi\nmov \$60, %eax\nsyscall" > /tmp/corpus.s
clang -Os -s /tmp/corpus.s -nostdlib -nostartfiles -m32 -o corpus
zip -r "$OUT"/irsb_fuzzer_seed_corpus.zip corpus

# Build fuzzers in $OUT
echo "=========================="
for fuzzer in $(find $SRC -name '*_fuzzer.py'); do
  compile_python_fuzzer "$fuzzer" --add-binary="pyvex/lib/libpyvex.so:pyvex/lib"
done
