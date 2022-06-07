#!/bin/bash -eu
# Copyright 2022 Google LLC.
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

pip3 install .

cp /usr/lib/x86_64-linux-gnu/libcrypt.so.1.1.0 /out/libcrypt.so
cd $SRC

# Build fuzzers in $OUT.
for fuzzer in $(find $SRC -name 'fuzz_*.py'); do
  compile_python_fuzzer $fuzzer --add-data ansible/lib/ansible/config:ansible/config
done

# Build fuzz_encrypt with a specific wrapper only in non-coverage
if [ "$SANITIZER" != "coverage" ]; then
  cp $SRC/fuzz_encrypt.sh $OUT/fuzz_encrypt
  chmod +x $OUT/fuzz_encrypt
fi
