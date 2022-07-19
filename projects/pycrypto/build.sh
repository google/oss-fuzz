#!/bin/bash -eu
# Copyright 2022 Google LLC
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

# time.clock has been removed in OSS-Fuzz's Python version. Update pycrypto's source
# code. Pycrypto is deprecated so we can't expect Pycrypto to be updated.
sed -i 's/clock(/perf_counter(/g' lib/Crypto/Random/_UserFriendlyRNG.py

python3 setup.py build
python3 setup.py install

for fuzzer in $(find $SRC -name 'fuzz_*.py'); do
  compile_python_fuzzer $fuzzer
done
