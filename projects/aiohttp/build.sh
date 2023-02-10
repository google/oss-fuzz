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
ln -sf /usr/local/bin/python3 /usr/local/bin/python
ln -sf /usr/local/bin/pip3 /usr/local/bin/pip

# install aiohttp
pip3 install -r requirements/dev.txt
pre-commit install
make install-dev

# Duplicate fuzzers to use Pure python code (in addition
# to the existing C-compiled code).
cp fuzz_http_parser.py fuzz_http_parser_pure_python.py
sed -i 's/AIOHTTP_VAL=0/AIOHTTP_VAL=1/g' fuzz_http_parser_pure_python.py
cp fuzz_http_payload_parser.py fuzz_http_payload_parser_pure_python.py
sed -i 's/AIOHTTP_VAL=0/AIOHTTP_VAL=1/g' fuzz_http_payload_parser_pure_python.py

# Build fuzzers in $OUT.
for fuzzer in $(find $SRC -name 'fuzz_*.py'); do
  compile_python_fuzzer $fuzzer
done
