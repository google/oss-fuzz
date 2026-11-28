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

pip3 install .
# Build fuzzers in $OUT.
cat > "$OUT/openssl_legacy.cnf" << 'OPENSSL_EOF'
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
legacy = legacy_sect

[default_sect]
activate = 1

[legacy_sect]
activate = 1
OPENSSL_EOF

for fuzzer in $(find $SRC -name 'fuzz_*.py'); do
  compile_python_fuzzer $fuzzer
  wrapper="$OUT/$(basename -s .py "$fuzzer")"
  # OPENSSL_CONF must be set before Python starts: under coverage builds,
  # compile_python_fuzzer prepends `import coverage`, which loads `_hashlib`
  # and initializes OpenSSL before fuzz_ntlm_auth.py runs.
  if [ -f "$wrapper" ]; then
    sed -i 's|^LD_PRELOAD=|OPENSSL_CONF=$this_dir/openssl_legacy.cnf LD_PRELOAD=|' "$wrapper"
  fi
done
