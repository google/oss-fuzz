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

make_dictionary_for_fuzz_harness() {
  local fuzz_harness="$1"
  local base_dictionary="$SRC/__base.dict"
  local output_dict="$OUT/${fuzz_harness##*/}"
  output_dict="${output_dict%.py}.dict"

  [[ -r "$base_dictionary" ]] && {
    [[ -s "$output_dict" ]] && echo >>"$output_dict"
    cat "$base_dictionary" >>"$output_dict"
  }
}


# We need this because pyinstaller used in OSS-Fuzz will affect
# the path, which causes this assert check to fail.
sed -i 's/def do_override():/def do_override():\n    return True\n\ndef do_override2():/g' _distutils_hack/__init__.py

pushd "$SRC/distutils"
pip3 install .
popd

pip3 install .

cd ../
mkdir forbuilding
cd forbuilding
# Build fuzzers in $OUT.
for fuzzer in $(find "$SRC" -name 'fuzz_*.py'); do
  compile_python_fuzzer "$fuzzer"
  make_dictionary_for_fuzz_harness "$fuzzer"
done


wget https://raw.githubusercontent.com/pypa/setuptools/main/pyproject.toml
zip $OUT/fuzz_config_pyprojecttoml_seed_corpus.zip ./pyproject.toml
