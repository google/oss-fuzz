#!/bin/bash -eu
# Copyright 2020 Google LLC
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
cd pyyaml
python3 ./setup.py --without-libyaml install
#pip3 install .

# Build fuzzers in $OUT.
for fuzzer in $(find $SRC -name 'fuzz_*.py'); do
  fuzzer_basename=$(basename -s .py $fuzzer)
  fuzzer_package=${fuzzer_basename}.pkg
  pyinstaller --distpath $OUT --onefile --name $fuzzer_package $fuzzer

  # Create execution wrapper.
  # The documentation specifies we need to have LD_PRELOAD set (https://google.github.io/oss-fuzz/getting-started/new-project-guide/python-lang/#buildsh)
  # as follows:
  #LD_PRELOAD=\$(dirname "\$0")/libclang_rt.asan-x86_64.so \$(dirname "\$0")/$fuzzer_package \$@" > $OUT/$fuzzer_basename
  # However, in my experience this is only needed when fuzzing native libraries, and,
  # in fact causes an error to occur with fuzzing pure python modules.
  echo "#/bin/sh
# LLVMFuzzerTestOneInput for fuzzer detection.
\$(dirname "\$0")/$fuzzer_package \$@" > $OUT/$fuzzer_basename
  chmod u+x $OUT/$fuzzer_basename
done
