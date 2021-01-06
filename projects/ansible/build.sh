#!/bin/bash -eu
# Copyright 2019 Google Inc.
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

# Because Pillow's "./setup.py build_ext --inplace" does not work with custom CC and CFLAGS,
# it is necessary to build in the following manner:
#
# Build CPython without instrumentation/sanitization
# Build Pillow in a virtualenv based on uninstrumented and unsanitized CPython. Log the build steps to build.sh
# Build CPython with instrumentation/sanitization
# Rewrite build.sh to compile Pillow based on CPython with instrumentation/sanitization
#
# Why not build Pillow directly with a virtualenv based on instrumented CPython?
# Because the virtualenv will inherit CC and CFLAGS of the instrumented CPython, and that will fail.


pip3 uninstall ansible
pip3 install .
pip3 freeze

for fuzzer in $(find $SRC -name '*_fuzzer.py'); do
  fuzzer_basename=$(basename -s .py $fuzzer)
  fuzzer_package=${fuzzer_basename}.pkg
  pyinstaller --distpath $OUT --onefile --name $fuzzer_package $fuzzer

  # Create execution wrapper.
  echo "#!/bin/sh
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname \"\$0\")
LD_PRELOAD=\$this_dir/sanitizer_with_fuzzer.so \
ASAN_OPTIONS=\$ASAN_OPTIONS:symbolize=1:external_symbolizer_path=\$this_dir/llvm-symbolizer:detect_leaks=0 \
\$this_dir/$fuzzer_package \$@" > $OUT/$fuzzer_basename
  chmod u+x $OUT/$fuzzer_basename
done
