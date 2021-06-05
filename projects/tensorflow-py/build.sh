#!/bin/bash -eu
# Copyright 2021 Google Inc.
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

python3 -m pip install tf-nightly-cpu
python3 -m pip install numpy

# Rename to avoid the following: https://github.com/tensorflow/tensorflow/issues/40182
mv $SRC/tensorflow/tensorflow $SRC/tensorflow/tensorflow_src

# Build fuzzers into $OUT. These could be detected in other ways.

for fuzzer in $(find $SRC -name '*_fuzz.py'); do
  fuzzer_basename=$(basename -s .py $fuzzer)
  fuzzer_package=${fuzzer_basename}.pkg

  pyinstaller --distpath $OUT --onefile --name $fuzzer_package $fuzzer

  cp /usr/local/lib/python3.8/site-packages/numpy.libs/libz-eb09ad1d.so.1.2.3 $OUT
  cp /usr/local/lib/python3.8/site-packages/numpy.libs/libquadmath-2d0c479f.so.0.0.0 $OUT
  cp /usr/local/lib/python3.8/site-packages/numpy.libs/libgfortran-2e0d59d6.so.5.0.0 $OUT
  cp /usr/local/lib/python3.8/site-packages/numpy.libs/libopenblasp-r0-09e95953.3.13.so $OUT
  echo "#!/bin/sh
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname \"\$0\")
LD_PRELOAD=\"\$this_dir/sanitizer_with_fuzzer.so \$this_dir/libz-eb09ad1d.so.1.2.3 \$this_dir/libquadmath-2d0c479f.so.0.0.0 \$this_dir/libgfortran-2e0d59d6.so.5.0.0 \$this_dir/libopenblasp-r0-09e95953.3.13.so\" \
ASAN_OPTIONS=\$ASAN_OPTIONS:symbolize=1:external_symbolizer_path=\$this_dir/llvm-symbolizer:detect_leaks=0 \
\$this_dir/$fuzzer_package \$@" > $OUT/$fuzzer_basename
  chmod +x $OUT/$fuzzer_basename
done

mv $SRC/tensorflow/tensorflow_src $SRC/tensorflow/tensorflow
