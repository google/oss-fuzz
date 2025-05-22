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
##########################################################################
export TF_NEED_CUDA="0"

python3 -m pip install tensorflow
python3 ./configure.py

bazel build build_pip_pkg
bazel-bin/build_pip_pkg artifacts
python3 -m pip install artifacts/tensorflow_addons-*.whl

for fuzzer in $(find $SRC -name 'fuzz_*.py'); do
  compile_python_fuzzer $fuzzer --add-data '/usr/local/lib/python3.8/site-packages/tensorflow_addons/custom_ops/text/:tensorflow_addons/custom_ops/text/'
done
