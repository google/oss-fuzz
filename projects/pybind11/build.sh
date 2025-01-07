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

python3 -m pip install -r tests/requirements.txt
cmake -S . -B build -DDOWNLOAD_CATCH=ON -DDOWNLOAD_EIGEN=ON
cmake --build build -j4
python3 -m pip install .

cp /usr/local/lib/libpython3.10.so.1.0 $OUT/
for f in $SRC/*_fuzzer.cc; do
  fuzzer=$(basename "$f" _fuzzer.cc)
  $CXX $CXXFLAGS \
    -I$SRC/pybind11/include -isystem /usr/local/include/python3.10 \
    $SRC/${fuzzer}_fuzzer.cc -o $OUT/${fuzzer}_fuzzer \
    /usr/local/lib/libpython3.10.so.1.0 \
    $LIB_FUZZING_ENGINE -lpthread
  patchelf --set-rpath '$ORIGIN/'  $OUT/${fuzzer}_fuzzer
done
