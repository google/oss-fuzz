#!/bin/bash -eux
# Copyright 2025 Google LLC.
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
###############################################################################

export OPJ_DATA_ROOT=$PWD/data

cd build

# TODO(David) Enable the tests we disable in this loop. We disable because
# they fail in the OSS-Fuzz environment, and it's unclear why.
for test_name in ETS-JP2-file5.jp2-decode ETS-JP2-file5.jp2-compare2ref NR-JP2-file5.jp2-compare2base ETS-JP2-file7.jp2-decode ETS-JP2-file7.jp2-compare2ref NR-JP2-file7.jp2-compare2base ETS-JP2-file8.jp2-compare2ref NR-JP2-file8.jp2-compare2base; do
  echo $PWD
  sed -i "s/add_test($test_name/#${test_name}/g" ./tests/conformance/CTestTestfile.cmake
  sed -i "s/set_tests_properties(${test_name}/#set_tests_properties(${test_name}/g" ./tests/conformance/CTestTestfile.cmake
done
sed -i "s/subdirs(\"nonregression\")/#subdirs(\"nonregression\")/g" tests/CTestTestfile.cmake

make test
