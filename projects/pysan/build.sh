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

cd $SRC/pysecsan-lib

# install pysan
python3 ./setup.py install

# poc
cd tests
compile_python_fuzzer os_command_injection.py
compile_python_fuzzer subprocess_popen_injection.py

# libvcs
# https://github.com/advisories/GHSA-mv2w-4jqc-6fg4
cd $SRC/pysecsan-lib/tests/poe/libvcs-cve-2022-21187
./build.sh

cd $SRC/pysecsan-lib/tests/poe/ansible-runner-cve-2021-4041
./build.sh

cd $SRC/pysecsan-lib/tests/poe/python-ldap-GHSL-2021-117
./build.sh
