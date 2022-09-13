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

# poc
touch __init__.py
cp $SRC/target_lib.py .
cp $SRC/sanlib.py .
compile_python_fuzzer $SRC/fuzz_poc.py

# libvcs
# https://github.com/advisories/GHSA-mv2w-4jqc-6fg4
cd $SRC
pip3 install libvcs==0.11.0 
mkdir libvcs_poc
cd libvcs_poc
compile_python_fuzzer $SRC/fuzz_libvcs.py


cd $SRC
git clone https://github.com/23andMe/Yamale
cd Yamale
git checkout 788664233700c45fc756a963613869cf0a0896f9
pip3 install .
compile_python_fuzzer $SRC/fuzz_yamale.py

cd $SRC/
git clone https://github.com/ansible/ansible-runner/
cd ansible-runner
git checkout cdc0961df51fa1e10b44371944aafe5ae140b98c
pip3 install .
compile_python_fuzzer $SRC/fuzz_ansible_runner.py
