#!/bin/bash -eu
# Copyright 2024 Google LLC
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

# Fix hbfa-fl compatibility with edk2 that removed GCC5/GCC48/GCC49 toolchains.
# Replace GCC5_/GCC48_/GCC49_ macro references with GCC_ in the customized tools_def.
sed -i 's/GCC5_/GCC_/g; s/GCC48_/GCC_/g; s/GCC49_/GCC_/g' \
    $SRC/hbfa-fl/HBFA/UefiHostFuzzTestPkg/Conf/tools_def.customized

# Fix HBFAEnvSetup.py regex to match new GCC_ALL_CC_FLAGS (no version digits).
sed -i 's/GCC\\\\d{1,2}_ALL_CC_FLAGS/GCC\\\\d{0,2}_ALL_CC_FLAGS/' \
    $SRC/hbfa-fl/HBFA/UefiHostTestTools/HBFAEnvSetup.py

# Fix RunLibFuzzer.py to use GCC toolchain instead of removed GCC5.
sed -i 's/BuildCmdList.append(.GCC5.)/BuildCmdList.append("GCC")/' \
    $SRC/hbfa-fl/HBFA/UefiHostTestTools/RunLibFuzzer.py

hbfa-fl/oss-fuzz/build.sh
