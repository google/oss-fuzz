#!/bin/bash -eu
# Copyright 2025 Google LLC
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

unset CFLAGS
unset CXXFLAGS
unset RUSTFLAGS

rm -rf $OUT/*

source /env/bin/activate
meson setup build -Ddefault_library=static -Dtests=disabled -Dcpp_std=c++23 -Dread-interval-ms=10000 -Dmemory-region-size=1048576 -Dmemory-region-offset=3220176896 -Dbmc-interface-version=3 -Dqueue-region-size=16384 -Due-region-size=768 -Dmagic-number-byte1=2319403398 -Dmagic-number-byte2=1343703436 -Dmagic-number-byte3=2173375339 -Dmagic-number-byte4=3360702380 --buildtype=debug -Dfuzzing=true -Dcpp_args="-stdlib=libstdc++"
ninja -C build

cp build/src/bios-bmc-smm-error-logger_fuzzer $OUT
