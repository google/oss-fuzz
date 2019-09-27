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

# build project
mkdir -p build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS="${CXXFLAGS}" -DWDS_OSSFUZZ=ON ..
make libwds_rtsp_fuzzer

# Copy fuzzer, dictionary and fuzzer options
cp fuzz/libwds_rtsp_fuzzer $OUT
rm -f $OUT/libwds_rtsp_fuzzer.dict
for f in $SRC/wds/libwds/rtsp/tests/dict/*.dict;
do
  (cat "${f}"; echo) >> $OUT/libwds_rtsp_fuzzer.dict;
done
cat <<EOF >>$OUT/libwds_rtsp_fuzzer.options
[libfuzzer]
close_fd_mask = 3
EOF
