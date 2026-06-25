#!/bin/bash -eu
# Copyright 2021 Google LLC
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

cp Makefile Makefile.backup
sed -i 's/CFLAGS += -g -fsanitize=address,fuzzer,undefined/#CFLAGS += -g -fsanitize=address,fuzzer,undefined/' ./Makefile
export LDFLAGS="${LIB_FUZZING_ENGINE} ${CFLAGS}"

chmod +x ./fuzztest/build.sh
./fuzztest/build.sh
mv civetweb_fuzz* $OUT/

# Build unit tests with clean compiler flags (without fuzzing instrumentation)
mv Makefile.backup Makefile
export LDFLAGS=
mkdir build-test
gcc unittest/cgi_test.c -o build-test/cgi_test.cgi
cd build-test

cmake -DCIVETWEB_ENABLE_SSL=YES \
      -DCIVETWEB_DISABLE_CGI=NO \
      -DCIVETWEB_ENABLE_WEBSOCKETS=YES \
      -DCIVETWEB_ENABLE_SERVER_STATS=YES \
      -DCIVETWEB_ENABLE_IPV6=YES ..
make all
