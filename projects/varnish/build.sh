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


# build project
./autogen.sh
./configure --enable-oss-fuzz PCRE2_LIBS=-l:libpcre2-8.a
make -j2 -C include/
make -j2 -C lib/libvarnish/
make -j2 -C lib/libvgz/
make -j2 -C lib/libvsc/
make -j2 -C bin/varnishd/ esi_parse_fuzzer
cp bin/varnishd/*_fuzzer $OUT/
