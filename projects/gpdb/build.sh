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

mv $SRC/Makefile $SRC/gpdb/src/backend/parser/
mv $SRC/fuzzer.c $SRC/gpdb/src/backend/parser/
mv $SRC/backend_Makefile $SRC/gpdb/src/backend/Makefile
./configure --without-zstd \
	    --without-readline \
	    --without-apr-1-config \
	    --without-zlib \
	    --without-libbz2 \
	    --without-python \
	    --disable-orca \
	    --disable-pxf \
	    --without-libcurl
make OSS_FUZZ=ON -j$(nproc)
