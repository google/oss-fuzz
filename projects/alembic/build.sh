#!/bin/bash -eu
# Copyright 2020 Google Inc.
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

# build alembic
mkdir -p $WORK/build_alembic
cd $WORK/build_alembic
cmake $SRC/alembic -DALEMBIC_SHARED_LIBS=OFF -DALEMBIC_BUILD_FUZZERS=ON
make -j$(nproc)

cp tests/fuzz/alembic_dump_info_fuzzer $OUT/
