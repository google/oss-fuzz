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
cd $SRC/node

# Coverage build takes very long and time outs in the CI which blocks changes. Ignore Coverage build in OSS-Fuzz CI for now:
if [[ -n "${OSS_FUZZ_CI-}" && "$SANITIZER" = coverage ]]; then
	exit 0
fi

# Build node
export LDFLAGS="$CXXFLAGS"
export LD="$CXX"
./configure --with-ossfuzz
if [[ "$SANITIZER" = coverage ]]; then
	make
else
	make -j$(nproc)
fi

# Copy all fuzzers to OUT folder 
cp out/Release/fuzz_* ${OUT}/

zip $OUT/fuzz_env_seed_corpus.zip $SRC/node/test/fuzzers/corpus/fuzz_env_seed*
