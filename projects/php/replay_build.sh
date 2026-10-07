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


# This script is useful for OSS-Fuzz infrastructure which is used to rebuild
# code from cached images. This is to support various ongoing efforts in
# OSS-Fuzz.
# The key benefit of this particular rreplay script is to avoid building all
# corpuses etc. and also any configuration steps have been removed.
# performance:
# php: Compile times: Vanilla=62; Replay=2;  

make -j$(nproc)

# Copy fuzzers out.
FUZZERS="php-fuzz-json
php-fuzz-exif
php-fuzz-unserialize
php-fuzz-unserializehash
php-fuzz-parser
php-fuzz-execute"
for fuzzerName in $FUZZERS; do
	cp sapi/fuzzer/$fuzzerName $OUT/
done

# The JIT fuzzer is fundamentally incompatible with memory sanitizer,
# as that would require the JIT to emit msan instrumentation itself.
# In practice it is currently also incompatible with ubsan.
if [ "$SANITIZER" != "memory" ] && [ "$SANITIZER" != "undefined" ]; then
    cp sapi/fuzzer/php-fuzz-function-jit $OUT/
    cp sapi/fuzzer/php-fuzz-tracing-jit $OUT/
fi
