# Copyright 2016 Google Inc.
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

FROM gcr.io/oss-fuzz-base/base-clang
MAINTAINER mike.aizatsky@gmail.com
RUN apt-get install -y git subversion jq python3 zip make libunwind8-dev binutils-dev libblocksruntime-dev

# Default build flags for various sanitizers.
ENV SANITIZER_FLAGS_address "-fsanitize=address -fsanitize-address-use-after-scope"
ENV SANITIZER_FLAGS_undefined "-fsanitize=bool,array-bounds,float-divide-by-zero,function,integer-divide-by-zero,return,shift,signed-integer-overflow,vla-bound,vptr -fno-sanitize-recover=undefined"
ENV SANITIZER_FLAGS_memory "-fsanitize=memory -fsanitize-memory-track-origins"
ENV SANITIZER_FLAGS_profile "-fprofile-instr-generate -fcoverage-mapping"

# Default build flags for coverage.
ENV COVERAGE_FLAGS="-fsanitize-coverage=trace-pc-guard,trace-cmp"

# Coverage flags for generating coverage reports.
ENV COVERAGE_FLAGS_coverage="-fsanitize-coverage=bb,no-prune,trace-pc-guard -O0"

# Default sanitizer and fuzzing engine to use.
ENV SANITIZER="address"
ENV FUZZING_ENGINE="libfuzzer"

# Path to fuzzing engine library.
ENV LIB_FUZZING_ENGINE="/usr/lib/libFuzzingEngine.a"

# TODO: remove after tpm2 catchup.
ENV FUZZER_LDFLAGS ""

WORKDIR $SRC

ADD http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz $SRC/
RUN mkdir afl && \
    cd afl && \
    tar -xzv --strip-components=1 -f $SRC/afl-latest.tgz && \
    rm -rf $SRC/afl-latest.tgz

ADD https://github.com/google/honggfuzz/archive/oss-fuzz.tar.gz $SRC/
RUN mkdir honggfuzz && \
    cd honggfuzz && \
    tar -xzv --strip-components=1 -f $SRC/oss-fuzz.tar.gz && \
    rm -rf $SRC/oss-fuzz.tar.gz

COPY compile compile_afl compile_libfuzzer compile_honggfuzz coverage_report srcmap /usr/local/bin/

CMD ["compile"]

