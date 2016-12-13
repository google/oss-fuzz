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

FROM ossfuzz/base-clang
MAINTAINER mike.aizatsky@gmail.com
RUN apt-get install -y git subversion jq python3 zip

ENV SANITIZER_FLAGS_address "-fsanitize=address"
ENV SANITIZER_FLAGS_undefined "-fsanitize=bool,signed-integer-overflow,shift,vptr -fno-sanitize-recover=undefined"

# Default sanitizer to use
ENV SANITIZER="address"
ENV FUZZING_ENGINE="libfuzzer"

ENV COVERAGE_FLAGS="-fsanitize-coverage=edge,indirect-calls,8bit-counters"
ENV ASAN_OPTIONS="symbolize=1:detect_leaks=0"

ENV LIB_FUZZING_ENGINE="/usr/lib/libFuzzingEngine.a"

# TODO: remove after tpm2 catchup
ENV FUZZER_LDFLAGS ""

COPY coverage_report compile compile_libfuzzer srcmap reproduce run just_run \
     /usr/local/bin/

WORKDIR $SRC
CMD ["compile"]

