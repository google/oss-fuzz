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

FROM libfuzzer/base-clang

MAINTAINER aizatsky@google.com

RUN mkdir /workspace
WORKDIR /workspace
VOLUME /workspace

RUN mkdir -p /work/libfuzzer

ENV sanitizer_flags="-fsanitize=address"
ENV cov_flags="-fsanitize-coverage=edge,indirect-calls,8bit-counters"

ENV ASAN_OPTIONS="symbolize=1"

RUN mkdir /out
VOLUME /out
