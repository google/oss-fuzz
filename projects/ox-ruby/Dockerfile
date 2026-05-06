# Copyright 2024 Google LLC
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

FROM gcr.io/oss-fuzz-base/base-builder-ruby

RUN git clone --depth 1 --single-branch https://github.com/ohler55/ox.git $SRC/ox-ruby

ENV CFLAGS="$CFLAGS -fsanitize=fuzzer-no-link -fno-omit-frame-pointer -fno-common -fPIC -g"
ENV CXXFLAGS="$CXXFLAGS -fsanitize=fuzzer-no-link -fno-omit-frame-pointer -fno-common -fPIC -g"

COPY build.sh $SRC/build.sh
COPY fuzz_*.rb $SRC/harnesses/

WORKDIR $SRC
