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

FROM gcr.io/oss-fuzz-base/base-builder-ruby

# Install autotools needed to build libyaml from source
RUN apt-get update && apt-get install -y autoconf automake libtool

# Clone libyaml for static linking
RUN git clone --depth 1 https://github.com/yaml/libyaml.git $SRC/libyaml

# Clone psych
RUN git clone --depth 1 https://github.com/ruby/psych.git $SRC/psych

# Clone repo for seeds
RUN git clone --depth 1 https://github.com/yaml/yaml-test-suite.git $SRC/yaml-test-suite

ENV CFLAGS="$CFLAGS -fsanitize=fuzzer-no-link -fno-omit-frame-pointer -fno-common -fPIC -g"
ENV CXXFLAGS="$CXXFLAGS -fsanitize=fuzzer-no-link -fno-omit-frame-pointer -fno-common -fPIC -g"

COPY build.sh $SRC/build.sh
COPY fuzz_*.rb $SRC/harnesses/

WORKDIR $SRC
