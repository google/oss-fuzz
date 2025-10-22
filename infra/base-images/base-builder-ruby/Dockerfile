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

FROM gcr.io/oss-fuzz-base/base-builder

RUN git clone https://github.com/trailofbits/ruzzy.git $SRC/ruzzy

RUN install_ruby.sh
ENV PATH="$PATH:/usr/local/rvm/rubies/ruby-3.3.1/bin"

RUN gem update --system 3.5.11

# Install ruzzy
WORKDIR $SRC/ruzzy

# The MAKE variable allows overwriting the make command at runtime. This forces the
# Ruby C extension to respect ENV variables when compiling, like CC, CFLAGS, etc.
ENV MAKE="make --environment-overrides V=1"

RUN CC="clang" \
CXX="clang++" \
LDSHARED="clang -shared" \
LDSHAREDXX="clang++ -shared" \
gem build

RUN MAKE="make --environment-overrides V=1" \
CC="clang" \
CXX="clang++" \
LDSHARED="clang -shared" \
LDSHAREDXX="clang++ -shared" \
CXXFLAGS="-fPIC" \
CFLAGS="-fPIC" \
RUZZY_DEBUG=1 gem install --install-dir /install/ruzzy --development --verbose ruzzy-*.gem


ENV LDSHARED="$CC -shared"
ENV LDSHAREDXX="$CXX -shared"

ENV GEM_HOME="$OUT/fuzz-gem"
ENV GEM_PATH="/install/ruzzy"

COPY ruzzy-build /usr/bin/ruzzy-build
