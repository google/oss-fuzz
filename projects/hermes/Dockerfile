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

FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && \
    apt-get install -yqq make autoconf automake libtool wget \
    python3 zip libreadline-dev libatomic-ops-dev npm

# Building ninja requires PEP 517.
RUN pip3 install "pip>=22.3.1"

RUN pip3 install meson ninja
RUN ln -s /usr/local/bin/ninja /usr/bin/ninja

# Install NPM to strip comments
RUN npm install -g @prasadrajandran/strip-comments-cli

# Add JS dictionaries
RUN git clone --depth 1 https://github.com/chromium/chromium && \
    cat chromium/testing/libfuzzer/fuzzers/dicts/javascript_parser_proto.dict > $SRC/hermes.dict && \
    cat chromium/testing/libfuzzer/fuzzers/dicts/generated/javascript.dict >> $SRC/hermes.dict

RUN wget https://github.com/unicode-org/icu/archive/refs/tags/cldr/2021-08-25.tar.gz && \
    tar xzvf ./2021-08-25.tar.gz && \
    mv ./icu-cldr-2021-08-25/icu4c $SRC/icu

RUN git clone https://github.com/facebook/hermes.git && \
    git clone --depth 1 https://github.com/tc39/test262 && \
    git clone --depth 1 https://github.com/Zon8Research/v8-vulnerabilities && \
    git clone --depth 1 https://github.com/v8/v8

# Strip comments from corpus.
RUN find hermes/test -iname '*.js' -exec stripcomments --write --confirm-overwrite '{}' \+ && \
    find hermes/external/esprima/test_fixtures -iname '*.js' -exec stripcomments --write --confirm-overwrite '{}' \+ && \
    find hermes/external/flowtest/test/flow -iname '*.js' -exec stripcomments --write --confirm-overwrite '{}' \+ && \
    find test262/test -iname '*.js' -exec stripcomments --write --confirm-overwrite '{}' \+ && \
    find v8-vulnerabilities/pocs -iname '*.js' -exec stripcomments --write --confirm-overwrite '{}' \+ && \
    find v8/test/mjsunit -iname '*.js' -exec stripcomments --write --confirm-overwrite '{}' \+

# Process corpora
COPY preprocess-corpus.py $SRC/
RUN python preprocess-corpus.py
RUN rm $SRC/preprocess-corpus.py

# Add unit tests from project directory as seed corpus.
RUN find hermes/test -iname '*.js' | zip -@ -q $SRC/hermes_seed_corpus.zip && \
    # Add tests from test262 as seed corpus.
    find test262/test -iname '*.js' | zip -@ -q $SRC/hermes_seed_corpus.zip && \
    # Add V8 PoCs as seed corpus.
    find v8-vulnerabilities/pocs -iname '*.js' | zip -@ -q $SRC/hermes_seed_corpus.zip && \
    # Add tests from esprima as seed corpus.
    find hermes/external/esprima/test_fixtures -iname '*.js' | zip -@ -q $SRC/hermes_seed_corpus.zip && \
    # Add tests from flow as seed corpus.
    find hermes/external/flowtest/test/flow -iname '*.js' | zip -@ -q $SRC/hermes_seed_corpus.zip && \
    # Add tests from v8 as seed corpus.
    find v8/test/mjsunit -iname '*.js' | zip -@ -q $SRC/hermes_seed_corpus.zip

WORKDIR $SRC
COPY build.sh $SRC/
# This is to fix Fuzz Introspector build by using LLVM old pass manager
# re https://github.com/ossf/fuzz-introspector/issues/305
ENV OLD_LLVMPASS 1
