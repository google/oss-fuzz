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

FROM ossfuzz/base-libfuzzer
MAINTAINER alex.gaynor@gmail.com
RUN apt-get install -y make autoconf automake libtool autopoint libnettle6 nettle-dev pkg-config gperf bison autogen texinfo curl

RUN git clone https://gitlab.com/gnutls/gnutls.git
RUN cd gnutls && git submodule update --init

# Using the client_corpus transcripts from boringssl, they're a decent starting point.
RUN mkdir boringssl-testcases
RUN curl -o boringssl-testcases/client_corpus.tar.gz https://boringssl.googlesource.com/boringssl/+archive/master/fuzz/client_corpus.tar.gz
RUN curl -o boringssl-testcases/client_corpus_no_fuzzer_mode.tar.gz https://boringssl.googlesource.com/boringssl/+archive/master/fuzz/client_corpus_no_fuzzer_mode.tar.gz
RUN cd boringssl-testcases/ && tar -xf client_corpus.tar.gz
RUN cd boringssl-testcases/ && tar -xf client_corpus_no_fuzzer_mode.tar.gz
RUN rm boringssl-testcases/client_corpus.tar.gz boringssl-testcases/client_corpus_no_fuzzer_mode.tar.gz
RUN zip gnutls_client_fuzzer_seed_corpus.zip boringssl-testcases/*

WORKDIR gnutls
COPY build.sh gnutls_client_fuzzer.cc $SRC/
