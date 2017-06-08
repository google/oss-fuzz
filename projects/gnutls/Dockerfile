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

FROM gcr.io/oss-fuzz-base/base-builder
MAINTAINER alex.gaynor@gmail.com
RUN apt-get update && apt-get install -y make autoconf automake libtool autopoint pkg-config gperf bison autogen texinfo curl

RUN git clone --depth=1 https://gitlab.com/gnutls/gnutls.git
RUN cd gnutls && git clone --depth=1 https://git.lysator.liu.se/nettle/nettle.git
# clone OpenSSL to get its fuzzer testcases
RUN git clone --depth=1 https://github.com/openssl/openssl

# Using the client_corpus transcripts from BoringSSL and OpenSSL, they're a
# decent starting point.
RUN mkdir client-testcases
RUN cd client-testcases/ && curl https://boringssl.googlesource.com/boringssl/+archive/master/fuzz/client_corpus.tar.gz | tar -zx
RUN cd client-testcases/ && curl https://boringssl.googlesource.com/boringssl/+archive/master/fuzz/client_corpus_no_fuzzer_mode.tar.gz | tar -zx
RUN cp openssl/fuzz/corpora/client/* client-testcases/
RUN zip gnutls_client_fuzzer_seed_corpus.zip client-testcases/*

# Applies to servers as well
RUN mkdir server-testcases
RUN cd server-testcases && curl https://boringssl.googlesource.com/boringssl/+archive/master/fuzz/server_corpus.tar.gz | tar -zx
RUN cd server-testcases/ && curl https://boringssl.googlesource.com/boringssl/+archive/master/fuzz/server_corpus_no_fuzzer_mode.tar.gz | tar -zx
RUN cp openssl/fuzz/corpora/server/* server-testcases/
RUN zip gnutls_server_fuzzer_seed_corpus.zip server-testcases/*

# Same thing for X.509
RUN mkdir x509-testcases
RUN cd x509-testcases/ && curl https://boringssl.googlesource.com/boringssl/+archive/master/fuzz/cert_corpus.tar.gz | tar -zx
RUN cp openssl/fuzz/corpora/x509/* x509-testcases/
RUN zip gnutls_x509_parser_fuzzer_seed_corpus.zip x509-testcases/*

# And private keys
RUN mkdir private-key-testcases
RUN cd private-key-testcases && curl https://boringssl.googlesource.com/boringssl/+archive/master/fuzz/privkey_corpus.tar.gz | tar -zx
RUN cd private-key-testcases && curl https://boringssl.googlesource.com/boringssl/+archive/master/fuzz/pkcs8_corpus.tar.gz | tar -zx
RUN zip gnutls_private_key_parser_fuzzer_seed_corpus.zip private-key-testcases/*

WORKDIR gnutls
COPY build.sh $SRC/
