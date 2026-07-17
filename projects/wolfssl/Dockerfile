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

RUN apt-get update && apt-get install -y make autoconf automake libtool zip wget python bsdmainutils libcrypt-dev:i386
RUN git clone --depth 1 https://github.com/wolfssl/wolfssl $SRC/wolfssl
RUN git clone --depth 1 https://github.com/wolfSSL/wolfsm
RUN git clone --depth 1 https://github.com/wolfSSL/wolfssh.git
RUN git clone --depth 1 https://github.com/JacobBarthelmeh/fuzzing-headers.git
RUN git clone --depth 1 https://github.com/JacobBarthelmeh/wolf-ssl-ssh-fuzzers
RUN git clone --depth 1 https://github.com/MozillaSecurity/cryptofuzz
RUN git clone --depth 1 https://github.com/google/wycheproof.git
RUN wget https://archives.boost.io/release/1.82.0/source/boost_1_82_0.tar.bz2
RUN git clone https://github.com/wolfssl/oss-fuzz-targets --depth 1 $SRC/fuzz-targets

# Retrieve corpora from other projects
RUN wget https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-linux-x86_64.tar.gz -O $SRC/gcloud.tar.gz
RUN tar zxf $SRC/gcloud.tar.gz
ENV PATH="${PATH}:$SRC/google-cloud-sdk/bin"
RUN wget https://storage.googleapis.com/bearssl-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/bearssl_cryptofuzz-bearssl/public.zip -O $SRC/corpus_bearssl.zip
RUN wget https://storage.googleapis.com/libecc-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/libecc_cryptofuzz-libecc/public.zip -O $SRC/corpus_libecc.zip
RUN wget https://storage.googleapis.com/relic-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/relic_cryptofuzz-relic/public.zip -O $SRC/corpus_relic.zip
RUN wget https://storage.googleapis.com/cryptofuzz-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/cryptofuzz_cryptofuzz-openssl/public.zip -O $SRC/corpus_cryptofuzz-openssl.zip
RUN wget https://storage.googleapis.com/cryptofuzz-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/cryptofuzz_cryptofuzz-boringssl/public.zip -O $SRC/corpus_cryptofuzz-boringssl.zip
RUN wget https://storage.googleapis.com/cryptofuzz-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/cryptofuzz_cryptofuzz-nss/public.zip -O $SRC/corpus_cryptofuzz-nss.zip

# OpenSSL/LibreSSL corpora, which require a special import procedure
RUN wget https://storage.googleapis.com/openssl-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/openssl_bignum/public.zip -O $SRC/corpus_openssl_expmod.zip
RUN wget https://storage.googleapis.com/libressl-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/libressl_bignum/public.zip -O $SRC/corpus_libressl_expmod.zip

WORKDIR wolfssl

COPY build.sh $SRC/
