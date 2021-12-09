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

RUN apt-get update && apt-get install -y make autoconf automake libtool zip wget python
RUN git clone https://github.com/wolfssl/wolfssl --depth 1 $SRC/wolfssl
RUN git clone --depth 1 https://github.com/wolfSSL/wolfssh.git
RUN git clone --depth 1 https://github.com/guidovranken/fuzzing-headers.git
RUN git clone --depth 1 https://github.com/guidovranken/wolf-ssl-ssh-fuzzers
RUN git clone --depth 1 https://github.com/guidovranken/cryptofuzz
RUN git clone --depth 1 https://github.com/randombit/botan.git
RUN git clone --depth 1 https://github.com/google/wycheproof.git
RUN wget https://boostorg.jfrog.io/artifactory/main/release/1.74.0/source/boost_1_74_0.tar.bz2
RUN git clone https://github.com/wolfssl/oss-fuzz-targets --depth 1 $SRC/fuzz-targets

# Retrieve corpora from other projects
RUN wget https://storage.googleapis.com/pub/gsutil.tar.gz -O $SRC/gsutil.tar.gz
RUN tar zxf $SRC/gsutil.tar.gz
ENV PATH="${PATH}:$SRC/gsutil"
RUN gsutil cp gs://bearssl-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/bearssl_cryptofuzz-bearssl/public.zip $SRC/corpus_bearssl.zip
RUN gsutil cp gs://nettle-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/nettle_cryptofuzz-nettle-with-mini-gmp/public.zip $SRC/corpus_nettle.zip
RUN gsutil cp gs://libecc-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/libecc_cryptofuzz-libecc/public.zip $SRC/corpus_libecc.zip
RUN gsutil cp gs://relic-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/relic_cryptofuzz-relic/public.zip $SRC/corpus_relic.zip
RUN gsutil cp gs://cryptofuzz-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/cryptofuzz_cryptofuzz-openssl/public.zip $SRC/corpus_cryptofuzz.zip
RUN gsutil cp gs://wolfssl-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/wolfssl_cryptofuzz-sp-math-all/public.zip $SRC/corpus_wolfssl_sp-math-all.zip
RUN gsutil cp gs://wolfssl-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/wolfssl_cryptofuzz-sp-math-all-8bit/public.zip $SRC/corpus_wolfssl_sp-math-all-8bit.zip
RUN gsutil cp gs://wolfssl-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/wolfssl_cryptofuzz-sp-math/public.zip $SRC/corpus_wolfssl_sp-math.zip
RUN gsutil cp gs://wolfssl-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/wolfssl_cryptofuzz-disable-fastmath/public.zip $SRC/corpus_wolfssl_disable-fastmath.zip

# Botan corpora, which require a special import procedure
RUN gsutil cp gs://botan-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/botan_ecc_p256/public.zip $SRC/corpus_botan_ecc_p256.zip
RUN gsutil cp gs://botan-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/botan_ecc_p384/public.zip $SRC/corpus_botan_ecc_p384.zip
RUN gsutil cp gs://botan-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/botan_ecc_p521/public.zip $SRC/corpus_botan_ecc_p521.zip
RUN gsutil cp gs://botan-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/botan_ecc_bp256/public.zip $SRC/corpus_botan_ecc_bp256.zip

WORKDIR wolfssl

COPY build.sh $SRC/
