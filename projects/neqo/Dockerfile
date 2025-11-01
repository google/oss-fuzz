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

FROM gcr.io/oss-fuzz-base/base-builder-rust

RUN git clone --depth 1 https://github.com/nss-dev/nspr $SRC/nspr
RUN git clone --depth 1 https://github.com/nss-dev/nss $SRC/nss
RUN git clone --depth 1 https://github.com/mozilla/neqo $SRC/neqo
RUN ls -l $SRC

RUN apt-get update && apt-get install -y --no-install-recommends \
        libclang-dev gyp ninja-build python-is-python3 zlib1g-dev \
        && apt-get autoremove -y && apt-get clean -y \
        && rm -rf /var/lib/apt/lists/*

# We unfortunately need to build NSS from source, because the Debian package
# in the base distribution is too old.
ENV NSS_DIR=$SRC/nss NSS_PREBUILT=1

# FIXME: Optimized NSS build fails with assembler errors.
# Maybe not critical since the fuzzer uses AeadNull.
RUN CXX="$CXX -stdlib=libc++" $SRC/nss/build.sh --static --disable-tests

RUN rustup default nightly
RUN rustup component add --toolchain nightly rust-src

WORKDIR $SRC
COPY build.sh $SRC/
