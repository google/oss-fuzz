# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Defines a docker image that can build fuzzers.
#
FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y make libssl-dev binutils libgcc-9-dev
RUN git clone --depth 1 https://chromium.googlesource.com/chromiumos/third_party/tpm2
WORKDIR tpm2
RUN cp /src/tpm2/fuzz/build.sh /src/
