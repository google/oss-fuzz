# Copyright 2026 the Linux Foundation and the
# OpenSSF Best Practices badge contributors
# SPDX-License-Identifier: MIT

FROM gcr.io/oss-fuzz-base/base-builder-ruby

# commonmarker ships a pre-built x86_64-linux native gem (backed by Rust/comrak),
# so no Rust toolchain is required in this image.

RUN git clone --depth=1 \
    https://github.com/coreinfrastructure/best-practices-badge.git \
    "$SRC/best-practices-badge"

COPY build.sh "$SRC/"
