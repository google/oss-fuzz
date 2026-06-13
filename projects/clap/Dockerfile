# Copyright 2026 Google LLC
FROM gcr.io/oss-fuzz-base/base-builder-rust
RUN git clone --depth 1 https://github.com/clap-rs/clap.git clap
WORKDIR clap
COPY build.sh $SRC/
