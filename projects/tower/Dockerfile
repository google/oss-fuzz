# Copyright 2026 Google LLC
FROM gcr.io/oss-fuzz-base/base-builder-rust
RUN git clone --depth 1 https://github.com/tower-rs/tower.git tower
WORKDIR tower
COPY build.sh $SRC/
