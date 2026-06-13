# Copyright 2026 Google LLC
FROM gcr.io/oss-fuzz-base/base-builder-rust
RUN git clone --depth 1 https://github.com/rwf2/Rocket.git rocket
WORKDIR rocket
COPY build.sh $SRC/
