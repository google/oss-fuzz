# Copyright 2026 Google LLC
FROM gcr.io/oss-fuzz-base/base-builder-rust
RUN git clone --depth 1 https://github.com/actix/actix-web actix-web
WORKDIR actix-web
COPY build.sh $SRC/
