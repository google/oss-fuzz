# Copyright 2026 Google LLC
FROM gcr.io/oss-fuzz-base/base-builder-javascript
COPY build.sh $SRC/
RUN git clone --depth 1 https://github.com/jquery/jquery
moment/moment.git
COPY fuzz.js $SRC/jquery
WORKDIR $SRC/jquery
