FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y cmake

RUN git clone --depth 1 https://github.com/simdjson/simdjson.git

WORKDIR simdjson
COPY build.sh simdjson_fuzzer.cc $SRC/
