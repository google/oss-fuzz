FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y cmake

RUN git clone --depth 1 https://github.com/ibireme/yyjson.git

WORKDIR yyjson
COPY build.sh yyjson_fuzzer.cc $SRC/
