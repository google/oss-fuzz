FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y cmake

RUN git clone --depth 1 https://github.com/aklomp/base64.git

WORKDIR base64
COPY build.sh base64_fuzzer.cc $SRC/
