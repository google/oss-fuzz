FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y make

RUN git clone --depth 1 https://github.com/facebook/zstd.git

WORKDIR zstd
COPY build.sh zstd_fuzzer.cc $SRC/
