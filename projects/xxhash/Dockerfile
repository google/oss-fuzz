FROM gcr.io/oss-fuzz-base/base-builder

RUN git clone --depth 1 https://github.com/Cyan4973/xxHash.git

WORKDIR xxHash
COPY build.sh xxhash_fuzzer.cc $SRC/
