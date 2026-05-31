FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y \
    cmake \
    libjpeg-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth=1 https://github.com/jasper-software/jasper.git

WORKDIR jasper

COPY build.sh $SRC/
COPY jasper_decode_fuzzer.c $SRC/
COPY jasper_encode_fuzzer.c $SRC/
COPY jasper_transcode_fuzzer.c $SRC/
