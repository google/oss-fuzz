# OSS-Fuzz Dockerfile for libiqxmlrpc
# Copyright (C) 2024 libiqxmlrpc contributors

FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y \
    libboost-dev \
    libboost-date-time-dev \
    libboost-thread-dev \
    libxml2-dev \
    libssl-dev \
    pkg-config \
    zlib1g-dev \
    liblzma-dev \
    libicu-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/yarikmsu/libiqxmlrpc.git $SRC/libiqxmlrpc
WORKDIR $SRC/libiqxmlrpc

COPY build.sh $SRC/
