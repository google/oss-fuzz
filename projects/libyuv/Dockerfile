FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y cmake make
RUN git clone --depth 1 https://chromium.googlesource.com/libyuv/libyuv
WORKDIR /libyuv/
COPY build.sh libyuv_fuzzer.cc *.options $SRC/
