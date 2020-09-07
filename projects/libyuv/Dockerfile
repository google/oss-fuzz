FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update
RUN git clone https://chromium.googlesource.com/libyuv/libyuv

WORKDIR $SRC
COPY libyuv_rotate_fuzzer.options $SRC/libyuv_rotate_fuzzer.options
COPY libyuv_rotate_fuzzer.cc $SRC/libyuv_rotate_fuzzer.cc
COPY build.sh $SRC/