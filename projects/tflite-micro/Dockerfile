FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y make python3

RUN git clone --depth 1 https://github.com/tensorflow/tflite-micro /src/tflite-micro

WORKDIR /src/tflite-micro

# Download third-party dependencies (flatbuffers, gemmlowp, etc.)
RUN make -f tensorflow/lite/micro/tools/make/Makefile third_party_downloads

COPY build.sh $SRC/
