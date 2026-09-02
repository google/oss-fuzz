FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y cmake
RUN git clone --depth 1 https://github.com/google/draco.git /src/draco
COPY build.sh fuzz_decode.cc $SRC/
WORKDIR $SRC/draco
