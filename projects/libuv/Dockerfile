FROM gcr.io/oss-fuzz-base/base-builder

# Install build dependencies
RUN apt-get update && apt-get install -y make cmake

# Clone the target repository
RUN git clone --depth 1 https://github.com/libuv/libuv.git libuv

WORKDIR libuv
COPY build.sh $SRC/
