# Build Stage
FROM gcr.io/oss-fuzz-base/base-builder-rust as builder

## Install build dependencies.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y cmake clang curl
RUN git clone --depth 1 https://github.com/cloud-hypervisor/cloud-hypervisor.git
COPY build.sh $SRC/



