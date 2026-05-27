FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y \
    cmake \
    curl \
    git \
    python3 \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install Bazel via Bazelisk
RUN wget https://github.com/bazelbuild/bazelisk/releases/latest/download/bazelisk-linux-amd64 \
    -O /usr/local/bin/bazel && \
    chmod +x /usr/local/bin/bazel

# Clone gRPC with submodules
RUN git clone --depth=1 https://github.com/grpc/grpc.git $SRC/grpc && \
    cd $SRC/grpc && \
    git submodule update --init --recursive --depth=1

COPY build.sh $SRC/
WORKDIR $SRC/grpc
