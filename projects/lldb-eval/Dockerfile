FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update \
    && apt-get install -y build-essential make cmake ninja-build git binutils-dev zlib1g-dev libtinfo-dev patchelf --no-install-recommends

RUN git clone --depth 1 --single-branch --branch release/11.x https://github.com/llvm/llvm-project
RUN git clone --depth 1 https://github.com/google/lldb-eval

COPY build.sh $SRC/

WORKDIR $SRC/lldb-eval
