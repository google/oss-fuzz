FROM gcr.io/oss-fuzz-base/base-builder
# Filament needs a recent CMake + Ninja; the base image already ships clang and
# the sanitizer/fuzzer runtimes used via $CC/$CXX/$CFLAGS/$LIB_FUZZING_ENGINE.
RUN apt-get update && \
    apt-get install -y --no-install-recommends ninja-build libc++-dev libc++abi-dev && \
    rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/google/filament.git $SRC/filament

WORKDIR $SRC/filament
# Fuzz target sources live alongside this integration (not yet upstreamed); they
# are dropped into a dedicated libs/ subdirectory by build.sh.
COPY filameshio_fuzzer.cpp gltfio_meshopt_fuzzer.cpp gltfio_accessor_fuzzer.cpp $SRC/
COPY build.sh $SRC/
