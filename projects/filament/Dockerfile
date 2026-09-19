FROM gcr.io/oss-fuzz-base/base-builder
RUN git clone --depth 1 https://github.com/google/filament.git $SRC/filament
COPY build.sh fuzz_gltf_meshopt.cpp $SRC/
WORKDIR $SRC
