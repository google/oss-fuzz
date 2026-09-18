FROM gcr.io/oss-fuzz-base/base-builder
RUN git clone --depth 1 https://github.com/jkuhlmann/cgltf.git /src/cgltf
WORKDIR /src/cgltf
COPY build.sh $SRC/
