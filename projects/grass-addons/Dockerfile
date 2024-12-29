FROM gcr.io/oss-fuzz-base/base-builder
RUN git clone --depth 1 https://github.com/OSGeo/grass-addons.git /src/grass-addons
WORKDIR /src/grass-addons
COPY build.sh $SRC/