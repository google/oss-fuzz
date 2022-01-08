FROM gcr.io/oss-fuzz-base/base-builder
MAINTAINER y0un9n132@googlt.com
RUN git clone --depth 1 https://github.com/n132/libfuzzer-go

WORKDIR libfuzzer-go

COPY build.sh *.options $SRC/

