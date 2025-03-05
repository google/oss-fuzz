FROM gcr.io/oss-fuzz-base/base-builder-rust

RUN git clone --depth 1 https://github.com/mozilla/neqo neqo
WORKDIR $SRC

COPY build.sh $SRC/
