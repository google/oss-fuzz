FROM gcr.io/oss-fuzz-base/base-builder-rust
RUN git clone --depth 1 https://github.com/intelogroup/spif.git spif
COPY build.sh $SRC/
WORKDIR spif/spif-rust
