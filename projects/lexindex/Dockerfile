FROM gcr.io/oss-fuzz-base/base-builder-rust
RUN git clone --depth 1 https://github.com/ilgrad/lexindex lexindex
WORKDIR lexindex
COPY build.sh $SRC/
