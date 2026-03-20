FROM gcr.io/oss-fuzz-base/base-builder-go
RUN git clone --depth 1 https://github.com/go-jose/go-jose go-jose
COPY build.sh $SRC/
COPY fuzz_*.go $SRC/go-jose/
WORKDIR $SRC/go-jose
