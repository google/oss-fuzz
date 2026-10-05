FROM gcr.io/oss-fuzz-base/base-builder-rust

RUN git clone --depth 1 https://github.com/indygreg/cryptography-rs

WORKDIR cryptography-rs/x509-certificate
COPY build.sh $SRC/
