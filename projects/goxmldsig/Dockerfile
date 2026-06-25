FROM gcr.io/oss-fuzz-base/base-builder-go

RUN git clone --depth 1 https://github.com/russellhaering/goxmldsig
COPY build.sh $SRC/
WORKDIR $SRC/goxmldsig
