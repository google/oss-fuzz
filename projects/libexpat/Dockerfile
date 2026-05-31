FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends cmake && \
    rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/libexpat/libexpat.git

WORKDIR $SRC/libexpat/expat
COPY build.sh $SRC/
