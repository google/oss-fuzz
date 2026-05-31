FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libssl-dev \
        libavahi-client-dev \
        libavahi-common-dev \
        libgnutls28-dev \
        libkrb5-dev \
        libpam-dev \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/apple/cups $SRC/cups
COPY build.sh $SRC/
COPY fuzz_ipp.c $SRC/
COPY fuzz_ppd.c $SRC/
COPY fuzz_http.c $SRC/
WORKDIR $SRC/cups
