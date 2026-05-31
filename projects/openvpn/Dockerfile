FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libssl-dev \
        liblz4-dev \
        liblzo2-dev \
        libpkcs11-helper1-dev \
        libnl-genl-3-dev \
        libcap-ng-dev \
        autoconf \
        automake \
        libtool \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/OpenVPN/openvpn $SRC/openvpn
COPY build.sh $SRC/
COPY fuzz_options.c $SRC/
COPY fuzz_tls_pre_decrypt.c $SRC/
WORKDIR $SRC/openvpn
