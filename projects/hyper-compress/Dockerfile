FROM gcr.io/oss-fuzz-base/base-builder

RUN git clone --depth 1 \
    https://chromium.googlesource.com/chromium/tools/depot_tools.git \
    /opt/depot_tools
ENV PATH="/opt/depot_tools:${PATH}"

RUN git clone --depth 1 https://github.com/alam00000/bentopdf-hyper-compress.git $SRC/hyper-compress
WORKDIR $SRC/hyper-compress
COPY build.sh $SRC/
