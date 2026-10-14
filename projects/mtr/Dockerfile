FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y \
    zip \
    autoconf \
    automake \
    libtool \
    pkg-config \
    libncurses-dev \
    libcap-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/traviscross/mtr.git $SRC/mtr

COPY build.sh $SRC/

WORKDIR $SRC/mtr

